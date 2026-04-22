use std::collections::HashMap;
use std::ffi::OsString;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper_util::client::legacy::Client as HttpClient;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use smallvec::SmallVec;

use arc_swap::ArcSwap;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use prefix_trie::PrefixMap;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::error::SocksError;
use crate::socks5::protocol::Address;

/// HTTP 客户端类型（用于 ACL 接口请求）
type AclHttpClient = HttpClient<HttpConnector, Empty<Bytes>>;

// ===== opt1 位标志常量 =====

/// bit0: 记录规则 action 日志
pub const OPT_LOG: u8 = 0b0000_0001;
/// bit1: 限制最大并发数（预留）
#[allow(dead_code)]
pub const OPT_MAX_CONCURRENCY: u8 = 0b0000_0010;
/// bit2: 限制单连接最大带宽（预留）
#[allow(dead_code)]
pub const OPT_MAX_BANDWIDTH: u8 = 0b0000_0100;

// ===== 规则数据结构 =====

/// 规则匹配类型
#[derive(Debug, Clone, PartialEq)]
pub enum RuleType {
    /// 精确域名匹配
    Domain,
    /// 域名后缀匹配
    DomainSuffix,
    /// IP/CIDR 匹配（IPv4 + IPv6）
    IpCidr,
}

/// 规则动作
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RuleAction {
    /// 放行
    Pass,
    /// 阻止
    Block,
}

/// 单条目标规则（解析后）
#[derive(Debug, Clone)]
pub struct TargetRule {
    pub rule_type: RuleType,
    pub value: String,
    pub port_start: u16,
    pub port_end: u16,
    pub action: RuleAction,
    /// opt1 解析后的位标志
    pub opt_flags: u8,
    /// opt2 数值
    pub opt_value: f64,
}

/// 匹配结果
pub struct MatchResult {
    pub allowed: bool,
    pub log: bool,
    /// 完整的位标志，供未来扩展使用
    pub opt_flags: u8,
    /// 数值参数，供未来扩展使用
    pub opt_value: f64,
    /// 命中的规则描述（如 "IPCIDR 10.0.0.0/8 0-65535 PASS"），未命中时为 None
    pub matched_rule: Option<String>,
}

// ===== 内部数据结构 =====

/// 带优先级的规则条目，priority 越小优先级越高（配置文件中越靠前）
#[derive(Debug, Clone)]
struct PrioritizedRule {
    priority: usize,
    port_start: u16,
    port_end: u16,
    action: RuleAction,
    opt_flags: u8,
    opt_value: f64,
    /// 规则描述，用于日志输出（如 "IPCIDR 10.0.0.0/8 0-65535 PASS"）
    rule_desc: String,
}

impl PrioritizedRule {
    #[inline]
    fn port_matches(&self, port: u16) -> bool {
        port >= self.port_start && port <= self.port_end
    }

    #[inline]
    fn is_higher_priority_than(&self, other: Option<&PrioritizedRule>) -> bool {
        match other {
            None => true,
            Some(o) => self.priority < o.priority,
        }
    }
}

/// 倒序域名 Trie 节点
///
/// 域名按 '.' 分割后倒序插入，例如：
/// - "baidu.com" → ["com", "baidu"]
/// - "test.com.cn" → ["cn", "com", "test"]
///
/// Trie 结构示例（规则: DOMAIN-SUFFIX baidu.com, DOMAIN-SUFFIX test.com.cn）：
/// ```text
/// Root
///  ├─ "com"
///  │   └─ "baidu" [suffix_rules: ...]
///  └─ "cn"
///      └─ "com"
///          └─ "test" [suffix_rules: ...]
/// ```
#[derive(Debug)]
struct TrieNode {
    /// 子节点映射：label → child node
    /// 使用 Box<str> 作为 key 减少内存开销（比 String 少 8 字节）
    children: HashMap<Box<str>, TrieNode>,
    /// 该节点上的 DOMAIN-SUFFIX 规则（如果有）
    suffix_rules: Vec<PrioritizedRule>,
}

impl TrieNode {
    fn new() -> Self {
        Self {
            children: HashMap::new(),
            suffix_rules: Vec::new(),
        }
    }

    /// 插入一条后缀规则
    /// labels 为域名按 '.' 分割后的倒序切片
    fn insert(&mut self, labels: &[&str], rule: PrioritizedRule) {
        let mut node = self;
        for &label in labels {
            node = node
                .children
                .entry(label.into())
                .or_insert_with(TrieNode::new);
        }
        node.suffix_rules.push(rule);
    }

    /// 查找域名的所有匹配后缀规则，返回优先级最高的
    /// labels 为待查询域名按 '.' 分割后的倒序切片
    fn find_best_match<'a>(
        &'a self,
        labels: &[&str],
        port: u16,
        mut best: Option<&'a PrioritizedRule>,
    ) -> Option<&'a PrioritizedRule> {
        let mut node = self;

        for &label in labels {
            match node.children.get(label) {
                Some(child) => {
                    node = child;
                    // 检查到达的节点是否有后缀规则
                    for r in &node.suffix_rules {
                        if r.port_matches(port) && r.is_higher_priority_than(best) {
                            best = Some(r);
                        }
                    }
                }
                None => break, // 提前终止：路径不存在
            }
        }

        best
    }
}


// ===== 配置文件解析 =====

/// 配置文件根结构
#[derive(Debug, Deserialize)]
struct TargetRulesConfig {
    #[serde(default)]
    target_rules: Vec<Vec<serde_yaml::Value>>,
}

/// 解析单条规则数组（5-7 元素）
fn parse_rule_array(arr: &[serde_yaml::Value], index: usize) -> Result<TargetRule, SocksError> {
    // 元素数量校验：最少 5 个，最多 7 个
    if arr.len() < 5 || arr.len() > 7 {
        return Err(SocksError::TargetRulesConfig(format!(
            "Rule #{}: expected 5-7 elements, got {}",
            index + 1,
            arr.len()
        )));
    }

    // type 解析
    let rule_type = match arr[0].as_str().unwrap_or("") {
        "DOMAIN" => RuleType::Domain,
        "DOMAIN-SUFFIX" => RuleType::DomainSuffix,
        "IPCIDR" => RuleType::IpCidr,
        other => {
            return Err(SocksError::TargetRulesConfig(format!(
                "Rule #{}: unknown type '{}'",
                index + 1,
                other
            )))
        }
    };

    // value 解析（容错：非字符串类型尝试 to_string 转换）
    let value = match arr[1].as_str() {
        Some(s) => s.to_string(),
        None => {
            // 某些 YAML 值可能被解析为非字符串（如纯数字），尝试转换
            let s = serde_yaml::to_string(&arr[1])
                .unwrap_or_default()
                .trim()
                .to_string();
            if s.is_empty() || s == "~" || s == "null" {
                return Err(SocksError::TargetRulesConfig(format!(
                    "Rule #{}: value field is empty or null, \
                     use quotes for special values like \"::1/128\"",
                    index + 1
                )));
            }
            s
        }
    };

    // value 非空校验
    if value.is_empty() {
        return Err(SocksError::TargetRulesConfig(format!(
            "Rule #{}: value field cannot be empty",
            index + 1
        )));
    }

    // port 解析
    let port_start = arr[2].as_u64().unwrap_or(0) as u16;
    let port_end = arr[3].as_u64().unwrap_or(65535) as u16;

    // port_start <= port_end 校验
    if port_start > port_end {
        return Err(SocksError::TargetRulesConfig(format!(
            "Rule #{}: port_start ({}) > port_end ({})",
            index + 1,
            port_start,
            port_end
        )));
    }

    // action 解析
    let action = match arr[4].as_str().unwrap_or("") {
        "PASS" => RuleAction::Pass,
        "BLOCK" => RuleAction::Block,
        other => {
            return Err(SocksError::TargetRulesConfig(format!(
                "Rule #{}: unknown action '{}'",
                index + 1,
                other
            )))
        }
    };

    // opt1: 0-255 整数（位标志），默认 0
    let opt_flags = if arr.len() > 5 {
        let opt1_val = arr[5].as_u64().ok_or_else(|| {
            SocksError::TargetRulesConfig(format!(
                "Rule #{}: invalid opt1: expected integer 0-255",
                index + 1
            ))
        })?;
        if opt1_val > 255 {
            return Err(SocksError::TargetRulesConfig(format!(
                "Rule #{}: invalid opt1 '{}': expected integer 0-255",
                index + 1,
                opt1_val
            )));
        }
        opt1_val as u8
    } else {
        0
    };

    // opt2: 浮点数，默认 0.0
    let opt_value = if arr.len() > 6 {
        arr[6].as_f64().unwrap_or(0.0)
    } else {
        0.0
    };

    Ok(TargetRule {
        rule_type,
        value,
        port_start,
        port_end,
        action,
        opt_flags,
        opt_value,
    })
}

// ===== 高性能规则集 =====

#[derive(Debug)]
pub struct TargetRuleSet {
    /// DOMAIN 精确匹配索引：key 为小写域名
    domain_index: HashMap<String, Vec<PrioritizedRule>>,
    /// DOMAIN-SUFFIX 后缀匹配：倒序域名 Trie
    suffix_trie: TrieNode,
    /// IPCIDR IPv4 规则 Radix Trie：key 为 Ipv4Net，value 为 Vec<PrioritizedRule>
    /// 查找时通过 cover_values 遍历所有匹配前缀，取 priority 最小的（min-priority-wins）
    cidr_trie_v4: PrefixMap<Ipv4Net, Vec<PrioritizedRule>>,
    /// IPCIDR IPv6 规则 Radix Trie
    cidr_trie_v6: PrefixMap<Ipv6Net, Vec<PrioritizedRule>>,
    /// 规则总数（用于日志/调试）
    total_rules: usize,
}

impl TargetRuleSet {
    /// 从解析后的规则列表编译为高性能索引结构
    pub fn compile(rules: Vec<TargetRule>) -> Result<Self, SocksError> {
        let total_rules = rules.len();
        let mut domain_index: HashMap<String, Vec<PrioritizedRule>> = HashMap::new();
        let mut suffix_trie = TrieNode::new();
        let mut cidr_trie_v4: PrefixMap<Ipv4Net, Vec<PrioritizedRule>> = PrefixMap::new();
        let mut cidr_trie_v6: PrefixMap<Ipv6Net, Vec<PrioritizedRule>> = PrefixMap::new();

        for (priority, rule) in rules.into_iter().enumerate() {
            let rule_type_str = match &rule.rule_type {
                RuleType::Domain => "DOMAIN",
                RuleType::DomainSuffix => "DOMAIN-SUFFIX",
                RuleType::IpCidr => "IPCIDR",
            };
            let action_str = match rule.action {
                RuleAction::Pass => "PASS",
                RuleAction::Block => "BLOCK",
            };
            let rule_desc = format!(
                "{} {} {}-{} {}",
                rule_type_str, rule.value, rule.port_start, rule.port_end, action_str
            );

            let pr = PrioritizedRule {
                priority,
                port_start: rule.port_start,
                port_end: rule.port_end,
                action: rule.action,
                opt_flags: rule.opt_flags,
                opt_value: rule.opt_value,
                rule_desc,
            };

            match rule.rule_type {
                RuleType::Domain => {
                    let key = rule.value.to_ascii_lowercase();
                    domain_index.entry(key).or_default().push(pr);
                }
                RuleType::DomainSuffix => {
                    let lower = rule.value.to_ascii_lowercase();
                    let labels: Vec<&str> = lower.split('.').rev().collect();
                    suffix_trie.insert(&labels, pr);
                }
                RuleType::IpCidr => {
                    let network: IpNet = rule.value.parse::<IpNet>()
                        .map(|n| n.trunc()) // 显式规范化：10.0.0.128/24 → 10.0.0.0/24
                        .map_err(|e| {
                            SocksError::TargetRulesConfig(format!(
                                "Invalid CIDR '{}': {}",
                                rule.value, e
                            ))
                        })?;
                    match network {
                        IpNet::V4(v4net) => {
                            cidr_trie_v4.entry(v4net).or_default().push(pr);
                        }
                        IpNet::V6(v6net) => {
                            cidr_trie_v6.entry(v6net).or_default().push(pr);
                        }
                    }
                }
            }
        }

        Ok(Self {
            domain_index,
            suffix_trie,
            cidr_trie_v4,
            cidr_trie_v6,
            total_rules,
        })
    }

    /// 检查目标地址是否允许连接
    pub fn check(&self, address: &Address, port: u16) -> MatchResult {
        let best = match address {
            Address::Domain(domain) => self.match_domain(domain, port),
            Address::IPv4(ip) => self.match_cidr(&IpAddr::V4(*ip), port),
            Address::IPv6(ip) => self.match_cidr(&IpAddr::V6(*ip), port),
        };

        match best {
            Some(rule) => MatchResult {
                allowed: rule.action == RuleAction::Pass,
                log: rule.opt_flags & OPT_LOG != 0,
                opt_flags: rule.opt_flags,
                opt_value: rule.opt_value,
                matched_rule: Some(rule.rule_desc.clone()),
            },
            // 默认 BLOCK，不记录日志
            None => MatchResult {
                allowed: false,
                log: false,
                opt_flags: 0,
                opt_value: 0.0,
                matched_rule: None,
            },
        }
    }

    /// 域名匹配：查询 domain_index 和 suffix_trie，取全局优先级最高的
    ///
    /// 使用 `SmallVec<[&str; 8]>` 收集倒序 labels，域名层级 ≤ 8 时零堆分配。
    fn match_domain(&self, domain: &str, port: u16) -> Option<&PrioritizedRule> {
        let lower = domain.to_ascii_lowercase();
        let mut best: Option<&PrioritizedRule> = None;

        // 1. 精确域名匹配（HashMap O(1)）
        if let Some(rules) = self.domain_index.get(&lower) {
            for r in rules {
                if r.port_matches(port) && r.is_higher_priority_than(best) {
                    best = Some(r);
                }
            }
        }

        // 2. 后缀匹配：倒序 Trie 一次遍历
        //    对于 "api.test.com.cn"，倒序为 ["cn", "com", "test", "api"]
        //    沿 Trie 路径遍历，每个节点只 hash 一个短 label
        let labels: SmallVec<[&str; 8]> = lower.split('.').rev().collect();
        best = self.suffix_trie.find_best_match(&labels, port, best);

        best
    }

    /// Vec 版本的域名匹配（仅供 benchmark 对比）
    ///
    /// 与 `match_domain` 逻辑完全相同，唯一区别是使用 `Vec<&str>`
    /// 替代 `SmallVec<[&str; 8]>` 收集倒序 labels，用于量化 SmallVec 的收益。
    #[cfg(feature = "bench")]
    pub fn check_with_vec(&self, address: &Address, port: u16) -> MatchResult {
        let best = match address {
            Address::Domain(domain) => self.match_domain_vec(domain, port),
            Address::IPv4(ip) => self.match_cidr(&IpAddr::V4(*ip), port),
            Address::IPv6(ip) => self.match_cidr(&IpAddr::V6(*ip), port),
        };

        match best {
            Some(rule) => MatchResult {
                allowed: rule.action == RuleAction::Pass,
                log: rule.opt_flags & OPT_LOG != 0,
                opt_flags: rule.opt_flags,
                opt_value: rule.opt_value,
                matched_rule: Some(rule.rule_desc.clone()),
            },
            None => MatchResult {
                allowed: false,
                log: false,
                opt_flags: 0,
                opt_value: 0.0,
                matched_rule: None,
            },
        }
    }

    /// Vec 版本的 match_domain（仅供 benchmark 对比）
    #[cfg(feature = "bench")]
    fn match_domain_vec(&self, domain: &str, port: u16) -> Option<&PrioritizedRule> {
        let lower = domain.to_ascii_lowercase();
        let mut best: Option<&PrioritizedRule> = None;

        if let Some(rules) = self.domain_index.get(&lower) {
            for r in rules {
                if r.port_matches(port) && r.is_higher_priority_than(best) {
                    best = Some(r);
                }
            }
        }

        let labels: Vec<&str> = lower.split('.').rev().collect();
        best = self.suffix_trie.find_best_match(&labels, port, best);

        best
    }

    /// CIDR 匹配：使用 Radix Trie 的 cover_values 遍历所有匹配前缀，
    /// 取 priority 最小且端口匹配的规则（min-priority-wins 语义）。
    ///
    /// 复杂度 O(W)（W = 32 或 128），与规则数量无关。
    fn match_cidr(&self, ip: &IpAddr, port: u16) -> Option<&PrioritizedRule> {
        let normalized = normalize_ip(*ip);

        match normalized {
            IpAddr::V4(v4) => {
                let host_prefix = Ipv4Net::new(v4, 32).unwrap();
                let mut best: Option<&PrioritizedRule> = None;
                for rules in self.cidr_trie_v4.cover_values(&host_prefix) {
                    for r in rules {
                        if r.port_matches(port) && r.is_higher_priority_than(best) {
                            best = Some(r);
                        }
                    }
                }
                best
            }
            IpAddr::V6(v6) => {
                let host_prefix = Ipv6Net::new(v6, 128).unwrap();
                let mut best: Option<&PrioritizedRule> = None;
                for rules in self.cidr_trie_v6.cover_values(&host_prefix) {
                    for r in rules {
                        if r.port_matches(port) && r.is_higher_priority_than(best) {
                            best = Some(r);
                        }
                    }
                }
                best
            }
        }
    }

    /// 返回规则总数
    pub fn rule_count(&self) -> usize {
        self.total_rules
    }
}

/// 将 IPv4-mapped IPv6 地址（`::ffff:x.x.x.x`）规范化为纯 IPv4 地址
///
/// 只处理标准的 IPv4-mapped 格式：`::ffff:x.x.x.x` → `x.x.x.x`
/// 纯 IPv4、纯 IPv6（包括 `::1` 等）保持不变。
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(v4)
            } else {
                IpAddr::V6(v6)
            }
        }
        IpAddr::V4(_) => ip,
    }
}

// ===== 外部 ACL 接口数据结构 =====

/// 外部 ACL 接口响应根结构
#[derive(Debug, Deserialize)]
pub struct AclResponse {
    pub data: AclData,
    #[allow(dead_code)]
    pub status: String,
}

/// ACL 数据层
#[derive(Debug, Deserialize)]
pub struct AclData {
    pub netacl: NetAcl,
}

/// 网络 ACL 规则
#[derive(Debug, Deserialize)]
pub struct NetAcl {
    #[serde(default, rename = "BlockDomains")]
    pub block_domains: Vec<String>,
    #[serde(default, rename = "PassDomains")]
    pub pass_domains: Vec<String>,
    #[serde(default, rename = "BlockIPs")]
    pub block_ips: Vec<String>,
    #[serde(default, rename = "PassIPs")]
    pub pass_ips: Vec<String>,
}

/// 将外部 ACL 接口数据转换为 target_rules YAML 格式字符串
pub fn convert_acl_to_yaml(acl: &NetAcl) -> String {
    let mut lines = Vec::new();
    lines.push("# 此文件由代理服务器自动生成，请勿手动修改".to_string());
    lines.push("# 数据来源：外部 ACL 接口定期拉取".to_string());
    lines.push(String::new());
    lines.push("target_rules:".to_string());

    // BlockDomains: 以 '.' 开头的为后缀匹配，否则为精确匹配
    for domain in &acl.block_domains {
        if let Some(suffix) = domain.strip_prefix('.') {
            lines.push(format!("  - [DOMAIN-SUFFIX, {}, 0, 65535, BLOCK, 1]", suffix));
        } else {
            lines.push(format!("  - [DOMAIN, {}, 0, 65535, BLOCK, 1]", domain));
        }
    }

    // PassDomains: 以 '.' 开头的为后缀匹配，否则为精确匹配
    for domain in &acl.pass_domains {
        if let Some(suffix) = domain.strip_prefix('.') {
            lines.push(format!("  - [DOMAIN-SUFFIX, {}, 0, 65535, PASS, 1]", suffix));
        } else {
            lines.push(format!("  - [DOMAIN, {}, 0, 65535, PASS, 1]", domain));
        }
    }

    // BlockIPs: CIDR 阻止
    for cidr in &acl.block_ips {
        lines.push(format!("  - [IPCIDR, {}, 0, 65535, BLOCK, 1]", cidr));
    }

    // PassIPs: CIDR 放行
    for cidr in &acl.pass_ips {
        lines.push(format!("  - [IPCIDR, {}, 0, 65535, PASS, 1]", cidr));
    }

    lines.join("\n") + "\n"
}

// ===== 热加载控制器 =====

#[derive(Debug)]
pub struct TargetRuleControl {
    rules: Arc<ArcSwap<TargetRuleSet>>,
    /// 动态规则文件路径（用户自定义，高优先级）
    dynamic_file: PathBuf,
    /// 静态规则文件路径（外部接口拉取，低优先级）
    static_file: PathBuf,
}

impl TargetRuleControl {
    /// 从双 YAML 文件加载目标规则（dynamic 优先级高于 static）
    pub fn load(dynamic_path: &Path, static_path: &Path) -> Result<Self, SocksError> {
        let merged_rules = Self::load_merged_rules(dynamic_path, static_path)?;
        let count = merged_rules.rule_count();
        info!(
            dynamic = %dynamic_path.display(),
            r#static = %static_path.display(),
            rules = count,
            "Target rules loaded (dynamic + static)"
        );
        Ok(Self {
            rules: Arc::new(ArcSwap::from_pointee(merged_rules)),
            dynamic_file: dynamic_path.to_path_buf(),
            static_file: static_path.to_path_buf(),
        })
    }

    /// 获取当前规则集的快照（无锁读取）
    pub fn rules(&self) -> arc_swap::Guard<Arc<TargetRuleSet>> {
        self.rules.load()
    }

    /// 重新加载规则文件，原子替换规则集
    pub fn reload(&self) -> Result<(), SocksError> {
        let new_rules = Self::load_merged_rules(&self.dynamic_file, &self.static_file)?;
        let count = new_rules.rule_count();
        self.rules.store(Arc::new(new_rules));
        info!(
            dynamic = %self.dynamic_file.display(),
            r#static = %self.static_file.display(),
            rules = count,
            "Target rules reloaded (dynamic + static)"
        );
        Ok(())
    }

    /// 启动文件变更监听，同时监听 dynamic 和 static 两个文件
    /// 返回 watchers（调用方需保持其存活）
    pub fn watch(self: &Arc<Self>) -> Result<Vec<RecommendedWatcher>, SocksError> {
        let mut watchers = Vec::new();

        // 收集需要监听的 (目录, 文件名) 对，自动去重同目录
        let files = [&self.dynamic_file, &self.static_file];
        let mut dir_to_filenames: HashMap<PathBuf, Vec<OsString>> = HashMap::new();

        for file in &files {
            let canonical = file
                .canonicalize()
                .unwrap_or_else(|_| (*file).clone());
            let dir = canonical
                .parent()
                .map(|p| p.to_path_buf())
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| PathBuf::from("."));
            let name = canonical
                .file_name()
                .unwrap_or_default()
                .to_os_string();
            dir_to_filenames.entry(dir).or_default().push(name);
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);

        for (watch_dir, filenames) in &dir_to_filenames {
            let tx = tx.clone();
            let filenames_for_log: Vec<OsString> = filenames.clone();
            let filenames_for_closure: Vec<OsString> = filenames.clone();

            let mut watcher = notify::recommended_watcher(
                move |result: Result<notify::Event, notify::Error>| {
                    match result {
                        Ok(event) => {
                            use notify::EventKind;
                            match event.kind {
                                EventKind::Create(_)
                                | EventKind::Modify(_)
                                | EventKind::Remove(_) => {}
                                _ => return,
                            }

                            let affects_target = event.paths.iter().any(|p| {
                                p.file_name()
                                    .map(|n| filenames_for_closure.iter().any(|f| f == n))
                                    .unwrap_or(false)
                            });

                            if affects_target {
                                let _ = tx.try_send(());
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "Target rules file watcher error");
                        }
                    }
                },
            )
            .map_err(|e| {
                SocksError::TargetRulesConfig(format!("Failed to create file watcher: {}", e))
            })?;

            watcher
                .watch(watch_dir, RecursiveMode::NonRecursive)
                .map_err(|e| {
                    SocksError::TargetRulesConfig(format!(
                        "Failed to watch directory {}: {}",
                        watch_dir.display(),
                        e
                    ))
                })?;

            info!(
                dir = %watch_dir.display(),
                files = ?filenames_for_log,
                "Target rules file watcher started"
            );

            watchers.push(watcher);
        }

        // 启动防抖消费任务
        let trc = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                if rx.recv().await.is_none() {
                    break;
                }

                // 防抖：等待 500ms，期间消费掉所有后续事件
                tokio::time::sleep(Duration::from_millis(500)).await;
                while rx.try_recv().is_ok() {}

                match trc.reload() {
                    Ok(()) => {}
                    Err(e) => {
                        warn!(
                            error = %e,
                            "Failed to reload target rules, keeping previous rules"
                        );
                    }
                }
            }
        });

        Ok(watchers)
    }

    /// 启动定期拉取外部 ACL 接口任务
    ///
    /// 定期从 `fetch_url` 拉取 ACL 数据，转换为 target-rules YAML 格式，
    /// 写入 `static_file`。文件变更后 watcher 会自动触发 reload。
    pub fn start_fetch_task(
        self: &Arc<Self>,
        fetch_url: String,
        interval: Duration,
        cancel_token: CancellationToken,
    ) {
        let static_file = self.static_file.clone();

        let client: AclHttpClient = HttpClient::builder(TokioExecutor::new())
            .build_http();

        info!(
            url = %fetch_url,
            interval_secs = interval.as_secs(),
            static_file = %static_file.display(),
            "Static target rules fetch task started"
        );

        tokio::spawn(async move {
            // 首次立即拉取
            Self::fetch_and_write_static(&client, &fetch_url, &static_file).await;

            let mut tick = tokio::time::interval(interval);
            tick.tick().await; // 跳过首次立即触发的 tick

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        info!("Static target rules fetch task stopped");
                        break;
                    }
                    _ = tick.tick() => {
                        Self::fetch_and_write_static(&client, &fetch_url, &static_file).await;
                    }
                }
            }
        });
    }

    /// 从外部 ACL 接口拉取数据并写入静态规则文件
    ///
    /// 写入成功后由 file watcher 自动检测变更并触发 reload（防抖 500ms），
    /// 不在此处主动 reload，避免双重 reload。
    async fn fetch_and_write_static(
        client: &AclHttpClient,
        fetch_url: &str,
        static_file: &Path,
    ) {
        match Self::fetch_acl(client, fetch_url).await {
            Ok(yaml_content) => {
                // 校验生成的 YAML 可被正确解析为规则，防止恶意/异常数据破坏静态规则文件
                if let Err(e) = Self::validate_yaml_rules(&yaml_content) {
                    error!(
                        error = %e,
                        url = %fetch_url,
                        "Generated YAML from remote ACL is invalid, keeping previous static rules"
                    );
                    return;
                }
                // 原子写入：先写临时文件再 rename，避免写入中途崩溃留下半截文件
                let tmp_file = static_file.with_extension("yaml.tmp");
                match tokio::fs::write(&tmp_file, &yaml_content).await {
                    Ok(()) => {
                        if let Err(e) = tokio::fs::rename(&tmp_file, static_file).await {
                            error!(
                                error = %e,
                                tmp = %tmp_file.display(),
                                target = %static_file.display(),
                                "Failed to rename tmp file to static target rules file"
                            );
                            // 清理临时文件
                            let _ = tokio::fs::remove_file(&tmp_file).await;
                        } else {
                            info!(
                                path = %static_file.display(),
                                "Static target rules file updated from remote ACL, watcher will trigger reload"
                            );
                        }
                    }
                    Err(e) => {
                        error!(
                            error = %e,
                            path = %tmp_file.display(),
                            "Failed to write tmp static target rules file"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(
                    error = %e,
                    url = %fetch_url,
                    "Failed to fetch ACL from remote, keeping previous static rules"
                );
            }
        }
    }

    /// 从外部 ACL 接口拉取数据并转换为 YAML 格式字符串
    async fn fetch_acl(client: &AclHttpClient, url: &str) -> Result<String, SocksError> {
        let uri: hyper::Uri = url.parse().map_err(|e: hyper::http::uri::InvalidUri| {
            SocksError::TargetRulesConfig(format!("Invalid URL '{}': {}", url, e))
        })?;

        let req = hyper::Request::get(uri)
            .body(Empty::<Bytes>::new())
            .map_err(|e| SocksError::TargetRulesConfig(format!(
                "Failed to build HTTP request: {}", e
            )))?;

        let response = tokio::time::timeout(
            Duration::from_secs(30),
            client.request(req),
        )
        .await
        .map_err(|_| SocksError::TargetRulesConfig(format!(
            "HTTP request to {} timed out", url
        )))?
        .map_err(|e| SocksError::TargetRulesConfig(format!(
            "HTTP request to {} failed: {}", url, e
        )))?;

        if !response.status().is_success() {
            return Err(SocksError::TargetRulesConfig(format!(
                "HTTP request to {} returned status {}", url, response.status()
            )));
        }

        let body = response.into_body().collect().await.map_err(|e| {
            SocksError::TargetRulesConfig(format!(
                "Failed to read response body from {}: {}", url, e
            ))
        })?;
        let bytes = body.to_bytes();

        let acl_response: AclResponse = serde_json::from_slice(&bytes).map_err(|e| {
            SocksError::TargetRulesConfig(format!(
                "Failed to parse ACL response from {}: {}", url, e
            ))
        })?;

        // 校验接口响应状态
        if acl_response.status != "ok" {
            return Err(SocksError::TargetRulesConfig(format!(
                "ACL response from {} returned status '{}', expected 'ok'",
                url, acl_response.status
            )));
        }

        Ok(convert_acl_to_yaml(&acl_response.data.netacl))
    }

    /// 校验生成的 YAML 内容是否可被正确解析为目标规则
    fn validate_yaml_rules(yaml_content: &str) -> Result<(), SocksError> {
        let config: TargetRulesConfig = serde_yaml::from_str(yaml_content).map_err(|e| {
            SocksError::TargetRulesConfig(format!("Invalid YAML format: {}", e))
        })?;
        for (i, arr) in config.target_rules.iter().enumerate() {
            parse_rule_array(arr, i)?;
        }
        Ok(())
    }

    /// 合并两份文件的规则（dynamic 在前，static 在后）
    fn load_merged_rules(
        dynamic_path: &Path,
        static_path: &Path,
    ) -> Result<TargetRuleSet, SocksError> {
        let dynamic_rules = Self::parse_rules_from_file(dynamic_path)?;
        let static_rules = Self::parse_rules_from_file(static_path)?;

        let dynamic_count = dynamic_rules.len();
        let static_count = static_rules.len();

        // dynamic 规则排前面（优先级高），static 排后面
        let mut merged = Vec::with_capacity(dynamic_count + static_count);
        merged.extend(dynamic_rules);
        merged.extend(static_rules);

        info!(
            dynamic_rules = dynamic_count,
            static_rules = static_count,
            total = merged.len(),
            "Merged target rules (dynamic first)"
        );

        TargetRuleSet::compile(merged)
    }

    /// 从 YAML 文件解析目标规则列表
    ///
    /// 文件不存在时返回空规则列表（static 文件初始可能不存在）
    fn parse_rules_from_file(path: &Path) -> Result<Vec<TargetRule>, SocksError> {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                info!(
                    path = %path.display(),
                    "Target rules file not found, using empty rules"
                );
                return Ok(Vec::new());
            }
            Err(e) => {
                return Err(SocksError::TargetRulesConfig(format!(
                    "Failed to read {}: {}",
                    path.display(),
                    e
                )));
            }
        };

        let config: TargetRulesConfig = serde_yaml::from_str(&content).map_err(|e| {
            SocksError::TargetRulesConfig(format!("Failed to parse {}: {}", path.display(), e))
        })?;

        let mut rules = Vec::with_capacity(config.target_rules.len());
        for (i, arr) in config.target_rules.iter().enumerate() {
            rules.push(parse_rule_array(arr, i)?);
        }

        Ok(rules)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ===== 辅助函数 =====

    fn make_rule(
        rule_type: RuleType,
        value: &str,
        port_start: u16,
        port_end: u16,
        action: RuleAction,
        opt_flags: u8,
        opt_value: f64,
    ) -> TargetRule {
        TargetRule {
            rule_type,
            value: value.to_string(),
            port_start,
            port_end,
            action,
            opt_flags,
            opt_value,
        }
    }

    // ===== parse_rule_array 测试 =====

    #[test]
    fn test_parse_7_element_array() {
        let arr: Vec<serde_yaml::Value> = vec![
            "DOMAIN-SUFFIX".into(),
            "baidu.com".into(),
            0u64.into(),
            65535u64.into(),
            "PASS".into(),
            1u64.into(),
            serde_yaml::Value::Number(serde_yaml::Number::from(1.5)),
        ];
        let rule = parse_rule_array(&arr, 0).unwrap();
        assert_eq!(rule.rule_type, RuleType::DomainSuffix);
        assert_eq!(rule.value, "baidu.com");
        assert_eq!(rule.port_start, 0);
        assert_eq!(rule.port_end, 65535);
        assert_eq!(rule.action, RuleAction::Pass);
        assert_eq!(rule.opt_flags, 1);
        assert!((rule.opt_value - 1.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_parse_5_element_array_defaults() {
        let arr: Vec<serde_yaml::Value> = vec![
            "DOMAIN".into(),
            "example.com".into(),
            443u64.into(),
            443u64.into(),
            "PASS".into(),
        ];
        let rule = parse_rule_array(&arr, 0).unwrap();
        assert_eq!(rule.rule_type, RuleType::Domain);
        assert_eq!(rule.value, "example.com");
        assert_eq!(rule.port_start, 443);
        assert_eq!(rule.port_end, 443);
        assert_eq!(rule.action, RuleAction::Pass);
        assert_eq!(rule.opt_flags, 0);
        assert!((rule.opt_value - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_parse_6_element_array() {
        let arr: Vec<serde_yaml::Value> = vec![
            "IPCIDR".into(),
            "10.0.0.0/8".into(),
            0u64.into(),
            65535u64.into(),
            "BLOCK".into(),
            3u64.into(),
        ];
        let rule = parse_rule_array(&arr, 0).unwrap();
        assert_eq!(rule.rule_type, RuleType::IpCidr);
        assert_eq!(rule.opt_flags, 3);
        assert!((rule.opt_value - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_parse_too_few_elements() {
        let arr: Vec<serde_yaml::Value> = vec![
            "DOMAIN".into(),
            "example.com".into(),
            0u64.into(),
            65535u64.into(),
        ];
        let result = parse_rule_array(&arr, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expected 5-7 elements"));
    }

    #[test]
    fn test_parse_too_many_elements() {
        let arr: Vec<serde_yaml::Value> = vec![
            "DOMAIN".into(),
            "example.com".into(),
            0u64.into(),
            65535u64.into(),
            "PASS".into(),
            0u64.into(),
            serde_yaml::Value::Number(serde_yaml::Number::from(0.0)),
            "extra".into(),
        ];
        let result = parse_rule_array(&arr, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expected 5-7 elements"));
    }

    #[test]
    fn test_parse_unknown_type() {
        let arr: Vec<serde_yaml::Value> = vec![
            "UNKNOWN".into(),
            "example.com".into(),
            0u64.into(),
            65535u64.into(),
            "PASS".into(),
        ];
        let result = parse_rule_array(&arr, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown type"));
    }

    #[test]
    fn test_parse_unknown_action() {
        let arr: Vec<serde_yaml::Value> = vec![
            "DOMAIN".into(),
            "example.com".into(),
            0u64.into(),
            65535u64.into(),
            "ALLOW".into(),
        ];
        let result = parse_rule_array(&arr, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown action"));
    }

    #[test]
    fn test_parse_invalid_opt1_not_integer() {
        let arr: Vec<serde_yaml::Value> = vec![
            "DOMAIN".into(),
            "example.com".into(),
            0u64.into(),
            65535u64.into(),
            "PASS".into(),
            "not_a_number".into(),
        ];
        let result = parse_rule_array(&arr, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid opt1"));
    }

    #[test]
    fn test_parse_invalid_opt1_out_of_range() {
        let arr: Vec<serde_yaml::Value> = vec![
            "DOMAIN".into(),
            "example.com".into(),
            0u64.into(),
            65535u64.into(),
            "PASS".into(),
            256u64.into(),
        ];
        let result = parse_rule_array(&arr, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid opt1"));
    }

    #[test]
    fn test_parse_port_start_greater_than_end() {
        let arr: Vec<serde_yaml::Value> = vec![
            "DOMAIN".into(),
            "example.com".into(),
            8080u64.into(),
            80u64.into(),
            "PASS".into(),
        ];
        let result = parse_rule_array(&arr, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("port_start"));
    }

    // ===== TargetRuleSet::compile 测试 =====

    #[test]
    fn test_compile_invalid_cidr() {
        let rules = vec![make_rule(
            RuleType::IpCidr,
            "not-a-cidr",
            0,
            65535,
            RuleAction::Block,
            0,
            0.0,
        )];
        let result = TargetRuleSet::compile(rules);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid CIDR"));
    }

    // ===== DOMAIN 精确匹配测试 =====

    #[test]
    fn test_domain_exact_match() {
        let rules = vec![make_rule(
            RuleType::Domain,
            "example.com",
            0,
            65535,
            RuleAction::Pass,
            0,
            0.0,
        )];
        let rs = TargetRuleSet::compile(rules).unwrap();

        let result = rs.check(&Address::Domain("example.com".to_string()), 80);
        assert!(result.allowed);

        let result = rs.check(&Address::Domain("other.com".to_string()), 80);
        assert!(!result.allowed);
    }

    #[test]
    fn test_domain_case_insensitive() {
        let rules = vec![make_rule(
            RuleType::Domain,
            "Example.COM",
            0,
            65535,
            RuleAction::Pass,
            0,
            0.0,
        )];
        let rs = TargetRuleSet::compile(rules).unwrap();

        let result = rs.check(&Address::Domain("example.com".to_string()), 80);
        assert!(result.allowed);

        let result = rs.check(&Address::Domain("EXAMPLE.COM".to_string()), 80);
        assert!(result.allowed);
    }

    // ===== DOMAIN-SUFFIX 后缀匹配测试 =====

    #[test]
    fn test_domain_suffix_match() {
        let rules = vec![make_rule(
            RuleType::DomainSuffix,
            "baidu.com",
            0,
            65535,
            RuleAction::Pass,
            0,
            0.0,
        )];
        let rs = TargetRuleSet::compile(rules).unwrap();

        // 子域名匹配
        let result = rs.check(&Address::Domain("www.baidu.com".to_string()), 80);
        assert!(result.allowed);

        let result = rs.check(&Address::Domain("tieba.baidu.com".to_string()), 80);
        assert!(result.allowed);

        // 精确匹配自身
        let result = rs.check(&Address::Domain("baidu.com".to_string()), 80);
        assert!(result.allowed);

        // 不误匹配 notbaidu.com
        let result = rs.check(&Address::Domain("notbaidu.com".to_string()), 80);
        assert!(!result.allowed);
    }

    // ===== IPCIDR 匹配测试 =====

    #[test]
    fn test_ipcidr_ipv4_match() {
        let rules = vec![
            make_rule(RuleType::IpCidr, "10.0.0.0/8", 0, 65535, RuleAction::Pass, 0, 0.0),
            make_rule(RuleType::IpCidr, "0.0.0.0/0", 0, 65535, RuleAction::Block, 0, 0.0),
        ];
        let rs = TargetRuleSet::compile(rules).unwrap();

        let result = rs.check(&Address::IPv4(Ipv4Addr::new(10, 1, 2, 3)), 80);
        assert!(result.allowed);

        let result = rs.check(&Address::IPv4(Ipv4Addr::new(192, 168, 1, 1)), 80);
        assert!(!result.allowed);
    }

    #[test]
    fn test_ipcidr_ipv4_host_route() {
        let rules = vec![make_rule(
            RuleType::IpCidr,
            "127.0.0.1/32",
            0,
            65535,
            RuleAction::Pass,
            0,
            0.0,
        )];
        let rs = TargetRuleSet::compile(rules).unwrap();

        let result = rs.check(&Address::IPv4(Ipv4Addr::new(127, 0, 0, 1)), 80);
        assert!(result.allowed);

        let result = rs.check(&Address::IPv4(Ipv4Addr::new(127, 0, 0, 2)), 80);
        assert!(!result.allowed);
    }

    #[test]
    fn test_ipcidr_ipv6_match() {
        let rules = vec![
            make_rule(RuleType::IpCidr, "::1/128", 0, 65535, RuleAction::Pass, 0, 0.0),
            make_rule(RuleType::IpCidr, "2001:db8::/32", 0, 65535, RuleAction::Pass, 0, 0.0),
            make_rule(RuleType::IpCidr, "::/0", 0, 65535, RuleAction::Block, 0, 0.0),
        ];
        let rs = TargetRuleSet::compile(rules).unwrap();

        let result = rs.check(&Address::IPv6(Ipv6Addr::LOCALHOST), 80);
        assert!(result.allowed);

        let result = rs.check(
            &Address::IPv6("2001:db8::1".parse().unwrap()),
            80,
        );
        assert!(result.allowed);

        let result = rs.check(
            &Address::IPv6("2001:db9::1".parse().unwrap()),
            80,
        );
        assert!(!result.allowed);
    }

    #[test]
    fn test_ipcidr_ipv4_mapped_ipv6_normalization() {
        // IPv4-mapped IPv6 地址应该能匹配 IPv4 CIDR 规则
        let rules = vec![make_rule(
            RuleType::IpCidr,
            "192.168.0.0/16",
            0,
            65535,
            RuleAction::Pass,
            0,
            0.0,
        )];
        let rs = TargetRuleSet::compile(rules).unwrap();

        // ::ffff:192.168.1.1 应该匹配 192.168.0.0/16
        let mapped: Ipv6Addr = "::ffff:192.168.1.1".parse().unwrap();
        let result = rs.check(&Address::IPv6(mapped), 80);
        assert!(result.allowed);

        // ::ffff:10.0.0.1 不应该匹配 192.168.0.0/16
        let mapped_outside: Ipv6Addr = "::ffff:10.0.0.1".parse().unwrap();
        let result = rs.check(&Address::IPv6(mapped_outside), 80);
        assert!(!result.allowed);
    }

    #[test]
    fn test_ipcidr_early_return() {
        // 验证 CIDR 匹配命中第一条即停止
        let rules = vec![
            make_rule(RuleType::IpCidr, "10.0.0.0/8", 0, 65535, RuleAction::Pass, 0, 0.0),
            make_rule(RuleType::IpCidr, "10.0.0.0/8", 0, 65535, RuleAction::Block, 0, 0.0),
        ];
        let rs = TargetRuleSet::compile(rules).unwrap();

        // 应该命中第一条 PASS，而不是第二条 BLOCK
        let result = rs.check(&Address::IPv4(Ipv4Addr::new(10, 1, 2, 3)), 80);
        assert!(result.allowed);
    }

    // ===== 端口范围测试 =====

    #[test]
    fn test_port_range_match() {
        let rules = vec![
            make_rule(RuleType::Domain, "example.com", 443, 443, RuleAction::Pass, 0, 0.0),
            make_rule(RuleType::Domain, "example.com", 8000, 9000, RuleAction::Pass, 0, 0.0),
        ];
        let rs = TargetRuleSet::compile(rules).unwrap();

        let result = rs.check(&Address::Domain("example.com".to_string()), 443);
        assert!(result.allowed);

        let result = rs.check(&Address::Domain("example.com".to_string()), 8500);
        assert!(result.allowed);

        let result = rs.check(&Address::Domain("example.com".to_string()), 80);
        assert!(!result.allowed);
    }

    // ===== 优先级测试 =====

    #[test]
    fn test_first_match_wins_domain() {
        // DOMAIN 和 DOMAIN-SUFFIX 的优先级由配置顺序决定
        let rules = vec![
            make_rule(RuleType::DomainSuffix, "example.com", 0, 65535, RuleAction::Block, 0, 0.0),
            make_rule(RuleType::Domain, "example.com", 0, 65535, RuleAction::Pass, 0, 0.0),
        ];
        let rs = TargetRuleSet::compile(rules).unwrap();

        // DOMAIN-SUFFIX 优先级更高（priority=0），应该 BLOCK
        let result = rs.check(&Address::Domain("example.com".to_string()), 80);
        assert!(!result.allowed);
    }

    #[test]
    fn test_cross_type_priority() {
        // DOMAIN 规则在前（priority=0），DOMAIN-SUFFIX 在后（priority=1）
        let rules = vec![
            make_rule(RuleType::Domain, "www.example.com", 0, 65535, RuleAction::Pass, 0, 0.0),
            make_rule(RuleType::DomainSuffix, "example.com", 0, 65535, RuleAction::Block, 0, 0.0),
        ];
        let rs = TargetRuleSet::compile(rules).unwrap();

        // www.example.com 同时匹配 DOMAIN(priority=0) 和 DOMAIN-SUFFIX(priority=1)
        // 应该取 priority=0 的 PASS
        let result = rs.check(&Address::Domain("www.example.com".to_string()), 80);
        assert!(result.allowed);

        // sub.example.com 只匹配 DOMAIN-SUFFIX，应该 BLOCK
        let result = rs.check(&Address::Domain("sub.example.com".to_string()), 80);
        assert!(!result.allowed);
    }

    // ===== 默认行为测试 =====

    #[test]
    fn test_empty_rules_blocks_all() {
        let rs = TargetRuleSet::compile(vec![]).unwrap();

        let result = rs.check(&Address::Domain("example.com".to_string()), 80);
        assert!(!result.allowed);
        assert!(!result.log);

        let result = rs.check(&Address::IPv4(Ipv4Addr::new(1, 2, 3, 4)), 80);
        assert!(!result.allowed);
    }

    // ===== opt_flags / opt_value 测试 =====

    #[test]
    fn test_opt_log_flag() {
        let rules = vec![
            make_rule(RuleType::Domain, "logged.com", 0, 65535, RuleAction::Pass, OPT_LOG, 0.0),
            make_rule(RuleType::Domain, "silent.com", 0, 65535, RuleAction::Pass, 0, 0.0),
        ];
        let rs = TargetRuleSet::compile(rules).unwrap();

        let result = rs.check(&Address::Domain("logged.com".to_string()), 80);
        assert!(result.allowed);
        assert!(result.log);

        let result = rs.check(&Address::Domain("silent.com".to_string()), 80);
        assert!(result.allowed);
        assert!(!result.log);
    }

    #[test]
    fn test_opt_flags_and_value_passthrough() {
        let rules = vec![make_rule(
            RuleType::Domain,
            "test.com",
            0,
            65535,
            RuleAction::Pass,
            0b0000_0111,
            42.5,
        )];
        let rs = TargetRuleSet::compile(rules).unwrap();

        let result = rs.check(&Address::Domain("test.com".to_string()), 80);
        assert!(result.allowed);
        assert_eq!(result.opt_flags, 0b0000_0111);
        assert!((result.opt_value - 42.5).abs() < f64::EPSILON);
    }

    // ===== rule_count 测试 =====

    #[test]
    fn test_rule_count() {
        let rules = vec![
            make_rule(RuleType::Domain, "a.com", 0, 65535, RuleAction::Pass, 0, 0.0),
            make_rule(RuleType::DomainSuffix, "b.com", 0, 65535, RuleAction::Pass, 0, 0.0),
            make_rule(RuleType::IpCidr, "10.0.0.0/8", 0, 65535, RuleAction::Pass, 0, 0.0),
        ];
        let rs = TargetRuleSet::compile(rules).unwrap();
        assert_eq!(rs.rule_count(), 3);
    }

    // ===== Radix Trie 优化验证测试 =====

    #[test]
    fn test_ipcidr_first_match_wins_with_trie() {
        // 宽范围 PASS（priority=0）+ 窄范围 BLOCK（priority=1）
        // min-priority-wins：宽范围优先级更高，应该 PASS
        let rules = vec![
            make_rule(RuleType::IpCidr, "10.0.0.0/8", 0, 65535, RuleAction::Pass, 0, 0.0),
            make_rule(RuleType::IpCidr, "10.1.0.0/16", 0, 65535, RuleAction::Block, 0, 0.0),
        ];
        let rs = TargetRuleSet::compile(rules).unwrap();

        // 10.1.2.3 同时匹配 10.0.0.0/8 和 10.1.0.0/16
        // 应该取 priority=0 的 PASS（宽范围，配置在前）
        let result = rs.check(&Address::IPv4(Ipv4Addr::new(10, 1, 2, 3)), 80);
        assert!(result.allowed);

        // 反向验证：窄范围 PASS（priority=0）+ 宽范围 BLOCK（priority=1）
        let rules2 = vec![
            make_rule(RuleType::IpCidr, "10.1.0.0/16", 0, 65535, RuleAction::Pass, 0, 0.0),
            make_rule(RuleType::IpCidr, "10.0.0.0/8", 0, 65535, RuleAction::Block, 0, 0.0),
        ];
        let rs2 = TargetRuleSet::compile(rules2).unwrap();

        // 10.1.2.3 同时匹配两条，应该取 priority=0 的 PASS（窄范围，配置在前）
        let result = rs2.check(&Address::IPv4(Ipv4Addr::new(10, 1, 2, 3)), 80);
        assert!(result.allowed);

        // 10.2.0.1 只匹配 10.0.0.0/8（BLOCK），不匹配 10.1.0.0/16
        let result = rs2.check(&Address::IPv4(Ipv4Addr::new(10, 2, 0, 1)), 80);
        assert!(!result.allowed);
    }

    #[test]
    fn test_ipcidr_same_cidr_different_ports() {
        // 同一 CIDR 配置不同端口范围
        let rules = vec![
            make_rule(RuleType::IpCidr, "10.0.0.0/8", 80, 80, RuleAction::Pass, 0, 0.0),
            make_rule(RuleType::IpCidr, "10.0.0.0/8", 443, 443, RuleAction::Pass, 0, 0.0),
            make_rule(RuleType::IpCidr, "0.0.0.0/0", 0, 65535, RuleAction::Block, 0, 0.0),
        ];
        let rs = TargetRuleSet::compile(rules).unwrap();

        // 端口 80 匹配第一条 PASS
        let result = rs.check(&Address::IPv4(Ipv4Addr::new(10, 1, 2, 3)), 80);
        assert!(result.allowed);

        // 端口 443 匹配第二条 PASS
        let result = rs.check(&Address::IPv4(Ipv4Addr::new(10, 1, 2, 3)), 443);
        assert!(result.allowed);

        // 端口 8080 不匹配 10.0.0.0/8 的任何端口规则，匹配 0.0.0.0/0 BLOCK
        let result = rs.check(&Address::IPv4(Ipv4Addr::new(10, 1, 2, 3)), 8080);
        assert!(!result.allowed);

        // 非 10.x.x.x 地址，任何端口都匹配 0.0.0.0/0 BLOCK
        let result = rs.check(&Address::IPv4(Ipv4Addr::new(192, 168, 1, 1)), 80);
        assert!(!result.allowed);
    }

    #[test]
    fn test_ipcidr_non_canonical_cidr_normalized() {
        // 非规范 CIDR（主机位非零）应通过 trunc() 规范化后正确匹配
        // 例如用户配置 "10.0.0.128/24" 应等价于 "10.0.0.0/24"
        let rules = vec![
            make_rule(RuleType::IpCidr, "10.0.0.128/24", 0, 65535, RuleAction::Pass, 0, 0.0),
            make_rule(RuleType::IpCidr, "192.168.1.50/16", 0, 65535, RuleAction::Pass, 0, 0.0),
        ];
        let rs = TargetRuleSet::compile(rules).unwrap();

        // 10.0.0.1 应匹配规范化后的 10.0.0.0/24
        let result = rs.check(&Address::IPv4(Ipv4Addr::new(10, 0, 0, 1)), 80);
        assert!(result.allowed);

        // 10.0.0.200 同样在 10.0.0.0/24 内
        let result = rs.check(&Address::IPv4(Ipv4Addr::new(10, 0, 0, 200)), 80);
        assert!(result.allowed);

        // 10.0.1.1 不在 10.0.0.0/24 内
        let result = rs.check(&Address::IPv4(Ipv4Addr::new(10, 0, 1, 1)), 80);
        assert!(!result.allowed);

        // 192.168.100.1 应匹配规范化后的 192.168.0.0/16
        let result = rs.check(&Address::IPv4(Ipv4Addr::new(192, 168, 100, 1)), 80);
        assert!(result.allowed);

        // 192.169.0.1 不在 192.168.0.0/16 内
        let result = rs.check(&Address::IPv4(Ipv4Addr::new(192, 169, 0, 1)), 80);
        assert!(!result.allowed);
    }

    #[test]
    fn test_ipcidr_many_rules_performance() {
        // 大量规则（500 条）下的正确性验证
        // 生成 500 条 /24 CIDR 规则：10.0.0.0/24, 10.0.1.0/24, ..., 10.1.243.0/24
        // 前 499 条 BLOCK，最后一条 PASS（10.1.243.0/24）
        let mut rules: Vec<TargetRule> = Vec::with_capacity(500);
        for i in 0..500u32 {
            let second = ((i >> 8) & 0xFF) as u8; // 0 or 1
            let third = (i & 0xFF) as u8;
            let cidr = format!("10.{}.{}.0/24", second, third);
            let action = if i == 499 {
                RuleAction::Pass
            } else {
                RuleAction::Block
            };
            rules.push(make_rule(RuleType::IpCidr, &cidr, 0, 65535, action, 0, 0.0));
        }
        let rs = TargetRuleSet::compile(rules).unwrap();
        assert_eq!(rs.rule_count(), 500);

        // 10.0.0.1 匹配第一条 10.0.0.0/24（priority=0, BLOCK）
        let result = rs.check(&Address::IPv4(Ipv4Addr::new(10, 0, 0, 1)), 80);
        assert!(!result.allowed);

        // 10.0.100.1 匹配 10.0.100.0/24（priority=100, BLOCK）
        let result = rs.check(&Address::IPv4(Ipv4Addr::new(10, 0, 100, 1)), 80);
        assert!(!result.allowed);

        // 10.1.243.1 匹配最后一条 10.1.243.0/24（priority=499, PASS）
        let result = rs.check(&Address::IPv4(Ipv4Addr::new(10, 1, 243, 1)), 80);
        assert!(result.allowed);

        // 192.168.1.1 不匹配任何规则，默认 BLOCK
        let result = rs.check(&Address::IPv4(Ipv4Addr::new(192, 168, 1, 1)), 80);
        assert!(!result.allowed);
    }
}
