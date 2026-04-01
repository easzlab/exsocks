use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use ipnet::IpNet;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use serde::Deserialize;
use tracing::{error, info, warn};

use crate::error::SocksError;
use crate::socks5::protocol::Address;

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

/// CIDR 规则条目（保持配置顺序）
#[derive(Debug)]
struct CidrEntry {
    network: IpNet,
    rule: PrioritizedRule,
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

    // opt1: 8 位二进制字符串，默认 "00000000"
    let opt_flags = if arr.len() > 5 {
        let opt1_str = arr[5].as_str().unwrap_or("00000000");
        u8::from_str_radix(opt1_str, 2).map_err(|e| {
            SocksError::TargetRulesConfig(format!(
                "Rule #{}: invalid opt1 '{}': expected 8-bit binary string (e.g. \"00000001\"), \
                 error: {}",
                index + 1,
                opt1_str,
                e
            ))
        })?
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
    /// DOMAIN-SUFFIX 后缀匹配索引：key 为小写后缀
    suffix_index: HashMap<String, Vec<PrioritizedRule>>,
    /// IPCIDR 规则列表，保持配置文件中的原始顺序（first-match-wins + early return）
    cidr_rules: Vec<CidrEntry>,
    /// 规则总数（用于日志/调试）
    total_rules: usize,
}

impl TargetRuleSet {
    /// 从解析后的规则列表编译为高性能索引结构
    pub fn compile(rules: Vec<TargetRule>) -> Result<Self, SocksError> {
        let total_rules = rules.len();
        let mut domain_index: HashMap<String, Vec<PrioritizedRule>> = HashMap::new();
        let mut suffix_index: HashMap<String, Vec<PrioritizedRule>> = HashMap::new();
        let mut cidr_rules: Vec<CidrEntry> = Vec::new();

        for (priority, rule) in rules.into_iter().enumerate() {
            let pr = PrioritizedRule {
                priority,
                port_start: rule.port_start,
                port_end: rule.port_end,
                action: rule.action,
                opt_flags: rule.opt_flags,
                opt_value: rule.opt_value,
            };

            match rule.rule_type {
                RuleType::Domain => {
                    let key = rule.value.to_ascii_lowercase();
                    domain_index.entry(key).or_default().push(pr);
                }
                RuleType::DomainSuffix => {
                    let key = rule.value.to_ascii_lowercase();
                    suffix_index.entry(key).or_default().push(pr);
                }
                RuleType::IpCidr => {
                    // IpNet 自动支持 IPv4 和 IPv6 CIDR
                    let network: IpNet = rule.value.parse().map_err(|e| {
                        SocksError::TargetRulesConfig(format!(
                            "Invalid CIDR '{}': {}",
                            rule.value, e
                        ))
                    })?;
                    cidr_rules.push(CidrEntry { network, rule: pr });
                }
            }
        }

        // CIDR 规则保持配置文件中的原始顺序，不排序
        // 匹配时按顺序遍历，first-match-wins + early return

        Ok(Self {
            domain_index,
            suffix_index,
            cidr_rules,
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
            },
            // 默认 BLOCK，不记录日志
            None => MatchResult {
                allowed: false,
                log: false,
                opt_flags: 0,
                opt_value: 0.0,
            },
        }
    }

    /// 域名匹配：查询 domain_index 和 suffix_index，取全局优先级最高的
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

        // 2. 后缀匹配：逐级拆分域名（O(L)，L=域名层级数）
        //    对于 "a.b.c.com"，依次查找 "a.b.c.com", "b.c.com", "c.com", "com"
        let mut search = lower.as_str();
        loop {
            if let Some(rules) = self.suffix_index.get(search) {
                for r in rules {
                    if r.port_matches(port) && r.is_higher_priority_than(best) {
                        best = Some(r);
                    }
                }
            }
            match search.find('.') {
                Some(pos) => search = &search[pos + 1..],
                None => break,
            }
        }

        best
    }

    /// CIDR 匹配：按配置顺序遍历，命中第一条即 early return
    ///
    /// 由于 IP 请求不会匹配 DOMAIN/DOMAIN-SUFFIX 规则，无需跨类型比较优先级，
    /// cidr_rules 保持配置顺序，第一个匹配的就是优先级最高的，直接返回。
    fn match_cidr(&self, ip: &IpAddr, port: u16) -> Option<&PrioritizedRule> {
        let normalized = normalize_ip(*ip);

        for entry in &self.cidr_rules {
            if entry.network.contains(&normalized) && entry.rule.port_matches(port) {
                return Some(&entry.rule); // early return: first-match-wins
            }
        }

        None
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

// ===== 热加载控制器 =====

#[derive(Debug)]
pub struct TargetRuleControl {
    rules: Arc<ArcSwap<TargetRuleSet>>,
    file_path: PathBuf,
}

impl TargetRuleControl {
    /// 从 YAML 文件加载目标规则
    pub fn load(path: &Path) -> Result<Self, SocksError> {
        let rule_set = Self::parse_file(path)?;
        info!(
            path = %path.display(),
            rules = rule_set.rule_count(),
            "Target rules loaded"
        );
        Ok(Self {
            rules: Arc::new(ArcSwap::from_pointee(rule_set)),
            file_path: path.to_path_buf(),
        })
    }

    /// 获取当前规则集的快照（无锁读取）
    pub fn rules(&self) -> arc_swap::Guard<Arc<TargetRuleSet>> {
        self.rules.load()
    }

    /// 重新加载规则文件，原子替换规则集
    pub fn reload(&self) -> Result<(), SocksError> {
        let new_rules = Self::parse_file(&self.file_path)?;
        let count = new_rules.rule_count();
        self.rules.store(Arc::new(new_rules));
        info!(
            path = %self.file_path.display(),
            rules = count,
            "Target rules reloaded"
        );
        Ok(())
    }

    /// 启动文件变更监听，返回 watcher（调用方需保持其存活）
    pub fn watch(self: &Arc<Self>) -> Result<RecommendedWatcher, SocksError> {
        let watch_path = self
            .file_path
            .canonicalize()
            .unwrap_or_else(|_| self.file_path.clone());
        let watch_dir = watch_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let file_name = watch_path
            .file_name()
            .unwrap_or_default()
            .to_os_string();

        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
        let trc = Arc::clone(self);

        let mut watcher = notify::recommended_watcher(
            move |result: Result<notify::Event, notify::Error>| {
                match result {
                    Ok(event) => {
                        use notify::EventKind;
                        match event.kind {
                            EventKind::Create(_)
                            | EventKind::Modify(_)
                            | EventKind::Remove(_) => {}
                            _ => {
                                return;
                            }
                        }

                        let affects_target = event.paths.iter().any(|p| {
                            p.file_name()
                                .map(|n| n == file_name)
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
            .watch(&watch_dir, RecursiveMode::NonRecursive)
            .map_err(|e| {
                SocksError::TargetRulesConfig(format!(
                    "Failed to watch directory {}: {}",
                    watch_dir.display(),
                    e
                ))
            })?;

        info!(
            path = %watch_path.display(),
            dir = %watch_dir.display(),
            "Target rules file watcher started"
        );

        // 启动防抖消费任务
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

        Ok(watcher)
    }

    /// 从 YAML 文件解析目标规则
    fn parse_file(path: &Path) -> Result<TargetRuleSet, SocksError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            SocksError::TargetRulesConfig(format!("Failed to read {}: {}", path.display(), e))
        })?;

        let config: TargetRulesConfig = serde_yaml::from_str(&content).map_err(|e| {
            SocksError::TargetRulesConfig(format!("Failed to parse {}: {}", path.display(), e))
        })?;

        let mut rules = Vec::with_capacity(config.target_rules.len());
        for (i, arr) in config.target_rules.iter().enumerate() {
            rules.push(parse_rule_array(arr, i)?);
        }

        TargetRuleSet::compile(rules)
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
            "00000001".into(),
            serde_yaml::Value::Number(serde_yaml::Number::from(1.5)),
        ];
        let rule = parse_rule_array(&arr, 0).unwrap();
        assert_eq!(rule.rule_type, RuleType::DomainSuffix);
        assert_eq!(rule.value, "baidu.com");
        assert_eq!(rule.port_start, 0);
        assert_eq!(rule.port_end, 65535);
        assert_eq!(rule.action, RuleAction::Pass);
        assert_eq!(rule.opt_flags, 0b0000_0001);
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
            "00000011".into(),
        ];
        let rule = parse_rule_array(&arr, 0).unwrap();
        assert_eq!(rule.rule_type, RuleType::IpCidr);
        assert_eq!(rule.opt_flags, 0b0000_0011);
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
            "00000000".into(),
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
    fn test_parse_invalid_opt1() {
        let arr: Vec<serde_yaml::Value> = vec![
            "DOMAIN".into(),
            "example.com".into(),
            0u64.into(),
            65535u64.into(),
            "PASS".into(),
            "not_binary".into(),
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
}
