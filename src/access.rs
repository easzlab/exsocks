use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use ipnet::IpNet;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::error::SocksError;

/// client-rules.yaml 的反序列化结构
#[derive(Debug, Deserialize)]
struct ClientRulesConfig {
    #[serde(default)]
    client_rules: Vec<String>,
}

/// 白名单规则集（不可变值对象，通过 ArcSwap 原子替换）
///
/// 规则列表按配置文件中的顺序保存，匹配时从上往下遍历，
/// 命中任意一条即放行。纯白名单语义下规则之间无优先级冲突，
/// 无需按前缀长度排序。
pub struct AccessRules {
    /// 白名单 CIDR 列表，按配置文件顺序排列
    allowed: Vec<IpNet>,
}

impl AccessRules {
    /// 检查 IP 是否在白名单中
    ///
    /// - 命中 `client_rules` 列表中任意 CIDR → 放行（返回 `true`）
    /// - 未命中（含列表为空）→ 拒绝（返回 `false`）
    ///
    /// 在匹配前会将 IPv4-mapped IPv6 地址（`::ffff:x.x.x.x`）规范化为纯 IPv4，
    /// 确保 IPv4 CIDR 规则对通过 IPv6 socket 连接的客户端同样有效。
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        let ip = normalize_ip(ip);
        self.allowed.iter().any(|net| net.contains(&ip))
    }

    /// 返回当前白名单规则数量
    pub fn rule_count(&self) -> usize {
        self.allowed.len()
    }
}

/// 线程安全的访问控制器，支持热加载
///
/// 使用 `ArcSwap` 实现无锁读 + 原子替换：
/// - 每次检查调用 `rules()` 时仅需一次原子 load，无锁竞争
/// - 热加载时通过 `store()` 原子替换整个规则集，对读端完全透明
pub struct AccessControl {
    /// 当前生效的白名单规则集
    rules: ArcSwap<AccessRules>,
    /// 配置文件路径
    path: PathBuf,
}

impl AccessControl {
    /// 从指定的 YAML 文件加载白名单规则，创建 `AccessControl` 实例。
    ///
    /// 如果文件不存在或格式错误，返回 `SocksError::AccessConfig`。
    pub fn load(path: impl AsRef<Path>) -> Result<Self, SocksError> {
        let path = path.as_ref().to_path_buf();
        let rules = Self::parse_file(&path)?;
        info!(
            path = %path.display(),
            rules = rules.rule_count(),
            "Access control rules loaded"
        );
        Ok(Self {
            rules: ArcSwap::new(Arc::new(rules)),
            path,
        })
    }

    /// 获取当前规则集的快照（无锁读）
    ///
    /// 返回的 `Guard` 持有当前 `Arc<AccessRules>` 的引用，
    /// 在 `Guard` 存活期间规则集不会被释放。
    pub fn rules(&self) -> arc_swap::Guard<Arc<AccessRules>> {
        self.rules.load()
    }

    /// 重新加载配置文件，原子替换内部规则集。
    ///
    /// 如果重载失败，保留旧的规则集不受影响，仅记录错误日志。
    pub fn reload(&self) -> Result<(), SocksError> {
        let rules = Self::parse_file(&self.path)?;
        let rule_count = rules.rule_count();
        self.rules.store(Arc::new(rules));
        info!(
            path = %self.path.display(),
            rules = rule_count,
            "Access control rules reloaded"
        );
        Ok(())
    }

    /// 启动文件变更监听任务。
    ///
    /// 使用 `notify` crate 监听配置文件所在目录，当检测到文件修改时自动重载。
    /// 内置 500ms 防抖机制，避免编辑器保存时触发多次重载。
    ///
    /// 返回的 `RecommendedWatcher` 必须保持存活，drop 后监听停止。
    pub fn watch(self: &Arc<Self>) -> Result<RecommendedWatcher, SocksError> {
        let ac = Arc::clone(self);
        let watch_path = self
            .path
            .canonicalize()
            .unwrap_or_else(|_| self.path.clone());
        let watch_dir = watch_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let file_name = watch_path
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_default();

        // 使用 tokio mpsc channel 将 notify 事件桥接到异步运行时
        let (tx, mut rx) = mpsc::channel::<()>(16);

        let mut watcher =
            notify::recommended_watcher(move |result: Result<Event, notify::Error>| {
                match result {
                    Ok(event) => {
                        let is_relevant = matches!(
                            event.kind,
                            EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
                        );
                        if !is_relevant {
                            return;
                        }

                        // 检查事件是否涉及目标文件
                        let affects_target = event.paths.iter().any(|p| {
                            p.file_name()
                                .map(|n| n == file_name)
                                .unwrap_or(false)
                        });

                        if affects_target {
                            // 非阻塞发送，如果 channel 满了说明已有待处理的重载请求
                            let _ = tx.try_send(());
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "Access control file watcher error");
                    }
                }
            })
            .map_err(|e| {
                SocksError::AccessConfig(format!("Failed to create file watcher: {}", e))
            })?;

        watcher
            .watch(&watch_dir, RecursiveMode::NonRecursive)
            .map_err(|e| {
                SocksError::AccessConfig(format!(
                    "Failed to watch directory {}: {}",
                    watch_dir.display(),
                    e
                ))
            })?;

        info!(
            path = %watch_path.display(),
            dir = %watch_dir.display(),
            "Access control file watcher started"
        );

        // 启动防抖消费任务
        tokio::spawn(async move {
            loop {
                // 等待第一个事件
                if rx.recv().await.is_none() {
                    // channel 关闭，watcher 已被 drop
                    break;
                }

                // 防抖：等待 500ms，期间消费掉所有后续事件
                tokio::time::sleep(Duration::from_millis(500)).await;
                while rx.try_recv().is_ok() {}

                // 执行重载
                match ac.reload() {
                    Ok(()) => {}
                    Err(e) => {
                        warn!(
                            error = %e,
                            "Failed to reload access control rules, keeping previous rules"
                        );
                    }
                }
            }
        });

        Ok(watcher)
    }

    /// 从 YAML 文件解析白名单规则
    fn parse_file(path: &Path) -> Result<AccessRules, SocksError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            SocksError::AccessConfig(format!("Failed to read {}: {}", path.display(), e))
        })?;

        let config: ClientRulesConfig = serde_yaml::from_str(&content).map_err(|e| {
            SocksError::AccessConfig(format!("Failed to parse {}: {}", path.display(), e))
        })?;

        let mut allowed = Vec::with_capacity(config.client_rules.len());
        for cidr_str in &config.client_rules {
            let net: IpNet = cidr_str.parse().map_err(|e| {
                SocksError::AccessConfig(format!(
                    "Invalid CIDR '{}' in {}: {}",
                    cidr_str,
                    path.display(),
                    e
                ))
            })?;
            allowed.push(net);
        }

        // 保持配置文件中的顺序，从上往下依次匹配
        Ok(AccessRules { allowed })
    }
}

/// 将 IPv4-mapped IPv6 地址规范化为纯 IPv4 地址
///
/// 只处理标准的 IPv4-mapped 格式：`::ffff:x.x.x.x` → `x.x.x.x`
/// 纯 IPv4、纯 IPv6（包括 `::1` 等）保持不变。
///
/// 注意：不处理旧式 IPv4-compatible 格式（`::x.x.x.x`），
/// 因为该格式已废弃（RFC 4291），且 `::1` 等纯 IPv6 地址会被误判。
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::Ipv6Addr;

    fn make_rules(cidrs: &[&str]) -> AccessRules {
        let allowed = cidrs
            .iter()
            .map(|cidr| cidr.parse::<IpNet>().unwrap())
            .collect();
        AccessRules { allowed }
    }

    // ===== normalize_ip 测试 =====

    #[test]
    fn test_normalize_ipv4_unchanged() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert_eq!(normalize_ip(ip), ip);
    }

    #[test]
    fn test_normalize_ipv6_unchanged() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(normalize_ip(ip), ip);
    }

    #[test]
    fn test_normalize_ipv4_mapped_ipv6() {
        // ::ffff:192.168.1.1 → 192.168.1.1
        let v6: Ipv6Addr = "::ffff:192.168.1.1".parse().unwrap();
        let ip = IpAddr::V6(v6);
        let normalized = normalize_ip(ip);
        assert_eq!(normalized, "192.168.1.1".parse::<IpAddr>().unwrap());
    }

    // ===== is_allowed 测试 =====

    #[test]
    fn test_allowed_ip_in_cidr() {
        let rules = make_rules(&["192.168.0.0/16"]);
        assert!(rules.is_allowed("192.168.1.100".parse().unwrap()));
        assert!(rules.is_allowed("192.168.0.1".parse().unwrap()));
        assert!(rules.is_allowed("192.168.255.255".parse().unwrap()));
    }

    #[test]
    fn test_denied_ip_not_in_cidr() {
        let rules = make_rules(&["192.168.0.0/16"]);
        assert!(!rules.is_allowed("10.0.0.1".parse().unwrap()));
        assert!(!rules.is_allowed("172.16.0.1".parse().unwrap()));
        assert!(!rules.is_allowed("193.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_empty_rules_denies_all() {
        let rules = make_rules(&[]);
        assert!(!rules.is_allowed("127.0.0.1".parse().unwrap()));
        assert!(!rules.is_allowed("192.168.1.1".parse().unwrap()));
        assert!(!rules.is_allowed("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_ipv4_cidr_boundary_matching() {
        let rules = make_rules(&["10.0.0.0/8"]);
        // 网络地址
        assert!(rules.is_allowed("10.0.0.0".parse().unwrap()));
        // 广播地址
        assert!(rules.is_allowed("10.255.255.255".parse().unwrap()));
        // 范围内
        assert!(rules.is_allowed("10.1.2.3".parse().unwrap()));
        // 范围外
        assert!(!rules.is_allowed("11.0.0.0".parse().unwrap()));
        assert!(!rules.is_allowed("9.255.255.255".parse().unwrap()));
    }

    #[test]
    fn test_ipv6_cidr_matching() {
        let rules = make_rules(&["2001:db8::/32"]);
        assert!(rules.is_allowed("2001:db8::1".parse().unwrap()));
        assert!(rules.is_allowed("2001:db8:ffff::1".parse().unwrap()));
        assert!(!rules.is_allowed("2001:db9::1".parse().unwrap()));
        assert!(!rules.is_allowed("::1".parse().unwrap()));
    }

    #[test]
    fn test_ipv4_mapped_ipv6_normalization() {
        // IPv4-mapped IPv6 地址应该能匹配 IPv4 CIDR 规则
        let rules = make_rules(&["192.168.0.0/16"]);
        let mapped: IpAddr = "::ffff:192.168.1.100".parse().unwrap();
        assert!(rules.is_allowed(mapped));

        let mapped_outside: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert!(!rules.is_allowed(mapped_outside));
    }

    #[test]
    fn test_host_route_32() {
        let rules = make_rules(&["127.0.0.1/32"]);
        assert!(rules.is_allowed("127.0.0.1".parse().unwrap()));
        assert!(!rules.is_allowed("127.0.0.2".parse().unwrap()));
        assert!(!rules.is_allowed("127.0.0.0".parse().unwrap()));
    }

    #[test]
    fn test_multiple_cidrs_any_match_allows() {
        let rules = make_rules(&["10.0.0.0/8", "192.168.0.0/16", "127.0.0.1/32"]);
        assert!(rules.is_allowed("10.1.2.3".parse().unwrap()));
        assert!(rules.is_allowed("192.168.100.200".parse().unwrap()));
        assert!(rules.is_allowed("127.0.0.1".parse().unwrap()));
        assert!(!rules.is_allowed("172.16.0.1".parse().unwrap()));
        assert!(!rules.is_allowed("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_config_order_preserved() {
        // 验证规则按配置文件顺序保存（从上往下）
        let rules = make_rules(&["10.0.0.0/8", "10.1.0.0/16", "10.1.1.0/24"]);
        // 所有规则都应该能匹配（纯白名单，命中任意一条即放行）
        assert!(rules.is_allowed("10.1.1.1".parse().unwrap()));
        assert!(rules.is_allowed("10.1.2.1".parse().unwrap()));
        assert!(rules.is_allowed("10.2.0.1".parse().unwrap()));
        // 验证顺序：与配置文件一致，/8 在前，/24 在后
        assert_eq!(rules.allowed[0].prefix_len(), 8);
        assert_eq!(rules.allowed[1].prefix_len(), 16);
        assert_eq!(rules.allowed[2].prefix_len(), 24);
    }

    // ===== YAML 加载测试 =====

    fn create_temp_yaml(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
        write!(f, "{}", content).unwrap();
        f
    }

    #[test]
    fn test_load_from_yaml_valid() {
        let yaml = r#"
client_rules:
  - 10.0.0.0/8
  - 192.168.0.0/16
  - 127.0.0.1/32
"#;
        let f = create_temp_yaml(yaml);
        let ac = AccessControl::load(f.path()).unwrap();
        assert_eq!(ac.rules().rule_count(), 3);
        assert!(ac.rules().is_allowed("10.1.2.3".parse().unwrap()));
        assert!(ac.rules().is_allowed("192.168.1.1".parse().unwrap()));
        assert!(ac.rules().is_allowed("127.0.0.1".parse().unwrap()));
        assert!(!ac.rules().is_allowed("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_load_from_yaml_invalid_cidr() {
        let yaml = r#"
client_rules:
  - not-a-cidr
"#;
        let f = create_temp_yaml(yaml);
        let result = AccessControl::load(f.path());
        assert!(result.is_err());
        let err = result.err().unwrap().to_string();
        assert!(err.contains("Invalid CIDR") || err.contains("Access config error"));
    }

    #[test]
    fn test_load_nonexistent_file() {
        let result = AccessControl::load("/nonexistent/path/client-rules.yaml");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_empty_yaml() {
        // 空文件：client_rules 字段缺失，使用默认空列表
        let yaml = "";
        let f = create_temp_yaml(yaml);
        let ac = AccessControl::load(f.path()).unwrap();
        assert_eq!(ac.rules().rule_count(), 0);
        assert!(!ac.rules().is_allowed("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_load_empty_client_rules_field() {
        let yaml = r#"
client_rules: []
"#;
        let f = create_temp_yaml(yaml);
        let ac = AccessControl::load(f.path()).unwrap();
        assert_eq!(ac.rules().rule_count(), 0);
        assert!(!ac.rules().is_allowed("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_load_invalid_yaml_syntax() {
        let yaml = "invalid: yaml: [unclosed";
        let f = create_temp_yaml(yaml);
        let result = AccessControl::load(f.path());
        assert!(result.is_err());
    }

    // ===== reload 测试 =====

    #[test]
    fn test_reload_updates_rules() {
        let yaml = r#"
client_rules:
  - 10.0.0.0/8
"#;
        let mut f = create_temp_yaml(yaml);
        let ac = AccessControl::load(f.path()).unwrap();
        assert!(ac.rules().is_allowed("10.1.2.3".parse().unwrap()));
        assert!(!ac.rules().is_allowed("192.168.1.1".parse().unwrap()));

        // 更新文件内容
        let new_yaml = r#"
client_rules:
  - 192.168.0.0/16
"#;
        f.as_file_mut().set_len(0).unwrap();
        use std::io::Seek;
        f.as_file_mut().seek(std::io::SeekFrom::Start(0)).unwrap();
        write!(f, "{}", new_yaml).unwrap();
        f.as_file_mut().flush().unwrap();

        ac.reload().unwrap();
        assert!(!ac.rules().is_allowed("10.1.2.3".parse().unwrap()));
        assert!(ac.rules().is_allowed("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_reload_on_invalid_keeps_old_rules() {
        let yaml = r#"
client_rules:
  - 10.0.0.0/8
"#;
        let mut f = create_temp_yaml(yaml);
        let ac = AccessControl::load(f.path()).unwrap();
        assert!(ac.rules().is_allowed("10.1.2.3".parse().unwrap()));

        // 写入非法内容
        let invalid_yaml = "invalid: yaml: [unclosed";
        f.as_file_mut().set_len(0).unwrap();
        use std::io::Seek;
        f.as_file_mut().seek(std::io::SeekFrom::Start(0)).unwrap();
        write!(f, "{}", invalid_yaml).unwrap();
        f.as_file_mut().flush().unwrap();

        // reload 应该失败，但旧规则保留
        assert!(ac.reload().is_err());
        assert!(ac.rules().is_allowed("10.1.2.3".parse().unwrap()));
    }

    // ===== 并发测试 =====

    #[test]
    fn test_concurrent_check_during_reload() {
        use std::sync::Arc;
        use std::thread;

        let yaml = r#"
client_rules:
  - 10.0.0.0/8
"#;
        let mut f = create_temp_yaml(yaml);
        let ac = Arc::new(AccessControl::load(f.path()).unwrap());

        let readers: Vec<_> = (0..8)
            .map(|_| {
                let ac_clone = Arc::clone(&ac);
                thread::spawn(move || {
                    for _ in 0..1000 {
                        let _ = ac_clone.rules().is_allowed("10.1.2.3".parse().unwrap());
                    }
                })
            })
            .collect();

        // 主线程并发执行 reload
        let new_yaml = r#"
client_rules:
  - 192.168.0.0/16
"#;
        f.as_file_mut().set_len(0).unwrap();
        use std::io::Seek;
        f.as_file_mut().seek(std::io::SeekFrom::Start(0)).unwrap();
        write!(f, "{}", new_yaml).unwrap();
        f.as_file_mut().flush().unwrap();

        for _ in 0..10 {
            let _ = ac.reload();
        }

        for handle in readers {
            handle.join().unwrap();
        }
        // 最终规则应该是新规则
        assert!(ac.rules().is_allowed("192.168.1.1".parse().unwrap()));
    }

    // ===== watch 热加载测试 =====

    #[tokio::test]
    async fn test_watch_auto_reload() {
        use std::io::Seek;
        use std::sync::Arc;

        let yaml = r#"
client_rules:
  - 10.0.0.0/8
"#;
        let mut f = create_temp_yaml(yaml);
        let ac = Arc::new(AccessControl::load(f.path()).unwrap());
        assert!(ac.rules().is_allowed("10.1.2.3".parse().unwrap()));
        assert!(!ac.rules().is_allowed("192.168.1.1".parse().unwrap()));

        let _watcher = ac.watch().unwrap();

        // 修改文件内容
        let new_yaml = r#"
client_rules:
  - 192.168.0.0/16
  - 127.0.0.1/32
"#;
        f.as_file_mut().set_len(0).unwrap();
        f.as_file_mut().seek(std::io::SeekFrom::Start(0)).unwrap();
        write!(f, "{}", new_yaml).unwrap();
        f.as_file_mut().flush().unwrap();

        // 等待防抖（500ms）+ 余量
        let mut reloaded = false;
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            if ac.rules().rule_count() == 2 && ac.rules().is_allowed("192.168.1.1".parse().unwrap()) {
                reloaded = true;
                break;
            }
        }
        assert!(reloaded, "File watcher did not auto-reload within timeout");
        assert!(!ac.rules().is_allowed("10.1.2.3".parse().unwrap()));
        assert!(ac.rules().is_allowed("127.0.0.1".parse().unwrap()));
    }

    #[tokio::test]
    async fn test_watch_survives_invalid_content() {
        use std::io::Seek;
        use std::sync::Arc;

        let yaml = r#"
client_rules:
  - 10.0.0.0/8
"#;
        let mut f = create_temp_yaml(yaml);
        let ac = Arc::new(AccessControl::load(f.path()).unwrap());
        assert!(ac.rules().is_allowed("10.1.2.3".parse().unwrap()));

        let _watcher = ac.watch().unwrap();

        // 写入非法内容，重载应失败但保留旧规则
        let invalid_yaml = "invalid: yaml: [unclosed";
        f.as_file_mut().set_len(0).unwrap();
        f.as_file_mut().seek(std::io::SeekFrom::Start(0)).unwrap();
        write!(f, "{}", invalid_yaml).unwrap();
        f.as_file_mut().flush().unwrap();

        // 等待 watcher 尝试重载
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

        // 旧规则应该仍然有效
        assert!(ac.rules().is_allowed("10.1.2.3".parse().unwrap()));
        assert_eq!(ac.rules().rule_count(), 1);

        // 再写入有效内容，应该能恢复
        let valid_yaml = r#"
client_rules:
  - 192.168.0.0/16
"#;
        f.as_file_mut().set_len(0).unwrap();
        f.as_file_mut().seek(std::io::SeekFrom::Start(0)).unwrap();
        write!(f, "{}", valid_yaml).unwrap();
        f.as_file_mut().flush().unwrap();

        let mut recovered = false;
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            if ac.rules().is_allowed("192.168.1.1".parse().unwrap()) {
                recovered = true;
                break;
            }
        }
        assert!(recovered, "File watcher did not recover after invalid content");
        assert!(!ac.rules().is_allowed("10.1.2.3".parse().unwrap()));
    }
}
