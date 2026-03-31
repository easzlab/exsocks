/// 访问控制模块集成测试
///
/// 通过公共 API 测试 AccessControl 的完整行为，
/// 包括 YAML 加载、规则匹配、热加载和并发安全性。
use std::io::Write;
use std::sync::Arc;

use exsocks::access::AccessControl;

/// 创建包含指定内容的临时 YAML 文件，返回 (AccessControl, TempFile)
/// TempFile 必须保持存活，否则文件会被删除
fn create_test_ac(yaml: &str) -> (AccessControl, tempfile::NamedTempFile) {
    let mut f = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
    write!(f, "{}", yaml).unwrap();
    let ac = AccessControl::load(f.path()).unwrap();
    (ac, f)
}

// ===== 基础白名单匹配测试 =====

#[test]
fn test_allowed_ip_in_cidr() {
    let yaml = r#"
client_rules:
  - 192.168.0.0/16
"#;
    let (ac, _f) = create_test_ac(yaml);
    assert!(ac.rules().is_allowed("192.168.1.100".parse().unwrap()));
    assert!(ac.rules().is_allowed("192.168.0.1".parse().unwrap()));
    assert!(ac.rules().is_allowed("192.168.255.255".parse().unwrap()));
}

#[test]
fn test_denied_ip_not_in_cidr() {
    let yaml = r#"
client_rules:
  - 192.168.0.0/16
"#;
    let (ac, _f) = create_test_ac(yaml);
    assert!(!ac.rules().is_allowed("10.0.0.1".parse().unwrap()));
    assert!(!ac.rules().is_allowed("172.16.0.1".parse().unwrap()));
    assert!(!ac.rules().is_allowed("193.0.0.1".parse().unwrap()));
}

#[test]
fn test_empty_rules_denies_all() {
    let yaml = r#"
client_rules: []
"#;
    let (ac, _f) = create_test_ac(yaml);
    assert!(!ac.rules().is_allowed("127.0.0.1".parse().unwrap()));
    assert!(!ac.rules().is_allowed("192.168.1.1".parse().unwrap()));
    assert!(!ac.rules().is_allowed("10.0.0.1".parse().unwrap()));
    assert!(!ac.rules().is_allowed("0.0.0.0".parse().unwrap()));
}

#[test]
fn test_missing_client_rules_field_denies_all() {
    // client_rules 字段缺失时使用默认空列表
    let yaml = r#"
some_other_field: "value"
"#;
    let (ac, _f) = create_test_ac(yaml);
    assert!(!ac.rules().is_allowed("127.0.0.1".parse().unwrap()));
}

// ===== IPv4 CIDR 边界测试 =====

#[test]
fn test_ipv4_cidr_boundary_matching() {
    let yaml = r#"
client_rules:
  - 10.0.0.0/8
"#;
    let (ac, _f) = create_test_ac(yaml);
    // 网络地址
    assert!(ac.rules().is_allowed("10.0.0.0".parse().unwrap()));
    // 广播地址
    assert!(ac.rules().is_allowed("10.255.255.255".parse().unwrap()));
    // 范围内
    assert!(ac.rules().is_allowed("10.1.2.3".parse().unwrap()));
    // 范围外
    assert!(!ac.rules().is_allowed("11.0.0.0".parse().unwrap()));
    assert!(!ac.rules().is_allowed("9.255.255.255".parse().unwrap()));
}

#[test]
fn test_host_route_32() {
    let yaml = r#"
client_rules:
  - 127.0.0.1/32
"#;
    let (ac, _f) = create_test_ac(yaml);
    assert!(ac.rules().is_allowed("127.0.0.1".parse().unwrap()));
    assert!(!ac.rules().is_allowed("127.0.0.2".parse().unwrap()));
    assert!(!ac.rules().is_allowed("127.0.0.0".parse().unwrap()));
    assert!(!ac.rules().is_allowed("127.1.0.1".parse().unwrap()));
}

// ===== IPv6 CIDR 测试 =====

#[test]
fn test_ipv6_cidr_matching() {
    // IPv6 CIDR 在 YAML 中加引号，避免解析歧义
    let yaml = r#"
client_rules:
  - "2001:db8::/32"
"#;
    let (ac, _f) = create_test_ac(yaml);
    assert!(ac.rules().is_allowed("2001:db8::1".parse().unwrap()));
    assert!(ac.rules().is_allowed("2001:db8:ffff::1".parse().unwrap()));
    assert!(!ac.rules().is_allowed("2001:db9::1".parse().unwrap()));
    assert!(!ac.rules().is_allowed("::1".parse().unwrap()));
}

#[test]
fn test_ipv6_loopback() {
    // IPv6 CIDR 在 YAML 中需要加引号，否则 :: 开头会被解析为 null
    let yaml = r#"
client_rules:
  - "::1/128"
"#;
    let (ac, _f) = create_test_ac(yaml);
    assert!(ac.rules().is_allowed("::1".parse().unwrap()));
    assert!(!ac.rules().is_allowed("::2".parse().unwrap()));
}

// ===== IPv4-mapped IPv6 规范化测试 =====

#[test]
fn test_ipv4_mapped_ipv6_normalization() {
    let yaml = r#"
client_rules:
  - 192.168.0.0/16
"#;
    let (ac, _f) = create_test_ac(yaml);
    // ::ffff:192.168.1.100 应该被规范化为 192.168.1.100 并匹配 IPv4 规则
    let mapped: std::net::IpAddr = "::ffff:192.168.1.100".parse().unwrap();
    assert!(ac.rules().is_allowed(mapped));

    // ::ffff:10.0.0.1 不在白名单中
    let mapped_outside: std::net::IpAddr = "::ffff:10.0.0.1".parse().unwrap();
    assert!(!ac.rules().is_allowed(mapped_outside));
}

#[test]
fn test_ipv4_mapped_ipv6_loopback() {
    let yaml = r#"
client_rules:
  - 127.0.0.1/32
"#;
    let (ac, _f) = create_test_ac(yaml);
    // ::ffff:127.0.0.1 应该匹配 127.0.0.1/32
    let mapped: std::net::IpAddr = "::ffff:127.0.0.1".parse().unwrap();
    assert!(ac.rules().is_allowed(mapped));
}

// ===== 多规则测试 =====

#[test]
fn test_multiple_cidrs_any_match_allows() {
    let yaml = r#"
client_rules:
  - 10.0.0.0/8
  - 192.168.0.0/16
  - 127.0.0.1/32
"#;
    let (ac, _f) = create_test_ac(yaml);
    assert!(ac.rules().is_allowed("10.1.2.3".parse().unwrap()));
    assert!(ac.rules().is_allowed("192.168.100.200".parse().unwrap()));
    assert!(ac.rules().is_allowed("127.0.0.1".parse().unwrap()));
    // 不在任何规则中
    assert!(!ac.rules().is_allowed("172.16.0.1".parse().unwrap()));
    assert!(!ac.rules().is_allowed("8.8.8.8".parse().unwrap()));
}

// ===== YAML 加载测试 =====

#[test]
fn test_load_from_yaml_valid() {
    let yaml = r#"
client_rules:
  - 10.0.0.0/8
  - 192.168.0.0/16
  - 127.0.0.1/32
"#;
    let (ac, _f) = create_test_ac(yaml);
    assert_eq!(ac.rules().rule_count(), 3);
}

#[test]
fn test_load_from_yaml_invalid_cidr() {
    let yaml = r#"
client_rules:
  - not-a-cidr
"#;
    let mut f = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
    write!(f, "{}", yaml).unwrap();
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
    let yaml = "";
    let (ac, _f) = create_test_ac(yaml);
    assert_eq!(ac.rules().rule_count(), 0);
    assert!(!ac.rules().is_allowed("127.0.0.1".parse().unwrap()));
}

#[test]
fn test_load_invalid_yaml_syntax() {
    let yaml = "invalid: yaml: [unclosed";
    let mut f = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
    write!(f, "{}", yaml).unwrap();
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
    let (ac, mut f) = create_test_ac(yaml);
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
fn test_reload_adds_new_rule() {
    let yaml = r#"
client_rules:
  - 10.0.0.0/8
"#;
    let (ac, mut f) = create_test_ac(yaml);
    assert_eq!(ac.rules().rule_count(), 1);
    assert!(!ac.rules().is_allowed("192.168.1.1".parse().unwrap()));

    let new_yaml = r#"
client_rules:
  - 10.0.0.0/8
  - 192.168.0.0/16
"#;
    f.as_file_mut().set_len(0).unwrap();
    use std::io::Seek;
    f.as_file_mut().seek(std::io::SeekFrom::Start(0)).unwrap();
    write!(f, "{}", new_yaml).unwrap();
    f.as_file_mut().flush().unwrap();

    ac.reload().unwrap();
    assert_eq!(ac.rules().rule_count(), 2);
    assert!(ac.rules().is_allowed("10.1.2.3".parse().unwrap()));
    assert!(ac.rules().is_allowed("192.168.1.1".parse().unwrap()));
}

#[test]
fn test_reload_removes_rule() {
    let yaml = r#"
client_rules:
  - 10.0.0.0/8
  - 192.168.0.0/16
"#;
    let (ac, mut f) = create_test_ac(yaml);
    assert_eq!(ac.rules().rule_count(), 2);
    assert!(ac.rules().is_allowed("192.168.1.1".parse().unwrap()));

    let new_yaml = r#"
client_rules:
  - 10.0.0.0/8
"#;
    f.as_file_mut().set_len(0).unwrap();
    use std::io::Seek;
    f.as_file_mut().seek(std::io::SeekFrom::Start(0)).unwrap();
    write!(f, "{}", new_yaml).unwrap();
    f.as_file_mut().flush().unwrap();

    ac.reload().unwrap();
    assert_eq!(ac.rules().rule_count(), 1);
    assert!(ac.rules().is_allowed("10.1.2.3".parse().unwrap()));
    assert!(!ac.rules().is_allowed("192.168.1.1".parse().unwrap()));
}

#[test]
fn test_reload_on_invalid_keeps_old_rules() {
    let yaml = r#"
client_rules:
  - 10.0.0.0/8
"#;
    let (ac, mut f) = create_test_ac(yaml);
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
    assert_eq!(ac.rules().rule_count(), 1);
}

#[test]
fn test_reload_on_invalid_cidr_keeps_old_rules() {
    let yaml = r#"
client_rules:
  - 10.0.0.0/8
"#;
    let (ac, mut f) = create_test_ac(yaml);
    assert!(ac.rules().is_allowed("10.1.2.3".parse().unwrap()));

    // 写入包含非法 CIDR 的内容
    let bad_cidr_yaml = r#"
client_rules:
  - not-a-cidr
"#;
    f.as_file_mut().set_len(0).unwrap();
    use std::io::Seek;
    f.as_file_mut().seek(std::io::SeekFrom::Start(0)).unwrap();
    write!(f, "{}", bad_cidr_yaml).unwrap();
    f.as_file_mut().flush().unwrap();

    assert!(ac.reload().is_err());
    // 旧规则仍然有效
    assert!(ac.rules().is_allowed("10.1.2.3".parse().unwrap()));
}

// ===== 并发安全测试 =====

#[test]
fn test_concurrent_check_during_reload() {
    use std::thread;

    let yaml = r#"
client_rules:
  - 10.0.0.0/8
"#;
    let (ac, mut f) = create_test_ac(yaml);
    let ac = Arc::new(ac);

    // 启动 8 个并发读取线程
    let readers: Vec<_> = (0..8)
        .map(|_| {
            let ac_clone = Arc::clone(&ac);
            thread::spawn(move || {
                for _ in 0..2000 {
                    // 读取结果可能是新规则或旧规则，但不能 panic
                    let _ = ac_clone.rules().is_allowed("10.1.2.3".parse().unwrap());
                    let _ = ac_clone.rules().is_allowed("192.168.1.1".parse().unwrap());
                }
            })
        })
        .collect();

    // 主线程并发执行多次 reload
    let new_yaml = r#"
client_rules:
  - 192.168.0.0/16
"#;
    f.as_file_mut().set_len(0).unwrap();
    use std::io::Seek;
    f.as_file_mut().seek(std::io::SeekFrom::Start(0)).unwrap();
    write!(f, "{}", new_yaml).unwrap();
    f.as_file_mut().flush().unwrap();

    for _ in 0..20 {
        let _ = ac.reload();
    }

    for handle in readers {
        handle.join().unwrap();
    }

    // 最终规则应该是新规则
    assert!(ac.rules().is_allowed("192.168.1.1".parse().unwrap()));
    assert!(!ac.rules().is_allowed("10.1.2.3".parse().unwrap()));
}

// ===== watch 热加载测试 =====

#[tokio::test]
async fn test_watch_auto_reload() {
    use std::io::Seek;

    let yaml = r#"
client_rules:
  - 10.0.0.0/8
"#;
    let (ac, mut f) = create_test_ac(yaml);
    let ac = Arc::new(ac);
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
async fn test_watch_auto_reload_password_change() {
    use std::io::Seek;

    let yaml = r#"
client_rules:
  - 10.0.0.0/8
  - 192.168.0.0/16
"#;
    let (ac, mut f) = create_test_ac(yaml);
    let ac = Arc::new(ac);
    assert_eq!(ac.rules().rule_count(), 2);

    let _watcher = ac.watch().unwrap();

    // 缩减为单条规则
    let new_yaml = r#"
client_rules:
  - 127.0.0.1/32
"#;
    f.as_file_mut().set_len(0).unwrap();
    f.as_file_mut().seek(std::io::SeekFrom::Start(0)).unwrap();
    write!(f, "{}", new_yaml).unwrap();
    f.as_file_mut().flush().unwrap();

    let mut reloaded = false;
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        if ac.rules().rule_count() == 1 && ac.rules().is_allowed("127.0.0.1".parse().unwrap()) {
            reloaded = true;
            break;
        }
    }
    assert!(reloaded, "File watcher did not auto-reload rule change within timeout");
    assert!(!ac.rules().is_allowed("10.1.2.3".parse().unwrap()));
    assert!(!ac.rules().is_allowed("192.168.1.1".parse().unwrap()));
}

#[tokio::test]
async fn test_watch_survives_invalid_content() {
    use std::io::Seek;

    let yaml = r#"
client_rules:
  - 10.0.0.0/8
"#;
    let (ac, mut f) = create_test_ac(yaml);
    let ac = Arc::new(ac);
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
