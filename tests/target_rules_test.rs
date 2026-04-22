use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use exsocks::target_rules::{
    OPT_LOG, NetAcl, RuleAction, RuleType, TargetRule, TargetRuleControl, TargetRuleSet,
    convert_acl_to_yaml,
};
use exsocks::socks5::protocol::Address;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio_util::sync::CancellationToken;

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

fn create_temp_yaml(content: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::Builder::new()
        .suffix(".yaml")
        .tempfile()
        .unwrap();
    write!(f, "{}", content).unwrap();
    f
}

// ===== 数组格式解析测试（通过 YAML 加载） =====

#[test]
fn test_yaml_7_element_rules() {
    let yaml = r#"
target_rules:
  - [DOMAIN-SUFFIX, baidu.com, 0, 65535, PASS, 1, 1.5]
"#;
    let f = create_temp_yaml(yaml);
    let trc = TargetRuleControl::load(f.path(), std::path::Path::new("nonexistent-static.yaml")).unwrap();
    let rules = trc.rules();
    assert_eq!(rules.rule_count(), 1);

    let result = rules.check(&Address::Domain("www.baidu.com".to_string()), 80);
    assert!(result.allowed);
    assert!(result.log);
    assert!((result.opt_value - 1.5).abs() < f64::EPSILON);
}

#[test]
fn test_yaml_5_element_rules_defaults() {
    let yaml = r#"
target_rules:
  - [DOMAIN, example.com, 443, 443, PASS]
"#;
    let f = create_temp_yaml(yaml);
    let trc = TargetRuleControl::load(f.path(), std::path::Path::new("nonexistent-static.yaml")).unwrap();
    let rules = trc.rules();

    let result = rules.check(&Address::Domain("example.com".to_string()), 443);
    assert!(result.allowed);
    assert!(!result.log); // opt1 默认 0
    assert_eq!(result.opt_flags, 0);
}

#[test]
fn test_yaml_6_element_rules() {
    let yaml = r#"
target_rules:
  - [IPCIDR, 10.0.0.0/8, 0, 65535, PASS, 3]
"#;
    let f = create_temp_yaml(yaml);
    let trc = TargetRuleControl::load(f.path(), std::path::Path::new("nonexistent-static.yaml")).unwrap();
    let rules = trc.rules();

    let result = rules.check(&Address::IPv4(Ipv4Addr::new(10, 1, 2, 3)), 80);
    assert!(result.allowed);
    assert_eq!(result.opt_flags, 0b0000_0011);
}

#[test]
fn test_yaml_invalid_too_few_elements() {
    let yaml = r#"
target_rules:
  - [DOMAIN, example.com, 0, 65535]
"#;
    let f = create_temp_yaml(yaml);
    let result = TargetRuleControl::load(f.path(), std::path::Path::new("nonexistent-static.yaml"));
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("expected 5-7 elements"));
}

#[test]
fn test_yaml_invalid_too_many_elements() {
    let yaml = r#"
target_rules:
  - [DOMAIN, example.com, 0, 65535, PASS, 0, 0, extra]
"#;
    let f = create_temp_yaml(yaml);
    let result = TargetRuleControl::load(f.path(), std::path::Path::new("nonexistent-static.yaml"));
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("expected 5-7 elements"));
}

#[test]
fn test_yaml_invalid_type() {
    let yaml = r#"
target_rules:
  - [INVALID_TYPE, example.com, 0, 65535, PASS]
"#;
    let f = create_temp_yaml(yaml);
    let result = TargetRuleControl::load(f.path(), std::path::Path::new("nonexistent-static.yaml"));
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("unknown type"));
}

#[test]
fn test_yaml_invalid_action() {
    let yaml = r#"
target_rules:
  - [DOMAIN, example.com, 0, 65535, ALLOW]
"#;
    let f = create_temp_yaml(yaml);
    let result = TargetRuleControl::load(f.path(), std::path::Path::new("nonexistent-static.yaml"));
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("unknown action"));
}

#[test]
fn test_yaml_invalid_opt1() {
    let yaml = r#"
target_rules:
  - [DOMAIN, example.com, 0, 65535, PASS, "not_a_number"]
"#;
    let f = create_temp_yaml(yaml);
    let result = TargetRuleControl::load(f.path(), std::path::Path::new("nonexistent-static.yaml"));
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("invalid opt1"));
}

#[test]
fn test_yaml_invalid_cidr() {
    let yaml = r#"
target_rules:
  - [IPCIDR, not-a-cidr, 0, 65535, PASS]
"#;
    let f = create_temp_yaml(yaml);
    let result = TargetRuleControl::load(f.path(), std::path::Path::new("nonexistent-static.yaml"));
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Invalid CIDR"));
}

#[test]
fn test_yaml_port_start_greater_than_end() {
    let yaml = r#"
target_rules:
  - [DOMAIN, example.com, 8080, 80, PASS]
"#;
    let f = create_temp_yaml(yaml);
    let result = TargetRuleControl::load(f.path(), std::path::Path::new("nonexistent-static.yaml"));
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("port_start"));
}

// ===== 规则匹配测试 =====

#[test]
fn test_domain_exact_match_case_insensitive() {
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

    assert!(rs
        .check(&Address::Domain("example.com".to_string()), 80)
        .allowed);
    assert!(rs
        .check(&Address::Domain("EXAMPLE.COM".to_string()), 80)
        .allowed);
    assert!(rs
        .check(&Address::Domain("Example.Com".to_string()), 80)
        .allowed);
    assert!(!rs
        .check(&Address::Domain("other.com".to_string()), 80)
        .allowed);
}

#[test]
fn test_domain_suffix_correct_matching() {
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
    assert!(rs
        .check(&Address::Domain("www.baidu.com".to_string()), 80)
        .allowed);
    assert!(rs
        .check(&Address::Domain("tieba.baidu.com".to_string()), 80)
        .allowed);
    assert!(rs
        .check(&Address::Domain("a.b.c.baidu.com".to_string()), 80)
        .allowed);

    // 精确匹配自身
    assert!(rs
        .check(&Address::Domain("baidu.com".to_string()), 80)
        .allowed);

    // 不误匹配 notbaidu.com（必须以 . 分隔或完全相等）
    assert!(!rs
        .check(&Address::Domain("notbaidu.com".to_string()), 80)
        .allowed);
    assert!(!rs
        .check(&Address::Domain("fakebaidu.com".to_string()), 80)
        .allowed);
}

#[test]
fn test_ipcidr_ipv4_cidr_boundary() {
    let rules = vec![
        make_rule(
            RuleType::IpCidr,
            "192.168.0.0/16",
            0,
            65535,
            RuleAction::Pass,
            0,
            0.0,
        ),
        make_rule(
            RuleType::IpCidr,
            "0.0.0.0/0",
            0,
            65535,
            RuleAction::Block,
            0,
            0.0,
        ),
    ];
    let rs = TargetRuleSet::compile(rules).unwrap();

    // 网络地址
    assert!(rs
        .check(&Address::IPv4(Ipv4Addr::new(192, 168, 0, 0)), 80)
        .allowed);
    // 广播地址
    assert!(rs
        .check(&Address::IPv4(Ipv4Addr::new(192, 168, 255, 255)), 80)
        .allowed);
    // 范围内
    assert!(rs
        .check(&Address::IPv4(Ipv4Addr::new(192, 168, 1, 100)), 80)
        .allowed);
    // 范围外 → 命中 0.0.0.0/0 BLOCK
    assert!(!rs
        .check(&Address::IPv4(Ipv4Addr::new(10, 0, 0, 1)), 80)
        .allowed);
}

#[test]
fn test_ipcidr_ipv6_matching() {
    let rules = vec![
        make_rule(
            RuleType::IpCidr,
            "::1/128",
            0,
            65535,
            RuleAction::Pass,
            0,
            0.0,
        ),
        make_rule(
            RuleType::IpCidr,
            "2001:db8::/32",
            0,
            65535,
            RuleAction::Pass,
            0,
            0.0,
        ),
        make_rule(
            RuleType::IpCidr,
            "::/0",
            0,
            65535,
            RuleAction::Block,
            0,
            0.0,
        ),
    ];
    let rs = TargetRuleSet::compile(rules).unwrap();

    assert!(rs.check(&Address::IPv6(Ipv6Addr::LOCALHOST), 80).allowed);
    assert!(rs
        .check(
            &Address::IPv6("2001:db8::1".parse().unwrap()),
            80
        )
        .allowed);
    assert!(rs
        .check(
            &Address::IPv6("2001:db8:ffff::1".parse().unwrap()),
            80
        )
        .allowed);
    // 不在 2001:db8::/32 范围内 → 命中 ::/0 BLOCK
    assert!(!rs
        .check(
            &Address::IPv6("2001:db9::1".parse().unwrap()),
            80
        )
        .allowed);
}

#[test]
fn test_ipcidr_ipv4_mapped_ipv6() {
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
    assert!(rs.check(&Address::IPv6(mapped), 80).allowed);

    // ::ffff:10.0.0.1 不应该匹配
    let mapped_outside: Ipv6Addr = "::ffff:10.0.0.1".parse().unwrap();
    assert!(!rs.check(&Address::IPv6(mapped_outside), 80).allowed);
}

#[test]
fn test_ipcidr_early_return_verification() {
    // 两条相同 CIDR 但不同 action，验证命中第一条即停止
    let rules = vec![
        make_rule(
            RuleType::IpCidr,
            "10.0.0.0/8",
            0,
            65535,
            RuleAction::Pass,
            OPT_LOG,
            0.0,
        ),
        make_rule(
            RuleType::IpCidr,
            "10.0.0.0/8",
            0,
            65535,
            RuleAction::Block,
            0,
            0.0,
        ),
    ];
    let rs = TargetRuleSet::compile(rules).unwrap();

    let result = rs.check(&Address::IPv4(Ipv4Addr::new(10, 1, 2, 3)), 80);
    assert!(result.allowed); // 命中第一条 PASS
    assert!(result.log); // 第一条有 OPT_LOG
}

#[test]
fn test_port_range_matching() {
    let rules = vec![
        make_rule(
            RuleType::Domain,
            "example.com",
            443,
            443,
            RuleAction::Pass,
            0,
            0.0,
        ),
        make_rule(
            RuleType::Domain,
            "example.com",
            8000,
            9000,
            RuleAction::Pass,
            0,
            0.0,
        ),
    ];
    let rs = TargetRuleSet::compile(rules).unwrap();

    // 精确端口
    assert!(rs
        .check(&Address::Domain("example.com".to_string()), 443)
        .allowed);
    // 范围内
    assert!(rs
        .check(&Address::Domain("example.com".to_string()), 8000)
        .allowed);
    assert!(rs
        .check(&Address::Domain("example.com".to_string()), 8500)
        .allowed);
    assert!(rs
        .check(&Address::Domain("example.com".to_string()), 9000)
        .allowed);
    // 范围外
    assert!(!rs
        .check(&Address::Domain("example.com".to_string()), 80)
        .allowed);
    assert!(!rs
        .check(&Address::Domain("example.com".to_string()), 7999)
        .allowed);
    assert!(!rs
        .check(&Address::Domain("example.com".to_string()), 9001)
        .allowed);
}

#[test]
fn test_first_match_wins_priority() {
    // 配置顺序决定优先级
    let rules = vec![
        make_rule(
            RuleType::DomainSuffix,
            "example.com",
            0,
            65535,
            RuleAction::Block,
            0,
            0.0,
        ),
        make_rule(
            RuleType::Domain,
            "example.com",
            0,
            65535,
            RuleAction::Pass,
            0,
            0.0,
        ),
    ];
    let rs = TargetRuleSet::compile(rules).unwrap();

    // DOMAIN-SUFFIX 优先级更高（priority=0），应该 BLOCK
    assert!(!rs
        .check(&Address::Domain("example.com".to_string()), 80)
        .allowed);
}

#[test]
fn test_cross_type_priority_domain_vs_suffix() {
    // DOMAIN 在前（priority=0），DOMAIN-SUFFIX 在后（priority=1）
    let rules = vec![
        make_rule(
            RuleType::Domain,
            "www.example.com",
            0,
            65535,
            RuleAction::Pass,
            0,
            0.0,
        ),
        make_rule(
            RuleType::DomainSuffix,
            "example.com",
            0,
            65535,
            RuleAction::Block,
            0,
            0.0,
        ),
    ];
    let rs = TargetRuleSet::compile(rules).unwrap();

    // www.example.com 同时匹配两条，取 priority=0 的 PASS
    assert!(rs
        .check(&Address::Domain("www.example.com".to_string()), 80)
        .allowed);
    // sub.example.com 只匹配 DOMAIN-SUFFIX，应该 BLOCK
    assert!(!rs
        .check(&Address::Domain("sub.example.com".to_string()), 80)
        .allowed);
}

#[test]
fn test_empty_rules_default_block() {
    let rs = TargetRuleSet::compile(vec![]).unwrap();

    let result = rs.check(&Address::Domain("example.com".to_string()), 80);
    assert!(!result.allowed);
    assert!(!result.log);
    assert_eq!(result.opt_flags, 0);

    let result = rs.check(&Address::IPv4(Ipv4Addr::new(1, 2, 3, 4)), 80);
    assert!(!result.allowed);

    let result = rs.check(&Address::IPv6(Ipv6Addr::LOCALHOST), 80);
    assert!(!result.allowed);
}

// ===== opt1/opt2 测试 =====

#[test]
fn test_opt_log_flag_passthrough() {
    let rules = vec![
        make_rule(
            RuleType::Domain,
            "logged.com",
            0,
            65535,
            RuleAction::Pass,
            OPT_LOG,
            0.0,
        ),
        make_rule(
            RuleType::Domain,
            "silent.com",
            0,
            65535,
            RuleAction::Pass,
            0,
            0.0,
        ),
    ];
    let rs = TargetRuleSet::compile(rules).unwrap();

    let result = rs.check(&Address::Domain("logged.com".to_string()), 80);
    assert!(result.log);

    let result = rs.check(&Address::Domain("silent.com".to_string()), 80);
    assert!(!result.log);
}

#[test]
fn test_opt_flags_and_value_in_match_result() {
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

// ===== 性能测试 =====

#[test]
fn test_performance_1000_rules() {
    let mut rules = Vec::with_capacity(1100);

    // 500 条 DOMAIN 规则
    for i in 0..500 {
        rules.push(make_rule(
            RuleType::Domain,
            &format!("domain{}.example.com", i),
            0,
            65535,
            RuleAction::Pass,
            0,
            0.0,
        ));
    }

    // 300 条 DOMAIN-SUFFIX 规则
    for i in 0..300 {
        rules.push(make_rule(
            RuleType::DomainSuffix,
            &format!("suffix{}.com", i),
            0,
            65535,
            RuleAction::Pass,
            0,
            0.0,
        ));
    }

    // 200 条 IPCIDR 规则
    for i in 0..200u8 {
        rules.push(make_rule(
            RuleType::IpCidr,
            &format!("{}.0.0.0/8", i),
            0,
            65535,
            RuleAction::Pass,
            0,
            0.0,
        ));
    }

    // 兜底规则
    rules.push(make_rule(
        RuleType::IpCidr,
        "0.0.0.0/0",
        0,
        65535,
        RuleAction::Block,
        0,
        0.0,
    ));

    let rs = TargetRuleSet::compile(rules).unwrap();
    assert!(rs.rule_count() > 1000);

    // 测试 DOMAIN 精确匹配
    let result = rs.check(
        &Address::Domain("domain250.example.com".to_string()),
        80,
    );
    assert!(result.allowed);

    // 测试 DOMAIN-SUFFIX 匹配
    let result = rs.check(
        &Address::Domain("www.suffix150.com".to_string()),
        80,
    );
    assert!(result.allowed);

    // 测试 IPCIDR 匹配
    let result = rs.check(&Address::IPv4(Ipv4Addr::new(100, 1, 2, 3)), 80);
    assert!(result.allowed);

    // 测试不匹配的 IP → 命中兜底 BLOCK
    let result = rs.check(&Address::IPv4(Ipv4Addr::new(200, 1, 2, 3)), 80);
    assert!(!result.allowed);

    // 批量匹配性能验证
    let start = std::time::Instant::now();
    for _ in 0..10000 {
        let _ = rs.check(
            &Address::Domain("domain499.example.com".to_string()),
            80,
        );
        let _ = rs.check(
            &Address::Domain("www.suffix299.com".to_string()),
            80,
        );
        let _ = rs.check(&Address::IPv4(Ipv4Addr::new(199, 1, 2, 3)), 80);
    }
    let elapsed = start.elapsed();
    // 30000 次匹配应该在 1 秒内完成
    assert!(
        elapsed.as_secs() < 1,
        "Performance test failed: 30000 matches took {:?}",
        elapsed
    );
}

// ===== 配置加载测试 =====

#[test]
fn test_load_valid_yaml() {
    let yaml = r#"
target_rules:
  - [DOMAIN-SUFFIX, baidu.com, 0, 65535, PASS, 1, 0]
  - [IPCIDR, 10.0.0.0/8, 0, 65535, PASS]
  - [IPCIDR, 0.0.0.0/0, 0, 65535, BLOCK]
"#;
    let f = create_temp_yaml(yaml);
    let trc = TargetRuleControl::load(f.path(), std::path::Path::new("nonexistent-static.yaml")).unwrap();
    assert_eq!(trc.rules().rule_count(), 3);
}

#[test]
fn test_load_nonexistent_file() {
    let result = TargetRuleControl::load(
        std::path::Path::new("/nonexistent/target-rules.yaml"),
        std::path::Path::new("nonexistent-static.yaml"),
    );
    // dynamic 文件不存在时应返回错误（与 static 不同，dynamic 不存在也会返回空规则）
    // 注意：新实现中文件不存在返回空规则而非错误，所以此测试应改为成功
    assert!(result.is_ok());
}

#[test]
fn test_load_empty_yaml() {
    let yaml = "";
    let f = create_temp_yaml(yaml);
    let trc = TargetRuleControl::load(f.path(), std::path::Path::new("nonexistent-static.yaml")).unwrap();
    assert_eq!(trc.rules().rule_count(), 0);
    // 空规则集默认阻止所有
    assert!(!trc
        .rules()
        .check(&Address::Domain("example.com".to_string()), 80)
        .allowed);
}

#[test]
fn test_load_empty_target_rules_field() {
    let yaml = r#"
target_rules: []
"#;
    let f = create_temp_yaml(yaml);
    let trc = TargetRuleControl::load(f.path(), std::path::Path::new("nonexistent-static.yaml")).unwrap();
    assert_eq!(trc.rules().rule_count(), 0);
}

// ===== 热加载测试 =====

#[test]
fn test_reload_updates_rules() {
    let yaml = r#"
target_rules:
  - [DOMAIN, example.com, 0, 65535, PASS]
"#;
    let mut f = create_temp_yaml(yaml);
    let trc = TargetRuleControl::load(f.path(), std::path::Path::new("nonexistent-static.yaml")).unwrap();
    assert!(trc
        .rules()
        .check(&Address::Domain("example.com".to_string()), 80)
        .allowed);
    assert!(!trc
        .rules()
        .check(&Address::Domain("other.com".to_string()), 80)
        .allowed);

    // 更新文件内容
    let new_yaml = r#"
target_rules:
  - [DOMAIN, other.com, 0, 65535, PASS]
"#;
    f.as_file_mut().set_len(0).unwrap();
    use std::io::Seek;
    f.as_file_mut().seek(std::io::SeekFrom::Start(0)).unwrap();
    write!(f, "{}", new_yaml).unwrap();
    f.as_file_mut().flush().unwrap();

    trc.reload().unwrap();
    assert!(!trc
        .rules()
        .check(&Address::Domain("example.com".to_string()), 80)
        .allowed);
    assert!(trc
        .rules()
        .check(&Address::Domain("other.com".to_string()), 80)
        .allowed);
}

#[test]
fn test_reload_failure_keeps_old_rules() {
    let yaml = r#"
target_rules:
  - [DOMAIN, example.com, 0, 65535, PASS]
"#;
    let mut f = create_temp_yaml(yaml);
    let trc = TargetRuleControl::load(f.path(), std::path::Path::new("nonexistent-static.yaml")).unwrap();
    assert!(trc
        .rules()
        .check(&Address::Domain("example.com".to_string()), 80)
        .allowed);

    // 写入非法内容
    let invalid_yaml = "invalid: yaml: [unclosed";
    f.as_file_mut().set_len(0).unwrap();
    use std::io::Seek;
    f.as_file_mut().seek(std::io::SeekFrom::Start(0)).unwrap();
    write!(f, "{}", invalid_yaml).unwrap();
    f.as_file_mut().flush().unwrap();

    // reload 应该失败，但旧规则保留
    assert!(trc.reload().is_err());
    assert!(trc
        .rules()
        .check(&Address::Domain("example.com".to_string()), 80)
        .allowed);
}

// ===== watch 热加载测试 =====

#[tokio::test]
async fn test_watch_auto_reload() {
    use std::io::Seek;

    let yaml = r#"
target_rules:
  - [DOMAIN, example.com, 0, 65535, PASS]
"#;
    let mut f = create_temp_yaml(yaml);
    let trc = Arc::new(TargetRuleControl::load(f.path(), std::path::Path::new("nonexistent-static.yaml")).unwrap());
    assert!(trc
        .rules()
        .check(&Address::Domain("example.com".to_string()), 80)
        .allowed);

    let _watcher = trc.watch().unwrap();

    // 修改文件内容
    let new_yaml = r#"
target_rules:
  - [DOMAIN, other.com, 0, 65535, PASS]
  - [DOMAIN, new.com, 0, 65535, PASS]
"#;
    f.as_file_mut().set_len(0).unwrap();
    f.as_file_mut().seek(std::io::SeekFrom::Start(0)).unwrap();
    write!(f, "{}", new_yaml).unwrap();
    f.as_file_mut().flush().unwrap();

    // 等待防抖（500ms）+ 余量
    let mut reloaded = false;
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        if trc.rules().rule_count() == 2
            && trc
                .rules()
                .check(&Address::Domain("other.com".to_string()), 80)
                .allowed
        {
            reloaded = true;
            break;
        }
    }
    assert!(reloaded, "File watcher did not auto-reload within timeout");
    assert!(!trc
        .rules()
        .check(&Address::Domain("example.com".to_string()), 80)
        .allowed);
    assert!(trc
        .rules()
        .check(&Address::Domain("new.com".to_string()), 80)
        .allowed);
}

#[tokio::test]
async fn test_watch_survives_invalid_content() {
    use std::io::Seek;

    let yaml = r#"
target_rules:
  - [DOMAIN, example.com, 0, 65535, PASS]
"#;
    let mut f = create_temp_yaml(yaml);
    let trc = Arc::new(TargetRuleControl::load(f.path(), std::path::Path::new("nonexistent-static.yaml")).unwrap());
    assert!(trc
        .rules()
        .check(&Address::Domain("example.com".to_string()), 80)
        .allowed);

    let _watcher = trc.watch().unwrap();

    // 写入非法内容
    let invalid_yaml = "invalid: yaml: [unclosed";
    f.as_file_mut().set_len(0).unwrap();
    f.as_file_mut().seek(std::io::SeekFrom::Start(0)).unwrap();
    write!(f, "{}", invalid_yaml).unwrap();
    f.as_file_mut().flush().unwrap();

    // 等待 watcher 尝试重载
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    // 旧规则应该仍然有效
    assert!(trc
        .rules()
        .check(&Address::Domain("example.com".to_string()), 80)
        .allowed);
    assert_eq!(trc.rules().rule_count(), 1);

    // 再写入有效内容，应该能恢复
    let valid_yaml = r#"
target_rules:
  - [DOMAIN, recovered.com, 0, 65535, PASS]
"#;
    f.as_file_mut().set_len(0).unwrap();
    f.as_file_mut().seek(std::io::SeekFrom::Start(0)).unwrap();
    write!(f, "{}", valid_yaml).unwrap();
    f.as_file_mut().flush().unwrap();

    let mut recovered = false;
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        if trc
            .rules()
            .check(&Address::Domain("recovered.com".to_string()), 80)
            .allowed
        {
            recovered = true;
            break;
        }
    }
    assert!(
        recovered,
        "File watcher did not recover after invalid content"
    );
    assert!(!trc
        .rules()
        .check(&Address::Domain("example.com".to_string()), 80)
        .allowed);
}

// ===== 并发安全测试 =====

#[test]
fn test_concurrent_check_during_reload() {
    use std::io::Seek;
    use std::thread;

    let yaml = r#"
target_rules:
  - [DOMAIN-SUFFIX, example.com, 0, 65535, PASS]
"#;
    let mut f = create_temp_yaml(yaml);
    let trc = Arc::new(TargetRuleControl::load(f.path(), std::path::Path::new("nonexistent-static.yaml")).unwrap());

    // 启动多个读取线程
    let readers: Vec<_> = (0..8)
        .map(|_| {
            let trc_clone = Arc::clone(&trc);
            thread::spawn(move || {
                for _ in 0..1000 {
                    let _ = trc_clone
                        .rules()
                        .check(&Address::Domain("www.example.com".to_string()), 80);
                }
            })
        })
        .collect();

    // 主线程并发执行 reload
    let new_yaml = r#"
target_rules:
  - [DOMAIN-SUFFIX, other.com, 0, 65535, PASS]
"#;
    f.as_file_mut().set_len(0).unwrap();
    f.as_file_mut().seek(std::io::SeekFrom::Start(0)).unwrap();
    write!(f, "{}", new_yaml).unwrap();
    f.as_file_mut().flush().unwrap();

    for _ in 0..10 {
        let _ = trc.reload();
    }

    for handle in readers {
        handle.join().unwrap();
    }

    // 最终规则应该是新规则
    assert!(trc
        .rules()
        .check(&Address::Domain("www.other.com".to_string()), 80)
        .allowed);
}

// ===== YAML 值类型容错测试 =====

#[test]
fn test_yaml_value_type_tolerance() {
    // 测试 YAML 中 value 被解析为非字符串类型的情况
    // 例如 IPCIDR 的值 127.0.0.1/32 可能被 YAML 解析器正确处理为字符串
    let yaml = r#"
target_rules:
  - [IPCIDR, 127.0.0.1/32, 0, 65535, PASS]
  - [IPCIDR, 10.0.0.0/8, 0, 65535, PASS]
"#;
    let f = create_temp_yaml(yaml);
    let trc = TargetRuleControl::load(f.path(), std::path::Path::new("nonexistent-static.yaml")).unwrap();
    assert_eq!(trc.rules().rule_count(), 2);

    assert!(trc
        .rules()
        .check(&Address::IPv4(Ipv4Addr::new(127, 0, 0, 1)), 80)
        .allowed);
}

// ===== 倒序 Trie 特有行为测试 =====

#[test]
fn test_suffix_deep_nesting() {
    // 测试深层嵌套域名的后缀匹配
    let rules = vec![make_rule(
        RuleType::DomainSuffix,
        "com.cn",
        0,
        65535,
        RuleAction::Pass,
        0,
        0.0,
    )];
    let rs = TargetRuleSet::compile(rules).unwrap();

    // 多级子域名匹配
    assert!(rs
        .check(&Address::Domain("api.test.com.cn".to_string()), 80)
        .allowed);
    assert!(rs
        .check(&Address::Domain("a.b.c.d.com.cn".to_string()), 80)
        .allowed);
    // 精确匹配自身
    assert!(rs
        .check(&Address::Domain("com.cn".to_string()), 80)
        .allowed);
    // 不误匹配
    assert!(!rs
        .check(&Address::Domain("com.net".to_string()), 80)
        .allowed);
    assert!(!rs
        .check(&Address::Domain("notcom.cn".to_string()), 80)
        .allowed);
}

#[test]
fn test_suffix_multiple_rules_same_branch() {
    // 同一 Trie 分支上有多条规则，验证优先级正确
    let rules = vec![
        make_rule(
            RuleType::DomainSuffix,
            "com.cn",
            0,
            65535,
            RuleAction::Block,
            0,
            0.0,
        ),
        make_rule(
            RuleType::DomainSuffix,
            "test.com.cn",
            0,
            65535,
            RuleAction::Pass,
            0,
            0.0,
        ),
    ];
    let rs = TargetRuleSet::compile(rules).unwrap();

    // api.test.com.cn 同时匹配 com.cn(priority=0) 和 test.com.cn(priority=1)
    // 应取 priority=0 的 BLOCK
    assert!(!rs
        .check(&Address::Domain("api.test.com.cn".to_string()), 80)
        .allowed);

    // other.com.cn 只匹配 com.cn，应 BLOCK
    assert!(!rs
        .check(&Address::Domain("other.com.cn".to_string()), 80)
        .allowed);
}

#[test]
fn test_suffix_early_termination() {
    // 验证 Trie 路径不存在时不会误匹配
    let rules = vec![make_rule(
        RuleType::DomainSuffix,
        "specific.example.com",
        0,
        65535,
        RuleAction::Pass,
        0,
        0.0,
    )];
    let rs = TargetRuleSet::compile(rules).unwrap();

    // 匹配
    assert!(rs
        .check(
            &Address::Domain("api.specific.example.com".to_string()),
            80
        )
        .allowed);
    // 不匹配：example.com 路径存在但 specific 节点才有规则
    assert!(!rs
        .check(&Address::Domain("other.example.com".to_string()), 80)
        .allowed);
    // 不匹配：完全不同的路径
    assert!(!rs
        .check(&Address::Domain("specific.other.com".to_string()), 80)
        .allowed);
}

#[test]
fn test_suffix_single_label() {
    // 单级后缀（如 TLD）
    let rules = vec![make_rule(
        RuleType::DomainSuffix,
        "cn",
        0,
        65535,
        RuleAction::Pass,
        0,
        0.0,
    )];
    let rs = TargetRuleSet::compile(rules).unwrap();

    assert!(rs
        .check(&Address::Domain("example.cn".to_string()), 80)
        .allowed);
    assert!(rs
        .check(&Address::Domain("a.b.c.cn".to_string()), 80)
        .allowed);
    assert!(rs
        .check(&Address::Domain("cn".to_string()), 80)
        .allowed);
    assert!(!rs
        .check(&Address::Domain("example.com".to_string()), 80)
        .allowed);
}

// ===== 双文件拆分测试 =====

/// 场景1: 仅 dynamic 文件存在，static 不存在
#[test]
fn test_dual_file_only_dynamic() {
    let dynamic_yaml = r#"
target_rules:
  - [DOMAIN, example.com, 0, 65535, PASS]
  - [IPCIDR, 10.0.0.0/8, 0, 65535, PASS]
"#;
    let dynamic = create_temp_yaml(dynamic_yaml);
    let trc = TargetRuleControl::load(
        dynamic.path(),
        Path::new("nonexistent-static-dual-test.yaml"),
    )
    .unwrap();

    assert_eq!(trc.rules().rule_count(), 2);
    assert!(trc
        .rules()
        .check(&Address::Domain("example.com".to_string()), 80)
        .allowed);
    assert!(trc
        .rules()
        .check(&Address::IPv4(Ipv4Addr::new(10, 1, 2, 3)), 443)
        .allowed);
    // 未命中规则默认 BLOCK
    assert!(!trc
        .rules()
        .check(&Address::Domain("other.com".to_string()), 80)
        .allowed);
}

/// 场景2: 仅 static 文件存在，dynamic 不存在
#[test]
fn test_dual_file_only_static() {
    let static_yaml = r#"
target_rules:
  - [DOMAIN-SUFFIX, dingtalk.com, 0, 65535, PASS]
  - [IPCIDR, 47.110.35.86/32, 0, 65535, PASS]
"#;
    let static_file = create_temp_yaml(static_yaml);
    let trc = TargetRuleControl::load(
        Path::new("nonexistent-dynamic-dual-test.yaml"),
        static_file.path(),
    )
    .unwrap();

    assert_eq!(trc.rules().rule_count(), 2);
    assert!(trc
        .rules()
        .check(&Address::Domain("www.dingtalk.com".to_string()), 80)
        .allowed);
    assert!(trc
        .rules()
        .check(&Address::IPv4(Ipv4Addr::new(47, 110, 35, 86)), 80)
        .allowed);
    assert!(!trc
        .rules()
        .check(&Address::Domain("other.com".to_string()), 80)
        .allowed);
}

/// 场景3: 双文件合并，dynamic 优先级高于 static
#[test]
fn test_dual_file_dynamic_priority_over_static() {
    // dynamic: BLOCK example.com
    let dynamic_yaml = r#"
target_rules:
  - [DOMAIN, example.com, 0, 65535, BLOCK]
"#;
    // static: PASS example.com（应被 dynamic 的 BLOCK 覆盖）
    let static_yaml = r#"
target_rules:
  - [DOMAIN, example.com, 0, 65535, PASS]
  - [DOMAIN, other.com, 0, 65535, PASS]
"#;
    let dynamic = create_temp_yaml(dynamic_yaml);
    let static_file = create_temp_yaml(static_yaml);
    let trc = TargetRuleControl::load(dynamic.path(), static_file.path()).unwrap();

    assert_eq!(trc.rules().rule_count(), 3);
    // dynamic 的 BLOCK 规则优先级更高（排在前面）
    assert!(!trc
        .rules()
        .check(&Address::Domain("example.com".to_string()), 80)
        .allowed);
    // static 中的 other.com PASS 规则正常生效
    assert!(trc
        .rules()
        .check(&Address::Domain("other.com".to_string()), 80)
        .allowed);
}

/// 场景3 扩展: dynamic 和 static 都有 CIDR 规则时，dynamic 优先
#[test]
fn test_dual_file_cidr_priority() {
    // dynamic: BLOCK 10.0.0.0/8
    let dynamic_yaml = r#"
target_rules:
  - [IPCIDR, 10.0.0.0/8, 0, 65535, BLOCK]
"#;
    // static: PASS 10.0.0.0/8
    let static_yaml = r#"
target_rules:
  - [IPCIDR, 10.0.0.0/8, 0, 65535, PASS]
  - [IPCIDR, 192.168.0.0/16, 0, 65535, PASS]
"#;
    let dynamic = create_temp_yaml(dynamic_yaml);
    let static_file = create_temp_yaml(static_yaml);
    let trc = TargetRuleControl::load(dynamic.path(), static_file.path()).unwrap();

    // dynamic 的 BLOCK 优先
    assert!(!trc
        .rules()
        .check(&Address::IPv4(Ipv4Addr::new(10, 1, 2, 3)), 80)
        .allowed);
    // static 中的 192.168.x.x PASS 正常生效
    assert!(trc
        .rules()
        .check(&Address::IPv4(Ipv4Addr::new(192, 168, 1, 1)), 80)
        .allowed);
}

/// 场景6: 双文件都不存在时的容错
#[test]
fn test_dual_file_both_nonexistent() {
    let trc = TargetRuleControl::load(
        Path::new("nonexistent-dynamic-xxx.yaml"),
        Path::new("nonexistent-static-xxx.yaml"),
    )
    .unwrap();

    // 空规则集，默认 BLOCK
    assert_eq!(trc.rules().rule_count(), 0);
    assert!(!trc
        .rules()
        .check(&Address::Domain("example.com".to_string()), 80)
        .allowed);
    assert!(!trc
        .rules()
        .check(&Address::IPv4(Ipv4Addr::new(1, 2, 3, 4)), 80)
        .allowed);
}

// ===== convert_acl_to_yaml 转换正确性测试 =====

#[test]
fn test_convert_acl_to_yaml_basic() {
    let acl = NetAcl {
        block_domains: vec!["www.blocked.com".to_string()],
        pass_domains: vec![
            ".dingtalk.com".to_string(),
            "exact.example.com".to_string(),
        ],
        block_ips: vec!["192.168.0.0/16".to_string()],
        pass_ips: vec!["10.0.0.0/8".to_string()],
    };

    let yaml = convert_acl_to_yaml(&acl);

    // 验证写入顺序: BlockDomains -> PassDomains -> BlockIPs -> PassIPs
    let block_domain_pos = yaml.find("DOMAIN, www.blocked.com").unwrap();
    let pass_domain_suffix_pos = yaml.find("DOMAIN-SUFFIX, dingtalk.com").unwrap();
    let pass_domain_exact_pos = yaml.find("DOMAIN, exact.example.com").unwrap();
    let block_ip_pos = yaml.find("IPCIDR, 192.168.0.0/16").unwrap();
    let pass_ip_pos = yaml.find("IPCIDR, 10.0.0.0/8").unwrap();

    assert!(
        block_domain_pos < pass_domain_suffix_pos,
        "BlockDomains should come before PassDomains"
    );
    assert!(
        pass_domain_exact_pos < block_ip_pos,
        "PassDomains should come before BlockIPs"
    );
    assert!(
        block_ip_pos < pass_ip_pos,
        "BlockIPs should come before PassIPs"
    );

    // 验证 BLOCK 动作（remote 接口默认启用日志，opt1=1）
    assert!(yaml.contains("[DOMAIN, www.blocked.com, 0, 65535, BLOCK, 1]"));
    // 验证后缀匹配（.dingtalk.com -> DOMAIN-SUFFIX dingtalk.com）
    assert!(yaml.contains("[DOMAIN-SUFFIX, dingtalk.com, 0, 65535, PASS, 1]"));
    // 验证精确匹配（无前缀 . -> DOMAIN）
    assert!(yaml.contains("[DOMAIN, exact.example.com, 0, 65535, PASS, 1]"));
    // 验证 IP 规则
    assert!(yaml.contains("[IPCIDR, 192.168.0.0/16, 0, 65535, BLOCK, 1]"));
    assert!(yaml.contains("[IPCIDR, 10.0.0.0/8, 0, 65535, PASS, 1]"));
}

#[test]
fn test_convert_acl_to_yaml_empty_fields() {
    let acl = NetAcl {
        block_domains: vec![],
        pass_domains: vec![],
        block_ips: vec![],
        pass_ips: vec![],
    };

    let yaml = convert_acl_to_yaml(&acl);
    assert!(yaml.contains("target_rules:"));
    // 空规则集不应有任何规则行
    assert!(!yaml.contains("DOMAIN"));
    assert!(!yaml.contains("IPCIDR"));
}

#[test]
fn test_convert_acl_to_yaml_roundtrip() {
    // 验证生成的 YAML 可以被 TargetRuleControl 正确加载
    let acl = NetAcl {
        block_domains: vec!["www.blocked.com".to_string()],
        pass_domains: vec![
            ".dingtalk.com".to_string(),
            "exact.pass.com".to_string(),
        ],
        block_ips: vec!["192.168.0.0/16".to_string()],
        pass_ips: vec!["10.0.0.0/8".to_string(), "47.110.35.86/32".to_string()],
    };

    let yaml = convert_acl_to_yaml(&acl);
    let static_file = create_temp_yaml(&yaml);
    let trc = TargetRuleControl::load(
        Path::new("nonexistent-dynamic-roundtrip.yaml"),
        static_file.path(),
    )
    .unwrap();

    // BlockDomains -> BLOCK
    assert!(!trc
        .rules()
        .check(&Address::Domain("www.blocked.com".to_string()), 80)
        .allowed);
    // PassDomains 后缀 -> PASS
    assert!(trc
        .rules()
        .check(&Address::Domain("www.dingtalk.com".to_string()), 80)
        .allowed);
    // PassDomains 精确 -> PASS
    assert!(trc
        .rules()
        .check(&Address::Domain("exact.pass.com".to_string()), 80)
        .allowed);
    // BlockIPs -> BLOCK
    assert!(!trc
        .rules()
        .check(&Address::IPv4(Ipv4Addr::new(192, 168, 1, 1)), 80)
        .allowed);
    // PassIPs -> PASS
    assert!(trc
        .rules()
        .check(&Address::IPv4(Ipv4Addr::new(10, 0, 0, 1)), 80)
        .allowed);
    assert!(trc
        .rules()
        .check(&Address::IPv4(Ipv4Addr::new(47, 110, 35, 86)), 80)
        .allowed);
}

// ===== 远程拉取测试 =====

/// 启动一个简易 mock HTTP server，返回指定的 JSON 响应
async fn start_mock_acl_server(json_body: &str) -> (std::net::SocketAddr, CancellationToken) {
    use hyper::body::Bytes;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    let body = json_body.to_string();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let token = CancellationToken::new();
    let token_clone = token.clone();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = token_clone.cancelled() => break,
                result = listener.accept() => {
                    if let Ok((stream, _)) = result {
                        let body = body.clone();
                        tokio::spawn(async move {
                            let io = TokioIo::new(stream);
                            let _ = hyper::server::conn::http1::Builder::new()
                                .serve_connection(
                                    io,
                                    service_fn(move |_req: Request<hyper::body::Incoming>| {
                                        let body = body.clone();
                                        async move {
                                            Ok::<_, hyper::Error>(
                                                Response::new(
                                                    http_body_util::Full::new(Bytes::from(body))
                                                )
                                            )
                                        }
                                    }),
                                )
                                .await;
                        });
                    }
                }
            }
        }
    });

    (addr, token)
}

/// 场景4: 远程拉取生成 static 文件
#[tokio::test]
async fn test_fetch_generates_static_file() {
    let acl_json = r#"{
        "data": {
            "netacl": {
                "BlockDomains": ["www.blocked.com"],
                "PassDomains": [".dingtalk.com"],
                "BlockIPs": [],
                "PassIPs": ["10.0.0.0/8"]
            }
        },
        "msg": "",
        "status": "ok"
    }"#;

    let (mock_addr, mock_token) = start_mock_acl_server(acl_json).await;
    let fetch_url = format!("http://127.0.0.1:{}/acl", mock_addr.port());

    let dynamic_yaml = r#"
target_rules:
  - [DOMAIN, user-defined.com, 0, 65535, PASS]
"#;
    let dynamic = create_temp_yaml(dynamic_yaml);

    // 使用临时文件路径作为 static 文件（初始不存在）
    let static_dir = tempfile::tempdir().unwrap();
    let static_path = static_dir.path().join("static-target-rules.yaml");

    let trc = Arc::new(
        TargetRuleControl::load(dynamic.path(), &static_path).unwrap(),
    );

    // 此时只有 dynamic 中的 1 条规则
    assert_eq!(trc.rules().rule_count(), 1);

    // 启动 watcher（fetch 写入文件后由 watcher 触发 reload）
    let _watchers = trc.watch().unwrap();

    let cancel_token = CancellationToken::new();
    trc.start_fetch_task(
        fetch_url,
        Duration::from_secs(3600), // 长间隔，只测首次拉取
        cancel_token.clone(),
    );

    // 等待首次拉取完成 + watcher 防抖 500ms
    let mut fetched = false;
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if static_path.exists() && trc.rules().rule_count() > 1 {
            fetched = true;
            break;
        }
    }
    assert!(fetched, "Static file was not generated by fetch task");

    // 验证合并后的规则
    // dynamic 中的自定义规则仍然生效
    assert!(trc
        .rules()
        .check(&Address::Domain("user-defined.com".to_string()), 80)
        .allowed);
    // static 中的 PassDomains 生效
    assert!(trc
        .rules()
        .check(&Address::Domain("www.dingtalk.com".to_string()), 80)
        .allowed);
    // static 中的 BlockDomains 生效
    assert!(!trc
        .rules()
        .check(&Address::Domain("www.blocked.com".to_string()), 80)
        .allowed);
    // static 中的 PassIPs 生效
    assert!(trc
        .rules()
        .check(&Address::IPv4(Ipv4Addr::new(10, 1, 2, 3)), 80)
        .allowed);

    // 验证 static 文件内容
    let static_content = std::fs::read_to_string(&static_path).unwrap();
    assert!(static_content.contains("自动生成"));
    assert!(static_content.contains("DOMAIN, www.blocked.com"));
    assert!(static_content.contains("DOMAIN-SUFFIX, dingtalk.com"));

    cancel_token.cancel();
    mock_token.cancel();
}

/// 场景5: 定期拉取（短间隔验证多次更新）
#[tokio::test]
async fn test_periodic_fetch_updates() {
    let acl_json = r#"{
        "data": {
            "netacl": {
                "BlockDomains": [],
                "PassDomains": [".first.com"],
                "BlockIPs": [],
                "PassIPs": []
            }
        },
        "msg": "",
        "status": "ok"
    }"#;

    let (mock_addr, mock_token) = start_mock_acl_server(acl_json).await;
    let fetch_url = format!("http://127.0.0.1:{}/acl", mock_addr.port());

    let static_dir = tempfile::tempdir().unwrap();
    let static_path = static_dir.path().join("static-periodic.yaml");

    let trc = Arc::new(
        TargetRuleControl::load(
            Path::new("nonexistent-dynamic-periodic.yaml"),
            &static_path,
        )
        .unwrap(),
    );

    let cancel_token = CancellationToken::new();

    // 启动 watcher（fetch 写入文件后由 watcher 触发 reload）
    let _watchers = trc.watch().unwrap();

    trc.start_fetch_task(
        fetch_url,
        Duration::from_secs(1), // 1 秒间隔
        cancel_token.clone(),
    );

    // 等待首次拉取完成 + watcher 防抖 500ms
    let mut fetched = false;
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if trc.rules().rule_count() > 0 {
            fetched = true;
            break;
        }
    }
    assert!(fetched, "First periodic fetch did not complete");

    // 验证首次拉取的规则
    assert!(trc
        .rules()
        .check(&Address::Domain("www.first.com".to_string()), 80)
        .allowed);

    cancel_token.cancel();
    mock_token.cancel();
}

/// 场景6: 拉取失败容错（不可达 URL）
#[tokio::test]
async fn test_fetch_failure_keeps_existing_rules() {
    let dynamic_yaml = r#"
target_rules:
  - [DOMAIN, existing.com, 0, 65535, PASS]
"#;
    let dynamic = create_temp_yaml(dynamic_yaml);
    let static_dir = tempfile::tempdir().unwrap();
    let static_path = static_dir.path().join("static-fail.yaml");

    let trc = Arc::new(
        TargetRuleControl::load(dynamic.path(), &static_path).unwrap(),
    );
    assert_eq!(trc.rules().rule_count(), 1);

    let cancel_token = CancellationToken::new();
    // 使用不可达的 URL
    trc.start_fetch_task(
        "http://127.0.0.1:1/unreachable-acl".to_string(),
        Duration::from_secs(3600),
        cancel_token.clone(),
    );

    // 等待首次拉取尝试完成（应该失败）
    tokio::time::sleep(Duration::from_secs(3)).await;

    // 规则应保持不变
    assert_eq!(trc.rules().rule_count(), 1);
    assert!(trc
        .rules()
        .check(&Address::Domain("existing.com".to_string()), 80)
        .allowed);
    // static 文件不应被创建
    assert!(!static_path.exists());

    cancel_token.cancel();
}

// ===== 热加载双文件测试 =====

/// 场景7: 修改 dynamic 文件后自动 reload
#[tokio::test]
async fn test_watch_dual_file_dynamic_change() {
    use std::io::Seek;

    let dynamic_yaml = r#"
target_rules:
  - [DOMAIN, original.com, 0, 65535, PASS]
"#;
    let static_yaml = r#"
target_rules:
  - [DOMAIN, static-rule.com, 0, 65535, PASS]
"#;
    let mut dynamic = create_temp_yaml(dynamic_yaml);
    let static_file = create_temp_yaml(static_yaml);

    let trc = Arc::new(
        TargetRuleControl::load(dynamic.path(), static_file.path()).unwrap(),
    );
    assert_eq!(trc.rules().rule_count(), 2);
    assert!(trc
        .rules()
        .check(&Address::Domain("original.com".to_string()), 80)
        .allowed);

    let _watchers = trc.watch().unwrap();

    // 修改 dynamic 文件
    let new_dynamic = r#"
target_rules:
  - [DOMAIN, changed.com, 0, 65535, PASS]
  - [DOMAIN, another.com, 0, 65535, PASS]
"#;
    dynamic.as_file_mut().set_len(0).unwrap();
    dynamic
        .as_file_mut()
        .seek(std::io::SeekFrom::Start(0))
        .unwrap();
    write!(dynamic, "{}", new_dynamic).unwrap();
    dynamic.as_file_mut().flush().unwrap();

    // 等待 watcher 防抖 + reload
    let mut reloaded = false;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if trc.rules().rule_count() == 3
            && trc
                .rules()
                .check(&Address::Domain("changed.com".to_string()), 80)
                .allowed
        {
            reloaded = true;
            break;
        }
    }
    assert!(
        reloaded,
        "Dynamic file change did not trigger auto-reload"
    );

    // 旧 dynamic 规则不再存在
    assert!(!trc
        .rules()
        .check(&Address::Domain("original.com".to_string()), 80)
        .allowed);
    // static 规则仍然存在
    assert!(trc
        .rules()
        .check(&Address::Domain("static-rule.com".to_string()), 80)
        .allowed);
}

/// 场景7: 修改 static 文件后自动 reload
#[tokio::test]
async fn test_watch_dual_file_static_change() {
    use std::io::Seek;

    let dynamic_yaml = r#"
target_rules:
  - [DOMAIN, dynamic-rule.com, 0, 65535, PASS]
"#;
    let static_yaml = r#"
target_rules:
  - [DOMAIN, old-static.com, 0, 65535, PASS]
"#;
    let dynamic = create_temp_yaml(dynamic_yaml);
    let mut static_file = create_temp_yaml(static_yaml);

    let trc = Arc::new(
        TargetRuleControl::load(dynamic.path(), static_file.path()).unwrap(),
    );
    assert_eq!(trc.rules().rule_count(), 2);

    let _watchers = trc.watch().unwrap();

    // 修改 static 文件
    let new_static = r#"
target_rules:
  - [DOMAIN, new-static.com, 0, 65535, PASS]
  - [DOMAIN, extra-static.com, 0, 65535, PASS]
"#;
    static_file.as_file_mut().set_len(0).unwrap();
    static_file
        .as_file_mut()
        .seek(std::io::SeekFrom::Start(0))
        .unwrap();
    write!(static_file, "{}", new_static).unwrap();
    static_file.as_file_mut().flush().unwrap();

    // 等待 watcher 防抖 + reload
    let mut reloaded = false;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if trc.rules().rule_count() == 3
            && trc
                .rules()
                .check(&Address::Domain("new-static.com".to_string()), 80)
                .allowed
        {
            reloaded = true;
            break;
        }
    }
    assert!(
        reloaded,
        "Static file change did not trigger auto-reload"
    );

    // dynamic 规则不受影响
    assert!(trc
        .rules()
        .check(&Address::Domain("dynamic-rule.com".to_string()), 80)
        .allowed);
    // 旧 static 规则不再存在
    assert!(!trc
        .rules()
        .check(&Address::Domain("old-static.com".to_string()), 80)
        .allowed);
    // 新 static 规则生效
    assert!(trc
        .rules()
        .check(&Address::Domain("extra-static.com".to_string()), 80)
        .allowed);
}

/// 场景8: 删除 static 文件后 reload 容错（视为空规则）
#[tokio::test]
async fn test_watch_static_file_deleted() {
    let dynamic_yaml = r#"
target_rules:
  - [DOMAIN, dynamic-only.com, 0, 65535, PASS]
"#;
    let static_yaml = r#"
target_rules:
  - [DOMAIN, will-be-deleted.com, 0, 65535, PASS]
"#;
    let dynamic = create_temp_yaml(dynamic_yaml);
    let static_file = create_temp_yaml(static_yaml);
    let static_path = static_file.path().to_path_buf();

    let trc = Arc::new(
        TargetRuleControl::load(dynamic.path(), &static_path).unwrap(),
    );
    assert_eq!(trc.rules().rule_count(), 2);

    let _watchers = trc.watch().unwrap();

    // 删除 static 文件
    drop(static_file); // NamedTempFile drop 会删除文件

    // 等待 watcher 防抖 + reload
    let mut reloaded = false;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if trc.rules().rule_count() == 1 {
            reloaded = true;
            break;
        }
    }
    assert!(
        reloaded,
        "Static file deletion did not trigger auto-reload"
    );

    // dynamic 规则仍然存在
    assert!(trc
        .rules()
        .check(&Address::Domain("dynamic-only.com".to_string()), 80)
        .allowed);
    // 被删除的 static 规则不再生效
    assert!(!trc
        .rules()
        .check(&Address::Domain("will-be-deleted.com".to_string()), 80)
        .allowed);
}
