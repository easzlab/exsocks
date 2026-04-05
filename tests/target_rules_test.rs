use std::io::Write;
use std::sync::Arc;

use exsocks::target_rules::{
    OPT_LOG, RuleAction, RuleType, TargetRule, TargetRuleControl, TargetRuleSet,
};
use exsocks::socks5::protocol::Address;
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
    let trc = TargetRuleControl::load(f.path()).unwrap();
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
    let trc = TargetRuleControl::load(f.path()).unwrap();
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
    let trc = TargetRuleControl::load(f.path()).unwrap();
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
    let result = TargetRuleControl::load(f.path());
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
    let result = TargetRuleControl::load(f.path());
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
    let result = TargetRuleControl::load(f.path());
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
    let result = TargetRuleControl::load(f.path());
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
    let result = TargetRuleControl::load(f.path());
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
    let result = TargetRuleControl::load(f.path());
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
    let result = TargetRuleControl::load(f.path());
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
    let trc = TargetRuleControl::load(f.path()).unwrap();
    assert_eq!(trc.rules().rule_count(), 3);
}

#[test]
fn test_load_nonexistent_file() {
    let result = TargetRuleControl::load(std::path::Path::new("/nonexistent/target-rules.yaml"));
    assert!(result.is_err());
}

#[test]
fn test_load_empty_yaml() {
    let yaml = "";
    let f = create_temp_yaml(yaml);
    let trc = TargetRuleControl::load(f.path()).unwrap();
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
    let trc = TargetRuleControl::load(f.path()).unwrap();
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
    let trc = TargetRuleControl::load(f.path()).unwrap();
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
    let trc = TargetRuleControl::load(f.path()).unwrap();
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
    let trc = Arc::new(TargetRuleControl::load(f.path()).unwrap());
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
    let trc = Arc::new(TargetRuleControl::load(f.path()).unwrap());
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
    let trc = Arc::new(TargetRuleControl::load(f.path()).unwrap());

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
    let trc = TargetRuleControl::load(f.path()).unwrap();
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
