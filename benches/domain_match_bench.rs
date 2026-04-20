use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use exsocks::socks5::protocol::Address;
use exsocks::target_rules::{RuleAction, RuleType, TargetRule, TargetRuleSet};

/// 构造一条 TargetRule
fn make_rule(
    rule_type: RuleType,
    value: &str,
    port_start: u16,
    port_end: u16,
    action: RuleAction,
) -> TargetRule {
    TargetRule {
        rule_type,
        value: value.to_string(),
        port_start,
        port_end,
        action,
        opt_flags: 0,
        opt_value: 0.0,
    }
}

/// 构造包含不同规模后缀规则的 TargetRuleSet
fn build_ruleset(suffix_count: usize) -> TargetRuleSet {
    let base_suffixes = [
        "baidu.com",
        "taobao.com",
        "aliyun.com",
        "alibaba.com",
        "tmall.com",
        "jd.com",
        "qq.com",
        "weixin.com",
        "bytedance.com",
        "douyin.com",
        "bilibili.com",
        "zhihu.com",
        "weibo.com",
        "163.com",
        "sohu.com",
        "sina.com",
        "github.com",
        "google.com",
        "youtube.com",
        "facebook.com",
    ];

    let mut rules = Vec::with_capacity(suffix_count + 2);

    // 添加一些精确匹配规则
    rules.push(make_rule(
        RuleType::Domain,
        "www.example.com",
        0,
        65535,
        RuleAction::Pass,
    ));
    rules.push(make_rule(
        RuleType::Domain,
        "api.internal.corp.com",
        0,
        65535,
        RuleAction::Pass,
    ));

    // 添加后缀规则
    for i in 0..suffix_count {
        let suffix = if i < base_suffixes.len() {
            base_suffixes[i].to_string()
        } else {
            format!("generated-{}.example.org", i)
        };
        rules.push(make_rule(
            RuleType::DomainSuffix,
            &suffix,
            0,
            65535,
            RuleAction::Pass,
        ));
    }

    TargetRuleSet::compile(rules).unwrap()
}

/// 测试用域名：覆盖不同层级深度和命中/未命中场景
const TEST_DOMAINS: &[&str] = &[
    // 3 级，命中 baidu.com 后缀
    "www.baidu.com",
    // 4 级，命中 taobao.com 后缀
    "item.detail.taobao.com",
    // 5 级深层域名，命中 alibaba.com 后缀
    "api.service.internal.alibaba.com",
    // 2 级，命中 qq.com 后缀
    "qq.com",
    // 4 级，未命中任何规则
    "api.test.unknown.xyz",
    // 6 级深层域名，未命中
    "a.b.c.d.e.nowhere.invalid",
    // 精确匹配命中
    "www.example.com",
    // 4 级精确匹配命中
    "api.internal.corp.com",
];

fn bench_vec_vs_smallvec(c: &mut Criterion) {
    let mut group = c.benchmark_group("domain_match_vec_vs_smallvec");

    for &rule_count in &[10, 50, 200] {
        let ruleset = build_ruleset(rule_count);

        group.bench_with_input(
            BenchmarkId::new("smallvec", rule_count),
            &ruleset,
            |b, rs| {
                b.iter(|| {
                    for &domain in TEST_DOMAINS {
                        black_box(rs.check(
                            &Address::Domain(domain.to_string()),
                            black_box(80),
                        ));
                    }
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("vec", rule_count),
            &ruleset,
            |b, rs| {
                b.iter(|| {
                    for &domain in TEST_DOMAINS {
                        black_box(rs.check_with_vec(
                            &Address::Domain(domain.to_string()),
                            black_box(80),
                        ));
                    }
                });
            },
        );
    }

    group.finish();
}

fn bench_domain_depth(c: &mut Criterion) {
    let ruleset = build_ruleset(50);

    let domains_by_depth: &[(&str, &str)] = &[
        ("depth_2", "baidu.com"),
        ("depth_3", "www.baidu.com"),
        ("depth_4", "api.www.baidu.com"),
        ("depth_5", "v1.api.www.baidu.com"),
        ("depth_6", "cn.v1.api.www.baidu.com"),
        ("depth_3_miss", "unknown.example.xyz"),
        ("depth_6_miss", "a.b.c.d.e.nowhere.invalid"),
    ];

    let mut group = c.benchmark_group("domain_match_by_depth");

    for &(label, domain) in domains_by_depth {
        group.bench_with_input(
            BenchmarkId::new("smallvec", label),
            &domain,
            |b, &d| {
                b.iter(|| {
                    black_box(ruleset.check(
                        &Address::Domain(d.to_string()),
                        black_box(80),
                    ));
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("vec", label),
            &domain,
            |b, &d| {
                b.iter(|| {
                    black_box(ruleset.check_with_vec(
                        &Address::Domain(d.to_string()),
                        black_box(80),
                    ));
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_vec_vs_smallvec, bench_domain_depth);
criterion_main!(benches);
