use std::net::{IpAddr, Ipv4Addr};

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ipnet::IpNet;

use exsocks::socks5::protocol::Address;
use exsocks::target_rules::{RuleAction, RuleType, TargetRule, TargetRuleSet};

// ===== Vec 线性扫描基准实现（模拟旧方案） =====

/// 旧方案的 CIDR 规则条目
struct VecCidrEntry {
    network: IpNet,
    port_start: u16,
    port_end: u16,
    action: RuleAction,
}

/// 旧方案的 Vec 线性扫描 CIDR 匹配器
struct VecCidrMatcher {
    entries: Vec<VecCidrEntry>,
}

impl VecCidrMatcher {
    fn compile(rules: &[TargetRule]) -> Self {
        let entries = rules
            .iter()
            .filter(|r| r.rule_type == RuleType::IpCidr)
            .map(|r| VecCidrEntry {
                network: r.value.parse().unwrap(),
                port_start: r.port_start,
                port_end: r.port_end,
                action: r.action,
            })
            .collect();
        Self { entries }
    }

    /// 线性扫描匹配：遍历所有规则，返回第一个匹配的（first-match-wins）
    #[inline]
    fn match_ip(&self, ip: IpAddr, port: u16) -> Option<RuleAction> {
        for entry in &self.entries {
            if entry.network.contains(&ip)
                && port >= entry.port_start
                && port <= entry.port_end
            {
                return Some(entry.action);
            }
        }
        None
    }
}

// ===== 公共辅助函数 =====

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

/// 生成指定数量的 CIDR 规则列表
///
/// 生成 `count` 条 /24 规则：10.0.0.0/24, 10.0.1.0/24, ..., 10.x.y.0/24
/// 全部为 PASS，最后追加一条 0.0.0.0/0 BLOCK 作为兜底。
fn build_cidr_rules(count: usize) -> Vec<TargetRule> {
    let mut rules = Vec::with_capacity(count + 1);
    for i in 0..count {
        let second = ((i >> 8) & 0xFF) as u8;
        let third = (i & 0xFF) as u8;
        let cidr = format!("10.{}.{}.0/24", second, third);
        rules.push(make_rule(
            RuleType::IpCidr,
            &cidr,
            0,
            65535,
            RuleAction::Pass,
        ));
    }
    // 兜底规则
    rules.push(make_rule(
        RuleType::IpCidr,
        "0.0.0.0/0",
        0,
        65535,
        RuleAction::Block,
    ));
    rules
}

/// 构造 Radix Trie 版 TargetRuleSet
fn build_cidr_ruleset(count: usize) -> TargetRuleSet {
    TargetRuleSet::compile(build_cidr_rules(count)).unwrap()
}

/// 构造 Vec 线性扫描版匹配器
fn build_vec_matcher(count: usize) -> VecCidrMatcher {
    VecCidrMatcher::compile(&build_cidr_rules(count))
}

/// 构造包含嵌套 CIDR 规则的 TargetRuleSet（模拟多层前缀覆盖）
///
/// 规则从宽到窄：10.0.0.0/8, 10.0.0.0/12, 10.0.0.0/16, ..., 10.0.0.0/28
/// 共 (28 - 8) / 4 + 1 = 6 条嵌套规则，查询 10.0.0.1 时 cover_values 会遍历所有。
fn build_nested_cidr_ruleset() -> TargetRuleSet {
    let mut rules = Vec::new();
    let mut prefix_len = 8;
    while prefix_len <= 28 {
        let cidr = format!("10.0.0.0/{}", prefix_len);
        rules.push(make_rule(
            RuleType::IpCidr,
            &cidr,
            0,
            65535,
            RuleAction::Pass,
        ));
        prefix_len += 4;
    }
    // 兜底
    rules.push(make_rule(
        RuleType::IpCidr,
        "0.0.0.0/0",
        0,
        65535,
        RuleAction::Block,
    ));
    TargetRuleSet::compile(rules).unwrap()
}

/// Benchmark: Vec 线性扫描 vs Radix Trie，不同规则数量下的 CIDR 匹配性能对比
///
/// 测试场景（每种规则数量下各 4 个 benchmark）：
/// - trie/hit vs vec/hit：命中场景对比
/// - trie/miss vs vec/miss：未命中（仅兜底）场景对比
fn bench_cidr_vec_vs_trie(c: &mut Criterion) {
    let mut group = c.benchmark_group("cidr_vec_vs_trie");

    for &rule_count in &[50, 500, 2000] {
        let trie_ruleset = build_cidr_ruleset(rule_count);
        let vec_matcher = build_vec_matcher(rule_count);

        // 命中场景：IP 在第 50 条规则的 CIDR 范围内（或第一条，如果 count < 50）
        let hit_third = if rule_count > 50 { 50u8 } else { 0u8 };
        let hit_ip_addr = Address::IPv4(Ipv4Addr::new(10, 0, hit_third, 1));
        let hit_ip_raw = IpAddr::V4(Ipv4Addr::new(10, 0, hit_third, 1));

        // Trie 命中
        group.bench_with_input(
            BenchmarkId::new("trie/hit", rule_count),
            &trie_ruleset,
            |b, rs| {
                b.iter(|| {
                    black_box(rs.check(black_box(&hit_ip_addr), black_box(80)));
                });
            },
        );

        // Vec 命中
        group.bench_with_input(
            BenchmarkId::new("vec/hit", rule_count),
            &vec_matcher,
            |b, vm| {
                b.iter(|| {
                    black_box(vm.match_ip(black_box(hit_ip_raw), black_box(80)));
                });
            },
        );

        // 未命中场景：只匹配兜底 0.0.0.0/0（Vec 需遍历全部规则才能到达兜底）
        let miss_ip_addr = Address::IPv4(Ipv4Addr::new(192, 168, 1, 1));
        let miss_ip_raw = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Trie 未命中
        group.bench_with_input(
            BenchmarkId::new("trie/miss", rule_count),
            &trie_ruleset,
            |b, rs| {
                b.iter(|| {
                    black_box(rs.check(black_box(&miss_ip_addr), black_box(80)));
                });
            },
        );

        // Vec 未命中（最坏情况：遍历全部规则后命中兜底）
        group.bench_with_input(
            BenchmarkId::new("vec/miss", rule_count),
            &vec_matcher,
            |b, vm| {
                b.iter(|| {
                    black_box(vm.match_ip(black_box(miss_ip_raw), black_box(80)));
                });
            },
        );
    }

    group.finish();
}

/// Benchmark: 嵌套 CIDR 前缀的匹配性能
///
/// 验证 cover_values 在多层嵌套前缀下的实际开销。
/// 6 条嵌套规则 + 1 条兜底，查询 10.0.0.1 时所有嵌套规则都会被遍历。
fn bench_cidr_nested_prefixes(c: &mut Criterion) {
    let ruleset = build_nested_cidr_ruleset();

    let mut group = c.benchmark_group("cidr_match_nested_prefixes");

    // 命中所有嵌套前缀 + 兜底
    let nested_hit = Address::IPv4(Ipv4Addr::new(10, 0, 0, 1));
    group.bench_function("all_nested_hit", |b| {
        b.iter(|| {
            black_box(ruleset.check(black_box(&nested_hit), black_box(80)));
        });
    });

    // 只命中最宽的 10.0.0.0/8 + 兜底（不在窄范围内）
    let partial_hit = Address::IPv4(Ipv4Addr::new(10, 1, 0, 1));
    group.bench_function("partial_nested_hit", |b| {
        b.iter(|| {
            black_box(ruleset.check(black_box(&partial_hit), black_box(80)));
        });
    });

    // 完全不匹配任何 10.x 规则，只命中兜底
    let no_hit = Address::IPv4(Ipv4Addr::new(172, 16, 0, 1));
    group.bench_function("fallback_only", |b| {
        b.iter(|| {
            black_box(ruleset.check(black_box(&no_hit), black_box(80)));
        });
    });

    group.finish();
}

/// Benchmark: 批量 IP 查询吞吐量
///
/// 模拟真实场景：对 200 条规则的 ruleset 连续查询 100 个不同 IP。
fn bench_cidr_throughput(c: &mut Criterion) {
    let ruleset = build_cidr_ruleset(200);

    // 生成 100 个测试 IP：50 个命中 + 50 个未命中
    let test_addresses: Vec<Address> = (0..100u8)
        .map(|i| {
            if i < 50 {
                // 命中：10.0.{i}.1
                Address::IPv4(Ipv4Addr::new(10, 0, i, 1))
            } else {
                // 未命中：172.16.{i}.1
                Address::IPv4(Ipv4Addr::new(172, 16, i, 1))
            }
        })
        .collect();

    c.bench_function("cidr_throughput_100_ips", |b| {
        b.iter(|| {
            for addr in &test_addresses {
                black_box(ruleset.check(black_box(addr), black_box(443)));
            }
        });
    });
}

criterion_group!(
    benches,
    bench_cidr_vec_vs_trie,
    bench_cidr_nested_prefixes,
    bench_cidr_throughput
);
criterion_main!(benches);
