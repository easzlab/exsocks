//! Prometheus Metrics 指标注册表
//!
//! 集中定义所有 metrics 指标名称常量和描述注册。
//! 所有指标通过 `metrics` crate 的宏（`counter!`、`gauge!`）在使用处按需记录。

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

// ========== 指标名称常量 ==========

/// 当前活跃连接数 (Gauge)
pub const ACTIVE_CONNECTIONS: &str = "exsocks_active_connections";

/// 连接总数 (Counter)，标签: status=accepted|blocked
pub const CONNECTIONS_TOTAL: &str = "exsocks_connections_total";

/// 传输字节总数 (Counter)，标签: direction=up|down
pub const BYTES_TOTAL: &str = "exsocks_bytes_total";

/// 连接目标失败总数 (Counter)
pub const CONNECT_TARGET_ERRORS_TOTAL: &str = "exsocks_connect_target_errors_total";

/// 认证结果计数 (Counter)，标签: result=success|failure
pub const AUTH_TOTAL: &str = "exsocks_auth_total";

/// DNS 缓存命中/未命中 (Counter)，标签: result=hit|miss
pub const DNS_CACHE_TOTAL: &str = "exsocks_dns_cache_total";

/// DNS 解析结果 (Counter)，标签: result=success|failure
pub const DNS_RESOLVE_TOTAL: &str = "exsocks_dns_resolve_total";

/// 目标规则命中计数 (Counter)，标签: action=pass|block
pub const TARGET_RULE_TOTAL: &str = "exsocks_target_rule_total";

/// DNS 缓存当前条目数 (Gauge)
pub const DNS_CACHE_ENTRIES: &str = "exsocks_dns_cache_entries";

/// 注册所有指标的描述信息
///
/// 在 Prometheus recorder 初始化后调用，使 `/metrics` 端点输出包含 HELP 和 TYPE 注释
pub fn describe_metrics() {
    metrics::describe_gauge!(
        ACTIVE_CONNECTIONS,
        "Current number of active connections"
    );
    metrics::describe_counter!(
        CONNECTIONS_TOTAL,
        "Total number of connections (accepted/blocked)"
    );
    metrics::describe_counter!(
        BYTES_TOTAL,
        "Total bytes transferred (up/down)"
    );
    metrics::describe_counter!(
        CONNECT_TARGET_ERRORS_TOTAL,
        "Total number of target connection failures"
    );
    metrics::describe_counter!(
        AUTH_TOTAL,
        "Total authentication attempts (success/failure)"
    );
    metrics::describe_counter!(
        DNS_CACHE_TOTAL,
        "Total DNS cache lookups (hit/miss)"
    );
    metrics::describe_counter!(
        DNS_RESOLVE_TOTAL,
        "Total DNS resolution attempts (success/failure)"
    );
    metrics::describe_counter!(
        TARGET_RULE_TOTAL,
        "Total target rule evaluations (pass/block)"
    );
    metrics::describe_gauge!(
        DNS_CACHE_ENTRIES,
        "Current number of DNS cache entries"
    );
}

/// 初始化 Prometheus metrics recorder 并返回 handle
///
/// `PrometheusHandle` 用于在 HTTP 端点中调用 `render()` 生成 Prometheus 格式文本。
/// 此函数只能调用一次（`metrics` crate 全局 recorder 只能设置一次）。
///
/// 返回 `Result`，初始化失败时不会 panic，由调用方决定降级策略。
pub fn init_metrics_recorder() -> Result<PrometheusHandle, Box<dyn std::error::Error + Send + Sync>> {
    let builder = PrometheusBuilder::new();
    let handle = builder.install_recorder()?;

    describe_metrics();

    Ok(handle)
}
