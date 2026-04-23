use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use metrics::{counter, gauge};
use tokio::net::lookup_host;
use tokio::sync::Notify;
use tracing::{debug, info, warn};

use crate::error::SocksError;
use crate::metrics_registry::{DNS_CACHE_ENTRIES, DNS_CACHE_TOTAL, DNS_RESOLVE_TOTAL};

/// DNS 解析结果
enum DnsResult {
    /// 解析成功，包含纯 IP 地址列表（不含端口，连接时动态组合）
    Success(Vec<IpAddr>),
    /// 解析失败，包含错误描述
    Failure(String),
}

/// DNS 缓存条目
struct DnsCacheEntry {
    /// 解析结果（成功或失败）
    result: DnsResult,
    /// 条目创建时间
    created_at: Instant,
}

/// 基于 TTL 的 DNS 解析缓存
///
/// 使用 `DashMap` 实现无锁并发访问，避免全局 `Mutex` 瓶颈。
/// 缓存条目在 TTL 过期后惰性淘汰（查询时检查并移除）。
///
/// 支持正缓存和负缓存：
/// - **正缓存**：解析成功的结果，使用 `ttl` 控制过期时间
/// - **负缓存**：解析失败的结果，使用 `negative_ttl` 控制过期时间，
///   避免短时间内对同一不可达域名反复发起 DNS 查询
///
/// 本模块只负责 DNS 解析和缓存，不涉及 TCP 连接。
/// 连接建立由调用方（如 `Address::connect()`）负责。
pub struct DnsCache {
    cache: DashMap<String, DnsCacheEntry>,
    /// 并发解析请求合并：同一域名同时只有一个任务执行 DNS 解析，其余等待
    in_flight: DashMap<String, Arc<Notify>>,
    /// 正缓存 TTL（解析成功）
    ttl: Duration,
    /// 负缓存 TTL（解析失败）
    negative_ttl: Duration,
    /// 单次 DNS 解析超时，防止系统 DNS 解析器无限阻塞
    resolve_timeout: Duration,
    max_entries: usize,
    /// 自定义 DNS 解析器（指定 DNS 服务器时使用），None 表示使用系统默认
    custom_resolver: Option<TokioAsyncResolver>,
}

/// Drop guard：确保 in_flight 条目在 resolve 完成或被取消时都能正确清理，
/// 避免 future 被 drop 后 in_flight 条目泄漏导致后续请求永久阻塞
struct InFlightGuard<'a> {
    in_flight: &'a DashMap<String, Arc<Notify>>,
    domain: String,
    notify: Arc<Notify>,
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.in_flight.remove(&self.domain);
        self.notify.notify_waiters();
    }
}

impl DnsCache {
    /// 创建新的 DNS 缓存实例
    ///
    /// - `ttl`: 解析成功时缓存条目的生存时间
    /// - `negative_ttl`: 解析失败时缓存条目的生存时间
    /// - `resolve_timeout`: 单次 DNS 解析的超时时间
    /// - `max_entries`: 最大缓存条目数，超限时触发惰性淘汰
    /// - `dns_server`: 自定义 DNS 服务器地址（如 "8.8.8.8"），空字符串表示使用系统默认
    pub fn new(
        ttl: Duration,
        negative_ttl: Duration,
        resolve_timeout: Duration,
        max_entries: usize,
        dns_server: &str,
    ) -> Self {
        let custom_resolver = Self::build_custom_resolver(dns_server, resolve_timeout);
        Self {
            cache: DashMap::new(),
            in_flight: DashMap::new(),
            ttl,
            negative_ttl,
            resolve_timeout,
            max_entries,
            custom_resolver,
        }
    }

    /// 根据 DNS 服务器地址构建自定义解析器
    ///
    /// 返回 None 时使用系统默认的 `lookup_host`，返回 Some 时使用 hickory-resolver
    fn build_custom_resolver(
        dns_server: &str,
        resolve_timeout: Duration,
    ) -> Option<TokioAsyncResolver> {
        let trimmed = dns_server.trim();
        if trimmed.is_empty() {
            return None;
        }
        let ip: IpAddr = match trimmed.parse() {
            Ok(ip) => ip,
            Err(e) => {
                warn!(
                    server = trimmed,
                    error = %e,
                    "Invalid DNS server address, falling back to system default"
                );
                return None;
            }
        };
        let socket_addr = SocketAddr::new(ip, 53);
        let mut resolver_config = ResolverConfig::new();
        resolver_config.add_name_server(NameServerConfig::new(socket_addr, Protocol::Udp));
        resolver_config.add_name_server(NameServerConfig::new(socket_addr, Protocol::Tcp));
        let mut resolver_opts = ResolverOpts::default();
        resolver_opts.timeout = resolve_timeout;
        resolver_opts.attempts = 2;
        // 禁用 hickory-resolver 内置缓存，由 DnsCache 统一管理
        resolver_opts.cache_size = 0;
        let resolver = TokioAsyncResolver::tokio(resolver_config, resolver_opts);
        info!(server = trimmed, "Using custom DNS resolver");
        Some(resolver)
    }

    /// 解析域名并返回 IP 地址列表
    ///
    /// 查询流程：
    /// 1. 查缓存，命中且未过期 → 返回缓存的 IP 地址列表
    /// 2. 缓存未命中或已过期 → 并发请求合并，同一域名只有一个 leader 执行 DNS 解析
    /// 3. leader 完成后通知所有等待者，等待者从缓存获取结果
    ///
    /// 本方法只负责 DNS 解析和缓存，不涉及 TCP 连接。
    /// 调用方拿到 IP 列表后自行建立连接、控制超时。
    pub async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>, SocksError> {
        // 1. 查缓存
        if let Some(result) = self.check_cache(domain) {
            return result;
        }

        // 2. 并发请求合并：同一域名只有一个任务执行 DNS 解析
        loop {
            match self.in_flight.entry(domain.to_owned()) {
                Entry::Occupied(e) => {
                    // 其他任务正在解析此域名，等待其完成
                    let notify = e.get().clone();
                    let notified = notify.notified();
                    drop(e);
                    notified.await;
                    // 重新检查缓存（leader 已缓存结果）
                    if let Some(result) = self.check_cache(domain) {
                        return result;
                    }
                    // 缓存仍为空（极罕见：leader 被取消），循环重试成为新 leader
                }
                Entry::Vacant(e) => {
                    // 成为 leader，负责执行 DNS 解析
                    let notify = Arc::new(Notify::new());
                    e.insert(notify.clone());
                    let _guard = InFlightGuard {
                        in_flight: &self.in_flight,
                        domain: domain.to_owned(),
                        notify,
                    };
                    return self.do_resolve(domain).await;
                }
            }
        }
    }

    /// 检查缓存，返回 Some(result) 表示命中，None 表示未命中或已过期
    fn check_cache(&self, domain: &str) -> Option<Result<Vec<IpAddr>, SocksError>> {
        let entry = self.cache.get(domain)?;
        let entry_ttl = match &entry.result {
            DnsResult::Success(_) => self.ttl,
            DnsResult::Failure(_) => self.negative_ttl,
        };
        if entry.created_at.elapsed() >= entry_ttl {
            drop(entry);
            self.cache.remove(domain);
            debug!(domain, "DNS cache expired");
            return None;
        }
        match &entry.result {
            DnsResult::Success(addrs) => {
                debug!(domain, "DNS cache hit (positive)");
                counter!(DNS_CACHE_TOTAL, "result" => "hit").increment(1);
                let addrs = addrs.clone();
                drop(entry);
                Some(Ok(addrs))
            }
            DnsResult::Failure(err_msg) => {
                debug!(domain, "DNS cache hit (negative)");
                counter!(DNS_CACHE_TOTAL, "result" => "hit").increment(1);
                let err_msg = err_msg.clone();
                drop(entry);
                Some(Err(SocksError::CachedDnsFailure(err_msg)))
            }
        }
    }

    /// 缓存 DNS 解析结果并更新 metrics
    fn cache_result(&self, domain: &str, result: DnsResult) {
        self.cache.insert(
            domain.to_owned(),
            DnsCacheEntry {
                result,
                created_at: Instant::now(),
            },
        );
        gauge!(DNS_CACHE_ENTRIES).set(self.cache.len() as f64);
    }

    /// 执行实际的 DNS 解析并缓存结果
    ///
    /// 当配置了自定义 DNS 服务器时使用 hickory-resolver，
    /// 否则使用 `resolve_timeout` 包装系统 `lookup_host` 调用，
    /// 防止系统 DNS 解析器长时间阻塞（Linux 默认 5s × 重试次数）。
    async fn do_resolve(&self, domain: &str) -> Result<Vec<IpAddr>, SocksError> {
        counter!(DNS_CACHE_TOTAL, "result" => "miss").increment(1);
        debug!(domain, "DNS cache miss, resolving");

        // 容量检查，超限时清理过期条目
        if self.cache.len() >= self.max_entries {
            self.evict_expired();
        }

        // 根据是否配置了自定义 DNS 服务器选择解析方式
        let ip_addrs = if let Some(resolver) = &self.custom_resolver {
            self.resolve_with_custom(resolver, domain).await?
        } else {
            self.resolve_with_system(domain).await?
        };

        counter!(DNS_RESOLVE_TOTAL, "result" => "success").increment(1);
        self.cache_result(domain, DnsResult::Success(ip_addrs.clone()));
        Ok(ip_addrs)
    }

    /// 使用系统默认 DNS 解析器（tokio::net::lookup_host）
    async fn resolve_with_system(&self, domain: &str) -> Result<Vec<IpAddr>, SocksError> {
        // lookup_host 需要 "host:port" 格式，端口不影响 DNS 解析结果，使用 0 作为占位
        let host = format!("{}:0", domain);

        let lookup_result =
            match tokio::time::timeout(self.resolve_timeout, lookup_host(&host)).await {
                Ok(result) => result,
                Err(_) => {
                    counter!(DNS_RESOLVE_TOTAL, "result" => "failure").increment(1);
                    let err_msg = format!("DNS resolution timed out for {}", domain);
                    warn!(domain, timeout = ?self.resolve_timeout, "DNS resolution timed out");
                    self.cache_result(domain, DnsResult::Failure(err_msg.clone()));
                    return Err(SocksError::InvalidAddress(err_msg));
                }
            };

        match lookup_result {
            Ok(addrs_iter) => {
                let ip_addrs: Vec<IpAddr> = addrs_iter.map(|sa| sa.ip()).collect();
                if ip_addrs.is_empty() {
                    counter!(DNS_RESOLVE_TOTAL, "result" => "failure").increment(1);
                    let err_msg = format!("DNS resolution returned no addresses for {}", domain);
                    self.cache_result(domain, DnsResult::Failure(err_msg.clone()));
                    return Err(SocksError::InvalidAddress(err_msg));
                }
                Ok(ip_addrs)
            }
            Err(e) => {
                counter!(DNS_RESOLVE_TOTAL, "result" => "failure").increment(1);
                let err_msg = e.to_string();
                debug!(domain, error = %err_msg, "DNS resolution failed, caching negative result");
                self.cache_result(domain, DnsResult::Failure(err_msg.clone()));
                Err(SocksError::InvalidAddress(format!(
                    "DNS resolution failed: {}",
                    err_msg
                )))
            }
        }
    }

    /// 使用自定义 DNS 服务器（hickory-resolver）解析
    async fn resolve_with_custom(
        &self,
        resolver: &TokioAsyncResolver,
        domain: &str,
    ) -> Result<Vec<IpAddr>, SocksError> {
        // hickory-resolver 自带超时控制（通过 ResolverOpts::timeout 配置），
        // 但仍使用外层 timeout 作为兜底，防止极端情况下的阻塞
        let lookup_result =
            match tokio::time::timeout(self.resolve_timeout, resolver.lookup_ip(domain)).await {
                Ok(result) => result,
                Err(_) => {
                    counter!(DNS_RESOLVE_TOTAL, "result" => "failure").increment(1);
                    let err_msg = format!("DNS resolution timed out for {}", domain);
                    warn!(domain, timeout = ?self.resolve_timeout, "DNS resolution timed out (custom resolver)");
                    self.cache_result(domain, DnsResult::Failure(err_msg.clone()));
                    return Err(SocksError::InvalidAddress(err_msg));
                }
            };

        match lookup_result {
            Ok(lookup) => {
                let ip_addrs: Vec<IpAddr> = lookup.iter().collect();
                if ip_addrs.is_empty() {
                    counter!(DNS_RESOLVE_TOTAL, "result" => "failure").increment(1);
                    let err_msg = format!("DNS resolution returned no addresses for {}", domain);
                    self.cache_result(domain, DnsResult::Failure(err_msg.clone()));
                    return Err(SocksError::InvalidAddress(err_msg));
                }
                Ok(ip_addrs)
            }
            Err(e) => {
                counter!(DNS_RESOLVE_TOTAL, "result" => "failure").increment(1);
                let err_msg = e.to_string();
                debug!(domain, error = %err_msg, "DNS resolution failed (custom resolver), caching negative result");
                self.cache_result(domain, DnsResult::Failure(err_msg.clone()));
                Err(SocksError::InvalidAddress(format!(
                    "DNS resolution failed: {}",
                    err_msg
                )))
            }
        }
    }

    /// 惰性淘汰：移除所有已过期的缓存条目
    ///
    /// 根据条目类型使用对应的 TTL 判断是否过期：
    /// - 正缓存使用 `ttl`
    /// - 负缓存使用 `negative_ttl`
    fn evict_expired(&self) {
        let before = self.cache.len();
        let ttl = self.ttl;
        let negative_ttl = self.negative_ttl;
        self.cache.retain(|_, entry| {
            let entry_ttl = match &entry.result {
                DnsResult::Success(_) => ttl,
                DnsResult::Failure(_) => negative_ttl,
            };
            entry.created_at.elapsed() < entry_ttl
        });
        let evicted = before - self.cache.len();
        if evicted > 0 {
            debug!(evicted, "DNS cache evicted expired entries");
        }
    }

    /// 返回当前缓存条目数（用于测试和监控）
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// 缓存是否为空
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_cache() {
        let cache = DnsCache::new(Duration::from_secs(300), Duration::from_secs(30), Duration::from_secs(5), 1024, "");
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_evict_expired_positive() {
        let cache = DnsCache::new(Duration::from_millis(1), Duration::from_millis(1), Duration::from_secs(5), 1024, "");

        // 手动插入一个过期的正缓存条目
        cache.cache.insert(
            "example.com".to_owned(),
            DnsCacheEntry {
                result: DnsResult::Success(vec!["93.184.216.34".parse().unwrap()]),
                created_at: Instant::now() - Duration::from_secs(10),
            },
        );
        assert_eq!(cache.len(), 1);

        cache.evict_expired();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_evict_expired_negative() {
        let cache = DnsCache::new(Duration::from_secs(300), Duration::from_millis(1), Duration::from_secs(5), 1024, "");

        // 插入一个过期的负缓存条目
        cache.cache.insert(
            "bad.com".to_owned(),
            DnsCacheEntry {
                result: DnsResult::Failure("DNS failed".to_owned()),
                created_at: Instant::now() - Duration::from_secs(10),
            },
        );
        assert_eq!(cache.len(), 1);

        cache.evict_expired();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_evict_keeps_fresh_entries() {
        let cache = DnsCache::new(Duration::from_secs(300), Duration::from_secs(30), Duration::from_secs(5), 1024, "");

        // 插入一个新鲜的正缓存条目
        cache.cache.insert(
            "fresh.com".to_owned(),
            DnsCacheEntry {
                result: DnsResult::Success(vec!["1.2.3.4".parse().unwrap()]),
                created_at: Instant::now(),
            },
        );

        // 插入一个新鲜的负缓存条目
        cache.cache.insert(
            "fresh-neg.com".to_owned(),
            DnsCacheEntry {
                result: DnsResult::Failure("DNS failed".to_owned()),
                created_at: Instant::now(),
            },
        );

        // 插入一个过期的正缓存条目
        cache.cache.insert(
            "stale.com".to_owned(),
            DnsCacheEntry {
                result: DnsResult::Success(vec!["5.6.7.8".parse().unwrap()]),
                created_at: Instant::now() - Duration::from_secs(600),
            },
        );

        assert_eq!(cache.len(), 3);
        cache.evict_expired();
        assert_eq!(cache.len(), 2);
        assert!(cache.cache.contains_key("fresh.com"));
        assert!(cache.cache.contains_key("fresh-neg.com"));
        assert!(!cache.cache.contains_key("stale.com"));
    }
}
