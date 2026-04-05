use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use metrics::{counter, gauge};
use tokio::net::{TcpStream, lookup_host};
use tracing::debug;

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
pub struct DnsCache {
    cache: DashMap<String, DnsCacheEntry>,
    /// 正缓存 TTL（解析成功）
    ttl: Duration,
    /// 负缓存 TTL（解析失败）
    negative_ttl: Duration,
    max_entries: usize,
}

impl DnsCache {
    /// 创建新的 DNS 缓存实例
    ///
    /// - `ttl`: 解析成功时缓存条目的生存时间
    /// - `negative_ttl`: 解析失败时缓存条目的生存时间
    /// - `max_entries`: 最大缓存条目数，超限时触发惰性淘汰
    pub fn new(ttl: Duration, negative_ttl: Duration, max_entries: usize) -> Self {
        Self {
            cache: DashMap::new(),
            ttl,
            negative_ttl,
            max_entries,
        }
    }

    /// 解析域名并连接目标地址
    ///
    /// 查询流程：
    /// 1. 查缓存，命中且未过期 →
    ///    - 正缓存：直接使用缓存的地址连接
    ///    - 负缓存：直接返回缓存的错误
    /// 2. 缓存未命中或已过期 → 调用 `lookup_host` 解析
    ///    - 解析成功 → 缓存结果（正缓存）→ 连接
    ///    - 解析失败 → 缓存错误（负缓存）→ 返回错误
    ///
    /// 连接策略：依次尝试缓存中的所有地址，直到成功或全部失败。
    pub async fn resolve(&self, domain: &str, port: u16) -> Result<TcpStream, SocksError> {
        // 1. 查缓存
        if let Some(entry) = self.cache.get(domain) {
            let entry_ttl = match &entry.result {
                DnsResult::Success(_) => self.ttl,
                DnsResult::Failure(_) => self.negative_ttl,
            };
            if entry.created_at.elapsed() < entry_ttl {
                match &entry.result {
                    DnsResult::Success(addrs) => {
                        debug!(domain, "DNS cache hit (positive)");
                        counter!(DNS_CACHE_TOTAL, "result" => "hit").increment(1);
                        return Self::try_connect(addrs, port).await;
                    }
                    DnsResult::Failure(err_msg) => {
                        debug!(domain, "DNS cache hit (negative)");
                        counter!(DNS_CACHE_TOTAL, "result" => "hit").increment(1);
                        return Err(SocksError::InvalidAddress(format!(
                            "DNS resolution failed (cached): {}",
                            err_msg
                        )));
                    }
                }
            }
            // 过期，移除
            drop(entry);
            self.cache.remove(domain);
            debug!(domain, "DNS cache expired");
        }

        // 2. 缓存未命中，执行 DNS 解析
        counter!(DNS_CACHE_TOTAL, "result" => "miss").increment(1);
        debug!(domain, "DNS cache miss, resolving");
        let host = format!("{}:{}", domain, port);

        // 3. 容量检查，超限时清理过期条目
        if self.cache.len() >= self.max_entries {
            self.evict_expired();
        }

        match lookup_host(&host).await {
            Ok(addrs_iter) => {
                let ip_addrs: Vec<IpAddr> = addrs_iter.map(|sa| sa.ip()).collect();
                if ip_addrs.is_empty() {
                    // DNS 解析返回空结果，视为失败，缓存负结果
                    counter!(DNS_RESOLVE_TOTAL, "result" => "failure").increment(1);
                    let err_msg = format!("DNS resolution returned no addresses for {}", domain);
                    self.cache.insert(
                        domain.to_owned(),
                        DnsCacheEntry {
                            result: DnsResult::Failure(err_msg.clone()),
                            created_at: Instant::now(),
                        },
                    );
                    gauge!(DNS_CACHE_ENTRIES).set(self.cache.len() as f64);
                    return Err(SocksError::InvalidAddress(err_msg));
                }

                // 解析成功，先尝试连接，再缓存正结果
                counter!(DNS_RESOLVE_TOTAL, "result" => "success").increment(1);
                let connect_result = Self::try_connect(&ip_addrs, port).await;
                self.cache.insert(
                    domain.to_owned(),
                    DnsCacheEntry {
                        result: DnsResult::Success(ip_addrs),
                        created_at: Instant::now(),
                    },
                );
                gauge!(DNS_CACHE_ENTRIES).set(self.cache.len() as f64);
                connect_result
            }
            Err(e) => {
                // DNS 解析失败，缓存负结果
                counter!(DNS_RESOLVE_TOTAL, "result" => "failure").increment(1);
                let err_msg = e.to_string();
                debug!(domain, error = %err_msg, "DNS resolution failed, caching negative result");
                self.cache.insert(
                    domain.to_owned(),
                    DnsCacheEntry {
                        result: DnsResult::Failure(err_msg.clone()),
                        created_at: Instant::now(),
                    },
                );
                gauge!(DNS_CACHE_ENTRIES).set(self.cache.len() as f64);
                Err(SocksError::Io(e))
            }
        }
    }

    /// 依次尝试连接地址列表中的每个 IP，动态组合端口，返回第一个成功的连接
    async fn try_connect(addrs: &[IpAddr], port: u16) -> Result<TcpStream, SocksError> {
        let mut last_err = None;
        for ip in addrs {
            let sock_addr = SocketAddr::new(*ip, port);
            match TcpStream::connect(sock_addr).await {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    debug!(addr = %sock_addr, error = %e, "Connect attempt failed");
                    last_err = Some(e);
                }
            }
        }
        Err(SocksError::Io(last_err.unwrap()))
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
        let cache = DnsCache::new(Duration::from_secs(300), Duration::from_secs(30), 1024);
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_evict_expired_positive() {
        let cache = DnsCache::new(Duration::from_millis(1), Duration::from_millis(1), 1024);

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
        let cache = DnsCache::new(Duration::from_secs(300), Duration::from_millis(1), 1024);

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
        let cache = DnsCache::new(Duration::from_secs(300), Duration::from_secs(30), 1024);

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
