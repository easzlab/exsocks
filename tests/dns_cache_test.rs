use std::sync::Arc;
use std::time::Duration;

use exsocks::dns_cache::DnsCache;

#[tokio::test]
async fn test_resolve_caches_result() {
    let cache = DnsCache::new(Duration::from_secs(300), Duration::from_secs(30), Duration::from_secs(5), 1024, "");
    assert!(cache.is_empty());

    // 第一次解析 localhost
    let addrs1 = cache.resolve("localhost").await;
    assert!(
        addrs1.is_ok(),
        "First resolve should succeed: {:?}",
        addrs1.err()
    );
    assert!(!addrs1.unwrap().is_empty(), "Should resolve to at least one IP");
    assert_eq!(
        cache.len(),
        1,
        "Cache should have 1 entry after first resolve"
    );

    // 第二次解析应命中缓存
    let addrs2 = cache.resolve("localhost").await;
    assert!(addrs2.is_ok(), "Second resolve (cache hit) should succeed");
    assert_eq!(cache.len(), 1, "Cache should still have 1 entry");
}

#[tokio::test]
async fn test_cache_ttl_expiry() {
    // 使用极短的 TTL
    let cache = DnsCache::new(Duration::from_millis(50), Duration::from_secs(30), Duration::from_secs(5), 1024, "");

    // 第一次解析
    let addrs = cache.resolve("localhost").await;
    assert!(addrs.is_ok());
    assert_eq!(cache.len(), 1);

    // 等待 TTL 过期
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 再次解析，应该因为过期而重新解析
    let addrs = cache.resolve("localhost").await;
    assert!(addrs.is_ok());
    assert_eq!(cache.len(), 1);
}

#[tokio::test]
async fn test_cache_max_entries_eviction() {
    // 使用极短 TTL 和小容量
    let cache = DnsCache::new(Duration::from_millis(1), Duration::from_millis(1), Duration::from_secs(5), 2, "");

    // 解析 localhost
    let _ = cache.resolve("localhost").await;
    assert!(cache.len() <= 2);

    // 等待过期
    tokio::time::sleep(Duration::from_millis(10)).await;

    // 再次解析，触发淘汰
    let _ = cache.resolve("localhost").await;
    assert!(cache.len() <= 2);
}

#[tokio::test]
async fn test_negative_cache_hit() {
    // 负缓存 TTL 设为 5 秒，确保测试期间不会过期
    let cache = DnsCache::new(Duration::from_secs(300), Duration::from_secs(5), Duration::from_secs(5), 1024, "");

    // 解析一个不存在的域名，应该失败
    let result1 = cache.resolve("nonexistent.invalid.test.domain").await;
    assert!(
        result1.is_err(),
        "First resolve of invalid domain should fail"
    );
    assert_eq!(
        cache.len(),
        1,
        "Failed result should be cached (negative cache)"
    );

    // 第二次解析同一域名，应命中负缓存，直接返回错误
    let result2 = cache.resolve("nonexistent.invalid.test.domain").await;
    assert!(
        result2.is_err(),
        "Second resolve should also fail (negative cache hit)"
    );
    let err_msg = result2.unwrap_err().to_string();
    assert!(
        err_msg.contains("cached"),
        "Error message should indicate cached result, got: {}",
        err_msg
    );
    assert_eq!(cache.len(), 1, "Cache should still have 1 entry");
}

#[tokio::test]
async fn test_negative_cache_expiry() {
    // 负缓存 TTL 设为极短（50ms）
    let cache = DnsCache::new(Duration::from_secs(300), Duration::from_millis(50), Duration::from_secs(5), 1024, "");

    // 解析一个不存在的域名
    let result1 = cache.resolve("nonexistent.invalid.test.domain").await;
    assert!(result1.is_err());
    assert_eq!(cache.len(), 1);

    // 等待负缓存过期
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 再次解析，负缓存已过期，应重新尝试 DNS 解析（仍然失败，但不是 cached 错误）
    let result2 = cache.resolve("nonexistent.invalid.test.domain").await;
    assert!(result2.is_err());
    // 重新解析后会再次缓存负结果
    assert_eq!(cache.len(), 1);
}

#[tokio::test]
async fn test_positive_and_negative_cache_independent_ttl() {
    // 正缓存 TTL 300s，负缓存 TTL 50ms
    let cache = DnsCache::new(Duration::from_secs(300), Duration::from_millis(50), Duration::from_secs(5), 1024, "");

    // 先缓存一个失败的域名
    let _ = cache.resolve("nonexistent.invalid.test.domain").await;
    assert_eq!(cache.len(), 1);

    // 再缓存一个成功的域名
    let _ = cache.resolve("localhost").await;
    assert_eq!(cache.len(), 2);

    // 等待负缓存过期（50ms），但正缓存不过期（300s）
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 负缓存应过期，正缓存应仍然有效
    // 解析 localhost 应命中正缓存
    let result = cache.resolve("localhost").await;
    assert!(result.is_ok(), "Positive cache should still be valid");

    // 解析失败域名应重新解析（负缓存已过期）
    let result = cache.resolve("nonexistent.invalid.test.domain").await;
    assert!(result.is_err());
    // 错误信息不应包含 "cached"（因为是重新解析的）
    let err_msg = result.unwrap_err().to_string();
    assert!(
        !err_msg.contains("cached"),
        "Should be a fresh DNS error, not cached, got: {}",
        err_msg
    );
}

#[test]
fn test_cache_new_empty() {
    let cache = DnsCache::new(Duration::from_secs(60), Duration::from_secs(30), Duration::from_secs(5), 100, "");
    assert_eq!(cache.len(), 0);
    assert!(cache.is_empty());
}

#[test]
fn test_cache_new_with_zero_ttl_still_creates() {
    let cache = DnsCache::new(Duration::from_secs(0), Duration::from_secs(0), Duration::from_secs(5), 100, "");
    assert!(cache.is_empty());
}

/// 并发请求合并：多个并发 resolve 请求同一域名，应只触发一次 DNS 解析，所有请求均成功
#[tokio::test]
async fn test_concurrent_resolve_coalescing() {
    let cache = Arc::new(DnsCache::new(
        Duration::from_secs(300),
        Duration::from_secs(30),
        Duration::from_secs(5),
        1024,
        "",
    ));

    // 启动 10 个并发任务同时解析同一域名
    let mut handles = Vec::new();
    for _ in 0..10 {
        let cache = cache.clone();
        handles.push(tokio::spawn(async move {
            cache.resolve("localhost").await
        }));
    }

    // 所有请求均应成功
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok(), "Concurrent resolve should succeed: {:?}", result.err());
    }

    // 缓存应只有 1 个条目
    assert_eq!(cache.len(), 1, "Cache should have exactly 1 entry after concurrent resolves");
}

/// 并发请求合并（负缓存）：多个并发 resolve 请求不存在的域名，应只触发一次 DNS 解析
#[tokio::test]
async fn test_concurrent_resolve_coalescing_negative() {
    let cache = Arc::new(DnsCache::new(
        Duration::from_secs(300),
        Duration::from_secs(30),
        Duration::from_secs(5),
        1024,
        "",
    ));

    let mut handles = Vec::new();
    for _ in 0..10 {
        let cache = cache.clone();
        handles.push(tokio::spawn(async move {
            cache.resolve("nonexistent.invalid.test.domain").await
        }));
    }

    // 所有请求均应失败
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_err(), "Concurrent resolve of invalid domain should fail");
    }

    // 缓存应只有 1 个负缓存条目
    assert_eq!(cache.len(), 1, "Cache should have exactly 1 negative entry");
}

/// 自定义 DNS 服务器解析：使用 8.8.8.8 作为 DNS 服务器解析域名
#[tokio::test]
async fn test_resolve_with_custom_dns_server() {
    let cache = DnsCache::new(
        Duration::from_secs(300),
        Duration::from_secs(30),
        Duration::from_secs(5),
        1024,
        "8.8.8.8",
    );
    assert!(cache.is_empty());

    // 使用自定义 DNS 服务器解析一个公共域名
    let result = cache.resolve("dns.google").await;
    assert!(
        result.is_ok(),
        "Custom DNS server resolve should succeed: {:?}",
        result.err()
    );
    assert!(!result.unwrap().is_empty(), "Should resolve to at least one IP");
    assert_eq!(cache.len(), 1, "Cache should have 1 entry");

    // 第二次解析应命中缓存
    let result2 = cache.resolve("dns.google").await;
    assert!(result2.is_ok(), "Second resolve (cache hit) should succeed");
    assert_eq!(cache.len(), 1, "Cache should still have 1 entry");
}

/// 无效 DNS 服务器地址应回退到系统默认解析器
#[tokio::test]
async fn test_invalid_dns_server_falls_back_to_system() {
    let cache = DnsCache::new(
        Duration::from_secs(300),
        Duration::from_secs(30),
        Duration::from_secs(5),
        1024,
        "not-a-valid-ip",
    );

    // 应回退到系统默认解析器，仍然能解析 localhost
    let result = cache.resolve("localhost").await;
    assert!(
        result.is_ok(),
        "Should fall back to system resolver: {:?}",
        result.err()
    );
}

/// 空字符串 dns_server 应使用系统默认解析器
#[tokio::test]
async fn test_empty_dns_server_uses_system_default() {
    let cache = DnsCache::new(
        Duration::from_secs(300),
        Duration::from_secs(30),
        Duration::from_secs(5),
        1024,
        "",
    );

    let result = cache.resolve("localhost").await;
    assert!(
        result.is_ok(),
        "Empty dns_server should use system default: {:?}",
        result.err()
    );
}

/// 自定义 DNS 服务器的负缓存也应正常工作
#[tokio::test]
async fn test_custom_dns_server_negative_cache() {
    let cache = DnsCache::new(
        Duration::from_secs(300),
        Duration::from_secs(5),
        Duration::from_secs(5),
        1024,
        "8.8.8.8",
    );

    // 解析不存在的域名
    let result1 = cache.resolve("nonexistent.invalid.test.domain").await;
    assert!(result1.is_err(), "Should fail for invalid domain");
    assert_eq!(cache.len(), 1, "Failed result should be cached");

    // 第二次解析应命中负缓存
    let result2 = cache.resolve("nonexistent.invalid.test.domain").await;
    assert!(result2.is_err(), "Should fail again (negative cache hit)");
    let err_msg = result2.unwrap_err().to_string();
    assert!(
        err_msg.contains("cached"),
        "Error should indicate cached result, got: {}",
        err_msg
    );
}
