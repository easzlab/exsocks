use std::time::Duration;

use exsocks::dns_cache::DnsCache;

#[tokio::test]
async fn test_resolve_caches_result() {
    let cache = DnsCache::new(Duration::from_secs(300), Duration::from_secs(30), 1024);
    assert!(cache.is_empty());

    // 绑定到 IPv4 和 IPv6 双栈，确保 localhost 解析到任何地址都能连接
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    // 同时绑定 IPv6（如果可用）
    let listener6 = tokio::net::TcpListener::bind(format!("[::]:{}", port))
        .await
        .ok();

    // 在后台接受连接
    let accept_handle = tokio::spawn(async move {
        loop {
            let _ = listener.accept().await;
        }
    });
    let accept_handle6 = listener6.map(|l| {
        tokio::spawn(async move {
            loop {
                let _ = l.accept().await;
            }
        })
    });

    // 第一次解析 localhost 并连接
    let stream1 = cache.resolve("localhost", port).await;
    assert!(
        stream1.is_ok(),
        "First resolve should succeed: {:?}",
        stream1.err()
    );
    assert_eq!(
        cache.len(),
        1,
        "Cache should have 1 entry after first resolve"
    );

    // 第二次解析应命中缓存
    let stream2 = cache.resolve("localhost", port).await;
    assert!(stream2.is_ok(), "Second resolve (cache hit) should succeed");
    assert_eq!(cache.len(), 1, "Cache should still have 1 entry");

    accept_handle.abort();
    if let Some(h) = accept_handle6 {
        h.abort();
    }
}

#[tokio::test]
async fn test_cache_ttl_expiry() {
    // 使用极短的 TTL
    let cache = DnsCache::new(Duration::from_millis(50), Duration::from_secs(30), 1024);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let accept_handle = tokio::spawn(async move {
        loop {
            let _ = listener.accept().await;
        }
    });

    // 第一次解析
    let stream = cache.resolve("localhost", port).await;
    assert!(stream.is_ok());
    assert_eq!(cache.len(), 1);

    // 等待 TTL 过期
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 再次解析，应该因为过期而重新解析
    let stream = cache.resolve("localhost", port).await;
    assert!(stream.is_ok());
    assert_eq!(cache.len(), 1);

    accept_handle.abort();
}

#[tokio::test]
async fn test_cache_max_entries_eviction() {
    // 使用极短 TTL 和小容量
    let cache = DnsCache::new(Duration::from_millis(1), Duration::from_millis(1), 2);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let accept_handle = tokio::spawn(async move {
        loop {
            let _ = listener.accept().await;
        }
    });

    // 解析 localhost
    let _ = cache.resolve("localhost", port).await;
    assert!(cache.len() <= 2);

    // 等待过期
    tokio::time::sleep(Duration::from_millis(10)).await;

    // 再次解析，触发淘汰
    let _ = cache.resolve("localhost", port).await;
    assert!(cache.len() <= 2);

    accept_handle.abort();
}

#[tokio::test]
async fn test_negative_cache_hit() {
    // 负缓存 TTL 设为 5 秒，确保测试期间不会过期
    let cache = DnsCache::new(Duration::from_secs(300), Duration::from_secs(5), 1024);

    // 解析一个不存在的域名，应该失败
    let result1 = cache.resolve("nonexistent.invalid.test.domain", 80).await;
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
    let result2 = cache.resolve("nonexistent.invalid.test.domain", 80).await;
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
    let cache = DnsCache::new(Duration::from_secs(300), Duration::from_millis(50), 1024);

    // 解析一个不存在的域名
    let result1 = cache.resolve("nonexistent.invalid.test.domain", 80).await;
    assert!(result1.is_err());
    assert_eq!(cache.len(), 1);

    // 等待负缓存过期
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 再次解析，负缓存已过期，应重新尝试 DNS 解析（仍然失败，但不是 cached 错误）
    let result2 = cache.resolve("nonexistent.invalid.test.domain", 80).await;
    assert!(result2.is_err());
    // 重新解析后会再次缓存负结果
    assert_eq!(cache.len(), 1);
}

#[tokio::test]
async fn test_positive_and_negative_cache_independent_ttl() {
    // 正缓存 TTL 300s，负缓存 TTL 50ms
    let cache = DnsCache::new(Duration::from_secs(300), Duration::from_millis(50), 1024);

    // 先缓存一个失败的域名
    let _ = cache.resolve("nonexistent.invalid.test.domain", 80).await;
    assert_eq!(cache.len(), 1);

    // 再缓存一个成功的域名
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let _listener6 = tokio::net::TcpListener::bind(format!("[::]:{}", port))
        .await
        .ok();
    let accept_handle = tokio::spawn(async move {
        loop {
            let _ = listener.accept().await;
        }
    });
    let _ = cache.resolve("localhost", port).await;
    assert_eq!(cache.len(), 2);

    // 等待负缓存过期（50ms），但正缓存不过期（300s）
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 负缓存应过期，正缓存应仍然有效
    // 解析 localhost 应命中正缓存
    let result = cache.resolve("localhost", port).await;
    assert!(result.is_ok(), "Positive cache should still be valid");

    // 解析失败域名应重新解析（负缓存已过期）
    let result = cache.resolve("nonexistent.invalid.test.domain", 80).await;
    assert!(result.is_err());
    // 错误信息不应包含 "cached"（因为是重新解析的）
    let err_msg = result.unwrap_err().to_string();
    assert!(
        !err_msg.contains("cached"),
        "Should be a fresh DNS error, not cached, got: {}",
        err_msg
    );

    accept_handle.abort();
}

#[test]
fn test_cache_new_empty() {
    let cache = DnsCache::new(Duration::from_secs(60), Duration::from_secs(30), 100);
    assert_eq!(cache.len(), 0);
    assert!(cache.is_empty());
}

#[test]
fn test_cache_new_with_zero_ttl_still_creates() {
    let cache = DnsCache::new(Duration::from_secs(0), Duration::from_secs(0), 100);
    assert!(cache.is_empty());
}
