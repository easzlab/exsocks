mod common;

use exsocks::limiter::ConnectionLimiter;
use std::sync::Arc;

#[tokio::test]
async fn test_concurrent_connections_within_limit() {
    let limiter = Arc::new(ConnectionLimiter::new(5));
    let mut permits = Vec::new();

    for _ in 0..5 {
        let permit = limiter.acquire().unwrap();
        permits.push(permit);
    }

    assert_eq!(limiter.available(), 0);
    assert_eq!(permits.len(), 5);
}

#[tokio::test]
async fn test_concurrent_connections_exceed_limit() {
    let limiter = Arc::new(ConnectionLimiter::new(3));
    let mut permits = Vec::new();

    for _ in 0..3 {
        permits.push(limiter.acquire().unwrap());
    }

    // 第 4 个应该失败
    assert!(limiter.acquire().is_err());
    assert_eq!(limiter.available(), 0);
}

#[tokio::test]
async fn test_permit_release_allows_new_connection() {
    let limiter = Arc::new(ConnectionLimiter::new(2));

    let permit1 = limiter.acquire().unwrap();
    let permit2 = limiter.acquire().unwrap();
    assert_eq!(limiter.available(), 0);
    assert!(limiter.acquire().is_err());

    // 释放一个 permit
    drop(permit1);
    assert_eq!(limiter.available(), 1);

    // 现在可以获取新的 permit
    let permit3 = limiter.acquire().unwrap();
    assert_eq!(limiter.available(), 0);

    drop(permit2);
    drop(permit3);
    assert_eq!(limiter.available(), 2);
}
