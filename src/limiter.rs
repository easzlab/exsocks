#![allow(dead_code)]

use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::SocksError;

pub struct ConnectionLimiter {
    semaphore: Arc<Semaphore>,
    max_connections: usize,
}

impl ConnectionLimiter {
    pub fn new(max_connections: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_connections)),
            max_connections,
        }
    }

    /// 尝试获取连接许可，超时时立即拒绝而非阻塞等待。
    pub fn acquire(&self) -> Result<OwnedSemaphorePermit, SocksError> {
        match self.semaphore.clone().try_acquire_owned() {
            Ok(permit) => Ok(permit),
            Err(_) => Err(SocksError::ConnectionLimitExceeded(self.max_connections)),
        }
    }

    pub fn available(&self) -> usize {
        self.semaphore.available_permits()
    }

    pub fn max_connections(&self) -> usize {
        self.max_connections
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_limiter() {
        let limiter = ConnectionLimiter::new(10);
        assert_eq!(limiter.available(), 10);
    }

    #[test]
    fn test_acquire_success() {
        let limiter = ConnectionLimiter::new(5);
        let _permit = limiter.acquire().unwrap();
        assert_eq!(limiter.available(), 4);
    }

    #[test]
    fn test_acquire_exhausted() {
        let limiter = ConnectionLimiter::new(2);
        let _permit1 = limiter.acquire().unwrap();
        let _permit2 = limiter.acquire().unwrap();
        let result = limiter.acquire();
        assert!(matches!(
            result,
            Err(SocksError::ConnectionLimitExceeded(2))
        ));
    }

    #[test]
    fn test_release_on_drop() {
        let limiter = ConnectionLimiter::new(3);
        assert_eq!(limiter.available(), 3);
        {
            let _permit = limiter.acquire().unwrap();
            assert_eq!(limiter.available(), 2);
        }
        assert_eq!(limiter.available(), 3);
    }

    #[test]
    fn test_max_connections_getter() {
        let limiter = ConnectionLimiter::new(100);
        assert_eq!(limiter.max_connections(), 100);
    }

    #[test]
    fn test_boundary_one() {
        let limiter = ConnectionLimiter::new(1);
        let _permit = limiter.acquire().unwrap();
        assert_eq!(limiter.available(), 0);
        assert!(limiter.acquire().is_err());
        drop(_permit);
        assert_eq!(limiter.available(), 1);
        assert!(limiter.acquire().is_ok());
    }
}
