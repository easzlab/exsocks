#![allow(dead_code)]

use std::sync::Arc;
use tokio::sync::{Semaphore, OwnedSemaphorePermit};

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

    pub async fn acquire(&self) -> Result<OwnedSemaphorePermit, SocksError> {
        match self.semaphore.clone().acquire_owned().await {
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
