#![allow(dead_code)]

use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SocksError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Invalid SOCKS version: expected 0x05, got 0x{0:02x}")]
    InvalidVersion(u8),

    #[error("No acceptable authentication method")]
    NoAcceptableAuthMethod,

    #[error("Unsupported command: 0x{0:02x}")]
    UnsupportedCommand(u8),

    #[error("Unsupported address type: 0x{0:02x}")]
    UnsupportedAddressType(u8),

    #[error("Connection limit exceeded (max: {0})")]
    ConnectionLimitExceeded(usize),

    #[error("Failed to connect to target: {0}")]
    ConnectFailed(String),

    #[error("Connect to target timed out")]
    ConnectTimeout,

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Invalid address format: {0}")]
    InvalidAddress(String),
}

impl From<config::ConfigError> for SocksError {
    fn from(e: config::ConfigError) -> Self {
        SocksError::Config(e.to_string())
    }
}

