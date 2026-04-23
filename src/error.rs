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

    #[error("Failed to connect to target: {0}")]
    ConnectFailed(String),

    #[error("Connect to target timed out")]
    ConnectTimeout,

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Invalid address format: {0}")]
    InvalidAddress(String),

    #[error("DNS resolution failed (cached): {0}")]
    CachedDnsFailure(String),

    #[error("Authentication failed for user: {0}")]
    AuthenticationFailed(String),

    #[error("Invalid authentication sub-negotiation version: 0x{0:02x}")]
    InvalidAuthVersion(u8),

    #[error("User config error: {0}")]
    UserConfig(String),

    #[error("Access config error: {0}")]
    AccessConfig(String),

    #[error("Target denied: {0}:{1}")]
    TargetDenied(String, u16),

    #[error("Target rules config error: {0}")]
    TargetRulesConfig(String),
}

impl From<config::ConfigError> for SocksError {
    fn from(e: config::ConfigError) -> Self {
        SocksError::Config(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_io() {
        let io_err = io::Error::new(io::ErrorKind::Other, "test error");
        let socks_err = SocksError::Io(io_err);
        assert!(socks_err.to_string().contains("IO error"));
    }

    #[test]
    fn test_error_display_invalid_version() {
        let err = SocksError::InvalidVersion(0x04);
        let display = err.to_string();
        assert!(display.contains("expected 0x05"));
        assert!(display.contains("got 0x04"));
    }

    #[test]
    fn test_error_display_no_acceptable_auth() {
        let err = SocksError::NoAcceptableAuthMethod;
        let display = err.to_string();
        assert!(display.contains("No acceptable authentication method"));
    }

    #[test]
    fn test_error_display_unsupported_command() {
        let err = SocksError::UnsupportedCommand(0x02);
        assert!(err.to_string().contains("0x02"));
    }

    #[test]
    fn test_from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::Other, "test");
        let socks_err = SocksError::from(io_err);
        assert!(matches!(socks_err, SocksError::Io(_)));
    }

    #[test]
    fn test_from_config_error() {
        let config_err = config::ConfigError::NotFound("test".into());
        let socks_err = SocksError::from(config_err);
        assert!(matches!(socks_err, SocksError::Config(_)));
    }
}
