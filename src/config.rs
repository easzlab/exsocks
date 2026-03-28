use std::net::SocketAddr;
use std::path::PathBuf;

use config::{Config as ConfigBuilder, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};

fn default_bind() -> SocketAddr {
    "127.0.0.1:1080".parse().unwrap()
}

fn default_max_connections() -> usize {
    1024
}

fn default_log_dir() -> PathBuf {
    PathBuf::from("./logs")
}

fn default_connect_timeout() -> u64 {
    10
}

fn default_log_level() -> String {
    "info".to_string()
}

/// 默认转发缓冲区大小：64 KiB
///
/// 与 Linux 默认 pipe 容量和常见 TCP 窗口大小对齐
fn default_relay_buffer_size() -> usize {
    65536
}

/// 默认 DNS 缓存 TTL：300 秒（5 分钟）
fn default_dns_cache_ttl() -> u64 {
    300
}

/// 默认 DNS 缓存最大条目数
fn default_dns_cache_max_entries() -> usize {
    1024
}

/// 默认 DNS 负缓存 TTL：30 秒
///
/// 解析失败时缓存的时间，避免短时间内对同一不可达域名反复发起 DNS 查询
fn default_dns_cache_negative_ttl() -> u64 {
    30
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout: u64,
    #[serde(default = "default_log_dir")]
    pub log_dir: PathBuf,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// 转发缓冲区大小（字节），默认 65536 (64 KiB)
    #[serde(default = "default_relay_buffer_size")]
    pub relay_buffer_size: usize,
    /// DNS 缓存 TTL（秒），0 表示禁用缓存，默认 300
    #[serde(default = "default_dns_cache_ttl")]
    pub dns_cache_ttl: u64,
    /// DNS 缓存最大条目数，默认 1024
    #[serde(default = "default_dns_cache_max_entries")]
    pub dns_cache_max_entries: usize,
    /// DNS 负缓存 TTL（秒），解析失败时缓存的时间，默认 30
    #[serde(default = "default_dns_cache_negative_ttl")]
    pub dns_cache_negative_ttl: u64,
}

impl AppConfig {
    pub fn load(config_file: Option<&PathBuf>) -> Result<Self, ConfigError> {
        let mut builder = ConfigBuilder::builder()
            .set_default("bind", default_bind().to_string())?
            .set_default("max_connections", default_max_connections() as i64)?
            .set_default("connect_timeout", default_connect_timeout() as i64)?
            .set_default("log_dir", default_log_dir().to_str().unwrap())?
            .set_default("log_level", default_log_level())?
            .set_default("relay_buffer_size", default_relay_buffer_size() as i64)?
            .set_default("dns_cache_ttl", default_dns_cache_ttl() as i64)?
            .set_default("dns_cache_max_entries", default_dns_cache_max_entries() as i64)?
            .set_default("dns_cache_negative_ttl", default_dns_cache_negative_ttl() as i64)?;

        // 加载系统配置文件
        if let Some(config_dir) = dirs::config_dir() {
            let sys_config = config_dir.join("exsocks").join("server.yaml");
            builder = builder.add_source(File::from(sys_config).required(false));
        }

        // 加载当前目录配置文件
        builder =
            builder.add_source(File::from(PathBuf::from("./config/server.yaml")).required(false));

        // 加载指定配置文件（如果提供）
        if let Some(path) = config_file {
            builder = builder.add_source(File::from(path.as_path()).required(true));
        }

        // 环境变量覆盖
        builder = builder.add_source(
            Environment::with_prefix("EXSOCKS")
                .separator("_")
                .try_parsing(true),
        );

        let config = builder.build()?;
        config.try_deserialize()
    }

    pub fn apply_cli_args(
        &mut self,
        bind: Option<SocketAddr>,
        max_connections: Option<usize>,
        log_dir: Option<PathBuf>,
        log_level: Option<String>,
        connect_timeout: Option<u64>,
    ) {
        if let Some(bind) = bind {
            self.bind = bind;
        }
        if let Some(max) = max_connections {
            self.max_connections = max;
        }
        if let Some(dir) = log_dir {
            self.log_dir = dir;
        }
        if let Some(level) = log_level {
            self.log_level = level;
        }
        if let Some(timeout) = connect_timeout {
            self.connect_timeout = timeout;
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            max_connections: default_max_connections(),
            connect_timeout: default_connect_timeout(),
            log_dir: default_log_dir(),
            log_level: default_log_level(),
            relay_buffer_size: default_relay_buffer_size(),
            dns_cache_ttl: default_dns_cache_ttl(),
            dns_cache_max_entries: default_dns_cache_max_entries(),
            dns_cache_negative_ttl: default_dns_cache_negative_ttl(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::Builder;

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();
        assert_eq!(config.bind, "127.0.0.1:1080".parse().unwrap());
        assert_eq!(config.max_connections, 1024);
        assert_eq!(config.connect_timeout, 10);
        assert_eq!(config.log_dir, PathBuf::from("./logs"));
        assert_eq!(config.log_level, "info");
        assert_eq!(config.relay_buffer_size, 65536);
        assert_eq!(config.dns_cache_ttl, 300);
        assert_eq!(config.dns_cache_max_entries, 1024);
        assert_eq!(config.dns_cache_negative_ttl, 30);
    }

    #[test]
    fn test_apply_cli_args_override() {
        let mut config = AppConfig::default();
        let bind = "0.0.0.0:9999".parse().unwrap();
        let max_connections = 2048;
        let log_dir = PathBuf::from("/var/log/exsocks");
        let log_level = "debug".to_string();
        let connect_timeout = 30;

        config.apply_cli_args(
            Some(bind),
            Some(max_connections),
            Some(log_dir.clone()),
            Some(log_level.clone()),
            Some(connect_timeout),
        );

        assert_eq!(config.bind, bind);
        assert_eq!(config.max_connections, max_connections);
        assert_eq!(config.log_dir, log_dir);
        assert_eq!(config.log_level, log_level);
        assert_eq!(config.connect_timeout, connect_timeout);
    }

    #[test]
    fn test_apply_cli_args_partial() {
        let mut config = AppConfig::default();
        let bind = "0.0.0.0:9999".parse().unwrap();
        let log_level = "debug".to_string();

        config.apply_cli_args(Some(bind), None, None, Some(log_level.clone()), None);

        assert_eq!(config.bind, bind);
        assert_eq!(config.max_connections, 1024); // 保持默认
        assert_eq!(config.log_dir, PathBuf::from("./logs")); // 保持默认
        assert_eq!(config.log_level, log_level);
        assert_eq!(config.connect_timeout, 10); // 保持默认
    }

    #[test]
    fn test_load_from_yaml() {
        let yaml_content = r#"
bind: "0.0.0.0:9999"
max_connections: 2048
connect_timeout: 30
log_dir: "/var/log/exsocks"
log_level: "debug"
"#;

        let mut temp_file = Builder::new().suffix(".yaml").tempfile().unwrap();
        write!(temp_file, "{}", yaml_content).unwrap();

        let path = temp_file.path().to_path_buf();
        let config = AppConfig::load(Some(&path)).unwrap();
        assert_eq!(config.bind, "0.0.0.0:9999".parse().unwrap());
        assert_eq!(config.max_connections, 2048);
        assert_eq!(config.connect_timeout, 30);
        assert_eq!(config.log_dir, PathBuf::from("/var/log/exsocks"));
        assert_eq!(config.log_level, "debug");
    }

    #[test]
    fn test_load_invalid_yaml() {
        let invalid_yaml = "invalid: yaml: content: [unclosed";

        let mut temp_file = Builder::new().suffix(".yaml").tempfile().unwrap();
        write!(temp_file, "{}", invalid_yaml).unwrap();

        let path = temp_file.path().to_path_buf();
        let result = AppConfig::load(Some(&path));
        assert!(result.is_err());
    }
}
