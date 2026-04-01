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

/// 默认日志最大保留文件数：7
///
/// 按天滚动时相当于保留最近 7 天的日志
fn default_log_max_files() -> usize {
    7
}

/// 默认单个日志文件最大大小：0 表示不限制
///
/// 单位为字节，设置后日志文件达到此大小时也会触发滚动
/// 与按天滚动同时生效，任一条件满足即滚动
fn default_log_max_size() -> u64 {
    0
}

/// 默认缓冲区池容量：0 表示自动推导为 max_connections * 2
fn default_relay_pool_capacity() -> usize {
    0
}

/// 默认用户认证配置文件路径
fn default_auth_user_file() -> PathBuf {
    PathBuf::from("user.yaml")
}

/// 默认客户端白名单配置文件路径
fn default_access_file() -> PathBuf {
    PathBuf::from("client-rules.yaml")
}

/// 默认目标地址规则配置文件路径
fn default_target_rules_file() -> PathBuf {
    PathBuf::from("target-rules.yaml")
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
    /// 日志最大保留文件数，按天滚动时相当于保留天数，默认 7
    #[serde(default = "default_log_max_files")]
    pub log_max_files: usize,
    /// 单个日志文件最大大小（字节），0 表示不限制，默认 0
    /// 与按天滚动同时生效，任一条件满足即触发滚动
    #[serde(default = "default_log_max_size")]
    pub log_max_size: u64,
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
    /// 缓冲区对象池容量，0 表示自动使用 max_connections * 2
    #[serde(default = "default_relay_pool_capacity")]
    pub relay_pool_capacity: usize,
    /// 是否启用用户名/密码认证（RFC1929），默认 false
    /// 启用后客户端必须提供有效的用户名和密码
    /// 未启用时同时接受无认证和用户名密码认证，但不校验凭证
    #[serde(default)]
    pub auth_enabled: bool,
    /// 用户认证配置文件路径，默认 "user.yaml"
    /// 仅在 auth_enabled 为 true 时生效
    /// 支持热加载，修改后自动生效
    #[serde(default = "default_auth_user_file")]
    pub auth_user_file: PathBuf,
    /// 是否启用客户端源地址白名单，默认 false
    /// 启用后只有在 access_file 中配置的 CIDR 范围内的客户端才允许连接
    #[serde(default)]
    pub access_enabled: bool,
    /// 客户端白名单配置文件路径，默认 "client-rules.yaml"
    /// 仅在 access_enabled 为 true 时生效
    /// 支持热加载，修改后自动生效
    #[serde(default = "default_access_file")]
    pub access_file: PathBuf,
    /// 是否启用目标地址规则管控，默认 false
    /// 启用后根据配置的规则对目标地址（IP/域名）和端口进行匹配检查
    #[serde(default)]
    pub target_rules_enabled: bool,
    /// 目标地址规则配置文件路径，默认 "target-rules.yaml"
    /// 仅在 target_rules_enabled 为 true 时生效
    /// 支持热加载，修改后自动生效
    #[serde(default = "default_target_rules_file")]
    pub target_rules_file: PathBuf,
}

impl AppConfig {
    pub fn load(config_file: Option<&PathBuf>) -> Result<Self, ConfigError> {
        let mut builder = ConfigBuilder::builder()
            .set_default("bind", default_bind().to_string())?
            .set_default("max_connections", default_max_connections() as i64)?
            .set_default("connect_timeout", default_connect_timeout() as i64)?
            .set_default("log_dir", default_log_dir().to_str().unwrap())?
            .set_default("log_level", default_log_level())?
            .set_default("log_max_files", default_log_max_files() as i64)?
            .set_default("log_max_size", default_log_max_size() as i64)?
            .set_default("relay_buffer_size", default_relay_buffer_size() as i64)?
            .set_default("dns_cache_ttl", default_dns_cache_ttl() as i64)?
            .set_default(
                "dns_cache_max_entries",
                default_dns_cache_max_entries() as i64,
            )?
            .set_default(
                "dns_cache_negative_ttl",
                default_dns_cache_negative_ttl() as i64,
            )?
            .set_default("relay_pool_capacity", default_relay_pool_capacity() as i64)?
            .set_default("auth_enabled", false)?
            .set_default(
                "auth_user_file",
                default_auth_user_file().to_str().unwrap(),
            )?
            .set_default("access_enabled", false)?
            .set_default(
                "access_file",
                default_access_file().to_str().unwrap(),
            )?
            .set_default("target_rules_enabled", false)?
            .set_default(
                "target_rules_file",
                default_target_rules_file().to_str().unwrap(),
            )?;

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
        // - prefix: EXSOCKS 前缀，只读取 EXSOCKS_* 环境变量
        // - prefix_separator("_"): 前缀与字段名之间用单下划线
        // - separator("__"): 嵌套配置的层级分隔符用双下划线
        // 例如：EXSOCKS_AUTH_ENABLED -> auth_enabled
        //       EXSOCKS_DNS_CACHE_TTL -> dns_cache_ttl
        //       EXSOCKS_NESTED__KEY -> nested.key (如果有嵌套配置)
        builder = builder.add_source(
            Environment::with_prefix("EXSOCKS")
                .prefix_separator("_")
                .separator("__")
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

    /// 返回实际生效的缓冲区池容量
    ///
    /// 如果 `relay_pool_capacity` 大于 0，直接使用该值；
    /// 否则自动推导为 `max_connections * 2`。
    pub fn effective_pool_capacity(&self) -> usize {
        if self.relay_pool_capacity > 0 {
            self.relay_pool_capacity
        } else {
            self.max_connections * 2
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
            log_max_files: default_log_max_files(),
            log_max_size: default_log_max_size(),
            relay_buffer_size: default_relay_buffer_size(),
            dns_cache_ttl: default_dns_cache_ttl(),
            dns_cache_max_entries: default_dns_cache_max_entries(),
            dns_cache_negative_ttl: default_dns_cache_negative_ttl(),
            relay_pool_capacity: default_relay_pool_capacity(),
            auth_enabled: false,
            auth_user_file: default_auth_user_file(),
            access_enabled: false,
            access_file: default_access_file(),
            target_rules_enabled: false,
            target_rules_file: default_target_rules_file(),
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
        assert_eq!(config.log_max_files, 7);
        assert_eq!(config.log_max_size, 0);
        assert_eq!(config.relay_buffer_size, 65536);
        assert_eq!(config.dns_cache_ttl, 300);
        assert_eq!(config.dns_cache_max_entries, 1024);
        assert_eq!(config.dns_cache_negative_ttl, 30);
        assert_eq!(config.relay_pool_capacity, 0);
        assert_eq!(config.effective_pool_capacity(), 1024 * 2);
        assert!(!config.target_rules_enabled);
        assert_eq!(config.target_rules_file, PathBuf::from("target-rules.yaml"));
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

    #[test]
    fn test_default_access_fields() {
        let config = AppConfig::default();
        assert!(!config.access_enabled);
        assert_eq!(config.access_file, PathBuf::from("client-rules.yaml"));
    }

    #[test]
    fn test_load_access_fields_from_yaml() {
        let yaml_content = r#"
access_enabled: true
access_file: "/etc/exsocks/client-rules.yaml"
"#;
        let mut temp_file = Builder::new().suffix(".yaml").tempfile().unwrap();
        write!(temp_file, "{}", yaml_content).unwrap();

        let path = temp_file.path().to_path_buf();
        let config = AppConfig::load(Some(&path)).unwrap();
        assert!(config.access_enabled);
        assert_eq!(
            config.access_file,
            PathBuf::from("/etc/exsocks/client-rules.yaml")
        );
    }

    #[test]
    fn test_access_fields_default_when_not_in_yaml() {
        // 不包含 access 字段时，应使用默认值
        let yaml_content = r#"
bind: "0.0.0.0:1080"
"#;
        let mut temp_file = Builder::new().suffix(".yaml").tempfile().unwrap();
        write!(temp_file, "{}", yaml_content).unwrap();

        let path = temp_file.path().to_path_buf();
        let config = AppConfig::load(Some(&path)).unwrap();
        assert!(!config.access_enabled);
        assert_eq!(config.access_file, PathBuf::from("client-rules.yaml"));
    }

    #[test]
    fn test_default_target_rules_fields() {
        let config = AppConfig::default();
        assert!(!config.target_rules_enabled);
        assert_eq!(config.target_rules_file, PathBuf::from("target-rules.yaml"));
    }

    #[test]
    fn test_load_target_rules_fields_from_yaml() {
        let yaml_content = r#"
target_rules_enabled: true
target_rules_file: "/etc/exsocks/target-rules.yaml"
"#;
        let mut temp_file = Builder::new().suffix(".yaml").tempfile().unwrap();
        write!(temp_file, "{}", yaml_content).unwrap();

        let path = temp_file.path().to_path_buf();
        let config = AppConfig::load(Some(&path)).unwrap();
        assert!(config.target_rules_enabled);
        assert_eq!(
            config.target_rules_file,
            PathBuf::from("/etc/exsocks/target-rules.yaml")
        );
    }

    #[test]
    fn test_target_rules_fields_default_when_not_in_yaml() {
        let yaml_content = r#"
bind: "0.0.0.0:1080"
"#;
        let mut temp_file = Builder::new().suffix(".yaml").tempfile().unwrap();
        write!(temp_file, "{}", yaml_content).unwrap();

        let path = temp_file.path().to_path_buf();
        let config = AppConfig::load(Some(&path)).unwrap();
        assert!(!config.target_rules_enabled);
        assert_eq!(config.target_rules_file, PathBuf::from("target-rules.yaml"));
    }
}
