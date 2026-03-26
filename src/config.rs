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
}

impl AppConfig {
    pub fn load(config_file: Option<&PathBuf>) -> Result<Self, ConfigError> {
        let mut builder = ConfigBuilder::builder()
            .set_default("bind", default_bind().to_string())?
            .set_default("max_connections", default_max_connections() as i64)?
            .set_default("connect_timeout", default_connect_timeout() as i64)?
            .set_default("log_dir", default_log_dir().to_str().unwrap())?
            .set_default("log_level", default_log_level())?;

        // 加载系统配置文件
        if let Some(config_dir) = dirs::config_dir() {
            let sys_config = config_dir.join("exsocks").join("server.yaml");
            builder = builder.add_source(File::from(sys_config).required(false));
        }

        // 加载当前目录配置文件
        builder = builder.add_source(File::from(PathBuf::from("./config/server.yaml")).required(false));

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

    pub fn apply_cli_args(&mut self, bind: Option<SocketAddr>, max_connections: Option<usize>, log_dir: Option<PathBuf>, log_level: Option<String>, connect_timeout: Option<u64>) {
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
        }
    }
}
