use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::error::SocksError;

/// user.yaml 的反序列化结构
#[derive(Debug, Deserialize)]
struct UserConfig {
    #[serde(default)]
    users: Vec<UserEntry>,
}

/// 单个用户条目
#[derive(Debug, Deserialize)]
struct UserEntry {
    username: String,
    password: String,
}

/// 线程安全的用户凭证存储，支持热加载。
///
/// 使用 `ArcSwap` 实现无锁读 + 原子替换：
/// - 每次认证请求调用 `verify()` 时仅需一次原子 load，无锁竞争
/// - 热加载时通过 `store()` 原子替换整个 HashMap，对读端完全透明
pub struct UserStore {
    /// 用户名 -> 密码的映射
    credentials: ArcSwap<HashMap<String, String>>,
    /// 配置文件路径
    path: PathBuf,
}

impl UserStore {
    /// 从指定的 YAML 文件加载用户凭证，创建 `UserStore` 实例。
    ///
    /// 如果文件不存在或格式错误，返回 `SocksError::UserConfig`。
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, SocksError> {
        let path = path.as_ref().to_path_buf();
        let credentials = Self::parse_file(&path)?;
        info!(path = %path.display(), users = credentials.len(), "User store loaded");
        Ok(Self {
            credentials: ArcSwap::new(Arc::new(credentials)),
            path,
        })
    }

    /// 验证用户名和密码是否匹配。
    ///
    /// 使用 `ArcSwap::load()` 无锁读取当前凭证表。
    pub fn verify(&self, username: &str, password: &str) -> bool {
        let creds = self.credentials.load();
        match creds.get(username) {
            Some(stored_password) => stored_password == password,
            None => false,
        }
    }

    /// 重新加载配置文件，原子替换内部凭证表。
    ///
    /// 如果重载失败，保留旧的凭证表不受影响，仅记录错误日志。
    pub fn reload(&self) -> Result<(), SocksError> {
        let credentials = Self::parse_file(&self.path)?;
        let user_count = credentials.len();
        self.credentials.store(Arc::new(credentials));
        info!(path = %self.path.display(), users = user_count, "User store reloaded");
        Ok(())
    }

    /// 返回当前加载的用户数量
    pub fn user_count(&self) -> usize {
        self.credentials.load().len()
    }

    /// 启动文件变更监听任务。
    ///
    /// 使用 `notify` crate 监听配置文件所在目录，当检测到文件修改时自动重载。
    /// 内置 500ms 防抖机制，避免编辑器保存时触发多次重载。
    ///
    /// 返回的 `RecommendedWatcher` 必须保持存活，drop 后监听停止。
    pub fn watch(self: &Arc<Self>) -> Result<RecommendedWatcher, SocksError> {
        let store = Arc::clone(self);
        let watch_path = self
            .path
            .canonicalize()
            .unwrap_or_else(|_| self.path.clone());
        let watch_dir = watch_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let file_name = watch_path
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_default();

        // 使用 tokio mpsc channel 将 notify 事件桥接到异步运行时
        let (tx, mut rx) = mpsc::channel::<()>(16);

        let mut watcher =
            notify::recommended_watcher(move |result: Result<Event, notify::Error>| {
                match result {
                    Ok(event) => {
                        let is_relevant = matches!(
                            event.kind,
                            EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
                        );
                        if !is_relevant {
                            return;
                        }

                        // 检查事件是否涉及目标文件
                        let affects_target = event.paths.iter().any(|p| {
                            p.file_name()
                                .map(|n| n == file_name)
                                .unwrap_or(false)
                        });

                        if affects_target {
                            // 非阻塞发送，如果 channel 满了说明已有待处理的重载请求
                            let _ = tx.try_send(());
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "File watcher error");
                    }
                }
            })
            .map_err(|e| SocksError::UserConfig(format!("Failed to create file watcher: {}", e)))?;

        watcher
            .watch(&watch_dir, RecursiveMode::NonRecursive)
            .map_err(|e| {
                SocksError::UserConfig(format!(
                    "Failed to watch directory {}: {}",
                    watch_dir.display(),
                    e
                ))
            })?;

        info!(
            path = %watch_path.display(),
            dir = %watch_dir.display(),
            "File watcher started"
        );

        // 启动防抖消费任务
        tokio::spawn(async move {
            loop {
                // 等待第一个事件
                if rx.recv().await.is_none() {
                    // channel 关闭，watcher 已被 drop
                    break;
                }

                // 防抖：等待 500ms，期间消费掉所有后续事件
                tokio::time::sleep(Duration::from_millis(500)).await;
                while rx.try_recv().is_ok() {}

                // 执行重载
                match store.reload() {
                    Ok(()) => {}
                    Err(e) => {
                        warn!(error = %e, "Failed to reload user config, keeping previous config");
                    }
                }
            }
        });

        Ok(watcher)
    }

    /// 从 YAML 文件解析用户凭证表
    fn parse_file(path: &Path) -> Result<HashMap<String, String>, SocksError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            SocksError::UserConfig(format!("Failed to read {}: {}", path.display(), e))
        })?;

        let config: UserConfig = serde_yaml::from_str(&content).map_err(|e| {
            SocksError::UserConfig(format!("Failed to parse {}: {}", path.display(), e))
        })?;

        let mut credentials = HashMap::with_capacity(config.users.len());
        for entry in config.users {
            if credentials.contains_key(&entry.username) {
                warn!(username = %entry.username, "Duplicate username, later entry will overwrite");
            }
            credentials.insert(entry.username, entry.password);
        }

        Ok(credentials)
    }
}
