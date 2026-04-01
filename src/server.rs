use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::signal;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;
use tracing::{debug, error, info, info_span, warn};

use crate::access::AccessControl;
use crate::auth::UserStore;
use crate::buffer_pool::BufferPool;
use crate::config::AppConfig;
use crate::dns_cache::DnsCache;
use crate::error::SocksError;
use crate::limiter::ConnectionLimiter;
use crate::relay;
use crate::socks5;
use crate::socks5::protocol::{REP_CONNECTION_NOT_ALLOWED, REP_SUCCEEDED};
use crate::target_rules::TargetRuleControl;

pub async fn run(config: AppConfig) -> Result<(), SocksError> {
    let listener = TcpListener::bind(config.bind).await?;
    run_with_listener(config, listener, None).await
}

/// 使用已绑定的 listener 运行服务器，支持外部 CancellationToken 控制关闭。
/// 用于测试场景，避免端口竞态问题。
pub async fn run_with_listener(
    config: AppConfig,
    listener: TcpListener,
    external_token: Option<CancellationToken>,
) -> Result<(), SocksError> {
    let addr = listener.local_addr()?;
    info!("SOCKS5 server listening on {}", addr);

    let limiter = Arc::new(ConnectionLimiter::new(config.max_connections));
    let connect_timeout = Duration::from_secs(config.connect_timeout);
    let relay_buffer_size = config.relay_buffer_size;
    let pool_capacity = config.effective_pool_capacity();
    let buffer_pool = Arc::new(BufferPool::new(pool_capacity, relay_buffer_size));
    info!(
        capacity = pool_capacity,
        buffer_size = relay_buffer_size,
        "Buffer pool initialized"
    );
    let cancel_token = external_token.unwrap_or_default();
    let dns_cache = if config.dns_cache_ttl > 0 {
        let cache = Arc::new(DnsCache::new(
            Duration::from_secs(config.dns_cache_ttl),
            Duration::from_secs(config.dns_cache_negative_ttl),
            config.dns_cache_max_entries,
        ));
        info!(
            ttl = config.dns_cache_ttl,
            negative_ttl = config.dns_cache_negative_ttl,
            max_entries = config.dns_cache_max_entries,
            "DNS cache enabled"
        );
        Some(cache)
    } else {
        info!("DNS cache disabled");
        None
    };

    // 初始化用户认证存储
    let user_store = if config.auth_enabled {
        let store = Arc::new(
            UserStore::load_from_file(&config.auth_user_file)
                .map_err(|e| SocksError::UserConfig(format!("Failed to load user config: {}", e)))?,
        );
        // 启动文件变更监听（_watcher 必须保持存活）
        let _watcher = store.watch().map_err(|e| {
            SocksError::UserConfig(format!("Failed to start user config watcher: {}", e))
        })?;
        // 将 watcher 移入后台任务保持存活
        // watcher 的生命周期与 cancel_token 绑定
        let watcher_token = cancel_token.clone();
        tokio::spawn(async move {
            watcher_token.cancelled().await;
            drop(_watcher);
        });
        info!(
            path = %config.auth_user_file.display(),
            "Authentication enabled with user config hot-reload"
        );
        Some(store)
    } else {
        info!("Authentication disabled, accepting all connections");
        None
    };

    // 初始化客户端源地址白名单
    let access_control = if config.access_enabled {
        let ac = Arc::new(
            AccessControl::load(&config.access_file).map_err(|e| {
                SocksError::AccessConfig(format!("Failed to load access config: {}", e))
            })?,
        );
        let _watcher = ac.watch().map_err(|e| {
            SocksError::AccessConfig(format!("Failed to start access config watcher: {}", e))
        })?;
        let watcher_token = cancel_token.clone();
        tokio::spawn(async move {
            watcher_token.cancelled().await;
            drop(_watcher);
        });
        info!(
            path = %config.access_file.display(),
            "Access control (whitelist) enabled with hot-reload"
        );
        Some(ac)
    } else {
        info!("Access control disabled, accepting all source addresses");
        None
    };

    // 初始化目标地址规则管控
    let target_rule_control = if config.target_rules_enabled {
        let trc = Arc::new(
            TargetRuleControl::load(&config.target_rules_file).map_err(|e| {
                SocksError::TargetRulesConfig(format!(
                    "Failed to load target rules config: {}",
                    e
                ))
            })?,
        );
        let _watcher = trc.watch().map_err(|e| {
            SocksError::TargetRulesConfig(format!(
                "Failed to start target rules config watcher: {}",
                e
            ))
        })?;
        let watcher_token = cancel_token.clone();
        tokio::spawn(async move {
            watcher_token.cancelled().await;
            drop(_watcher);
        });
        info!(
            path = %config.target_rules_file.display(),
            "Target rules enabled with hot-reload"
        );
        Some(trc)
    } else {
        info!("Target rules disabled, allowing all destinations");
        None
    };

    info!("Max connections: {}", config.max_connections);

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (socket, peer_addr) = result?;
                socket.set_nodelay(true)?;

                // 白名单检查在 accept 后立即执行，避免为被拒绝的连接创建 tokio task 和消耗 permit
                if let Some(ac) = &access_control
                    && !ac.rules().is_allowed(peer_addr.ip())
                {
                    warn!(ip = %peer_addr.ip(), "Connection blocked by whitelist");
                    drop(socket);
                    continue;
                }

                let limiter = limiter.clone();
                let dns_cache = dns_cache.clone();
                let pool = buffer_pool.clone();
                let user_store = user_store.clone();
                let trc = target_rule_control.clone();
                let token = cancel_token.child_token();

                tokio::spawn(async move {
                    let result = handle_connection(socket, peer_addr, limiter, connect_timeout, pool, dns_cache, user_store, trc, token).await;
                    if let Err(e) = result {
                        error!(error = %e, "Connection error");
                    }
                }.instrument(info_span!("conn", %peer_addr)));
            }
            _ = cancel_token.cancelled() => {
                info!("External shutdown signal received");
                break;
            }
            _ = signal::ctrl_c() => {
                info!("Shutdown signal received, stopping accept loop");
                cancel_token.cancel();
                break;
            }
        }
    }

    info!("Server shut down gracefully");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    mut socket: TcpStream,
    _peer_addr: SocketAddr,
    limiter: Arc<ConnectionLimiter>,
    connect_timeout: Duration,
    pool: Arc<BufferPool>,
    dns_cache: Option<Arc<DnsCache>>,
    user_store: Option<Arc<UserStore>>,
    target_rule_control: Option<Arc<TargetRuleControl>>,
    cancel: CancellationToken,
) -> Result<(), SocksError> {
    let _permit = match limiter.acquire() {
        Ok(permit) => permit,
        Err(e) => {
            debug!("Rejected: limit exceeded");
            return Err(e);
        }
    };

    socks5::perform_handshake(&mut socket, user_store.as_ref().map(|s| s.as_ref())).await?;

    let request = socks5::parse_request(&mut socket).await?;
    debug!(target = %request.address, port = request.port, "CONNECT");

    // 目标地址规则检查
    if let Some(trc) = &target_rule_control {
        let result = trc.rules().check(&request.address, request.port);
        if result.log {
            if result.allowed {
                info!(target = %request.address, port = request.port, "Target PASS by rule");
            } else {
                warn!(target = %request.address, port = request.port, "Target BLOCKED by rule");
            }
        }
        if !result.allowed {
            let dummy_addr = std::net::SocketAddr::from(([0, 0, 0, 0], 0));
            socks5::send_reply(&mut socket, REP_CONNECTION_NOT_ALLOWED, dummy_addr).await?;
            return Err(SocksError::TargetDenied(
                request.address.to_string(),
                request.port,
            ));
        }
    }

    let target = match timeout(
        connect_timeout,
        request.address.connect(request.port, dns_cache.as_deref()),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            error!(error = %e, "Failed to connect to target");
            return Err(e);
        }
        Err(_) => {
            error!("Connect to target timed out");
            return Err(SocksError::ConnectTimeout);
        }
    };
    target.set_nodelay(true)?;

    let bind_addr = target.local_addr()?;
    socks5::send_reply(&mut socket, REP_SUCCEEDED, bind_addr).await?;
    info!(target = %request.address, port = request.port, "Established");

    let (client_to_target, target_to_client) = relay::relay(socket, target, &pool, cancel).await?;
    info!(
        bytes_up = client_to_target,
        bytes_down = target_to_client,
        "Closed"
    );

    Ok(())
}
