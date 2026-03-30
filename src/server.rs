use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::signal;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;
use tracing::{debug, error, info, info_span};

use crate::auth::UserStore;
use crate::buffer_pool::BufferPool;
use crate::config::AppConfig;
use crate::dns_cache::DnsCache;
use crate::error::SocksError;
use crate::limiter::ConnectionLimiter;
use crate::relay;
use crate::socks5;
use crate::socks5::protocol::REP_SUCCEEDED;

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
    let cancel_token = external_token.unwrap_or_else(CancellationToken::new);
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

    info!("Max connections: {}", config.max_connections);

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (socket, peer_addr) = result?;
                socket.set_nodelay(true)?;
                let limiter = limiter.clone();
                let dns_cache = dns_cache.clone();
                let pool = buffer_pool.clone();
                let user_store = user_store.clone();
                let token = cancel_token.child_token();

                tokio::spawn(async move {
                    let result = handle_connection(socket, peer_addr, limiter, connect_timeout, pool, dns_cache, user_store, token).await;
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

async fn handle_connection(
    mut socket: TcpStream,
    _peer_addr: SocketAddr,
    limiter: Arc<ConnectionLimiter>,
    connect_timeout: Duration,
    pool: Arc<BufferPool>,
    dns_cache: Option<Arc<DnsCache>>,
    user_store: Option<Arc<UserStore>>,
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
