use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::signal;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{info, error, debug, info_span};
use tracing::Instrument;

use crate::config::AppConfig;
use crate::error::SocksError;
use crate::limiter::ConnectionLimiter;
use crate::relay;
use crate::socks5;
use crate::socks5::protocol::REP_SUCCEEDED;

pub async fn run(config: AppConfig) -> Result<(), SocksError> {
    let listener = TcpListener::bind(config.bind).await?;
    info!("SOCKS5 server listening on {}", config.bind);

    let limiter = Arc::new(ConnectionLimiter::new(config.max_connections));
    let connect_timeout = Duration::from_secs(config.connect_timeout);
    let cancel_token = CancellationToken::new();
    info!("Max connections: {}", config.max_connections);

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (socket, peer_addr) = result?;
                socket.set_nodelay(true)?;
                let limiter = limiter.clone();
                let token = cancel_token.child_token();

                tokio::spawn(async move {
                    tokio::select! {
                        result = handle_connection(socket, peer_addr, limiter, connect_timeout) => {
                            if let Err(e) = result {
                                error!(error = %e, "Connection error");
                            }
                        }
                        _ = token.cancelled() => {
                            debug!("Connection cancelled by shutdown");
                        }
                    }
                }.instrument(info_span!("conn", %peer_addr)));
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
) -> Result<(), SocksError> {
    let _permit = match limiter.acquire() {
        Ok(permit) => permit,
        Err(e) => {
            debug!("Rejected: limit exceeded");
            return Err(e);
        }
    };

    socks5::perform_handshake(&mut socket).await?;

    let request = socks5::parse_request(&mut socket).await?;
    debug!(target = %request.address, port = request.port, "CONNECT");

    let target = match timeout(connect_timeout, request.address.connect(request.port)).await {
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

    let (client_to_target, target_to_client) = relay::relay(socket, target).await?;
    info!(bytes_up = client_to_target, bytes_down = target_to_client, "Closed");

    Ok(())
}
