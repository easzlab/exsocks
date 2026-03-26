use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tracing::{info, error, debug};

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
    info!("Max connections: {}", config.max_connections);

    loop {
        let (socket, peer_addr) = listener.accept().await?;
        socket.set_nodelay(true)?;
        let limiter = limiter.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, peer_addr, limiter).await {
                error!(%peer_addr, error = %e, "Connection error");
            }
        });
    }
}

async fn handle_connection(
    mut socket: TcpStream,
    peer_addr: SocketAddr,
    limiter: Arc<ConnectionLimiter>,
) -> Result<(), SocksError> {
    debug!(%peer_addr, "New connection");

    let _permit = match limiter.acquire() {
        Ok(permit) => permit,
        Err(e) => {
            debug!(%peer_addr, "Connection rejected: limit exceeded");
            return Err(e);
        }
    };
    debug!(%peer_addr, available = limiter.available(), "Connection permit acquired");

    socks5::perform_handshake(&mut socket).await?;
    debug!(%peer_addr, "SOCKS5 handshake completed");

    let request = socks5::parse_request(&mut socket).await?;
    debug!(%peer_addr, target = %request.address, port = request.port, "CONNECT request");

    let target = match request.address.connect(request.port).await {
        Ok(stream) => stream,
        Err(e) => {
            error!(%peer_addr, error = %e, "Failed to connect to target");
            return Err(e);
        }
    };
    target.set_nodelay(true)?;

    let bind_addr = target.local_addr()?;
    socks5::send_reply(&mut socket, REP_SUCCEEDED, bind_addr).await?;
    info!(%peer_addr, target = %request.address, port = request.port, "Connection established");

    let (client_to_target, target_to_client) = relay::relay(socket, target).await?;
    info!(%peer_addr, bytes_up = client_to_target, bytes_down = target_to_client, "Connection closed");

    Ok(())
}
