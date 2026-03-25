use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::error::SocksError;
use super::protocol::build_reply;

pub async fn send_reply(
    stream: &mut TcpStream,
    status: u8,
    bind_addr: SocketAddr,
) -> Result<(), SocksError> {
    let reply = build_reply(status, bind_addr);
    stream.write_all(&reply).await?;
    Ok(())
}
