use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::error::SocksError;
use super::protocol::{SOCKS5_VERSION, Address};

/// 构建 SOCKS5 响应报文。
pub fn build_reply(status: u8, bind_addr: SocketAddr) -> Vec<u8> {
    let mut reply = vec![
        SOCKS5_VERSION,
        status,
        0x00,
    ];

    let (addr_bytes, port) = match bind_addr {
        SocketAddr::V4(addr) => (Address::IPv4(*addr.ip()).to_bytes(), addr.port()),
        SocketAddr::V6(addr) => (Address::IPv6(*addr.ip()).to_bytes(), addr.port()),
    };

    reply.extend_from_slice(&addr_bytes);
    reply.extend_from_slice(&port.to_be_bytes());

    reply
}

pub async fn send_reply(
    stream: &mut TcpStream,
    status: u8,
    bind_addr: SocketAddr,
) -> Result<(), SocksError> {
    let reply = build_reply(status, bind_addr);
    stream.write_all(&reply).await?;
    Ok(())
}
