use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use super::protocol::{Address, SOCKS5_VERSION};
use crate::error::SocksError;

/// 构建 SOCKS5 响应报文。
pub fn build_reply(status: u8, bind_addr: SocketAddr) -> Vec<u8> {
    let mut reply = vec![SOCKS5_VERSION, status, 0x00];

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socks5::protocol::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn test_build_reply_success_ipv4() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080));
        let reply = build_reply(REP_SUCCEEDED, addr);
        assert_eq!(reply[0], SOCKS5_VERSION);
        assert_eq!(reply[1], REP_SUCCEEDED);
        assert_eq!(reply[2], 0x00);
        assert_eq!(reply[3], ATYP_IPV4);
        assert_eq!(reply[4..8], [127, 0, 0, 1]);
        assert_eq!(reply[8..10], [0x1F, 0x90]); // 8080 in big-endian
    }

    #[test]
    fn test_build_reply_success_ipv6() {
        let addr = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
            443,
            0,
            0,
        ));
        let reply = build_reply(REP_SUCCEEDED, addr);
        assert_eq!(reply[0], SOCKS5_VERSION);
        assert_eq!(reply[1], REP_SUCCEEDED);
        assert_eq!(reply[2], 0x00);
        assert_eq!(reply[3], ATYP_IPV6);
        assert_eq!(
            reply[4..20],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(reply[20..22], [0x01, 0xBB]); // 443 in big-endian
    }

    #[test]
    fn test_build_reply_failure() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));
        let reply = build_reply(REP_GENERAL_FAILURE, addr);
        assert_eq!(reply[0], SOCKS5_VERSION);
        assert_eq!(reply[1], REP_GENERAL_FAILURE);
        assert_eq!(reply[2], 0x00);
    }

    #[test]
    fn test_build_reply_version_byte() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 80));
        let reply = build_reply(REP_SUCCEEDED, addr);
        assert_eq!(reply[0], 0x05);
    }

    #[test]
    fn test_build_reply_port_big_endian() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080));
        let reply = build_reply(REP_SUCCEEDED, addr);
        // 端口8080 = 0x1F90，应该编码为[0x1F, 0x90]
        assert_eq!(reply[reply.len() - 2], 0x1F);
        assert_eq!(reply[reply.len() - 1], 0x90);
    }
}
