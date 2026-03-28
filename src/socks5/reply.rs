use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use super::protocol::{Address, SOCKS5_VERSION};
use crate::error::SocksError;

/// SOCKS5 回复报文的最大长度：3(头) + 1(ATYP) + 16(IPv6) + 2(端口) = 22 字节。
const MAX_REPLY_LEN: usize = 22;

/// 构建 SOCKS5 响应报文，返回栈上缓冲区和实际长度，零堆分配。
pub fn build_reply(status: u8, bind_addr: SocketAddr) -> ([u8; MAX_REPLY_LEN], usize) {
    let mut buf = [0u8; MAX_REPLY_LEN];
    buf[0] = SOCKS5_VERSION;
    buf[1] = status;
    buf[2] = 0x00;

    let (addr, port) = match bind_addr {
        SocketAddr::V4(ref addr) => (Address::IPv4(*addr.ip()), addr.port()),
        SocketAddr::V6(ref addr) => (Address::IPv6(*addr.ip()), addr.port()),
    };

    let addr_len = addr.write_bytes(&mut buf[3..]);
    let port_offset = 3 + addr_len;
    buf[port_offset..port_offset + 2].copy_from_slice(&port.to_be_bytes());

    (buf, port_offset + 2)
}

pub async fn send_reply(
    stream: &mut TcpStream,
    status: u8,
    bind_addr: SocketAddr,
) -> Result<(), SocksError> {
    let (buf, len) = build_reply(status, bind_addr);
    stream.write_all(&buf[..len]).await?;
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
        let (buf, len) = build_reply(REP_SUCCEEDED, addr);
        let reply = &buf[..len];
        assert_eq!(reply[0], SOCKS5_VERSION);
        assert_eq!(reply[1], REP_SUCCEEDED);
        assert_eq!(reply[2], 0x00);
        assert_eq!(reply[3], ATYP_IPV4);
        assert_eq!(reply[4..8], [127, 0, 0, 1]);
        assert_eq!(reply[8..10], [0x1F, 0x90]); // 8080 in big-endian
        assert_eq!(len, 10);
    }

    #[test]
    fn test_build_reply_success_ipv6() {
        let addr = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
            443,
            0,
            0,
        ));
        let (buf, len) = build_reply(REP_SUCCEEDED, addr);
        let reply = &buf[..len];
        assert_eq!(reply[0], SOCKS5_VERSION);
        assert_eq!(reply[1], REP_SUCCEEDED);
        assert_eq!(reply[2], 0x00);
        assert_eq!(reply[3], ATYP_IPV6);
        assert_eq!(
            reply[4..20],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(reply[20..22], [0x01, 0xBB]); // 443 in big-endian
        assert_eq!(len, 22);
    }

    #[test]
    fn test_build_reply_failure() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));
        let (buf, len) = build_reply(REP_GENERAL_FAILURE, addr);
        let reply = &buf[..len];
        assert_eq!(reply[0], SOCKS5_VERSION);
        assert_eq!(reply[1], REP_GENERAL_FAILURE);
        assert_eq!(reply[2], 0x00);
    }

    #[test]
    fn test_build_reply_version_byte() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 80));
        let (buf, _len) = build_reply(REP_SUCCEEDED, addr);
        assert_eq!(buf[0], 0x05);
    }

    #[test]
    fn test_build_reply_port_big_endian() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080));
        let (buf, len) = build_reply(REP_SUCCEEDED, addr);
        let reply = &buf[..len];
        // 端口8080 = 0x1F90，应该编码为[0x1F, 0x90]
        assert_eq!(reply[reply.len() - 2], 0x1F);
        assert_eq!(reply[reply.len() - 1], 0x90);
    }
}
