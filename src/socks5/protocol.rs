#![allow(dead_code)]

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::net::TcpStream;

use crate::error::SocksError;

pub const SOCKS5_VERSION: u8 = 0x05;

pub const AUTH_NO_AUTH: u8 = 0x00;
pub const AUTH_NO_ACCEPTABLE: u8 = 0xFF;

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

pub const REP_SUCCEEDED: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_CONNECTION_NOT_ALLOWED: u8 = 0x02;
pub const REP_NETWORK_UNREACHABLE: u8 = 0x03;
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
pub const REP_CONNECTION_REFUSED: u8 = 0x05;
pub const REP_TTL_EXPIRED: u8 = 0x06;
pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

#[derive(Debug, Clone, PartialEq)]
pub enum Address {
    IPv4(Ipv4Addr),
    IPv6(Ipv6Addr),
    Domain(String),
}

impl Address {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Address::IPv4(addr) => {
                let mut buf = vec![ATYP_IPV4];
                buf.extend_from_slice(&addr.octets());
                buf
            }
            Address::IPv6(addr) => {
                let mut buf = vec![ATYP_IPV6];
                buf.extend_from_slice(&addr.octets());
                buf
            }
            Address::Domain(domain) => {
                let mut buf = vec![ATYP_DOMAIN];
                buf.push(domain.len() as u8);
                buf.extend_from_slice(domain.as_bytes());
                buf
            }
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::IPv4(addr) => write!(f, "{}", addr),
            Address::IPv6(addr) => write!(f, "[{}]", addr),
            Address::Domain(domain) => write!(f, "{}", domain),
        }
    }
}

impl Address {
    /// 直接建立 TCP 连接，避免 IPv4/IPv6 地址经过 format → parse 的不必要堆分配。
    pub async fn connect(&self, port: u16) -> Result<TcpStream, SocksError> {
        match self {
            Address::IPv4(addr) => {
                let sock_addr = SocketAddr::new(IpAddr::V4(*addr), port);
                Ok(TcpStream::connect(sock_addr).await?)
            }
            Address::IPv6(addr) => {
                let sock_addr = SocketAddr::new(IpAddr::V6(*addr), port);
                Ok(TcpStream::connect(sock_addr).await?)
            }
            Address::Domain(domain) => Ok(TcpStream::connect((domain.as_str(), port)).await?),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_ipv4_to_bytes() {
        let addr = Address::IPv4(Ipv4Addr::new(192, 168, 1, 1));
        let bytes = addr.to_bytes();
        assert_eq!(bytes, vec![ATYP_IPV4, 192, 168, 1, 1]);
    }

    #[test]
    fn test_address_ipv6_to_bytes() {
        let addr = Address::IPv6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        let bytes = addr.to_bytes();
        assert_eq!(
            bytes,
            vec![ATYP_IPV6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
    }

    #[test]
    fn test_address_domain_to_bytes() {
        let addr = Address::Domain(String::from("example.com"));
        let bytes = addr.to_bytes();
        assert_eq!(
            bytes,
            vec![
                ATYP_DOMAIN,
                11,
                b'e',
                b'x',
                b'a',
                b'm',
                b'p',
                b'l',
                b'e',
                b'.',
                b'c',
                b'o',
                b'm'
            ]
        );
    }

    #[test]
    fn test_address_display_ipv4() {
        let addr = Address::IPv4(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(format!("{}", addr), "1.2.3.4");
    }

    #[test]
    fn test_address_display_ipv6() {
        let addr = Address::IPv6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(format!("{}", addr), "[::1]");
    }

    #[test]
    fn test_address_display_domain() {
        let addr = Address::Domain(String::from("example.com"));
        assert_eq!(format!("{}", addr), "example.com");
    }

    #[test]
    fn test_address_domain_max_length() {
        // 域名长度为255字节（包括长度字节），这是SOCKS5协议的最大限制
        let domain = "a".repeat(255);
        let addr = Address::Domain(domain);
        let bytes = addr.to_bytes();
        // 长度字节应该为255
        assert_eq!(bytes[1], 255);
        // 总长度为1(ATYP) + 1(len) + 255(domain) = 257
        assert_eq!(bytes.len(), 257);
    }
}
