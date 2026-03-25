#![allow(dead_code)]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::fmt;

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
    /// 转换为用于 TCP 连接的主机字符串（不含端口）
    pub fn to_host(&self) -> String {
        match self {
            Address::IPv4(addr) => addr.to_string(),
            Address::IPv6(addr) => addr.to_string(),
            Address::Domain(domain) => domain.clone(),
        }
    }
}

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
