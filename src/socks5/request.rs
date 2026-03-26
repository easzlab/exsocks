use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::SocksError;
use super::protocol::{
    SOCKS5_VERSION, CMD_CONNECT, ATYP_IPV4, ATYP_DOMAIN, ATYP_IPV6,
    REP_COMMAND_NOT_SUPPORTED, REP_ADDRESS_TYPE_NOT_SUPPORTED,
};
use super::reply::build_reply;
use super::protocol::Address;

pub struct ConnectRequest {
    pub address: Address,
    pub port: u16,
}

pub async fn parse_request(stream: &mut TcpStream) -> Result<ConnectRequest, SocksError> {
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await?;

    let version = buf[0];
    if version != SOCKS5_VERSION {
        return Err(SocksError::InvalidVersion(version));
    }

    let cmd = buf[1];
    if cmd != CMD_CONNECT {
        send_error_reply(stream, REP_COMMAND_NOT_SUPPORTED).await?;
        return Err(SocksError::UnsupportedCommand(cmd));
    }

    let atyp = buf[3];
    let address = match atyp {
        ATYP_IPV4 => {
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await?;
            Address::IPv4(Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]))
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;
            let mut domain_buf = vec![0u8; len];
            stream.read_exact(&mut domain_buf).await?;
            Address::Domain(String::from_utf8(domain_buf)
                .map_err(|e| SocksError::InvalidAddress(
                    format!("Invalid domain encoding: {}", e)
                ))?)
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 16];
            stream.read_exact(&mut buf).await?;
            let addr = Ipv6Addr::new(
                u16::from_be_bytes([buf[0], buf[1]]),
                u16::from_be_bytes([buf[2], buf[3]]),
                u16::from_be_bytes([buf[4], buf[5]]),
                u16::from_be_bytes([buf[6], buf[7]]),
                u16::from_be_bytes([buf[8], buf[9]]),
                u16::from_be_bytes([buf[10], buf[11]]),
                u16::from_be_bytes([buf[12], buf[13]]),
                u16::from_be_bytes([buf[14], buf[15]]),
            );
            Address::IPv6(addr)
        }
        _ => {
            send_error_reply(stream, REP_ADDRESS_TYPE_NOT_SUPPORTED).await?;
            return Err(SocksError::UnsupportedAddressType(atyp));
        }
    };

    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes([port_buf[0], port_buf[1]]);

    Ok(ConnectRequest { address, port })
}

async fn send_error_reply(stream: &mut TcpStream, rep: u8) -> Result<(), SocksError> {
    let dummy_addr = std::net::SocketAddr::from(([0, 0, 0, 0], 0));
    let reply = build_reply(rep, dummy_addr);
    stream.write_all(&reply).await?;
    Ok(())
}
