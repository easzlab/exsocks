use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::protocol::Address;
use super::protocol::{
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, CMD_CONNECT, REP_ADDRESS_TYPE_NOT_SUPPORTED,
    REP_COMMAND_NOT_SUPPORTED, SOCKS5_VERSION,
};
use super::reply::build_reply;
use crate::error::SocksError;

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
            let mut domain_buf = [0u8; 255];
            stream.read_exact(&mut domain_buf[..len]).await?;
            let domain = std::str::from_utf8(&domain_buf[..len])
                .map_err(|e| {
                    SocksError::InvalidAddress(format!("Invalid domain encoding: {}", e))
                })?
                .to_owned();
            Address::Domain(domain)
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
    let (buf, len) = build_reply(rep, dummy_addr);
    stream.write_all(&buf[..len]).await?;
    Ok(())
}
