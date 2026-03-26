use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::SocksError;
use super::protocol::{SOCKS5_VERSION, AUTH_NO_AUTH, AUTH_NO_ACCEPTABLE};

pub async fn perform_handshake(stream: &mut TcpStream) -> Result<(), SocksError> {
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;

    let version = buf[0];
    if version != SOCKS5_VERSION {
        return Err(SocksError::InvalidVersion(version));
    }

    let nmethods = buf[1] as usize;
    if nmethods == 0 {
        return Err(SocksError::NoAcceptableAuthMethod);
    }

    let mut methods = [0u8; 255];
    stream.read_exact(&mut methods[..nmethods]).await?;

    if !methods[..nmethods].contains(&AUTH_NO_AUTH) {
        stream.write_all(&[SOCKS5_VERSION, AUTH_NO_ACCEPTABLE]).await?;
        return Err(SocksError::NoAcceptableAuthMethod);
    }

    stream.write_all(&[SOCKS5_VERSION, AUTH_NO_AUTH]).await?;

    Ok(())
}
