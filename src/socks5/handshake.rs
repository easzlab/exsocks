use metrics::counter;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::protocol::{
    AUTH_FAILURE, AUTH_NO_ACCEPTABLE, AUTH_NO_AUTH, AUTH_SUCCESS, AUTH_USERNAME_PASSWORD,
    AUTH_VERSION, SOCKS5_VERSION,
};
use crate::auth::UserStore;
use crate::error::SocksError;
use crate::metrics_registry::AUTH_TOTAL;

/// 执行 SOCKS5 握手。
///
/// - 当 `user_store` 为 `Some` 时（认证模式）：
///   强制要求客户端使用用户名密码认证（METHOD 0x02），严格校验凭证
///
/// - 当 `user_store` 为 `None` 时（非认证模式）：
///   同时接受无认证（0x00）和用户名密码认证（0x02）
///   优先选择无认证方式（0x00），仅当客户端不支持 0x00 但支持 0x02 时才走子协商
///   走子协商时不校验凭证，直接返回成功
pub async fn perform_handshake(
    stream: &mut TcpStream,
    user_store: Option<&UserStore>,
) -> Result<(), SocksError> {
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
    let methods = &methods[..nmethods];

    let supports_no_auth = methods.contains(&AUTH_NO_AUTH);
    let supports_user_pass = methods.contains(&AUTH_USERNAME_PASSWORD);

    match user_store {
        Some(store) => {
            // 认证模式：强制要求用户名密码认证
            if supports_user_pass {
                stream
                    .write_all(&[SOCKS5_VERSION, AUTH_USERNAME_PASSWORD])
                    .await?;
                perform_username_password_auth(stream, Some(store)).await
            } else {
                stream
                    .write_all(&[SOCKS5_VERSION, AUTH_NO_ACCEPTABLE])
                    .await?;
                Err(SocksError::NoAcceptableAuthMethod)
            }
        }
        None => {
            // 非认证模式：同时接受 0x00 和 0x02，优先 0x00
            if supports_no_auth {
                stream
                    .write_all(&[SOCKS5_VERSION, AUTH_NO_AUTH])
                    .await?;
                Ok(())
            } else if supports_user_pass {
                stream
                    .write_all(&[SOCKS5_VERSION, AUTH_USERNAME_PASSWORD])
                    .await?;
                // 不校验凭证，直接通过
                perform_username_password_auth(stream, None).await
            } else {
                stream
                    .write_all(&[SOCKS5_VERSION, AUTH_NO_ACCEPTABLE])
                    .await?;
                Err(SocksError::NoAcceptableAuthMethod)
            }
        }
    }
}

/// RFC1929 用户名/密码认证子协商。
///
/// 协议格式：
/// ```text
/// 客户端 → 服务端: [VER(1), ULEN(1), UNAME(1..255), PLEN(1), PASSWD(1..255)]
/// 服务端 → 客户端: [VER(1), STATUS(1)]
/// ```
///
/// - 当 `user_store` 为 `Some` 时，使用 `user_store.verify()` 严格校验
/// - 当 `user_store` 为 `None` 时，跳过校验，直接返回成功
async fn perform_username_password_auth(
    stream: &mut TcpStream,
    user_store: Option<&UserStore>,
) -> Result<(), SocksError> {
    // 读取版本和用户名长度
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;

    let auth_version = buf[0];
    if auth_version != AUTH_VERSION {
        return Err(SocksError::InvalidAuthVersion(auth_version));
    }

    // RFC1929: ULEN 和 PLEN 均为 u8，最大 255 字节，使用栈上缓冲区避免堆分配
    let ulen = buf[1] as usize;
    let mut username_buf = [0u8; 255];
    stream.read_exact(&mut username_buf[..ulen]).await?;
    let username = String::from_utf8_lossy(&username_buf[..ulen]).to_string();

    // 读取密码长度和密码
    let mut plen_buf = [0u8; 1];
    stream.read_exact(&mut plen_buf).await?;
    let plen = plen_buf[0] as usize;
    let mut password_buf = [0u8; 255];
    stream.read_exact(&mut password_buf[..plen]).await?;
    let password = String::from_utf8_lossy(&password_buf[..plen]).to_string();

    // 校验凭证
    let authenticated = match user_store {
        Some(store) => store.verify(&username, &password),
        None => true, // 非认证模式，直接通过
    };

    if authenticated {
        // 仅在认证模式下记录 metrics，避免非认证模式的“跳过校验即通过”污染指标数据
        if user_store.is_some() {
            counter!(AUTH_TOTAL, "result" => "success").increment(1);
        }
        stream.write_all(&[AUTH_VERSION, AUTH_SUCCESS]).await?;
        Ok(())
    } else {
        counter!(AUTH_TOTAL, "result" => "failure").increment(1);
        stream.write_all(&[AUTH_VERSION, AUTH_FAILURE]).await?;
        Err(SocksError::AuthenticationFailed(username))
    }
}
