mod common;

use std::io::Write;
use std::sync::Arc;

use exsocks::auth::UserStore;
use exsocks::socks5::handshake::perform_handshake;
use exsocks::socks5::protocol::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ========== 辅助函数 ==========

/// 构造 RFC1929 用户名/密码认证子协商请求
fn build_auth_request(username: &str, password: &str) -> Vec<u8> {
    let mut buf = vec![AUTH_VERSION, username.len() as u8];
    buf.extend_from_slice(username.as_bytes());
    buf.push(password.len() as u8);
    buf.extend_from_slice(password.as_bytes());
    buf
}

/// 创建一个包含测试用户的临时 UserStore
fn create_test_user_store() -> Arc<UserStore> {
    let mut temp_file = tempfile::Builder::new()
        .suffix(".yaml")
        .tempfile()
        .unwrap();
    write!(
        temp_file,
        r#"users:
  - username: "admin"
    password: "admin123"
  - username: "user1"
    password: "pass1"
"#
    )
    .unwrap();
    Arc::new(UserStore::load_from_file(temp_file.path()).unwrap())
}

// ========== 非认证模式测试（user_store = None） ==========

#[tokio::test]
async fn test_no_auth_mode_client_supports_no_auth() {
    let (mut client, mut server) = common::create_tcp_pair().await;
    let request = common::build_handshake_request(&[AUTH_NO_AUTH]);

    let handle = tokio::spawn(async move { perform_handshake(&mut server, None).await });

    client.write_all(&request).await.unwrap();
    let mut response = [0u8; 2];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [SOCKS5_VERSION, AUTH_NO_AUTH]);

    handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn test_no_auth_mode_client_supports_both_prefers_no_auth() {
    let (mut client, mut server) = common::create_tcp_pair().await;
    // 客户端同时支持 0x00 和 0x02，服务端应优先选择 0x00
    let request = common::build_handshake_request(&[AUTH_USERNAME_PASSWORD, AUTH_NO_AUTH]);

    let handle = tokio::spawn(async move { perform_handshake(&mut server, None).await });

    client.write_all(&request).await.unwrap();
    let mut response = [0u8; 2];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [SOCKS5_VERSION, AUTH_NO_AUTH]);

    handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn test_no_auth_mode_client_only_supports_user_pass() {
    let (mut client, mut server) = common::create_tcp_pair().await;
    // 客户端仅支持 0x02，服务端应接受并走子协商但不校验
    let request = common::build_handshake_request(&[AUTH_USERNAME_PASSWORD]);

    let handle = tokio::spawn(async move { perform_handshake(&mut server, None).await });

    client.write_all(&request).await.unwrap();
    let mut response = [0u8; 2];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [SOCKS5_VERSION, AUTH_USERNAME_PASSWORD]);

    // 发送任意用户名密码，应直接通过
    let auth_req = build_auth_request("anyuser", "anypass");
    client.write_all(&auth_req).await.unwrap();
    let mut auth_response = [0u8; 2];
    client.read_exact(&mut auth_response).await.unwrap();
    assert_eq!(auth_response, [AUTH_VERSION, AUTH_SUCCESS]);

    handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn test_no_auth_mode_client_no_supported_method() {
    let (mut client, mut server) = common::create_tcp_pair().await;
    // 客户端既不支持 0x00 也不支持 0x02
    let request = common::build_handshake_request(&[0x03, 0x04]);

    let handle = tokio::spawn(async move { perform_handshake(&mut server, None).await });

    client.write_all(&request).await.unwrap();
    let mut response = [0u8; 2];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [SOCKS5_VERSION, AUTH_NO_ACCEPTABLE]);

    let result = handle.await.unwrap();
    assert!(result.is_err());
}

// ========== 认证模式测试（user_store = Some） ==========

#[tokio::test]
async fn test_auth_mode_correct_credentials() {
    let (mut client, mut server) = common::create_tcp_pair().await;
    let store = create_test_user_store();
    let request = common::build_handshake_request(&[AUTH_USERNAME_PASSWORD]);

    let handle = tokio::spawn(async move {
        perform_handshake(&mut server, Some(store.as_ref())).await
    });

    client.write_all(&request).await.unwrap();
    let mut response = [0u8; 2];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [SOCKS5_VERSION, AUTH_USERNAME_PASSWORD]);

    // 发送正确的用户名密码
    let auth_req = build_auth_request("admin", "admin123");
    client.write_all(&auth_req).await.unwrap();
    let mut auth_response = [0u8; 2];
    client.read_exact(&mut auth_response).await.unwrap();
    assert_eq!(auth_response, [AUTH_VERSION, AUTH_SUCCESS]);

    handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn test_auth_mode_wrong_password() {
    let (mut client, mut server) = common::create_tcp_pair().await;
    let store = create_test_user_store();
    let request = common::build_handshake_request(&[AUTH_USERNAME_PASSWORD]);

    let handle = tokio::spawn(async move {
        perform_handshake(&mut server, Some(store.as_ref())).await
    });

    client.write_all(&request).await.unwrap();
    let mut response = [0u8; 2];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [SOCKS5_VERSION, AUTH_USERNAME_PASSWORD]);

    // 发送错误密码
    let auth_req = build_auth_request("admin", "wrongpass");
    client.write_all(&auth_req).await.unwrap();
    let mut auth_response = [0u8; 2];
    client.read_exact(&mut auth_response).await.unwrap();
    assert_eq!(auth_response, [AUTH_VERSION, AUTH_FAILURE]);

    let result = handle.await.unwrap();
    assert!(result.is_err());
}

#[tokio::test]
async fn test_auth_mode_unknown_user() {
    let (mut client, mut server) = common::create_tcp_pair().await;
    let store = create_test_user_store();
    let request = common::build_handshake_request(&[AUTH_USERNAME_PASSWORD]);

    let handle = tokio::spawn(async move {
        perform_handshake(&mut server, Some(store.as_ref())).await
    });

    client.write_all(&request).await.unwrap();
    let mut response = [0u8; 2];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [SOCKS5_VERSION, AUTH_USERNAME_PASSWORD]);

    // 发送不存在的用户
    let auth_req = build_auth_request("nonexistent", "somepass");
    client.write_all(&auth_req).await.unwrap();
    let mut auth_response = [0u8; 2];
    client.read_exact(&mut auth_response).await.unwrap();
    assert_eq!(auth_response, [AUTH_VERSION, AUTH_FAILURE]);

    let result = handle.await.unwrap();
    assert!(result.is_err());
}

#[tokio::test]
async fn test_auth_mode_client_only_supports_no_auth() {
    let (mut client, mut server) = common::create_tcp_pair().await;
    let store = create_test_user_store();
    // 客户端仅支持 0x00，认证模式下应被拒绝
    let request = common::build_handshake_request(&[AUTH_NO_AUTH]);

    let handle = tokio::spawn(async move {
        perform_handshake(&mut server, Some(store.as_ref())).await
    });

    client.write_all(&request).await.unwrap();
    let mut response = [0u8; 2];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [SOCKS5_VERSION, AUTH_NO_ACCEPTABLE]);

    let result = handle.await.unwrap();
    assert!(result.is_err());
}

#[tokio::test]
async fn test_auth_mode_client_supports_both_selects_user_pass() {
    let (mut client, mut server) = common::create_tcp_pair().await;
    let store = create_test_user_store();
    // 客户端同时支持 0x00 和 0x02，认证模式下应选择 0x02
    let request = common::build_handshake_request(&[AUTH_NO_AUTH, AUTH_USERNAME_PASSWORD]);

    let handle = tokio::spawn(async move {
        perform_handshake(&mut server, Some(store.as_ref())).await
    });

    client.write_all(&request).await.unwrap();
    let mut response = [0u8; 2];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [SOCKS5_VERSION, AUTH_USERNAME_PASSWORD]);

    // 发送正确凭证
    let auth_req = build_auth_request("user1", "pass1");
    client.write_all(&auth_req).await.unwrap();
    let mut auth_response = [0u8; 2];
    client.read_exact(&mut auth_response).await.unwrap();
    assert_eq!(auth_response, [AUTH_VERSION, AUTH_SUCCESS]);

    handle.await.unwrap().unwrap();
}

// ========== 通用错误测试 ==========

#[tokio::test]
async fn test_handshake_wrong_version() {
    let (mut client, mut server) = common::create_tcp_pair().await;
    // 发送 SOCKS4 版本
    let handle = tokio::spawn(async move { perform_handshake(&mut server, None).await });
    client.write_all(&[0x04, 0x01, 0x00]).await.unwrap();
    let result = handle.await.unwrap();
    assert!(result.is_err());
}

#[tokio::test]
async fn test_handshake_zero_methods() {
    let (mut client, mut server) = common::create_tcp_pair().await;
    let handle = tokio::spawn(async move { perform_handshake(&mut server, None).await });
    client.write_all(&[SOCKS5_VERSION, 0x00]).await.unwrap();
    let result = handle.await.unwrap();
    assert!(result.is_err());
}

#[tokio::test]
async fn test_handshake_client_disconnect() {
    let (mut client, mut server) = common::create_tcp_pair().await;
    let handle = tokio::spawn(async move { perform_handshake(&mut server, None).await });
    // 只发送 1 字节就断开
    client.write_all(&[SOCKS5_VERSION]).await.unwrap();
    drop(client);
    let result = handle.await.unwrap();
    assert!(result.is_err());
}

#[tokio::test]
async fn test_auth_mode_invalid_auth_version() {
    let (mut client, mut server) = common::create_tcp_pair().await;
    let store = create_test_user_store();
    let request = common::build_handshake_request(&[AUTH_USERNAME_PASSWORD]);

    let handle = tokio::spawn(async move {
        perform_handshake(&mut server, Some(store.as_ref())).await
    });

    client.write_all(&request).await.unwrap();
    let mut response = [0u8; 2];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [SOCKS5_VERSION, AUTH_USERNAME_PASSWORD]);

    // 发送错误的认证版本号
    let mut auth_req = build_auth_request("admin", "admin123");
    auth_req[0] = 0x02; // 错误版本
    client.write_all(&auth_req).await.unwrap();

    let result = handle.await.unwrap();
    assert!(result.is_err());
}
