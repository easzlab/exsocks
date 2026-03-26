mod common;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use exsocks::socks5::handshake::perform_handshake;
use exsocks::socks5::protocol::*;

#[tokio::test]
async fn test_handshake_no_auth_success() {
    let (mut client, mut server) = common::create_tcp_pair().await;
    let request = common::build_handshake_request(&[AUTH_NO_AUTH]);
    
    let handle = tokio::spawn(async move {
        perform_handshake(&mut server).await
    });
    
    client.write_all(&request).await.unwrap();
    let mut response = [0u8; 2];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [SOCKS5_VERSION, AUTH_NO_AUTH]);
    
    handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn test_handshake_wrong_version() {
    let (mut client, mut server) = common::create_tcp_pair().await;
    // 发送 SOCKS4 版本
    let handle = tokio::spawn(async move {
        perform_handshake(&mut server).await
    });
    client.write_all(&[0x04, 0x01, 0x00]).await.unwrap();
    let result = handle.await.unwrap();
    assert!(result.is_err());
}

#[tokio::test]
async fn test_handshake_no_acceptable_method() {
    let (mut client, mut server) = common::create_tcp_pair().await;
    // 只提供用户名密码认证
    let request = common::build_handshake_request(&[0x02]);
    let handle = tokio::spawn(async move {
        perform_handshake(&mut server).await
    });
    client.write_all(&request).await.unwrap();
    let mut response = [0u8; 2];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [SOCKS5_VERSION, AUTH_NO_ACCEPTABLE]);
    let result = handle.await.unwrap();
    assert!(result.is_err());
}

#[tokio::test]
async fn test_handshake_multiple_methods() {
    let (mut client, mut server) = common::create_tcp_pair().await;
    let request = common::build_handshake_request(&[0x01, 0x02, AUTH_NO_AUTH]);
    let handle = tokio::spawn(async move {
        perform_handshake(&mut server).await
    });
    client.write_all(&request).await.unwrap();
    let mut response = [0u8; 2];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [SOCKS5_VERSION, AUTH_NO_AUTH]);
    handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn test_handshake_zero_methods() {
    let (mut client, mut server) = common::create_tcp_pair().await;
    let handle = tokio::spawn(async move {
        perform_handshake(&mut server).await
    });
    client.write_all(&[SOCKS5_VERSION, 0x00]).await.unwrap();
    let result = handle.await.unwrap();
    assert!(result.is_err());
}

#[tokio::test]
async fn test_handshake_client_disconnect() {
    let (mut client, mut server) = common::create_tcp_pair().await;
    let handle = tokio::spawn(async move {
        perform_handshake(&mut server).await
    });
    // 只发送 1 字节就断开
    client.write_all(&[SOCKS5_VERSION]).await.unwrap();
    drop(client);
    let result = handle.await.unwrap();
    assert!(result.is_err());
}
