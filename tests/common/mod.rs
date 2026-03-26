#![allow(dead_code)]

use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use exsocks::config::AppConfig;
use exsocks::socks5::protocol::*;

/// 创建一对已连接的 TCP 流（用于测试）
pub async fn create_tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    (client, server)
}

/// 构造 SOCKS5 握手请求字节
pub fn build_handshake_request(methods: &[u8]) -> Vec<u8> {
    let mut buf = vec![SOCKS5_VERSION, methods.len() as u8];
    buf.extend_from_slice(methods);
    buf
}

/// 构造 SOCKS5 CONNECT 请求字节
pub fn build_connect_request(addr: &Address, port: u16) -> Vec<u8> {
    let mut buf = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00];
    buf.extend_from_slice(&addr.to_bytes());
    buf.extend_from_slice(&port.to_be_bytes());
    buf
}

/// 启动一个简单的 TCP echo 服务器，返回监听地址
pub async fn start_echo_server() -> (tokio::task::JoinHandle<()>, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    (handle, addr)
}

/// 启动 exsocks 测试服务器，返回 (JoinHandle, 监听地址, CancellationToken)
/// 使用已绑定的 listener 避免端口竞态问题
pub async fn start_test_server(config: AppConfig) -> (tokio::task::JoinHandle<Result<(), exsocks::error::SocksError>>, SocketAddr, CancellationToken) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let token = CancellationToken::new();
    let token_clone = token.clone();
    
    let handle = tokio::spawn(async move {
        exsocks::server::run_with_listener(config, listener, Some(token_clone)).await
    });
    
    // 等待服务器启动
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (handle, addr, token)
}

/// 启动一个简单的可控制 echo 服务器，支持 CancellationToken
pub async fn start_echo_server_with_token() -> (tokio::task::JoinHandle<()>, SocketAddr, CancellationToken) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let token = CancellationToken::new();
    let token_clone = token.clone();
    
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                result = listener.accept() => {
                    if let Ok((mut stream, _)) = result {
                        let child_token = token_clone.child_token();
                        tokio::spawn(async move {
                            let mut buf = [0u8; 4096];
                            loop {
                                tokio::select! {
                                    result = stream.read(&mut buf) => {
                                        match result {
                                            Ok(0) | Err(_) => break,
                                            Ok(n) => {
                                                if stream.write_all(&buf[..n]).await.is_err() {
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    _ = child_token.cancelled() => break,
                                }
                            }
                        });
                    }
                }
                _ = token_clone.cancelled() => break,
            }
        }
    });
    (handle, addr, token)
}

/// 执行完整的 SOCKS5 握手 + CONNECT
pub async fn socks5_connect(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    
    // 握手
    let handshake = build_handshake_request(&[AUTH_NO_AUTH]);
    stream.write_all(&handshake).await.unwrap();
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [SOCKS5_VERSION, AUTH_NO_AUTH]);
    
    // CONNECT 请求
    let addr = match target {
        SocketAddr::V4(v4) => Address::IPv4(*v4.ip()),
        SocketAddr::V6(v6) => Address::IPv6(*v6.ip()),
    };
    let request = build_connect_request(&addr, target.port());
    stream.write_all(&request).await.unwrap();
    
    // 读取回复
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], SOCKS5_VERSION);
    assert_eq!(reply[1], REP_SUCCEEDED);
    
    stream
}

/// 执行 SOCKS5 握手 + CONNECT （使用域名）
pub async fn socks5_connect_domain(proxy: SocketAddr, domain: &str, port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    
    // 握手
    let handshake = build_handshake_request(&[AUTH_NO_AUTH]);
    stream.write_all(&handshake).await.unwrap();
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [SOCKS5_VERSION, AUTH_NO_AUTH]);
    
    // CONNECT 请求（域名）
    let addr = Address::Domain(domain.to_string());
    let request = build_connect_request(&addr, port);
    stream.write_all(&request).await.unwrap();
    
    // 读取回复（IPv4 回复 10 字节）
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], SOCKS5_VERSION);
    assert_eq!(reply[1], REP_SUCCEEDED);
    
    stream
}
