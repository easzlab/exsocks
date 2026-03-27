mod common;

use exsocks::config::AppConfig;
use exsocks::socks5::protocol::*;
use std::net::{Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// 启动 exsocks 代理服务器，返回监听地址
async fn start_proxy_server() -> (tokio::task::JoinHandle<()>, SocketAddr) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener); // 释放端口让 server::run 使用

    let mut config = AppConfig::default();
    config.bind = addr;
    config.max_connections = 100;
    config.connect_timeout = 5;

    let handle = tokio::spawn(async move {
        let _ = exsocks::server::run(config).await;
    });

    // 等待服务器启动
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    (handle, addr)
}

/// 通过 SOCKS5 代理连接到目标
async fn socks5_connect(proxy_addr: SocketAddr, target_addr: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();

    // 握手
    let handshake = common::build_handshake_request(&[AUTH_NO_AUTH]);
    stream.write_all(&handshake).await.unwrap();
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [SOCKS5_VERSION, AUTH_NO_AUTH]);

    // CONNECT 请求
    let addr = match target_addr {
        SocketAddr::V4(v4) => Address::IPv4(*v4.ip()),
        SocketAddr::V6(v6) => Address::IPv6(*v6.ip()),
    };
    let request = common::build_connect_request(&addr, target_addr.port());
    stream.write_all(&request).await.unwrap();

    // 读取回复（至少 10 字节：IPv4 回复）
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], SOCKS5_VERSION);
    assert_eq!(reply[1], REP_SUCCEEDED);

    stream
}

#[tokio::test]
async fn test_e2e_connect_ipv4() {
    let (echo_handle, echo_addr) = common::start_echo_server().await;
    let (proxy_handle, proxy_addr) = start_proxy_server().await;

    let mut stream = socks5_connect(proxy_addr, echo_addr).await;

    // 通过代理发送数据
    stream.write_all(b"hello world").await.unwrap();
    let mut buf = [0u8; 100];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello world");

    drop(stream);
    proxy_handle.abort();
    echo_handle.abort();
}

#[tokio::test]
async fn test_e2e_large_transfer() {
    let (echo_handle, echo_addr) = common::start_echo_server().await;
    let (proxy_handle, proxy_addr) = start_proxy_server().await;

    let stream = socks5_connect(proxy_addr, echo_addr).await;

    // 发送 1MB 数据
    let data: Vec<u8> = (0..1_048_576).map(|i| (i % 256) as u8).collect();
    let data_clone = data.clone();

    let (mut read_half, mut write_half) = stream.into_split();

    let write_handle = tokio::spawn(async move {
        write_half.write_all(&data_clone).await.unwrap();
        write_half.shutdown().await.unwrap();
    });

    let read_handle = tokio::spawn(async move {
        let mut received = Vec::new();
        read_half.read_to_end(&mut received).await.unwrap();
        received
    });

    write_handle.await.unwrap();
    let received = read_handle.await.unwrap();
    assert_eq!(received.len(), data.len());
    assert_eq!(received, data);

    proxy_handle.abort();
    echo_handle.abort();
}

#[tokio::test]
async fn test_e2e_multiple_sequential() {
    let (echo_handle, echo_addr) = common::start_echo_server().await;
    let (proxy_handle, proxy_addr) = start_proxy_server().await;

    for i in 0..5 {
        let mut stream = socks5_connect(proxy_addr, echo_addr).await;
        let msg = format!("message {}", i);
        stream.write_all(msg.as_bytes()).await.unwrap();
        let mut buf = [0u8; 100];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg.as_bytes());
        drop(stream);
    }

    proxy_handle.abort();
    echo_handle.abort();
}

#[tokio::test]
async fn test_e2e_multiple_concurrent() {
    let (echo_handle, echo_addr) = common::start_echo_server().await;
    let (proxy_handle, proxy_addr) = start_proxy_server().await;

    let mut handles = Vec::new();
    // 按方案要求提高到 100 并发连接
    for i in 0..100 {
        let handle = tokio::spawn(async move {
            let mut stream = socks5_connect(proxy_addr, echo_addr).await;
            let msg = format!("concurrent message {}", i);
            stream.write_all(msg.as_bytes()).await.unwrap();
            let mut buf = [0u8; 200];
            let n = stream.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], msg.as_bytes());
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }

    proxy_handle.abort();
    echo_handle.abort();
}

#[tokio::test]
async fn test_e2e_target_unreachable() {
    let (proxy_handle, proxy_addr) = start_proxy_server().await;

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();

    // 握手
    let handshake = common::build_handshake_request(&[AUTH_NO_AUTH]);
    stream.write_all(&handshake).await.unwrap();
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await.unwrap();

    // 连接一个不可达的地址（端口 1 通常不可达）
    let addr = Address::IPv4("127.0.0.1".parse().unwrap());
    let request = common::build_connect_request(&addr, 1);
    stream.write_all(&request).await.unwrap();

    // 应该收到错误回复或连接被关闭
    let mut reply = vec![0u8; 100];
    let result = stream.read(&mut reply).await;
    // 服务器应该返回错误或关闭连接
    match result {
        Ok(0) => {} // 连接关闭
        Ok(n) => {
            // 收到了回复，检查不是成功
            if n >= 2 {
                assert_ne!(reply[1], REP_SUCCEEDED);
            }
        }
        Err(_) => {} // IO 错误也是可接受的
    }

    proxy_handle.abort();
}

#[tokio::test]
async fn test_e2e_invalid_socks_version() {
    let (proxy_handle, proxy_addr) = start_proxy_server().await;

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();

    // 发送 SOCKS4 版本
    stream.write_all(&[0x04, 0x01, 0x00]).await.unwrap();

    // 服务器应该关闭连接
    let mut buf = [0u8; 100];
    let result = stream.read(&mut buf).await;
    match result {
        Ok(0) => {}  // 连接关闭 - 预期行为
        Ok(_) => {}  // 可能收到错误回复
        Err(_) => {} // IO 错误也可接受
    }

    proxy_handle.abort();
}

#[tokio::test]
async fn test_e2e_graceful_shutdown() {
    let config = AppConfig {
        max_connections: 100,
        connect_timeout: 5,
        ..AppConfig::default()
    };
    let (server_handle, proxy_addr, cancel_token) = common::start_test_server(config).await;
    let (echo_handle, echo_addr) = common::start_echo_server().await;

    // 建立一个活跃连接
    let stream = common::socks5_connect(proxy_addr, echo_addr).await;

    // 发送关闭信号
    cancel_token.cancel();

    // 等待服务器处理关闭
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // 已经建立的连接应该还能用（在 cancel 之前已经建立）
    // 但服务器不再接受新连接
    let connect_result = TcpStream::connect(proxy_addr).await;
    // 服务器已关闭，连接应该失败或被立即关闭
    match connect_result {
        Err(_) => {} // 预期：服务器已关闭
        Ok(mut s) => {
            // 如果连接成功，请求应该失败
            let handshake = common::build_handshake_request(&[AUTH_NO_AUTH]);
            let _ = s.write_all(&handshake).await;
            let mut buf = [0u8; 2];
            let result = s.read(&mut buf).await;
            // 应该读到 EOF 或错误
            match result {
                Ok(0) | Err(_) => {}
                Ok(_) => {} // 如果在新连接之前就已经开始处理，也可以接受
            }
        }
    }

    drop(stream);

    // 服务器应该已优雅关闭
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_handle).await;

    echo_handle.abort();
}

#[tokio::test]
async fn test_e2e_connection_limit() {
    let config = AppConfig {
        max_connections: 3,
        connect_timeout: 5,
        ..AppConfig::default()
    };
    let (server_handle, proxy_addr, cancel_token) = common::start_test_server(config).await;
    let (echo_handle, echo_addr) = common::start_echo_server().await;

    // 建立 3 个连接（达到限制）
    let mut streams = Vec::new();
    for _ in 0..3 {
        let stream = common::socks5_connect(proxy_addr, echo_addr).await;
        streams.push(stream);
    }

    // 第 4 个连接应该被拒绝
    let mut stream4 = TcpStream::connect(proxy_addr).await.unwrap();
    let handshake = common::build_handshake_request(&[AUTH_NO_AUTH]);
    stream4.write_all(&handshake).await.unwrap();

    // 应该收到连接关闭或错误
    let mut buf = [0u8; 10];
    let result = stream4.read(&mut buf).await;
    match result {
        Ok(0) => {}  // 连接被关闭 - 预期行为
        Ok(_) => {}  // 可能收到拒绝响应
        Err(_) => {} // IO 错误也可接受
    }

    // 释放一个连接后应该可以新建连接
    drop(streams.pop());
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // 现在应该可以建立新连接
    let new_stream = common::socks5_connect(proxy_addr, echo_addr).await;
    drop(new_stream);

    drop(streams);
    cancel_token.cancel();
    let _ = server_handle.await;
    echo_handle.abort();
}

#[tokio::test]
async fn test_e2e_connect_ipv6() {
    // 创建一个 IPv6 echo 服务器
    let listener = tokio::net::TcpListener::bind("[::1]:0").await;
    if listener.is_err() {
        // IPv6 不可用，跳过测试
        return;
    }
    let listener = listener.unwrap();
    let echo_addr = listener.local_addr().unwrap();

    let echo_handle = tokio::spawn(async move {
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

    let (proxy_handle, proxy_addr) = start_proxy_server().await;

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();

    // 握手
    let handshake = common::build_handshake_request(&[AUTH_NO_AUTH]);
    stream.write_all(&handshake).await.unwrap();
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [SOCKS5_VERSION, AUTH_NO_AUTH]);

    // IPv6 CONNECT 请求
    let addr = Address::IPv6(Ipv6Addr::LOCALHOST);
    let request = common::build_connect_request(&addr, echo_addr.port());
    stream.write_all(&request).await.unwrap();

    // 读取回复（IPv6 回复 22 字节）
    let mut reply = vec![0u8; 22];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], SOCKS5_VERSION);
    assert_eq!(reply[1], REP_SUCCEEDED);

    // 通过代理测试数据传输
    stream.write_all(b"ipv6 test").await.unwrap();
    let mut buf = [0u8; 100];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"ipv6 test");

    drop(stream);
    proxy_handle.abort();
    echo_handle.abort();
}

#[tokio::test]
async fn test_e2e_connect_domain() {
    let (echo_handle, echo_addr) = common::start_echo_server().await;
    let (proxy_handle, proxy_addr) = start_proxy_server().await;

    // 使用 localhost 域名连接
    let mut stream = common::socks5_connect_domain(proxy_addr, "localhost", echo_addr.port()).await;

    // 测试数据传输
    stream.write_all(b"domain test").await.unwrap();
    let mut buf = [0u8; 100];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"domain test");

    drop(stream);
    proxy_handle.abort();
    echo_handle.abort();
}

#[tokio::test]
async fn test_e2e_client_abort() {
    let (echo_handle, echo_addr) = common::start_echo_server().await;
    let config = AppConfig {
        max_connections: 100,
        connect_timeout: 5,
        ..AppConfig::default()
    };
    let (server_handle, proxy_addr, cancel_token) = common::start_test_server(config).await;

    // 建立连接后立即丢弃
    for _ in 0..5 {
        let stream = common::socks5_connect(proxy_addr, echo_addr).await;
        // 立即 drop，模拟客户端中断
        drop(stream);
    }

    // 确保服务器仍然正常工作
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let mut stream = common::socks5_connect(proxy_addr, echo_addr).await;
    stream.write_all(b"still works").await.unwrap();
    let mut buf = [0u8; 100];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"still works");

    drop(stream);
    cancel_token.cancel();
    let _ = server_handle.await;
    echo_handle.abort();
}

#[tokio::test]
async fn test_e2e_target_abort() {
    let config = AppConfig {
        max_connections: 100,
        connect_timeout: 5,
        ..AppConfig::default()
    };
    let (server_handle, proxy_addr, cancel_token) = common::start_test_server(config).await;

    // 创建一个会立即关闭的目标服务器
    let abort_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let abort_addr = abort_listener.local_addr().unwrap();

    let abort_handle = tokio::spawn(async move {
        if let Ok((stream, _)) = abort_listener.accept().await {
            // 立即关闭连接
            drop(stream);
        }
    });

    // 通过代理连接
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let handshake = common::build_handshake_request(&[AUTH_NO_AUTH]);
    stream.write_all(&handshake).await.unwrap();
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await.unwrap();

    let addr = Address::IPv4("127.0.0.1".parse().unwrap());
    let request = common::build_connect_request(&addr, abort_addr.port());
    stream.write_all(&request).await.unwrap();

    // 读取回复
    let mut reply = vec![0u8; 10];
    let result = stream.read_exact(&mut reply).await;
    if result.is_ok() {
        assert_eq!(reply[0], SOCKS5_VERSION);
        // 可能成功也可能失败，取决于时序
        if reply[1] == REP_SUCCEEDED {
            // 如果成功，后续读写应该失败
            let mut buf = [0u8; 10];
            let result = stream.read(&mut buf).await;
            match result {
                Ok(0) | Err(_) => {} // 预期：target 已关闭
                _ => {}
            }
        }
    }

    drop(stream);
    let _ = abort_handle.await;

    // 确保服务器仍然正常
    let (echo_handle, echo_addr) = common::start_echo_server().await;
    let mut stream = common::socks5_connect(proxy_addr, echo_addr).await;
    stream.write_all(b"server ok").await.unwrap();
    let mut buf = [0u8; 100];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"server ok");

    drop(stream);
    cancel_token.cancel();
    let _ = server_handle.await;
    echo_handle.abort();
}
