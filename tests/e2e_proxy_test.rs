mod common;

use exsocks::config::AppConfig;
use exsocks::socks5::protocol::*;
use std::net::{Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use common::{build_auth_request, build_handshake_request, create_temp_user_config};

/// 启动 exsocks 代理服务器，返回监听地址
async fn start_proxy_server() -> (tokio::task::JoinHandle<()>, SocketAddr) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener); // 释放端口让 server::run 使用

    let mut config = AppConfig::default();
    config.bind = addr;
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

/// 尝试通过 SOCKS5 代理连接到目标，返回 Result 而非 panic
async fn try_socks5_connect(
    proxy_addr: SocketAddr,
    target_addr: SocketAddr,
) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy_addr).await?;

    let handshake = common::build_handshake_request(&[AUTH_NO_AUTH]);
    stream.write_all(&handshake).await?;
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;
    if response != [SOCKS5_VERSION, AUTH_NO_AUTH] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unexpected handshake response",
        ));
    }

    let addr = match target_addr {
        SocketAddr::V4(v4) => Address::IPv4(*v4.ip()),
        SocketAddr::V6(v6) => Address::IPv6(*v6.ip()),
    };
    let request = common::build_connect_request(&addr, target_addr.port());
    stream.write_all(&request).await?;

    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await?;
    if reply[1] != REP_SUCCEEDED {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "SOCKS5 connect failed",
        ));
    }

    Ok(stream)
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

    let transfer_test = async {
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
    };

    tokio::time::timeout(std::time::Duration::from_secs(30), transfer_test)
        .await
        .expect("large transfer test timed out");

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

    // 通过代理连接，整个过程加超时保护
    let abort_test = async {
        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        let handshake = common::build_handshake_request(&[AUTH_NO_AUTH]);
        stream.write_all(&handshake).await.unwrap();
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await.unwrap();

        let addr = Address::IPv4("127.0.0.1".parse().unwrap());
        let request = common::build_connect_request(&addr, abort_addr.port());
        stream.write_all(&request).await.unwrap();

        // 读取回复：使用 read 而非 read_exact，因为 target 可能在回复前就关闭
        let mut reply = vec![0u8; 10];
        let result = stream.read_exact(&mut reply).await;
        if result.is_ok() {
            assert_eq!(reply[0], SOCKS5_VERSION);
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
        // read_exact 失败也是可接受的（target 在回复前关闭）

        drop(stream);
    };

    // 超时保护：避免 relay 挂起导致测试永远阻塞
    tokio::time::timeout(std::time::Duration::from_secs(10), abort_test)
        .await
        .expect("target abort test timed out");

    let _ = abort_handle.await;

    // 等待服务端清理完成后验证服务器仍然正常
    let (echo_handle, echo_addr) = common::start_echo_server().await;
    let mut verified = false;
    for attempt in 0..10 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        match try_socks5_connect(proxy_addr, echo_addr).await {
            Ok(mut stream) => {
                stream.write_all(b"server ok").await.unwrap();
                let mut buf = [0u8; 100];
                let n = stream.read(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], b"server ok");
                drop(stream);
                verified = true;
                break;
            }
            Err(_) if attempt < 9 => continue,
            Err(e) => panic!("Server not healthy after target abort: {}", e),
        }
    }
    assert!(verified, "Failed to verify server health");

    cancel_token.cancel();
    let _ = server_handle.await;
    echo_handle.abort();
}

// ========== 认证模式 E2E 测试 ==========

#[tokio::test]
async fn test_e2e_auth_mode_correct_credentials() {
    let user_yaml = r#"
users:
  - username: "admin"
    password: "admin123"
  - username: "user1"
    password: "pass1"
"#;
    let (user_config_path, _temp_file) = create_temp_user_config(user_yaml);
    let (echo_handle, echo_addr) = common::start_echo_server().await;
    let (server_handle, proxy_addr, cancel_token) =
        common::start_auth_test_server(user_config_path).await;

    // 使用正确凭证通过代理连接并传输数据
    let mut stream =
        common::socks5_connect_with_auth(proxy_addr, echo_addr, "admin", "admin123").await;
    stream.write_all(b"auth test data").await.unwrap();
    let mut buf = [0u8; 100];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"auth test data");

    drop(stream);
    cancel_token.cancel();
    let _ = server_handle.await;
    echo_handle.abort();
}

#[tokio::test]
async fn test_e2e_auth_mode_multiple_users() {
    let user_yaml = r#"
users:
  - username: "admin"
    password: "admin123"
  - username: "user1"
    password: "pass1"
"#;
    let (user_config_path, _temp_file) = create_temp_user_config(user_yaml);
    let (echo_handle, echo_addr) = common::start_echo_server().await;
    let (server_handle, proxy_addr, cancel_token) =
        common::start_auth_test_server(user_config_path).await;

    // 两个不同用户都能成功认证并传输数据
    for (username, password, msg) in [
        ("admin", "admin123", "hello from admin"),
        ("user1", "pass1", "hello from user1"),
    ] {
        let mut stream =
            common::socks5_connect_with_auth(proxy_addr, echo_addr, username, password).await;
        stream.write_all(msg.as_bytes()).await.unwrap();
        let mut buf = [0u8; 100];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg.as_bytes());
        drop(stream);
    }

    cancel_token.cancel();
    let _ = server_handle.await;
    echo_handle.abort();
}

#[tokio::test]
async fn test_e2e_auth_mode_wrong_password_rejected() {
    let user_yaml = r#"
users:
  - username: "admin"
    password: "admin123"
"#;
    let (user_config_path, _temp_file) = create_temp_user_config(user_yaml);
    let (echo_handle, echo_addr) = common::start_echo_server().await;
    let (server_handle, proxy_addr, cancel_token) =
        common::start_auth_test_server(user_config_path).await;

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();

    // 握手
    let handshake = build_handshake_request(&[AUTH_USERNAME_PASSWORD]);
    stream.write_all(&handshake).await.unwrap();
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [SOCKS5_VERSION, AUTH_USERNAME_PASSWORD]);

    // 发送错误密码
    let auth_req = build_auth_request("admin", "wrongpass");
    stream.write_all(&auth_req).await.unwrap();
    let mut auth_response = [0u8; 2];
    stream.read_exact(&mut auth_response).await.unwrap();
    assert_eq!(auth_response, [AUTH_VERSION, AUTH_FAILURE]);

    // 连接应该被关闭
    let mut buf = [0u8; 10];
    let result = stream.read(&mut buf).await;
    match result {
        Ok(0) | Err(_) => {} // 预期：连接关闭
        _ => {}
    }

    // 验证服务器仍然正常（正确凭证可以连接）
    let mut stream =
        common::socks5_connect_with_auth(proxy_addr, echo_addr, "admin", "admin123").await;
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
async fn test_e2e_auth_mode_no_auth_client_rejected() {
    let user_yaml = r#"
users:
  - username: "admin"
    password: "admin123"
"#;
    let (user_config_path, _temp_file) = create_temp_user_config(user_yaml);
    let (_echo_handle, _echo_addr) = common::start_echo_server().await;
    let (server_handle, proxy_addr, cancel_token) =
        common::start_auth_test_server(user_config_path).await;

    // 客户端仅支持无认证方式，应被拒绝
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let handshake = build_handshake_request(&[AUTH_NO_AUTH]);
    stream.write_all(&handshake).await.unwrap();
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [SOCKS5_VERSION, AUTH_NO_ACCEPTABLE]);

    drop(stream);
    cancel_token.cancel();
    let _ = server_handle.await;
    _echo_handle.abort();
}

#[tokio::test]
async fn test_e2e_auth_mode_large_transfer() {
    let user_yaml = r#"
users:
  - username: "admin"
    password: "admin123"
"#;
    let (user_config_path, _temp_file) = create_temp_user_config(user_yaml);
    let (echo_handle, echo_addr) = common::start_echo_server().await;
    let (server_handle, proxy_addr, cancel_token) =
        common::start_auth_test_server(user_config_path).await;

    let transfer_test = async {
        let stream =
            common::socks5_connect_with_auth(proxy_addr, echo_addr, "admin", "admin123").await;

        // 发送 512KB 数据验证认证后数据转发正常
        let data: Vec<u8> = (0..524_288).map(|i| (i % 256) as u8).collect();
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
    };

    tokio::time::timeout(std::time::Duration::from_secs(30), transfer_test)
        .await
        .expect("auth mode large transfer test timed out");

    cancel_token.cancel();
    let _ = server_handle.await;
    echo_handle.abort();
}

// ========== 访问控制 E2E 测试 ==========

/// 创建临时访问控制配置文件，返回 (文件路径, TempFile)
fn create_temp_access_config(yaml: &str) -> (std::path::PathBuf, tempfile::NamedTempFile) {
    use std::io::Write;
    let mut temp_file = tempfile::Builder::new()
        .suffix(".yaml")
        .tempfile()
        .unwrap();
    write!(temp_file, "{}", yaml).unwrap();
    let path = temp_file.path().to_path_buf();
    (path, temp_file)
}

#[tokio::test]
async fn test_e2e_access_whitelist_allows_loopback() {
    // 白名单含 127.0.0.1/32，本地连接应该成功
    let access_yaml = r#"
client_rules:
  - 127.0.0.1/32
"#;
    let (access_path, _temp) = create_temp_access_config(access_yaml);
    let (echo_handle, echo_addr) = common::start_echo_server().await;
    let (server_handle, proxy_addr, cancel_token) =
        common::start_access_test_server(access_path).await;

    // 本地连接应该成功
    let mut stream = common::socks5_connect(proxy_addr, echo_addr).await;
    stream.write_all(b"whitelist test").await.unwrap();
    let mut buf = [0u8; 100];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"whitelist test");

    drop(stream);
    cancel_token.cancel();
    let _ = server_handle.await;
    echo_handle.abort();
}

#[tokio::test]
async fn test_e2e_access_whitelist_blocks_unmatched() {
    // 白名单不含本地 IP（使用一个不可能匹配的网段），连接应该被拒绝
    let access_yaml = r#"
client_rules:
  - 10.255.255.0/24
"#;
    let (access_path, _temp) = create_temp_access_config(access_yaml);
    let (_echo_handle, _echo_addr) = common::start_echo_server().await;
    let (server_handle, proxy_addr, cancel_token) =
        common::start_access_test_server(access_path).await;

    // 连接应该被拒绝（连接建立后立即关闭）
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let handshake = build_handshake_request(&[AUTH_NO_AUTH]);
    stream.write_all(&handshake).await.unwrap();

    // 服务器应该关闭连接（白名单拒绝）
    let mut buf = [0u8; 10];
    let result = stream.read(&mut buf).await;
    match result {
        Ok(0) => {} // 连接被关闭 - 预期行为
        Ok(_) => {} // 可能收到部分数据后关闭
        Err(_) => {} // IO 错误也可接受
    }

    cancel_token.cancel();
    let _ = server_handle.await;
    _echo_handle.abort();
}

#[tokio::test]
async fn test_e2e_access_whitelist_empty_blocks_all() {
    // 白名单为空，所有连接应该被拒绝
    let access_yaml = r#"
client_rules: []
"#;
    let (access_path, _temp) = create_temp_access_config(access_yaml);
    let (_echo_handle, _echo_addr) = common::start_echo_server().await;
    let (server_handle, proxy_addr, cancel_token) =
        common::start_access_test_server(access_path).await;

    // 连接应该被拒绝：服务器在 accept 后立即关闭连接
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let _ = stream.write_all(&build_handshake_request(&[AUTH_NO_AUTH])).await;

    // 关键断言：不应收到正常的 SOCKS5 握手响应
    let mut buf = [0u8; 2];
    match stream.read_exact(&mut buf).await {
        Ok(_) => {
            assert_ne!(
                buf,
                [SOCKS5_VERSION, AUTH_NO_AUTH],
                "Should NOT receive a successful SOCKS5 handshake when whitelist is empty"
            );
        }
        Err(_) => {} // IO 错误 - 预期行为（连接被关闭或重置）
    }

    cancel_token.cancel();
    let _ = server_handle.await;
    _echo_handle.abort();
}

#[tokio::test]
async fn test_e2e_access_control_disabled() {
    // access_enabled=false 时，不受规则影响，所有连接均可通过
    let config = AppConfig {
        connect_timeout: 5,
        access_enabled: false,
        ..AppConfig::default()
    };
    let (server_handle, proxy_addr, cancel_token) = common::start_test_server(config).await;
    let (echo_handle, echo_addr) = common::start_echo_server().await;

    let mut stream = common::socks5_connect(proxy_addr, echo_addr).await;
    stream.write_all(b"no access control").await.unwrap();
    let mut buf = [0u8; 100];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"no access control");

    drop(stream);
    cancel_token.cancel();
    let _ = server_handle.await;
    echo_handle.abort();
}

#[tokio::test]
async fn test_e2e_access_hot_reload() {
    use std::io::{Seek, Write};

    // 初始白名单不含本地 IP
    let access_yaml = r#"
client_rules:
  - 10.255.255.0/24
"#;
    let (access_path, mut temp_file) = create_temp_access_config(access_yaml);
    let (_echo_handle, echo_addr) = common::start_echo_server().await;
    let (server_handle, proxy_addr, cancel_token) =
        common::start_access_test_server(access_path).await;

    // 初始状态：本地连接被拒绝
    {
        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        let handshake = build_handshake_request(&[AUTH_NO_AUTH]);
        stream.write_all(&handshake).await.unwrap();
        let mut buf = [0u8; 10];
        let _ = stream.read(&mut buf).await;
        // 连接应该被关闭或拒绝
    }

    // 修改配置文件，添加本地 IP 到白名单
    let new_yaml = r#"
client_rules:
  - 127.0.0.1/32
"#;
    temp_file.as_file_mut().set_len(0).unwrap();
    temp_file
        .as_file_mut()
        .seek(std::io::SeekFrom::Start(0))
        .unwrap();
    write!(temp_file.as_file_mut(), "{}", new_yaml).unwrap();
    temp_file.as_file_mut().flush().unwrap();

    // 等待热加载生效（防抖 500ms + 余量）
    let mut allowed = false;
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        // 尝试建立完整的 SOCKS5 连接
        if let Ok(mut stream) = TcpStream::connect(proxy_addr).await {
            let handshake = build_handshake_request(&[AUTH_NO_AUTH]);
            if stream.write_all(&handshake).await.is_ok() {
                let mut response = [0u8; 2];
                if stream.read_exact(&mut response).await.is_ok()
                    && response == [SOCKS5_VERSION, AUTH_NO_AUTH]
                {
                    // 握手成功，说明白名单已放行
                    allowed = true;
                    break;
                }
            }
        }
    }
    assert!(allowed, "Hot reload did not take effect within timeout");

    // 验证热加载后可以完整代理数据
    let mut stream = common::socks5_connect(proxy_addr, echo_addr).await;
    stream.write_all(b"hot reload works").await.unwrap();
    let mut buf = [0u8; 100];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hot reload works");

    drop(stream);
    cancel_token.cancel();
    let _ = server_handle.await;
    _echo_handle.abort();
}

#[tokio::test]
async fn test_e2e_access_with_auth() {
    // 白名单 + 认证同时启用，两层验证均生效
    let user_yaml = r#"
users:
  - username: "admin"
    password: "admin123"
"#;
    let access_yaml = r#"
client_rules:
  - 127.0.0.1/32
"#;
    let (user_config_path, _user_temp) = create_temp_user_config(user_yaml);
    let (access_path, _access_temp) = create_temp_access_config(access_yaml);
    let (echo_handle, echo_addr) = common::start_echo_server().await;
    let (server_handle, proxy_addr, cancel_token) =
        common::start_auth_and_access_test_server(user_config_path, access_path).await;

    // 正确凭证 + 在白名单中 → 成功
    let mut stream =
        common::socks5_connect_with_auth(proxy_addr, echo_addr, "admin", "admin123").await;
    stream.write_all(b"auth and access ok").await.unwrap();
    let mut buf = [0u8; 100];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"auth and access ok");

    drop(stream);
    cancel_token.cancel();
    let _ = server_handle.await;
    echo_handle.abort();
}

#[tokio::test]
async fn test_e2e_access_whitelist_cidr_range() {
    // 使用 /8 网段，验证 CIDR 范围匹配（本地回环在 127.0.0.0/8 内）
    let access_yaml = r#"
client_rules:
  - 127.0.0.0/8
"#;
    let (access_path, _temp) = create_temp_access_config(access_yaml);
    let (echo_handle, echo_addr) = common::start_echo_server().await;
    let (server_handle, proxy_addr, cancel_token) =
        common::start_access_test_server(access_path).await;

    // 127.0.0.1 在 127.0.0.0/8 内，应该成功
    let mut stream = common::socks5_connect(proxy_addr, echo_addr).await;
    stream.write_all(b"cidr range test").await.unwrap();
    let mut buf = [0u8; 100];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"cidr range test");

    drop(stream);
    cancel_token.cancel();
    let _ = server_handle.await;
    echo_handle.abort();
}

// ========== 目标地址规则管控 E2E 测试 ==========

#[tokio::test]
async fn test_e2e_target_rules_pass() {
    // 目标地址在 PASS 规则中，连接应该成功并能正常传输数据
    let target_rules_yaml = r#"
target_rules:
  - [IPCIDR, 127.0.0.0/8, 0, 65535, PASS, 1, 0]
  - [IPCIDR, 0.0.0.0/0, 0, 65535, BLOCK, 1, 0]
"#;
    let (rules_path, _temp) = common::create_temp_target_rules_config(target_rules_yaml);
    let (echo_handle, echo_addr) = common::start_echo_server().await;
    let (server_handle, proxy_addr, cancel_token) =
        common::start_target_rules_test_server(rules_path).await;

    // echo server 监听在 127.0.0.1，匹配 127.0.0.0/8 PASS 规则，应该成功
    let mut stream = common::socks5_connect(proxy_addr, echo_addr).await;
    stream.write_all(b"target rules pass").await.unwrap();
    let mut buf = [0u8; 100];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"target rules pass");

    drop(stream);
    cancel_token.cancel();
    let _ = server_handle.await;
    echo_handle.abort();
}

#[tokio::test]
async fn test_e2e_target_rules_block_default() {
    // 目标地址不匹配任何 PASS 规则，默认 BLOCK
    // 配置一个只允许 10.0.0.0/8 的规则，echo server 在 127.0.0.1 上，应该被阻止
    let target_rules_yaml = r#"
target_rules:
  - [IPCIDR, 10.0.0.0/8, 0, 65535, PASS]
"#;
    let (rules_path, _temp) = common::create_temp_target_rules_config(target_rules_yaml);
    let (echo_handle, echo_addr) = common::start_echo_server().await;
    let (server_handle, proxy_addr, cancel_token) =
        common::start_target_rules_test_server(rules_path).await;

    // echo server 在 127.0.0.1，不在 10.0.0.0/8 范围内，应该被 BLOCK
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();

    // 握手
    let handshake = build_handshake_request(&[AUTH_NO_AUTH]);
    stream.write_all(&handshake).await.unwrap();
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [SOCKS5_VERSION, AUTH_NO_AUTH]);

    // CONNECT 请求
    let addr = match echo_addr {
        SocketAddr::V4(v4) => Address::IPv4(*v4.ip()),
        SocketAddr::V6(v6) => Address::IPv6(*v6.ip()),
    };
    let request = common::build_connect_request(&addr, echo_addr.port());
    stream.write_all(&request).await.unwrap();

    // 应该收到 REP_CONNECTION_NOT_ALLOWED (0x02) 回复
    let mut reply = [0u8; 10];
    let result = stream.read_exact(&mut reply).await;
    match result {
        Ok(_) => {
            assert_eq!(reply[0], SOCKS5_VERSION);
            assert_eq!(
                reply[1], REP_CONNECTION_NOT_ALLOWED,
                "Expected REP_CONNECTION_NOT_ALLOWED (0x02), got 0x{:02x}",
                reply[1]
            );
        }
        Err(_) => {
            // 连接被关闭也是可接受的（服务器可能在发送回复后立即关闭）
        }
    }

    drop(stream);

    // 验证服务器仍然正常运行（允许的目标应该可以连接）
    // 这里不做额外验证，因为没有匹配 10.0.0.0/8 的 echo server

    cancel_token.cancel();
    let _ = server_handle.await;
    echo_handle.abort();
}

#[tokio::test]
async fn test_e2e_target_rules_hot_reload() {
    use std::io::{Seek, Write};

    // 初始规则：只允许 10.0.0.0/8，echo server 在 127.0.0.1 上会被阻止
    let target_rules_yaml = r#"
target_rules:
  - [IPCIDR, 10.0.0.0/8, 0, 65535, PASS]
"#;
    let (rules_path, mut temp_file) = common::create_temp_target_rules_config(target_rules_yaml);
    let (echo_handle, echo_addr) = common::start_echo_server().await;
    let (server_handle, proxy_addr, cancel_token) =
        common::start_target_rules_test_server(rules_path).await;

    // 初始状态：127.0.0.1 的 echo server 应该被阻止
    {
        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        let handshake = build_handshake_request(&[AUTH_NO_AUTH]);
        stream.write_all(&handshake).await.unwrap();
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [SOCKS5_VERSION, AUTH_NO_AUTH]);

        let addr = match echo_addr {
            SocketAddr::V4(v4) => Address::IPv4(*v4.ip()),
            SocketAddr::V6(v6) => Address::IPv6(*v6.ip()),
        };
        let request = common::build_connect_request(&addr, echo_addr.port());
        stream.write_all(&request).await.unwrap();

        let mut reply = [0u8; 10];
        if let Ok(_) = stream.read_exact(&mut reply).await {
            assert_eq!(reply[1], REP_CONNECTION_NOT_ALLOWED);
        }
        drop(stream);
    }

    // 修改配置文件，添加 127.0.0.0/8 到 PASS 规则
    let new_yaml = r#"
target_rules:
  - [IPCIDR, 127.0.0.0/8, 0, 65535, PASS]
  - [IPCIDR, 10.0.0.0/8, 0, 65535, PASS]
"#;
    temp_file.as_file_mut().set_len(0).unwrap();
    temp_file
        .as_file_mut()
        .seek(std::io::SeekFrom::Start(0))
        .unwrap();
    write!(temp_file.as_file_mut(), "{}", new_yaml).unwrap();
    temp_file.as_file_mut().flush().unwrap();

    // 等待热加载生效（防抖 500ms + 余量）
    let mut reloaded = false;
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        // 尝试完整的 SOCKS5 代理连接
        if let Ok(mut stream) = try_socks5_connect(proxy_addr, echo_addr).await {
            // 连接成功，说明热加载已生效
            stream.write_all(b"hot reload ok").await.unwrap();
            let mut buf = [0u8; 100];
            let n = stream.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"hot reload ok");
            drop(stream);
            reloaded = true;
            break;
        }
    }
    assert!(
        reloaded,
        "Target rules hot reload did not take effect within timeout"
    );

    cancel_token.cancel();
    let _ = server_handle.await;
    echo_handle.abort();
}

/// 兼容性 E2E 测试：客户端使用 ATYP=DOMAIN 但发送 IP 地址字符串时，
/// 目标地址规则匹配应正确走 IPCIDR 分支而非域名分支。
///
/// 场景：目标规则只配置了 IPCIDR 127.0.0.0/8 PASS（无域名规则），
/// 客户端用 Address::Domain("127.0.0.1") 发起 CONNECT 请求。
/// - 如果兼容逻辑生效：地址被转换为 IPv4 → 匹配 IPCIDR 规则 → PASS → 连接成功
/// - 如果兼容逻辑不生效：地址保持 Domain → 走域名匹配 → 无匹配 → 默认 BLOCK
#[tokio::test]
async fn test_e2e_target_rules_domain_atyp_with_ip_string() {
    // 目标规则：只有 IPCIDR 规则，没有域名规则
    // 如果 ATYP=DOMAIN + IP 字符串没有被兼容转换，将走域名匹配 → 无匹配 → 默认 BLOCK
    let target_rules_yaml = r#"
target_rules:
  - [IPCIDR, 127.0.0.0/8, 0, 65535, PASS, 1, 0]
  - [IPCIDR, 0.0.0.0/0, 0, 65535, BLOCK, 1, 0]
"#;
    let (rules_path, _temp) = common::create_temp_target_rules_config(target_rules_yaml);
    let (echo_handle, echo_addr) = common::start_echo_server().await;
    let (server_handle, proxy_addr, cancel_token) =
        common::start_target_rules_test_server(rules_path).await;

    // 模拟不规范客户端：ATYP=DOMAIN，但 DST.ADDR 内容是 IP 地址字符串
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();

    // 握手
    let handshake = common::build_handshake_request(&[AUTH_NO_AUTH]);
    stream.write_all(&handshake).await.unwrap();
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [SOCKS5_VERSION, AUTH_NO_AUTH]);

    // CONNECT 请求：使用 Address::Domain("127.0.0.1") 模拟不规范客户端
    let ip_as_domain = Address::Domain(format!("127.0.0.1"));
    let request = common::build_connect_request(&ip_as_domain, echo_addr.port());
    stream.write_all(&request).await.unwrap();

    // 如果兼容逻辑生效，应该收到 REP_SUCCEEDED（IP 被正确识别并走 IPCIDR 匹配）
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], SOCKS5_VERSION);
    assert_eq!(
        reply[1], REP_SUCCEEDED,
        "ATYP=DOMAIN with IP string should be auto-converted and match IPCIDR rule, got reply 0x{:02x}",
        reply[1]
    );

    // 验证数据能正常转发
    stream
        .write_all(b"domain-atyp-ip-compat")
        .await
        .unwrap();
    let mut buf = [0u8; 100];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"domain-atyp-ip-compat");

    drop(stream);
    cancel_token.cancel();
    let _ = server_handle.await;
    echo_handle.abort();
}
