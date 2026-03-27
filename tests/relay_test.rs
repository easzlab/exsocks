mod common;

use exsocks::relay::{relay, DEFAULT_BUFFER_SIZE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn test_relay_bidirectional() {
    // 创建 client_proxy 和 proxy_client 对（模拟 client <-> proxy）
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();

    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();

    // proxy 侧的两个连接
    let proxy_to_client = tokio::net::TcpStream::connect(client_addr).await.unwrap();
    let proxy_to_target = tokio::net::TcpStream::connect(target_addr).await.unwrap();

    let (mut client, _) = client_listener.accept().await.unwrap();
    let (mut target, _) = target_listener.accept().await.unwrap();

    let relay_handle = tokio::spawn(async move { relay(proxy_to_client, proxy_to_target, DEFAULT_BUFFER_SIZE, CancellationToken::new()).await });

    // client 发送数据
    let client_data = b"hello from client";
    client.write_all(client_data).await.unwrap();

    // target 接收数据
    let mut buf = vec![0u8; 100];
    let n = target.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], client_data);

    // target 发送数据
    let target_data = b"hello from target";
    target.write_all(target_data).await.unwrap();

    // client 接收数据
    let n = client.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], target_data);

    // 关闭双方
    drop(client);
    drop(target);

    let (up, down) = relay_handle.await.unwrap().unwrap();
    assert!(up > 0);
    assert!(down > 0);
}

#[tokio::test]
async fn test_relay_large_data() {
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();

    let proxy_to_client = tokio::net::TcpStream::connect(client_addr).await.unwrap();
    let proxy_to_target = tokio::net::TcpStream::connect(target_addr).await.unwrap();

    let (mut client, _) = client_listener.accept().await.unwrap();
    let (mut target, _) = target_listener.accept().await.unwrap();

    let relay_handle = tokio::spawn(async move { relay(proxy_to_client, proxy_to_target, DEFAULT_BUFFER_SIZE, CancellationToken::new()).await });

    // 发送 1MB 数据
    let data: Vec<u8> = (0..1_048_576).map(|i| (i % 256) as u8).collect();
    let data_clone = data.clone();

    let send_handle = tokio::spawn(async move {
        client.write_all(&data_clone).await.unwrap();
        client.shutdown().await.unwrap();
    });

    let recv_handle = tokio::spawn(async move {
        let mut received = Vec::new();
        target.read_to_end(&mut received).await.unwrap();
        received
    });

    send_handle.await.unwrap();
    let received = recv_handle.await.unwrap();
    assert_eq!(received.len(), data.len());
    assert_eq!(received, data);

    let _ = relay_handle.await;
}

#[tokio::test]
async fn test_relay_client_close() {
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();

    let proxy_to_client = tokio::net::TcpStream::connect(client_addr).await.unwrap();
    let proxy_to_target = tokio::net::TcpStream::connect(target_addr).await.unwrap();

    let (client, _) = client_listener.accept().await.unwrap();
    let (mut target, _) = target_listener.accept().await.unwrap();

    let relay_handle = tokio::spawn(async move { relay(proxy_to_client, proxy_to_target, DEFAULT_BUFFER_SIZE, CancellationToken::new()).await });

    // 客户端立即关闭
    drop(client);

    // target 应该收到 EOF
    let mut buf = [0u8; 100];
    let n = target.read(&mut buf).await.unwrap();
    assert_eq!(n, 0);

    drop(target);
    let _ = relay_handle.await;
}

#[tokio::test]
async fn test_relay_empty_transfer() {
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();

    let proxy_to_client = tokio::net::TcpStream::connect(client_addr).await.unwrap();
    let proxy_to_target = tokio::net::TcpStream::connect(target_addr).await.unwrap();

    let (client, _) = client_listener.accept().await.unwrap();
    let (target, _) = target_listener.accept().await.unwrap();

    let relay_handle = tokio::spawn(async move { relay(proxy_to_client, proxy_to_target, DEFAULT_BUFFER_SIZE, CancellationToken::new()).await });

    // 双方都不发送数据直接关闭
    drop(client);
    drop(target);

    let result = relay_handle.await.unwrap();
    assert!(result.is_ok());
    let (up, down) = result.unwrap();
    assert_eq!(up, 0);
    assert_eq!(down, 0);
}

#[tokio::test]
async fn test_relay_target_close() {
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();

    let proxy_to_client = tokio::net::TcpStream::connect(client_addr).await.unwrap();
    let proxy_to_target = tokio::net::TcpStream::connect(target_addr).await.unwrap();

    let (mut client, _) = client_listener.accept().await.unwrap();
    let (target, _) = target_listener.accept().await.unwrap();

    let relay_handle = tokio::spawn(async move { relay(proxy_to_client, proxy_to_target, DEFAULT_BUFFER_SIZE, CancellationToken::new()).await });

    // target 立即关闭
    drop(target);

    // client 应该收到 EOF
    let mut buf = [0u8; 100];
    let n = client.read(&mut buf).await.unwrap();
    assert_eq!(n, 0);

    drop(client);
    let _ = relay_handle.await;
}

#[tokio::test]
async fn test_relay_byte_count() {
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();

    let proxy_to_client = tokio::net::TcpStream::connect(client_addr).await.unwrap();
    let proxy_to_target = tokio::net::TcpStream::connect(target_addr).await.unwrap();

    let (mut client, _) = client_listener.accept().await.unwrap();
    let (mut target, _) = target_listener.accept().await.unwrap();

    let relay_handle = tokio::spawn(async move { relay(proxy_to_client, proxy_to_target, DEFAULT_BUFFER_SIZE, CancellationToken::new()).await });

    // client 发送 100 字节
    let client_data = vec![b'A'; 100];
    client.write_all(&client_data).await.unwrap();

    // target 接收
    let mut buf = vec![0u8; 200];
    let n = target.read(&mut buf).await.unwrap();
    assert_eq!(n, 100);

    // target 发送 50 字节
    let target_data = vec![b'B'; 50];
    target.write_all(&target_data).await.unwrap();

    // client 接收
    let n = client.read(&mut buf).await.unwrap();
    assert_eq!(n, 50);

    // 关闭双方
    drop(client);
    drop(target);

    let result = relay_handle.await.unwrap();
    assert!(result.is_ok());
    let (up, down) = result.unwrap();
    // client -> target: 100 字节
    assert_eq!(up, 100);
    // target -> client: 50 字节
    assert_eq!(down, 50);
}

/// 并发压力测试：100+ 并发连接同时进行双向数据传输
#[tokio::test]
async fn test_relay_concurrent_connections() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const NUM_CONNECTIONS: usize = 128;
    const DATA_SIZE: usize = 4096;

    let success_count = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(NUM_CONNECTIONS);

    for i in 0..NUM_CONNECTIONS {
        let success = success_count.clone();
        let handle = tokio::spawn(async move {
            // 每个连接独立的 listener
            let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client_addr = client_listener.local_addr().unwrap();
            let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target_addr = target_listener.local_addr().unwrap();

            let proxy_to_client = tokio::net::TcpStream::connect(client_addr).await.unwrap();
            let proxy_to_target = tokio::net::TcpStream::connect(target_addr).await.unwrap();

            let (mut client, _) = client_listener.accept().await.unwrap();
            let (mut target, _) = target_listener.accept().await.unwrap();

            let relay_handle = tokio::spawn(async move {
                relay(proxy_to_client, proxy_to_target, DEFAULT_BUFFER_SIZE, CancellationToken::new()).await
            });

            // 生成测试数据（每个连接不同）
            let client_data: Vec<u8> = (0..DATA_SIZE).map(|j| ((i + j) % 256) as u8).collect();
            let target_data: Vec<u8> = (0..DATA_SIZE).map(|j| ((i * 2 + j) % 256) as u8).collect();

            let client_data_clone = client_data.clone();
            let target_data_clone = target_data.clone();

            // client 发送并接收
            let client_task = tokio::spawn(async move {
                client.write_all(&client_data_clone).await.unwrap();
                let mut buf = vec![0u8; DATA_SIZE];
                client.read_exact(&mut buf).await.unwrap();
                client.shutdown().await.ok();
                buf
            });

            // target 接收并发送
            let target_task = tokio::spawn(async move {
                let mut buf = vec![0u8; DATA_SIZE];
                target.read_exact(&mut buf).await.unwrap();
                target.write_all(&target_data_clone).await.unwrap();
                target.shutdown().await.ok();
                buf
            });

            let (client_received, target_received) = tokio::join!(client_task, target_task);
            let client_received = client_received.unwrap();
            let target_received = target_received.unwrap();

            // 验证数据完整性
            if target_received == client_data && client_received == target_data {
                success.fetch_add(1, Ordering::Relaxed);
            }

            let _ = relay_handle.await;
        });
        handles.push(handle);
    }

    // 等待所有连接完成
    for handle in handles {
        let _ = handle.await;
    }

    let count = success_count.load(Ordering::Relaxed);
    assert_eq!(
        count, NUM_CONNECTIONS,
        "Expected {} successful connections, got {}",
        NUM_CONNECTIONS, count
    );
}

/// 超时场景测试：通过 CancellationToken 中断对端不响应的连接
#[tokio::test]
async fn test_relay_cancellation_on_unresponsive_peer() {
    use std::time::Duration;

    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();

    let proxy_to_client = tokio::net::TcpStream::connect(client_addr).await.unwrap();
    let proxy_to_target = tokio::net::TcpStream::connect(target_addr).await.unwrap();

    let (_client, _) = client_listener.accept().await.unwrap();
    let (_target, _) = target_listener.accept().await.unwrap();

    let cancel_token = CancellationToken::new();
    let cancel_clone = cancel_token.clone();

    let relay_handle = tokio::spawn(async move {
        relay(proxy_to_client, proxy_to_target, DEFAULT_BUFFER_SIZE, cancel_clone).await
    });

    // 模拟对端不响应，等待 50ms 后触发取消
    tokio::time::sleep(Duration::from_millis(50)).await;
    cancel_token.cancel();

    // relay 应该在取消后快速返回
    let result = tokio::time::timeout(Duration::from_millis(100), relay_handle).await;
    assert!(result.is_ok(), "Relay should complete quickly after cancellation");

    let relay_result = result.unwrap().unwrap();
    // 取消时可能返回 Ok (0, 0) 或者 Err（取决于取消时机）
    // 主要验证的是：取消后 relay 能正确退出，不会永久阻塞
    match relay_result {
        Ok((up, down)) => {
            assert_eq!(up, 0);
            assert_eq!(down, 0);
        }
        Err(_) => {
            // 取消导致的错误也是预期行为
        }
    }
}

/// 超时场景测试：验证取消时正在传输的数据能正确处理
#[tokio::test]
async fn test_relay_cancellation_during_transfer() {
    use std::time::Duration;

    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();

    let proxy_to_client = tokio::net::TcpStream::connect(client_addr).await.unwrap();
    let proxy_to_target = tokio::net::TcpStream::connect(target_addr).await.unwrap();

    let (mut client, _) = client_listener.accept().await.unwrap();
    let (mut target, _) = target_listener.accept().await.unwrap();

    let cancel_token = CancellationToken::new();
    let cancel_clone = cancel_token.clone();

    let relay_handle = tokio::spawn(async move {
        relay(proxy_to_client, proxy_to_target, DEFAULT_BUFFER_SIZE, cancel_clone).await
    });

    // 发送一些数据
    let data = b"some data before cancel";
    client.write_all(data).await.unwrap();

    // target 读取数据
    let mut buf = vec![0u8; 100];
    let n = target.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], data);

    // 现在取消 relay（client 保持连接但不关闭）
    cancel_token.cancel();

    // relay 应该快速退出
    let result = tokio::time::timeout(Duration::from_millis(100), relay_handle).await;
    assert!(result.is_ok(), "Relay should exit after cancellation");
}
