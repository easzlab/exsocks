mod common;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use exsocks::relay::relay;

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
    
    let relay_handle = tokio::spawn(async move {
        relay(proxy_to_client, proxy_to_target).await
    });
    
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
    
    let relay_handle = tokio::spawn(async move {
        relay(proxy_to_client, proxy_to_target).await
    });
    
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
    
    let relay_handle = tokio::spawn(async move {
        relay(proxy_to_client, proxy_to_target).await
    });
    
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
    
    let relay_handle = tokio::spawn(async move {
        relay(proxy_to_client, proxy_to_target).await
    });
    
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
    
    let relay_handle = tokio::spawn(async move {
        relay(proxy_to_client, proxy_to_target).await
    });
    
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
    
    let relay_handle = tokio::spawn(async move {
        relay(proxy_to_client, proxy_to_target).await
    });
    
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
