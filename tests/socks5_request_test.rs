mod common;

use exsocks::socks5::protocol::*;
use exsocks::socks5::request::parse_request;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn test_parse_connect_ipv4() {
    let (mut client, mut server) = common::create_tcp_pair().await;
    let addr = Address::IPv4(Ipv4Addr::new(192, 168, 1, 1));
    let request = common::build_connect_request(&addr, 8080);
    let handle = tokio::spawn(async move { parse_request(&mut server).await });
    client.write_all(&request).await.unwrap();
    let result = handle.await.unwrap().unwrap();
    assert_eq!(result.address, addr);
    assert_eq!(result.port, 8080);
}

#[tokio::test]
async fn test_parse_connect_ipv6() {
    let (mut client, mut server) = common::create_tcp_pair().await;
    let addr = Address::IPv6(Ipv6Addr::LOCALHOST);
    let request = common::build_connect_request(&addr, 443);
    let handle = tokio::spawn(async move { parse_request(&mut server).await });
    client.write_all(&request).await.unwrap();
    let result = handle.await.unwrap().unwrap();
    assert_eq!(result.address, addr);
    assert_eq!(result.port, 443);
}

#[tokio::test]
async fn test_parse_connect_domain() {
    let (mut client, mut server) = common::create_tcp_pair().await;
    let addr = Address::Domain("example.com".to_string());
    let request = common::build_connect_request(&addr, 80);
    let handle = tokio::spawn(async move { parse_request(&mut server).await });
    client.write_all(&request).await.unwrap();
    let result = handle.await.unwrap().unwrap();
    assert_eq!(result.address, addr);
    assert_eq!(result.port, 80);
}

#[tokio::test]
async fn test_parse_unsupported_command_bind() {
    let (mut client, mut server) = common::create_tcp_pair().await;
    // CMD_BIND = 0x02
    let request = vec![
        SOCKS5_VERSION,
        CMD_BIND,
        0x00,
        ATYP_IPV4,
        127,
        0,
        0,
        1,
        0x00,
        0x50,
    ];
    let handle = tokio::spawn(async move { parse_request(&mut server).await });
    client.write_all(&request).await.unwrap();
    // 读取错误回复
    let mut response = vec![0u8; 10];
    let _ = client.read(&mut response).await;
    let result = handle.await.unwrap();
    assert!(result.is_err());
}

#[tokio::test]
async fn test_parse_unsupported_command_udp() {
    let (mut client, mut server) = common::create_tcp_pair().await;
    let request = vec![
        SOCKS5_VERSION,
        CMD_UDP_ASSOCIATE,
        0x00,
        ATYP_IPV4,
        127,
        0,
        0,
        1,
        0x00,
        0x50,
    ];
    let handle = tokio::spawn(async move { parse_request(&mut server).await });
    client.write_all(&request).await.unwrap();
    let mut response = vec![0u8; 10];
    let _ = client.read(&mut response).await;
    let result = handle.await.unwrap();
    assert!(result.is_err());
}

#[tokio::test]
async fn test_parse_unsupported_atyp() {
    let (mut client, mut server) = common::create_tcp_pair().await;
    // 使用无效的地址类型 0x05
    let request = vec![
        SOCKS5_VERSION,
        CMD_CONNECT,
        0x00,
        0x05,
        127,
        0,
        0,
        1,
        0x00,
        0x50,
    ];
    let handle = tokio::spawn(async move { parse_request(&mut server).await });
    client.write_all(&request).await.unwrap();
    let mut response = vec![0u8; 10];
    let _ = client.read(&mut response).await;
    let result = handle.await.unwrap();
    assert!(result.is_err());
}

#[tokio::test]
async fn test_parse_port_boundary() {
    let (mut client, mut server) = common::create_tcp_pair().await;
    let addr = Address::IPv4(Ipv4Addr::new(127, 0, 0, 1));
    // 端口 65535
    let request = common::build_connect_request(&addr, 65535);
    let handle = tokio::spawn(async move { parse_request(&mut server).await });
    client.write_all(&request).await.unwrap();
    let result = handle.await.unwrap().unwrap();
    assert_eq!(result.port, 65535);
}
