mod common;

use exsocks::socks5::protocol::*;
use exsocks::socks5::reply::send_reply;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio::io::AsyncReadExt;

#[tokio::test]
async fn test_send_reply_success() {
    let (mut client, mut server) = common::create_tcp_pair().await;
    let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080));

    tokio::spawn(async move {
        send_reply(&mut server, REP_SUCCEEDED, bind_addr)
            .await
            .unwrap();
    });

    let mut response = vec![0u8; 10];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response[0], SOCKS5_VERSION);
    assert_eq!(response[1], REP_SUCCEEDED);
    assert_eq!(response[3], ATYP_IPV4);
}

#[tokio::test]
async fn test_send_reply_failure() {
    let (mut client, mut server) = common::create_tcp_pair().await;
    let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));

    tokio::spawn(async move {
        send_reply(&mut server, REP_GENERAL_FAILURE, bind_addr)
            .await
            .unwrap();
    });

    let mut response = vec![0u8; 10];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response[0], SOCKS5_VERSION);
    assert_eq!(response[1], REP_GENERAL_FAILURE);
}
