//! 双向数据转发模块
//!
//! 使用 64 KiB 缓冲区的异步双向拷贝，纯事件驱动，无阻塞线程开销。
//! 相比 splice(2) 零拷贝方案，在高并发 SOCKS5 代理场景下具有更好的可扩展性：
//!   - 不占用阻塞线程池（splice 每连接消耗 2 个阻塞线程，上限 ~256 并发）
//!   - 纯 epoll/kqueue 驱动，单 worker 可处理数万连接
//!   - 缓冲区从默认 8 KiB 提升到 64 KiB，缩小与零拷贝的吞吐差距

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::SocksError;

/// 转发缓冲区大小：64 KiB
///
/// tokio::io::copy 默认使用 8 KiB 缓冲区，对于代理转发场景偏小。
/// 64 KiB 与 Linux 默认 pipe 容量和常见 TCP 窗口大小对齐，
/// 在减少系统调用次数和避免过度占用内存之间取得平衡。
const RELAY_BUFFER_SIZE: usize = 65536;

/// 单向异步拷贝：reader → writer，使用 64 KiB 缓冲区。
///
/// 拷贝完成后对 writer 执行 shutdown，通知对端 EOF。
async fn copy_with_shutdown<R, W>(reader: &mut R, writer: &mut W) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = tokio::io::BufReader::with_capacity(RELAY_BUFFER_SIZE, reader);
    let bytes_copied = tokio::io::copy_buf(&mut buffer, writer).await?;
    writer.shutdown().await?;
    Ok(bytes_copied)
}

/// 启动双向数据转发，返回 (client→target 字节数, target→client 字节数)。
///
/// 两个方向并发执行，任一方向 EOF 后通过 shutdown 通知对端，
/// 等待双方都完成后返回。
pub async fn relay(client: TcpStream, target: TcpStream) -> Result<(u64, u64), SocksError> {
    let (mut client_reader, mut client_writer) = tokio::io::split(client);
    let (mut target_reader, mut target_writer) = tokio::io::split(target);

    let client_to_target = tokio::spawn(async move {
        copy_with_shutdown(&mut client_reader, &mut target_writer).await
    });

    let target_to_client = tokio::spawn(async move {
        copy_with_shutdown(&mut target_reader, &mut client_writer).await
    });

    let (c2t_result, t2c_result) = tokio::join!(client_to_target, target_to_client);

    let bytes_up = c2t_result
        .map_err(|e| SocksError::Io(std::io::Error::other(e)))?
        .unwrap_or(0);
    let bytes_down = t2c_result
        .map_err(|e| SocksError::Io(std::io::Error::other(e)))?
        .unwrap_or(0);

    Ok((bytes_up, bytes_down))
}
