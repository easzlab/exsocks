//! 双向数据转发模块
//!
//! 使用可配置的缓冲区进行异步双向拷贝，纯事件驱动，无阻塞线程开销。
//! 相比 splice(2) 零拷贝方案，在高并发 SOCKS5 代理场景下具有更好的可扩展性：
//!   - 不占用阻塞线程池（splice 每连接消耗 2 个阻塞线程，上限 ~256 并发）
//!   - 纯 epoll/kqueue 驱动，单 worker 可处理数万连接
//!   - 默认缓冲区 64 KiB，可通过配置调整以适应不同场景
//!
//! ## 设计说明
//!
//! 使用 `BufReader::with_capacity` + `copy_buf` 而非直接用 `copy` 的原因：
//! - `tokio::io::copy` 内部使用固定 8 KiB 缓冲区，无法配置
//! - `copy_buf` 会利用 `BufRead::fill_buf` 批量读取，配合大缓冲区可以减少系统调用次数
//! - 这种组合在大数据传输场景下吞吐量提升显著
//!
//! ## 缓冲区大小选择建议
//!
//! - **64 KiB（默认）**：适合大多数场景，与 Linux 默认 pipe 容量对齐
//! - **128-256 KiB**：适合大文件传输、视频流等高吞吐场景
//! - **16-32 KiB**：适合低内存环境或大量短连接场景

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::error::SocksError;

/// 默认转发缓冲区大小：64 KiB
pub const DEFAULT_BUFFER_SIZE: usize = 65536;

/// 计数写入器：包装 AsyncWrite，实时累加写入字节数到共享原子计数器。
///
/// 用于在 cancel 场景下仍能获取已传输的准确字节数。
struct CountingWriter<'a, W> {
    inner: &'a mut W,
    counter: &'a AtomicU64,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for CountingWriter<'_, W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut *this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                this.counter.fetch_add(n as u64, Ordering::Relaxed);
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

/// 单向异步拷贝：reader → writer。
///
/// 使用指定大小构建 BufReader 进行拷贝，通过 CountingWriter 实时跟踪字节数，
/// 拷贝完成后对 writer 执行 shutdown 通知对端 EOF。
async fn copy_one_direction<R, W>(
    reader: &mut R,
    writer: &mut W,
    buffer_size: usize,
    bytes_counter: &AtomicU64,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut counting_writer = CountingWriter { inner: writer, counter: bytes_counter };
    let mut buffer = tokio::io::BufReader::with_capacity(buffer_size, reader);
    tokio::io::copy_buf(&mut buffer, &mut counting_writer).await?;
    counting_writer.inner.shutdown().await?;
    Ok(())
}

/// 启动双向数据转发，返回 (client→target 字节数, target→client 字节数)。
///
/// 两个方向并发执行，任一方向 EOF 后通过 shutdown 通知对端，
/// 等待双方都完成后返回。
///
/// # 参数
/// - `client`: 客户端连接
/// - `target`: 目标服务器连接
/// - `buffer_size`: 转发缓冲区大小（字节）
/// - `cancel`: 取消令牌，用于优雅关闭时中断转发
///
/// # 取消行为
/// 当 cancel token 被触发时，两个方向的拷贝任务都会被中断，
/// 返回截止到取消时刻已传输的字节数。
pub async fn relay(
    client: TcpStream,
    target: TcpStream,
    buffer_size: usize,
    cancel: CancellationToken,
) -> Result<(u64, u64), SocksError> {
    let (mut client_reader, mut client_writer) = client.into_split();
    let (mut target_reader, mut target_writer) = target.into_split();

    // 使用共享原子计数器跟踪字节数，即使 cancel 中断也能获取准确值
    let c2t_bytes = Arc::new(AtomicU64::new(0));
    let t2c_bytes = Arc::new(AtomicU64::new(0));

    let c2t_counter = c2t_bytes.clone();
    let cancel_c2t = cancel.clone();
    let client_to_target = tokio::spawn(async move {
        tokio::select! {
            biased;
            _ = cancel_c2t.cancelled() => Ok(()),
            result = copy_one_direction(&mut client_reader, &mut target_writer, buffer_size, &c2t_counter) => result,
        }
    });

    let t2c_counter = t2c_bytes.clone();
    let cancel_t2c = cancel.clone();
    let target_to_client = tokio::spawn(async move {
        tokio::select! {
            biased;
            _ = cancel_t2c.cancelled() => Ok(()),
            result = copy_one_direction(&mut target_reader, &mut client_writer, buffer_size, &t2c_counter) => result,
        }
    });

    let (c2t_result, t2c_result) = tokio::join!(client_to_target, target_to_client);

    // 传播 JoinError（任务 panic）和内部 io::Error
    c2t_result.map_err(|e| SocksError::Io(io::Error::other(e)))??;
    t2c_result.map_err(|e| SocksError::Io(io::Error::other(e)))??;

    // 从共享计数器读取实际传输字节数（cancel 场景下也是准确值）
    let bytes_up = c2t_bytes.load(Ordering::Relaxed);
    let bytes_down = t2c_bytes.load(Ordering::Relaxed);

    Ok((bytes_up, bytes_down))
}
