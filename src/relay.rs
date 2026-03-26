//! 双向数据转发模块
//!
//! 策略：
//!   - Linux：使用 splice(2) 系统调用实现零拷贝转发。
//!     数据路径：src_socket -> pipe -> dst_socket，全程不经过用户态缓冲区。
//!     由于 splice 是阻塞系统调用，在 tokio::task::spawn_blocking 中执行。
//!   - 非 Linux：使用 tokio::io::copy_bidirectional 作为 fallback。

use tokio::net::TcpStream;

use crate::error::SocksError;

// ─────────────────────────────────────────────────────────────────────────────
// Linux 零拷贝实现（splice）
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux_splice {
    use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
    use std::sync::Arc;

    use nix::fcntl::{splice, SpliceFFlags};
    use nix::unistd::pipe;
    use tokio::net::TcpStream;

    use crate::error::SocksError;

    /// 管道缓冲区大小：64 KiB，与 Linux 默认管道容量一致
    const SPLICE_BUF_SIZE: usize = 65536;

    /// 单向 splice 转发：src_fd -> pipe -> dst_fd，直到 EOF。
    ///
    /// pipe fd 用 OwnedFd 包裹，函数返回时自动关闭，避免 fd 泄漏。
    ///
    /// 读端 splice 使用 SPLICE_F_NONBLOCK 避免半关闭时永久阻塞：
    /// 当一个方向 EOF 后，另一个方向的阻塞 splice 会永久挂起（因为 Arc 持有 fd，
    /// fd 不会被关闭来触发唤醒）。NONBLOCK + yield_now 允许线程在无数据时短暂让出
    /// CPU，当对端 fd 最终关闭时（Arc 引用归零），splice 返回错误从而退出循环。
    ///
    /// 写端 splice 使用阻塞式（无 NONBLOCK），确保管道中的数据完整写出到目标 socket。
    fn splice_loop(src_fd: i32, dst_fd: i32) -> std::io::Result<u64> {
        let (pipe_read_raw, pipe_write_raw) = pipe()
            .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
        let pipe_read = unsafe { OwnedFd::from_raw_fd(pipe_read_raw) };
        let pipe_write = unsafe { OwnedFd::from_raw_fd(pipe_write_raw) };

        let pipe_r = pipe_read.as_raw_fd();
        let pipe_w = pipe_write.as_raw_fd();

        let mut total: u64 = 0;

        loop {
            // splice: src_fd -> pipe_w（读端非阻塞）
            let bytes_read = match splice(
                src_fd, None,
                pipe_w, None,
                SPLICE_BUF_SIZE,
                SpliceFFlags::SPLICE_F_MOVE | SpliceFFlags::SPLICE_F_NONBLOCK,
            ) {
                Ok(0) => break, // EOF
                Ok(n) => n,
                Err(nix::errno::Errno::EAGAIN) | Err(nix::errno::Errno::EWOULDBLOCK) => {
                    std::thread::yield_now();
                    continue;
                }
                Err(e) => return Err(std::io::Error::from_raw_os_error(e as i32)),
            };

            // splice: pipe_r -> dst_fd（写端阻塞，确保数据完整写出）
            let mut remaining = bytes_read;
            while remaining > 0 {
                match splice(
                    pipe_r, None,
                    dst_fd, None,
                    remaining,
                    SpliceFFlags::SPLICE_F_MOVE,
                ) {
                    Ok(0) => return Ok(total),
                    Ok(written) => remaining -= written,
                    Err(e) => return Err(std::io::Error::from_raw_os_error(e as i32)),
                }
            }
            total += bytes_read as u64;
        }

        // pipe_read 和 pipe_write 在此处自动 close（OwnedFd drop）
        Ok(total)
    }

    /// 基于 splice 的双向零拷贝转发。
    ///
    /// 将 tokio TcpStream 转为 std TcpStream，用 Arc 持有以确保两个阻塞线程
    /// 都结束后 fd 才被关闭。每个方向独立创建 pipe，互不干扰。
    pub async fn relay_splice(
        client: TcpStream,
        target: TcpStream,
    ) -> Result<(u64, u64), SocksError> {
        let client_std = client.into_std().map_err(SocksError::Io)?;
        let target_std = target.into_std().map_err(SocksError::Io)?;

        let client_fd = client_std.as_raw_fd();
        let target_fd = target_std.as_raw_fd();

        // Arc 持有 TcpStream，保证 fd 在两个线程都结束后才关闭
        let client_arc = Arc::new(client_std);
        let target_arc = Arc::new(target_std);

        let client_for_c2t = Arc::clone(&client_arc);
        let target_for_c2t = Arc::clone(&target_arc);
        let client_for_t2c = Arc::clone(&client_arc);
        let target_for_t2c = Arc::clone(&target_arc);

        // 方向1：client -> target
        let c2t_handle = tokio::task::spawn_blocking(move || {
            let _keep_alive = (client_for_c2t, target_for_c2t);
            splice_loop(client_fd, target_fd)
        });

        // 方向2：target -> client
        let t2c_handle = tokio::task::spawn_blocking(move || {
            let _keep_alive = (client_for_t2c, target_for_t2c);
            splice_loop(target_fd, client_fd)
        });

        let (c2t_result, t2c_result) = tokio::join!(c2t_handle, t2c_handle);

        let client_to_target = c2t_result
            .map_err(|e| SocksError::Io(std::io::Error::other(e)))?
            .map_err(SocksError::Io)?;
        let target_to_client = t2c_result
            .map_err(|e| SocksError::Io(std::io::Error::other(e)))?
            .map_err(SocksError::Io)?;

        Ok((client_to_target, target_to_client))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 非 Linux fallback（tokio copy_bidirectional）
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(not(target_os = "linux"))]
mod generic_relay {
    use tokio::io::copy_bidirectional;
    use tokio::net::TcpStream;

    use crate::error::SocksError;

    pub async fn relay_copy(
        mut client: TcpStream,
        mut target: TcpStream,
    ) -> Result<(u64, u64), SocksError> {
        let (client_to_target, target_to_client) =
            copy_bidirectional(&mut client, &mut target).await?;
        Ok((client_to_target, target_to_client))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 公开接口：根据平台自动选择实现
// ─────────────────────────────────────────────────────────────────────────────

/// 启动双向数据转发，返回 (client→target 字节数, target→client 字节数)。
///
/// - Linux：使用 splice(2) 零拷贝
/// - 其他平台：使用 tokio::io::copy_bidirectional
pub async fn relay(
    client: TcpStream,
    target: TcpStream,
) -> Result<(u64, u64), SocksError> {
    #[cfg(target_os = "linux")]
    {
        linux_splice::relay_splice(client, target).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        generic_relay::relay_copy(client, target).await
    }
}
