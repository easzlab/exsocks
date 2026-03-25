use tokio::io;
use tokio::net::TcpStream;

use crate::error::SocksError;

/// 非 Linux 平台：使用 tokio 标准双向拷贝
#[cfg(not(target_os = "linux"))]
pub async fn relay(
    mut client: TcpStream,
    mut target: TcpStream,
) -> Result<(u64, u64), SocksError> {
    let (client_to_target, target_to_client) =
        io::copy_bidirectional(&mut client, &mut target).await?;

    Ok((client_to_target, target_to_client))
}

/// Linux 平台：使用 splice(2) 系统调用实现零拷贝
/// 在独立阻塞线程中执行 splice，避免阻塞 Tokio 异步线程池
#[cfg(target_os = "linux")]
pub async fn relay(
    client: TcpStream,
    target: TcpStream,
) -> Result<(u64, u64), SocksError> {
    use std::os::unix::io::AsRawFd;

    let client_fd = client.as_raw_fd();
    let target_fd = target.as_raw_fd();

    // 启动两个独立的 spawn_blocking 任务处理双向数据传输
    // 这样可以避免阻塞 Tokio 的异步工作线程
    let c2t_handle = tokio::task::spawn_blocking(move || {
        splice_loop(client_fd, target_fd)
    });

    let t2c_handle = tokio::task::spawn_blocking(move || {
        splice_loop(target_fd, client_fd)
    });

    // 等待两个方向的传输完成
    let (c2t_result, t2c_result) = tokio::join!(c2t_handle, t2c_handle);

    let client_to_target = c2t_result
        .map_err(|e| SocksError::Io(std::io::Error::other(e)))?
        .map_err(SocksError::from)?;

    let target_to_client = t2c_result
        .map_err(|e| SocksError::Io(std::io::Error::other(e)))?
        .map_err(SocksError::from)?;

    Ok((client_to_target, target_to_client))
}

/// 在阻塞线程中执行单方向的 splice 循环
/// 创建专用 pipe 并循环传输直到 EOF
#[cfg(target_os = "linux")]
fn splice_loop(
    src_fd: std::os::unix::io::RawFd,
    dst_fd: std::os::unix::io::RawFd,
) -> Result<u64, nix::Error> {
    use nix::unistd::pipe;
    use std::os::unix::io::{FromRawFd, OwnedFd};

    // 每个方向使用独立的 pipe
    let (pipe_read, pipe_write) = pipe()?;
    let pipe_read = unsafe { OwnedFd::from_raw_fd(pipe_read) };
    let pipe_write = unsafe { OwnedFd::from_raw_fd(pipe_write) };

    use std::os::unix::io::AsRawFd;
    let pipe_read_fd = pipe_read.as_raw_fd();
    let pipe_write_fd = pipe_write.as_raw_fd();

    const SPLICE_SIZE: usize = 65536; // 64KB
    let mut total_bytes: u64 = 0;

    loop {
        match splice_one_direction(src_fd, dst_fd, pipe_read_fd, pipe_write_fd, SPLICE_SIZE) {
            Ok(0) => break, // EOF
            Ok(n) => total_bytes += n as u64,
            Err(nix::Error::EAGAIN) => {
                // 非阻塞模式下暂时无数据，短暂休眠后重试
                std::thread::sleep(std::time::Duration::from_micros(100));
            }
            Err(e) => return Err(e),
        }
    }

    Ok(total_bytes)
}

/// 使用 splice 在单个方向上传输数据
/// src_fd -> pipe_write -> pipe_read -> dst_fd
#[cfg(target_os = "linux")]
fn splice_one_direction(
    src_fd: std::os::unix::io::RawFd,
    dst_fd: std::os::unix::io::RawFd,
    pipe_read: std::os::unix::io::RawFd,
    pipe_write: std::os::unix::io::RawFd,
    max_len: usize,
) -> Result<usize, nix::Error> {
    use nix::fcntl::{splice, SpliceFFlags};

    // 第一次 splice：从 src_fd 读取到 pipe
    let n = splice(
        src_fd,
        None,
        pipe_write,
        None,
        max_len,
        SpliceFFlags::SPLICE_F_NONBLOCK | SpliceFFlags::SPLICE_F_MOVE,
    )?;

    if n == 0 {
        return Ok(0); // EOF
    }

    // 第二次 splice：从 pipe 写入到 dst_fd
    let mut written = 0;
    while written < n {
        let w = splice(
            pipe_read,
            None,
            dst_fd,
            None,
            n - written,
            SpliceFFlags::SPLICE_F_NONBLOCK | SpliceFFlags::SPLICE_F_MOVE,
        )?;
        written += w;
    }

    Ok(n)
}
