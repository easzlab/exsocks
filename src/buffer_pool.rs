//! 缓冲区对象池模块
//!
//! 基于 `crossbeam-queue` 的 `ArrayQueue` 实现无锁缓冲区对象池，
//! 用于复用双向转发（relay）中的 `Vec<u8>` 缓冲区，减少高频短连接场景下的
//! 堆分配/释放开销。
//!
//! ## 设计要点
//!
//! - **无锁**：`ArrayQueue` 的 `push`/`pop` 仅需一次 CAS 操作，高并发下无锁竞争
//! - **固定容量**：池容量在创建时确定，内存占用可预测
//! - **优雅降级**：池空时分配新缓冲区，池满时丢弃归还的缓冲区，不会阻塞或 panic

use crossbeam_queue::ArrayQueue;

/// 无锁缓冲区对象池
///
/// 持有一个固定容量的 `ArrayQueue<Vec<u8>>`，提供 get/put 接口
/// 用于复用预分配的字节缓冲区。
pub struct BufferPool {
    /// 空闲缓冲区队列
    queue: ArrayQueue<Vec<u8>>,
    /// 每个缓冲区的字节大小
    buffer_size: usize,
}

impl BufferPool {
    /// 创建一个新的缓冲区对象池。
    ///
    /// # 参数
    /// - `capacity`: 池中最大缓冲区数量
    /// - `buffer_size`: 每个缓冲区的字节大小
    pub fn new(capacity: usize, buffer_size: usize) -> Self {
        Self {
            queue: ArrayQueue::new(capacity),
            buffer_size,
        }
    }

    /// 从池中取出一个缓冲区。
    ///
    /// 如果池中有空闲缓冲区，直接返回；否则分配一个新的 `Vec<u8>`
    /// 并预分配 `buffer_size` 容量。
    pub fn get(&self) -> Vec<u8> {
        self.queue.pop().unwrap_or_else(|| Vec::with_capacity(self.buffer_size))
    }

    /// 归还缓冲区到池中。
    ///
    /// 归还前会清空缓冲区内容（保留已分配的容量）。
    /// 如果池已满，缓冲区将被直接丢弃（由系统回收）。
    pub fn put(&self, mut buf: Vec<u8>) {
        buf.clear();
        // 池满时 push 返回 Err，直接丢弃即可
        let _ = self.queue.push(buf);
    }

    /// 返回每个缓冲区的字节大小。
    pub fn buffer_size(&self) -> usize {
        self.buffer_size
    }
}
