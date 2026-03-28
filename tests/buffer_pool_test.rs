mod common;

use std::sync::Arc;

use exsocks::buffer_pool::BufferPool;

#[test]
fn test_get_put_reuse() {
    let pool = BufferPool::new(4, 1024);

    // 第一次 get：池空，分配新缓冲区
    let buf = pool.get();
    assert_eq!(buf.capacity(), 1024);
    let ptr = buf.as_ptr();

    // 归还到池中
    pool.put(buf);

    // 第二次 get：应该从池中取出同一块内存
    let buf2 = pool.get();
    assert_eq!(buf2.as_ptr(), ptr, "Should reuse the same buffer from pool");
    assert_eq!(buf2.len(), 0, "Returned buffer should be cleared");
    assert_eq!(buf2.capacity(), 1024);
}

#[test]
fn test_pool_full_discard() {
    let pool = BufferPool::new(2, 512);

    // 填满池
    let buf1 = Vec::with_capacity(512);
    let buf2 = Vec::with_capacity(512);
    pool.put(buf1);
    pool.put(buf2);

    // 再放一个，应该被丢弃（不 panic）
    let buf3 = Vec::with_capacity(512);
    pool.put(buf3);

    // 池中只有 2 个
    let _ = pool.get();
    let _ = pool.get();
    // 第三次 get 应该是新分配的
    let buf_new = pool.get();
    assert_eq!(buf_new.capacity(), 512);
}

#[test]
fn test_pool_empty_allocate() {
    let pool = BufferPool::new(2, 256);

    // 连续 get 超过池容量，每次都应该成功
    let bufs: Vec<_> = (0..10).map(|_| pool.get()).collect();
    for buf in &bufs {
        assert_eq!(buf.capacity(), 256);
    }
}

#[test]
fn test_concurrent_get_put() {
    use std::thread;

    let pool = Arc::new(BufferPool::new(64, 1024));
    let mut handles = Vec::new();

    for _ in 0..16 {
        let pool = pool.clone();
        let handle = thread::spawn(move || {
            for _ in 0..100 {
                let mut buf = pool.get();
                assert_eq!(buf.capacity(), 1024);
                // 模拟使用
                buf.extend_from_slice(&[42u8; 128]);
                pool.put(buf);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread should not panic");
    }
}

#[test]
fn test_buffer_size_query() {
    let pool = BufferPool::new(8, 65536);
    assert_eq!(pool.buffer_size(), 65536);

    let pool2 = BufferPool::new(4, 1024);
    assert_eq!(pool2.buffer_size(), 1024);
}
