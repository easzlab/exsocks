# ==========================================
# 阶段 1: 构建阶段 (Builder)
# ==========================================
FROM rust:1-slim-bookworm AS builder

WORKDIR /app

# 1. 先复制依赖文件，利用 Docker 缓存层
COPY Cargo.toml Cargo.lock ./

# 2. 创建虚拟项目结构，预编译依赖
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# 3. 复制真实源码并构建
COPY src ./src
# 使用 touch 确保 cargo 重新编译（因为 main.rs 时间戳更新了）
RUN touch src/main.rs && \
    cargo build --release

# ==========================================
# 阶段 2: 运行阶段 (Runtime)
# ==========================================
FROM debian:bookworm-slim AS runtime

WORKDIR /app

# 安装必要的运行时依赖（如需要 SSL/TLS）
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        curl \
        procps \
        iproute2 \
	; \
	rm -rf /var/lib/apt/lists/*

# 从构建阶段复制二进制文件
COPY --from=builder /app/target/release/exsocks /app/exsocks

ENTRYPOINT ["/app/exsocks"]