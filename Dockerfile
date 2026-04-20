# ==========================================
# 阶段 1: 构建阶段 (Builder)
# ==========================================
FROM rust:1-slim-bookworm AS builder

ARG APP_VERSION
ARG GIT_COMMIT
ARG BUILD_TIME
ARG USE_CHINA_MIRROR=false

WORKDIR /app

RUN set -eux; \
    if [ "$USE_CHINA_MIRROR" = "true" ]; then \
        echo '' > /etc/apt/sources.list.d/debian.sources; \
        echo 'deb http://mirrors.aliyun.com/debian/ bookworm main non-free non-free-firmware contrib' > /etc/apt/sources.list; \
        echo 'deb-src http://mirrors.aliyun.com/debian/ bookworm main non-free non-free-firmware contrib' >> /etc/apt/sources.list; \
        echo 'deb http://mirrors.aliyun.com/debian-security/ bookworm-security main' >> /etc/apt/sources.list; \
        echo 'deb-src http://mirrors.aliyun.com/debian-security/ bookworm-security main' >> /etc/apt/sources.list; \
        echo 'deb http://mirrors.aliyun.com/debian/ bookworm-updates main non-free non-free-firmware contrib' >> /etc/apt/sources.list; \
        echo 'deb-src http://mirrors.aliyun.com/debian/ bookworm-updates main non-free non-free-firmware contrib' >> /etc/apt/sources.list; \
        echo 'deb http://mirrors.aliyun.com/debian/ bookworm-backports main non-free non-free-firmware contrib' >> /etc/apt/sources.list; \
        echo 'deb-src http://mirrors.aliyun.com/debian/ bookworm-backports main non-free non-free-firmware contrib' >> /etc/apt/sources.list; \
    fi; \
    apt-get update && apt-get install -y \
    make \
    && rm -rf /var/lib/apt/lists/*

# ========== 配置 Cargo 镜像源（仅国内环境） ==========
ENV CARGO_HOME=/root/.cargo
ENV PATH="/root/.cargo/bin:${PATH}"

RUN mkdir -p $CARGO_HOME && \
    if [ "$USE_CHINA_MIRROR" = "true" ]; then \
        echo '[source.crates-io]' > $CARGO_HOME/config.toml && \
        echo "replace-with = 'rsproxy-sparse'" >> $CARGO_HOME/config.toml && \
        echo '[source.rsproxy]' >> $CARGO_HOME/config.toml && \
        echo 'registry = "https://rsproxy.cn/crates.io-index"' >> $CARGO_HOME/config.toml && \
        echo '[source.rsproxy-sparse]' >> $CARGO_HOME/config.toml && \
        echo 'registry = "sparse+https://rsproxy.cn/index/"' >> $CARGO_HOME/config.toml && \
        echo '[registries.rsproxy]' >> $CARGO_HOME/config.toml && \
        echo 'index = "https://rsproxy.cn/crates.io-index"' >> $CARGO_HOME/config.toml && \
        echo '[net]' >> $CARGO_HOME/config.toml && \
        echo 'git-fetch-with-cli = true' >> $CARGO_HOME/config.toml; \
    fi

# 1. 先复制依赖文件，利用 Docker 缓存层
COPY Cargo.toml Cargo.lock ./
COPY Makefile ./Makefile

# 2. 创建虚拟项目结构，预编译依赖（使用与正式构建相同的 target 路径）
RUN mkdir -p src benches && \
    echo "fn main() {}" > src/main.rs && \
    echo "fn main() {}" > benches/domain_match_bench.rs && \
    make build-release && \
    rm -rf src benches

# 3. 复制真实源码并构建
COPY src ./src
COPY build.rs ./build.rs
COPY benches ./benches

# 使用 touch 确保 cargo 重新编译（因为 main.rs 时间戳更新了）
RUN touch src/main.rs && \
    make build-release

# ==========================================
# 阶段 2: 运行阶段 (Runtime)
# ==========================================
FROM debian:bookworm-slim AS runtime

ARG APP_VERSION
ARG GIT_COMMIT
ARG BUILD_TIME
ARG USE_CHINA_MIRROR=false

# 元数据
LABEL org.opencontainers.image.version="${APP_VERSION}"
LABEL org.opencontainers.image.revision="${GIT_COMMIT}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"

WORKDIR /app

# 安装运行时依赖
RUN set -eux; \
    if [ "$USE_CHINA_MIRROR" = "true" ]; then \
        echo '' > /etc/apt/sources.list.d/debian.sources; \
        echo 'deb http://mirrors.aliyun.com/debian/ bookworm main non-free non-free-firmware contrib' > /etc/apt/sources.list; \
        echo 'deb-src http://mirrors.aliyun.com/debian/ bookworm main non-free non-free-firmware contrib' >> /etc/apt/sources.list; \
        echo 'deb http://mirrors.aliyun.com/debian-security/ bookworm-security main' >> /etc/apt/sources.list; \
        echo 'deb-src http://mirrors.aliyun.com/debian-security/ bookworm-security main' >> /etc/apt/sources.list; \
        echo 'deb http://mirrors.aliyun.com/debian/ bookworm-updates main non-free non-free-firmware contrib' >> /etc/apt/sources.list; \
        echo 'deb-src http://mirrors.aliyun.com/debian/ bookworm-updates main non-free non-free-firmware contrib' >> /etc/apt/sources.list; \
        echo 'deb http://mirrors.aliyun.com/debian/ bookworm-backports main non-free non-free-firmware contrib' >> /etc/apt/sources.list; \
        echo 'deb-src http://mirrors.aliyun.com/debian/ bookworm-backports main non-free non-free-firmware contrib' >> /etc/apt/sources.list; \
    fi; \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        curl \
        procps \
        iproute2 \
	; \
	rm -rf /var/lib/apt/lists/*

# 复制配置文件
COPY example ./

# 从构建阶段复制二进制文件
COPY --from=builder /app/target/*/release/exsocks /app/exsocks

CMD ["/app/exsocks", "-c", "server.yaml"]