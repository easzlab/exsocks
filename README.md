# exsocks

[English](README_EN.md) | 中文

**exsocks** 是一个用 Rust 编写的高性能 SOCKS5 代理服务器，基于 [Tokio](https://tokio.rs/) 异步运行时构建，专注于性能、安全性和可运维性。

## ✨ 特性

- **高性能异步架构** — 基于 Tokio epoll/kqueue 事件驱动，单进程可处理数万并发连接
- **SOCKS5 协议** — 完整实现 [RFC 1928](docs/protocol/RFC1928.txt) CONNECT 命令，支持 IPv4 / IPv6 / 域名地址类型
- **用户认证** — 支持 [RFC 1929](docs/protocol/RFC1929.txt) 用户名/密码认证，凭证文件热加载
- **源地址白名单** — 基于 CIDR 规则的客户端 IP 访问控制，配置文件热加载
- **DNS 缓存** — 内置 DNS 解析缓存（正缓存 + 负缓存），减少重复 DNS 查询
- **缓冲区对象池** — 基于无锁 `ArrayQueue` 的缓冲区复用，降低高频短连接场景下的堆分配开销
- **可配置缓冲区** — 转发缓冲区大小可调（16 KiB ~ 256 KiB），适配不同网络场景
- **结构化日志** — 基于 `tracing`，支持按天滚动、文件大小滚动、最大保留天数
- **多层配置** — 支持 YAML 配置文件 + 环境变量 + 命令行参数，优先级递增
- **Docker 支持** — 提供多阶段构建 Dockerfile，生产就绪
- **优雅关闭** — 支持 `Ctrl+C` 信号优雅关闭，等待活跃连接完成

## 📦 安装

### 从源码构建

```bash
# 克隆仓库
git clone <repo-url>
cd exsocks

# 开发构建
make build

# 生产优化构建（启用 LTO + 单 codegen unit）
make build-release

# 剥离符号表，减小二进制体积
make strip
```

### Docker

```bash
# 构建镜像
make docker-build

# 运行容器
make docker-run
```

## 🚀 快速开始

### 最简启动

```bash
# 使用默认配置启动（监听 127.0.0.1:1080，无认证）
./exsocks
```

### 指定配置文件

```bash
./exsocks --config example/server.yaml
```

### 命令行参数

```bash
./exsocks --bind 0.0.0.0:1080 --log-level debug
```

### 使用 curl 测试

```bash
curl -x socks5h://127.0.0.1:1080 https://httpbin.org/ip
```

## ⚙️ 配置

exsocks 支持多层配置，优先级从低到高：

1. **系统配置**：`~/.config/exsocks/server.yaml`
2. **当前目录**：`./config/server.yaml`
3. **命令行指定**：`--config <path>`
4. **环境变量**：`EXSOCKS_*`（如 `EXSOCKS_BIND`）

### 完整配置示例

```yaml
# 服务器监听地址
bind: "0.0.0.0:1080"

# 连接目标超时时间（秒）
connect_timeout: 10

# 日志配置
log_dir: "/var/log/exsocks"
log_level: "info"
log_max_files: 7
log_max_size: 104857600  # 100MB

# 转发缓冲区大小（字节），默认 64KB
relay_buffer_size: 65536

# 缓冲区对象池容量，0 = 使用默认值 2048
relay_pool_capacity: 0

# DNS 缓存配置
dns_cache_ttl: 300            # 正缓存 TTL（秒）
dns_cache_max_entries: 1024   # 最大缓存条目数
dns_cache_negative_ttl: 30    # 负缓存 TTL（秒）

# 认证配置
auth_enabled: false
auth_user_file: "user.yaml"

# 源地址白名单
access_enabled: false
access_file: "client-rules.yaml"
```

### 用户认证配置（`user.yaml`）

启用认证后（`auth_enabled: true`），客户端必须提供有效的用户名和密码。该文件支持**热加载**，修改后自动生效。

```yaml
users:
  - username: "admin"
    password: "admin123"
  - username: "user1"
    password: "pass1"
```

### 源地址白名单配置（`client-rules.yaml`）

启用白名单后（`access_enabled: true`），仅允许匹配 CIDR 规则的客户端 IP 连接。该文件支持**热加载**。

```yaml
client_rules:
  - 10.0.0.0/8
  - 192.168.0.0/16
  - 127.0.0.1/32
```

## 🏗️ 架构

### 连接处理流程

```
Accept → 白名单检查 → SOCKS5 握手 → 认证 → 请求解析 → DNS 解析 → 连接目标 → 双向转发
```

### 模块结构

```
src/
├── main.rs           # 程序入口、命令行解析、日志初始化
├── config.rs         # 多层配置管理（YAML + 环境变量 + CLI）
├── server.rs         # TCP 服务器核心逻辑、连接生命周期管理
├── socks5/
│   ├── mod.rs        # SOCKS5 模块导出
│   ├── protocol.rs   # 协议常量和类型定义
│   ├── handshake.rs  # 握手和认证协商
│   ├── request.rs    # CONNECT 请求解析
│   └── reply.rs      # 响应构建
├── relay.rs          # 异步双向数据转发（可配置缓冲区）
├── buffer_pool.rs    # 无锁缓冲区对象池（crossbeam ArrayQueue）
├── dns_cache.rs      # DNS 解析缓存（正缓存 + 负缓存）
├── auth.rs           # 用户认证存储与热加载（ArcSwap + notify）
├── access.rs         # 源地址白名单与热加载
├── error.rs          # 统一错误类型
└── lib.rs            # 库入口
```

### 性能设计要点

| 阶段 | 设计 | 说明 |
|------|------|------|
| **连接接受** | epoll/kqueue 事件驱动 | `tokio::spawn` 轻量异步 task |
| **握手/请求解析** | 栈上固定缓冲区 | 零堆分配，系统调用次数最小化 |
| **DNS 解析** | `DashMap` 并发缓存 | 正/负缓存分离 TTL，惰性淘汰 |
| **数据转发** | `BufReader` + `copy_buf` | 可配置缓冲区（默认 64 KiB），纯异步 |
| **缓冲区管理** | 无锁对象池 | `ArrayQueue` 单次 CAS，高并发无竞争 |
| **认证/白名单** | `ArcSwap` 无锁读 | 热加载时原子替换，读路径零开销 |

## 🧪 测试

```bash
# 运行所有测试
make test

# 仅单元测试
make unit-test

# 仅集成测试
make integration-test

# Docker 容器内测试（适用于 macOS 开发环境）
make test-docker

# 测试覆盖率（仅 Linux，需安装 cargo-tarpaulin）
make coverage
```

## 📄 协议参考

- [RFC 1928 — SOCKS Protocol Version 5](docs/protocol/RFC1928.txt)
- [RFC 1929 — Username/Password Authentication for SOCKS V5](docs/protocol/RFC1929.txt)

## 📝 License

MIT
