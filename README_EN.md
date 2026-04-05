# exsocks

English | [中文](README.md)

**exsocks** is a high-performance SOCKS5 proxy server written in Rust, built on the [Tokio](https://tokio.rs/) async runtime, focusing on performance, security, and operability.

## ✨ Features

- **High-Performance Async Architecture** — Powered by Tokio epoll/kqueue event-driven I/O, capable of handling tens of thousands of concurrent connections in a single process
- **SOCKS5 Protocol** — Full implementation of [RFC 1928](docs/protocol/RFC1928.txt) CONNECT command, supporting IPv4 / IPv6 / domain name address types
- **User Authentication** — [RFC 1929](docs/protocol/RFC1929.txt) username/password authentication with hot-reloadable credential files
- **Source IP Whitelist** — CIDR-based client IP access control with hot-reloadable configuration
- **Target Address Rules** — Supports PASS/BLOCK control via DOMAIN/DOMAIN-SUFFIX/IP-CIDR rules with priority-based matching; domain suffix matching optimized with reverse Trie, IP-CIDR matching optimized with Radix Trie
- **DNS Cache** — Built-in DNS resolution cache (positive + negative caching) to reduce redundant DNS queries
- **Configurable Buffers** — Adjustable relay buffer size (16 KiB ~ 256 KiB) for different network scenarios
- **Structured Logging** — Built on `tracing`, supports daily rotation, size-based rotation, and max file retention
- **Layered Configuration** — YAML config files + environment variables + CLI arguments with ascending priority
- **Docker Support** — Multi-stage build Dockerfile, production-ready
- **Graceful Shutdown** — Supports `Ctrl+C` signal for graceful shutdown, waiting for active connections to complete

## 📦 Installation

### Build from Source

```bash
# Clone the repository
git clone <repo-url>
cd exsocks

# Development build
make build

# Production optimized build (LTO + single codegen unit)
make build-release

# Strip symbols to reduce binary size
make strip
```

### Docker

```bash
# Build image
make docker-build

# Run container
make docker-run
```

## 🚀 Quick Start

### Minimal Startup

```bash
# Start with default config (listen on 127.0.0.1:1080, no auth)
./exsocks
```

### Specify Config File

```bash
./exsocks --config example/server.yaml
```

### CLI Arguments

```bash
./exsocks --bind 0.0.0.0:1080 --log-level debug
```

### Test with curl

```bash
curl -x socks5h://127.0.0.1:1080 https://httpbin.org/ip
```

## ⚙️ Configuration

exsocks supports layered configuration with ascending priority:

1. **System config**: `~/.config/exsocks/server.yaml`
2. **Current directory**: `./config/server.yaml`
3. **CLI specified**: `--config <path>`
4. **Environment variables**: `EXSOCKS_*` (e.g., `EXSOCKS_BIND`)

### Full Configuration Example

```yaml
# Server listen address
bind: "0.0.0.0:1080"

# Target connection timeout (seconds)
connect_timeout: 10

# Logging
log_dir: "/var/log/exsocks"
log_level: "info"
log_max_files: 7
log_max_size: 104857600  # 100MB

# Relay buffer size (bytes), default 64KB
relay_buffer_size: 65536

# DNS cache
dns_cache_ttl: 300            # Positive cache TTL (seconds)
dns_cache_max_entries: 1024   # Max cache entries
dns_cache_negative_ttl: 30    # Negative cache TTL (seconds)

# Authentication
auth_enabled: false
auth_user_file: "user.yaml"

# Source IP whitelist
access_enabled: false
access_file: "client-rules.yaml"
```

### User Authentication (`user.yaml`)

When authentication is enabled (`auth_enabled: true`), clients must provide valid credentials. This file supports **hot-reloading** — changes take effect automatically.

```yaml
users:
  - username: "admin"
    password: "admin123"
  - username: "user1"
    password: "pass1"
```

### Source IP Whitelist (`client-rules.yaml`)

When whitelist is enabled (`access_enabled: true`), only client IPs matching CIDR rules are allowed to connect. This file supports **hot-reloading**.

```yaml
client_rules:
  - 10.0.0.0/8
  - 192.168.0.0/16
  - 127.0.0.1/32
```

## 🏗️ Architecture

### Connection Processing Pipeline

```
Accept → Whitelist Check → SOCKS5 Handshake → Auth → Request Parse → DNS Resolve → Connect Target → Bidirectional Relay
```

### Module Structure

```
src/
├── main.rs           # Entry point, CLI parsing, logging initialization
├── config.rs         # Layered config management (YAML + env + CLI)
├── server.rs         # TCP server core logic, connection lifecycle
├── socks5/
│   ├── mod.rs        # SOCKS5 module exports
│   ├── protocol.rs   # Protocol constants and type definitions
│   ├── handshake.rs  # Handshake and auth negotiation
│   ├── request.rs    # CONNECT request parsing
│   └── reply.rs      # Response building
├── relay.rs          # Async bidirectional data relay (configurable buffers)
├── dns_cache.rs      # DNS resolution cache (positive + negative caching)
├── auth.rs           # User credential store with hot-reload (ArcSwap + notify)
├── access.rs         # Source IP whitelist with hot-reload
├── error.rs          # Unified error types
└── lib.rs            # Library entry
```

### Performance Design Highlights

| Stage | Design | Details |
|-------|--------|---------|
| **Accept** | epoll/kqueue event-driven | Lightweight async tasks via `tokio::spawn` |
| **Handshake/Parsing** | Stack-allocated fixed buffers | Zero heap allocation, minimal syscalls |
| **DNS Resolution** | `DashMap` concurrent cache | Separate TTLs for positive/negative cache, lazy eviction |
| **Data Relay** | `BufReader` + `copy_buf` | Configurable buffer (default 64 KiB), fully async |
| **Auth/Whitelist** | `ArcSwap` lock-free reads | Atomic swap on hot-reload, zero overhead on read path |

## 🧪 Testing

```bash
# Run all tests
make test

# Unit tests only
make unit-test

# Integration tests only
make integration-test

# Run tests in Docker container (useful for macOS dev environments)
make test-docker

# Test coverage (Linux only, requires cargo-tarpaulin)
make coverage
```

## 📄 Protocol References

- [RFC 1928 — SOCKS Protocol Version 5](docs/protocol/RFC1928.txt)
- [RFC 1929 — Username/Password Authentication for SOCKS V5](docs/protocol/RFC1929.txt)

## 📝 License

MIT
