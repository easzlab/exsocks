# exsocks

English | [中文](README_CN.md)

**exsocks** is a high-performance SOCKS5 proxy server written in Rust, built on the [Tokio](https://tokio.rs/) async runtime, focusing on performance, security, and operability.

## ✨ Features

- **High-Performance Async Architecture** — Powered by Tokio epoll/kqueue event-driven I/O, capable of handling tens of thousands of concurrent connections in a single process
- **SOCKS5 Protocol** — Full implementation of [RFC 1928](docs/protocol/RFC1928.txt) CONNECT command, supporting IPv4 / IPv6 / domain name address types
- **User Authentication** — [RFC 1929](docs/protocol/RFC1929.txt) username/password authentication with hot-reloadable credential files
- **Source IP Whitelist** — CIDR-based client IP access control with hot-reloadable configuration
- **Target Address Rules** — Supports PASS/BLOCK control via DOMAIN/DOMAIN-SUFFIX/IP-CIDR rules with priority-based matching; domain suffix matching optimized with reverse Trie, IP-CIDR matching optimized with Radix Trie
- **DNS Cache** — Built-in DNS resolution cache (positive + negative caching) to reduce redundant DNS queries
- **Configurable Buffers** — Adjustable relay buffer size (16 KiB ~ 256 KiB) for different network scenarios
- **Prometheus Monitoring** — Built-in Prometheus metrics endpoint with 9 core metrics (connections, bytes, auth, DNS cache, etc.), zero-overhead atomic operations
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

# Build image
make build-docker
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

Full Configuration Example (example/server.yaml)

## 📊 Prometheus Metrics

Enable `metrics_enabled: true` to expose a `/metrics` HTTP endpoint at the `metrics_bind` address for Prometheus scraping.

### Metrics List

| Type | Metric Name | Labels | Description |
|------|-------------|--------|-------------|
| Gauge | `exsocks_active_connections` | - | Current active connections |
| Counter | `exsocks_connections_total` | `status`=accepted/blocked | Total connections |
| Counter | `exsocks_bytes_total` | `direction`=up/down | Total bytes transferred |
| Counter | `exsocks_connect_target_errors_total` | - | Total target connection failures |
| Counter | `exsocks_auth_total` | `result`=success/failure | Authentication results |
| Counter | `exsocks_dns_cache_total` | `result`=hit/miss | DNS cache hit/miss |
| Counter | `exsocks_dns_resolve_total` | `result`=success/failure | DNS resolution results |
| Counter | `exsocks_target_rule_total` | `action`=pass/block | Target rule evaluations |
| Gauge | `exsocks_dns_cache_entries` | - | Current DNS cache entries |

### Prometheus Scrape Config

```yaml
scrape_configs:
  - job_name: 'exsocks'
    static_configs:
      - targets: ['127.0.0.1:9090']
```

### Performance Impact

All metric operations use lock-free atomic operations (`fetch_add`), ~5-10ns per operation, with no mutex contention or memory allocation. When `metrics_enabled: false`, the no-op recorder path costs ~1-2ns.

## 🏗️ Architecture

### Connection Processing Pipeline

```
Accept → Whitelist Check → SOCKS5 Handshake → Auth → Request Parse → DNS Resolve → Connect Target → Bidirectional Relay
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
make test-unit

# Integration tests only
make test-integration

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
