# =============================================================================
# exsocks Makefile
# 功能：构建、测试、Docker 全生命周期管理
# 兼容：macOS (Intel/Apple Silicon) + Linux (x86_64/aarch64)
# =============================================================================

# -----------------------------------------------------------------------------
# 配置变量
# -----------------------------------------------------------------------------

# 应用信息
APP_NAME := exsocks
APP_VERSION := $(shell cargo metadata --no-deps --format-version 1 2>/dev/null | grep -o '"version":"[^"]*"' | head -1 | grep -o '[0-9][0-9.]*')
APP_VERSION := $(or $(APP_VERSION),0.1.0)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u +%Y%m%d-%H%M%S)

# 自动检测当前平台的 Rust target triple
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Darwin)
  ifeq ($(UNAME_M),arm64)
    DEFAULT_TARGET := aarch64-apple-darwin
  else
    DEFAULT_TARGET := x86_64-apple-darwin
  endif
else
  ifeq ($(UNAME_M),aarch64)
    DEFAULT_TARGET := aarch64-unknown-linux-gnu
  else
    DEFAULT_TARGET := x86_64-unknown-linux-gnu
  endif
endif

TARGET ?= $(DEFAULT_TARGET)

# 构建配置
CARGO_FLAGS :=

# 目录
BUILD_DIR := target
RELEASE_DIR := $(BUILD_DIR)/$(TARGET)/release
DIST_DIR := $(BUILD_DIR)/dist
EXAMPLE_DIR := example

# Docker 配置
DOCKER_REGISTRY ?= docker.io
DOCKER_IMAGE := $(DOCKER_REGISTRY)/easzlab/$(APP_NAME)
DOCKER_TAG := $(APP_VERSION)

# 颜色输出
BLUE := \033[36m
GREEN := \033[32m
YELLOW := \033[33m
RED := \033[31m
NC := \033[0m

# -----------------------------------------------------------------------------
# 默认目标
# -----------------------------------------------------------------------------

.PHONY: all
all: check build test

# -----------------------------------------------------------------------------
# 帮助信息
# -----------------------------------------------------------------------------

.PHONY: help
help: ## 显示帮助信息
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# -----------------------------------------------------------------------------
# 开发环境
# -----------------------------------------------------------------------------

.PHONY: setup
setup: ## 初始化开发环境
	@echo "$(BLUE)=== 安装开发依赖 ===$(NC)"
	rustup component add rustfmt clippy llvm-tools-preview
	cargo install cargo-audit cargo-watch cargo-tarpaulin
	@echo "$(GREEN)✓ 开发环境就绪$(NC)"

.PHONY: update
update: ## 更新依赖
	@echo "$(BLUE)=== 更新 Rust 工具链 ===$(NC)"
	rustup update
	@echo "$(BLUE)=== 更新 Cargo 依赖 ===$(NC)"
	cargo update
	cargo upgrade --compatible
	@echo "$(GREEN)✓ 更新完成$(NC)"

# -----------------------------------------------------------------------------
# 代码质量
# -----------------------------------------------------------------------------

.PHONY: check
check: ## 格式化后编译检查
	@echo "$(BLUE)=== 自动格式化后编译检查 ===$(NC)"
	cargo fmt
	cargo check
	@echo "$(GREEN)✓ 编译检查完成$(NC)"

.PHONY: audit
audit: ## 安全审计（需安装 cargo-audit）
	@echo "$(BLUE)=== 安全审计 ===$(NC)"
	cargo audit

# -----------------------------------------------------------------------------
# 构建
# -----------------------------------------------------------------------------

.PHONY: build
build: ## 开发构建
	@echo "$(BLUE)=== 开发构建 [$(TARGET)] ===$(NC)"
	cargo build $(CARGO_FLAGS)

.PHONY: build-release
build-release: ## 生产优化构建
	@echo "$(BLUE)=== 生产构建 [$(TARGET)] ===$(NC)"
	@echo "版本: $(APP_VERSION), 提交: $(GIT_COMMIT), 时间: $(BUILD_TIME)"
	cargo build --release --target $(TARGET)
	@echo "$(GREEN)✓ 构建完成: $(RELEASE_DIR)/$(APP_NAME)$(NC)"

# 静态编译目标列表（musl，不依赖系统 GLIBC）
STATIC_TARGETS := x86_64-unknown-linux-musl aarch64-unknown-linux-musl

.PHONY: build-static
build-static: ## 静态编译 Linux 双架构（musl，不依赖 GLIBC）
	@echo "$(BLUE)=== 静态编译 [musl] ===$(NC)"
	@echo "版本: $(APP_VERSION), 提交: $(GIT_COMMIT), 时间: $(BUILD_TIME)"
	@echo "目标: $(STATIC_TARGETS)"
	@mkdir -p $(DIST_DIR)
	rustup target add $(STATIC_TARGETS)
	@for t in $(STATIC_TARGETS); do \
		echo "$(BLUE)--- 构建 [$t] ---$(NC)"; \
		cargo build --release --target $t || exit 1; \
		cp $(BUILD_DIR)/$t/release/$(APP_NAME) $(DIST_DIR)/$(APP_NAME)-$t; \
		echo "$(GREEN)✓ $(DIST_DIR)/$(APP_NAME)-$t$(NC)"; \
	done
	@echo "$(GREEN)✓ 静态构建完成，产物位于 $(DIST_DIR)/$(NC)"

# 当前平台的交叉编译目标列表（仅编译同操作系统的两种架构）
ifeq ($(UNAME_S),Darwin)
  BUILD_TARGETS := aarch64-apple-darwin x86_64-apple-darwin
else
  BUILD_TARGETS := aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu
endif

.PHONY: build-all
build-all: ## 编译当前操作系统的 arm64/amd64 双架构
	@echo "$(BLUE)=== 编译双架构 [$(UNAME_S)] ===$(NC)"
	@echo "版本: $(APP_VERSION), 提交: $(GIT_COMMIT), 时间: $(BUILD_TIME)"
	@echo "目标: $(BUILD_TARGETS)"
	@mkdir -p $(DIST_DIR)
	rustup target add $(BUILD_TARGETS)
	@for t in $(BUILD_TARGETS); do \
		echo "$(BLUE)--- 构建 [$$t] ---$(NC)"; \
		cargo build --release --target $t || exit 1; \
		cp $(BUILD_DIR)/$$t/release/$(APP_NAME) $(DIST_DIR)/$(APP_NAME)-$$t; \
		echo "$(GREEN)✓ $(DIST_DIR)/$(APP_NAME)-$$t$(NC)"; \
	done
	@echo "$(GREEN)✓ 构建完成，产物位于 $(DIST_DIR)/$(NC)"

.PHONY: build-docker
build-docker: ## 构建 Docker 镜像（本地默认启用国内镜像源，USE_CHINA_MIRROR=false 可关闭）
	@echo "$(BLUE)=== Docker 构建 ===$(NC)"
	docker build \
		--build-arg APP_VERSION=$(APP_VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		--build-arg USE_CHINA_MIRROR=$(or $(USE_CHINA_MIRROR),true) \
		-t $(DOCKER_IMAGE):v$(DOCKER_TAG) \
		-t $(DOCKER_IMAGE):latest \
		.
	@echo "$(GREEN)✓ 镜像: $(DOCKER_IMAGE):v$(DOCKER_TAG)$(NC)"

# -----------------------------------------------------------------------------
# 测试
# -----------------------------------------------------------------------------

.PHONY: test
test: test-unit test-integration ## 运行所有测试

.PHONY: test-unit
test-unit: ## 单元测试
	@echo "$(BLUE)=== 单元测试 ===$(NC)"
	cargo test --lib -- --nocapture

.PHONY: test-integration
test-integration: ## 集成测试
	@echo "$(BLUE)=== 集成测试 ===$(NC)"
	cargo test --test '*' -- --nocapture

.PHONY: test-docker
test-docker: ## 在测试容器中运行测试用例（本地默认启用国内镜像源，USE_CHINA_MIRROR=false 可关闭）
	@echo "Running containerized tests for macOS/Linux..."
	@USE_CHINA_MIRROR=$(or $(USE_CHINA_MIRROR),true) bash tests/run-test-container.sh
	@echo "✓ Containerized tests completed"

.PHONY: test-bench
test-bench: ## 基准测试
	@echo "$(BLUE)=== 基准测试 ===$(NC)"
	cargo bench --features bench --bench domain_match_bench
	cargo bench --bench cidr_match_bench

.PHONY: coverage
coverage: ## 生成测试覆盖率报告（需安装 cargo-tarpaulin，仅 Linux）
	@echo "$(BLUE)=== 覆盖率测试 ===$(NC)"
	cargo tarpaulin --out Html --out Xml --output-dir $(BUILD_DIR)/coverage
	@echo "$(GREEN)✓ 报告: $(BUILD_DIR)/coverage/tarpaulin-report.html$(NC)"

# -----------------------------------------------------------------------------
# 清理
# -----------------------------------------------------------------------------

.PHONY: clean
clean: ## 清理构建产物
	cargo clean
	rm -rf $(DIST_DIR)

.PHONY: clean-all
clean-all: clean ## 完全清理（包括 Docker 镜像）
	-docker rmi $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_IMAGE):latest 2>/dev/null

# -----------------------------------------------------------------------------
# CI 专用
# -----------------------------------------------------------------------------

.PHONY: ci
ci: fmt lint test build-release ## CI 完整流程
