# 域名匹配 Vec vs SmallVec Benchmark 对比报告

## 背景

`match_domain` 方法在后缀匹配时需要将域名按 `.` 分割并倒序收集为切片，用于 Trie 遍历。
原实现使用 `Vec<&str>`，每次调用都会触发堆分配。本次 benchmark 对比将其替换为
`SmallVec<[&str; 8]>` 后的性能差异——域名层级 ≤ 8 时 SmallVec 完全在栈上分配，零堆分配。

## 测试环境

- **硬件**: Apple Silicon (macOS)
- **Rust**: edition 2024, `--release` profile (LTO + codegen-units=1)
- **工具**: criterion 0.5, `--quick` 模式
- **日期**: 2026-04-20

## 测试设计

### 第一组：批量测试（`domain_match_vec_vs_smallvec`）

在不同规则数量（10/50/200 条 DOMAIN-SUFFIX 规则）下，对 8 个域名批量调用 `check`，
覆盖命中/未命中、不同层级深度、精确匹配/后缀匹配等场景。

**测试域名**:
- `www.baidu.com` — 3 级，命中后缀
- `item.detail.taobao.com` — 4 级，命中后缀
- `api.service.internal.alibaba.com` — 5 级，命中后缀
- `qq.com` — 2 级，命中后缀
- `api.test.unknown.xyz` — 4 级，未命中
- `a.b.c.d.e.nowhere.invalid` — 6 级，未命中
- `www.example.com` — 精确匹配命中
- `api.internal.corp.com` — 精确匹配命中

### 第二组：按深度测试（`domain_match_by_depth`）

固定 50 条规则，按域名层级深度（2-6 级）和命中/未命中分别测试。

## 测试结果

### 第一组：批量测试（8 个域名 × 1 次迭代）

| 规则数 | Vec (µs) | SmallVec (µs) | 提升幅度 |
|--------|----------|---------------|----------|
| 10 条  | 2.02     | 1.56          | **~23%** |
| 50 条  | 1.99     | 1.55          | **~22%** |
| 200 条 | 1.99     | 1.51          | **~24%** |

**关键发现**:
- SmallVec 稳定快 **22-24%**，差异显著且一致
- 规则数量（10 → 200）对性能几乎无影响（< 1%），说明 Trie 查找本身很快，瓶颈在分配上

### 第二组：按域名层级深度

| 场景 | 域名 | Vec (ns) | SmallVec (ns) | 提升幅度 |
|------|------|----------|---------------|----------|
| depth_2 | `baidu.com` | 208 | 171 | **~18%** |
| depth_3 | `www.baidu.com` | 215 | 178 | **~17%** |
| depth_4 | `api.www.baidu.com` | 221 | 184 | **~17%** |
| depth_5 | `v1.api.www.baidu.com` | 270 | 189 | **~30%** |
| depth_6 | `cn.v1.api.www.baidu.com` | 288 | 208 | **~28%** |
| depth_3_miss | `unknown.example.xyz` | 144 | 110 | **~24%** |
| depth_6_miss | `a.b.c.d.e.nowhere.invalid` | 222 | 136 | **~39%** |

**关键发现**:
- **层级越深，SmallVec 优势越大**: depth_2 快 18%，depth_6 快 28%
- **未命中场景差异最大**: depth_6_miss 快 **39%**，因为 Trie 遍历快速 break 后，分配开销在总耗时中占比更高
- 每次 `check` 调用节省约 **30-80 ns**

## 结论

SmallVec 优化值得采纳。理由：

1. **收益显著**: 平均提升 20-25%，深层域名和未命中场景提升 30-39%
2. **改动极小**: 仅修改 `match_domain` 中一行 `Vec<&str>` → `SmallVec<[&str; 8]>`
3. **无风险**: 域名层级通常 3-5 级，远小于 SmallVec 容量 8，不会退化为堆分配
4. **无可读性损失**: SmallVec API 与 Vec 完全兼容

已将 `match_domain` 正式实现替换为 SmallVec 版本，保留 Vec 版本作为 benchmark 对比基线。

## 复现方式

```bash
cargo bench --bench domain_match_bench
```

HTML 报告输出到 `target/criterion/` 目录。
