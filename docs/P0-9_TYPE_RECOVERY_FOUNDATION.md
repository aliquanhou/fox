# P0-9 Type Recovery Foundation Sprint

**阶段**: P0-9
**目标**: 基于字段访问频率生成类型候选提示
**基线**: `6efb2d2` (P0-8.6 Audit)
**日期**: 2026-09-11

---

## 1. 修改文件

| 文件 | 修改内容 |
|------|----------|
| `crates/fox-decompiler/src/emitter.rs` | 在结构证据注释中添加 type 字段访问频率推断 |

**未修改**: SSA、Memory SSA、Expression Recovery、CFG、ConditionRecovery、CallGraph、DynamicPluginResolver、Structured IR 等所有已封板模块。

---

## 2. 实现方法

### 2.1 类型推断规则

基于字段访问频率（单函数内）：

| 访问次数 | 类型候选 | 说明 |
|----------|----------|------|
| >= 10 | `DWORD/state (high-frequency)` | 高频状态字段 |
| 3-9 | `DWORD (medium-frequency)` | 中频访问 |
| 1-2 | `UNKNOWN` | 低频，证据不足 |

### 2.2 输出格式

```c
/* P0-8.5 Structure Evidence:
 * Object: global_46E920
 *   Fields: 9 unique, 24 total accesses
 *   +0x14       size:4  accesses:1    type:UNKNOWN
 *   +0x18       size:4  accesses:2    type:UNKNOWN
 *   +0xDBDD44   size:4  accesses:12   type:DWORD/state (high-frequency)
 *   Clusters (1): +0x14..+0x18 (8 bytes, 2 fields)
 *   Confidence: MEDIUM
 */
```

---

## 3. NtcMach 真实 Dogfood

| 指标 | 数值 |
|------|------|
| 339 OK | ✅ 保持 |
| 类型注释输出 | 97 个函数 |
| 高频字段识别 | +0xDBDD44 (12 accesses) |

---

## 4. 已知限制（GAP）

### GAP-P0-9-USAGE-PATTERN（P1）
当前只基于访问频率推断，不分析字段被如何使用（cmp? call? dereference?）。
真正的类型推断需要：
- 字段被 `call` 使用 → Pointer
- 字段被 `cmp + jcc` → BooleanLike
- 字段被解引用 → Pointer

### GAP-P0-9-CROSS-FUNCTION（P1）
当前统计在单函数内。跨函数汇总后类型置信度会更高。

### GAP-P0-9-POINTER-DETECTION（P2）
未检测指针类型。需要分析：
- `mov reg, [field]` → 可能是 pointer
- `mov [reg+offset], val` → reg 是 pointer

---

## 5. Tests

| 测试套件 | 结果 |
|----------|------|
| fox-decompiler lib tests | 42 PASS |
| 全部 integration tests | 27 PASS |
| **总计** | **69 PASS, 0 FAIL** |

- `cargo fmt`: PASS
- `cargo clippy --all-targets -- -D warnings`: PASS

---

## 6. 结论

P0-9 在结构证据注释中添加了基于访问频率的类型候选提示。这是类型恢复的第一步——先标记高频状态字段，后续再基于使用模式推断更精确的类型。

**状态**: IMPLEMENTATION COMPLETE → WAITING FOR AUDIT
