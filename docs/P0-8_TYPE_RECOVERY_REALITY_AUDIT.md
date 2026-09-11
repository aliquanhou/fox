# P0-8 Type Recovery Reality Audit

**阶段**: P0-8 Reality Audit
**性质**: 只读审计，未修改任何生产代码
**基线**: `c4c00c5` (P0-7.3 SEALED)
**日期**: 2026-09-11

---

## 1. 审计目标

回答：FOX 当前对"数据是什么"的理解能力到底如何？

- 内存访问能否恢复为 base+offset 字段模式？
- 有多少内存操作数已经可以结构化？
- 最大的可读性瓶颈是什么？
- 最小下一步是什么？

---

## 2. 函数覆盖

| 指标 | 数值 |
|------|------|
| 分析函数总数 | 341（有 SSA 的函数） |
| 有内存访问的函数 | 198 |
| 内存访问覆盖率 | 58.1% |

---

## 3. Expression 层统计

| 指标 | 数值 | 说明 |
|------|------|------|
| Expression::Load（内存加载） | **144,256** | FOX 能识别内存加载 |
| Unknown expressions | **2,278,735** | 巨大数字，主要来自 phi 展开 |
| Unknown memory operands | **293,766** | `<?memory operand>` 无法恢复 |
| Truncated expressions | 0 | P0-6.9 预算控制有效 |

### 寄存器使用 Top 10

| 寄存器 | 使用次数 |
|--------|----------|
| esp | 248,932 |
| ebx | 161,933 |
| esi | 7,456 |
| edx | 6,643 |
| eax | 5,504 |
| ecx | 4,739 |
| edi | 3,509 |
| ebp | 2,474 |

**关键观察**: esp 和 ebx 占绝对多数。esp 是栈指针（栈变量访问），ebx 通常是全局对象基址（PIC 代码）。

---

## 4. SSA 内存操作数分析

| 指标 | 数值 |
|------|------|
| SSA 内存操作数总数 | 21,595 |
| Base+register 模式 | **21,595 (100%)** |
| 常量地址 | 0 |
| Unknown/other | 0 |

**结论**: 所有 SSA 层内存操作数都是 `[reg+offset]` 模式，没有裸常量地址。这意味着 FOX 已经具备了完整的 base+offset 识别能力。

### Top 15 内存偏移分布

| 偏移 | 出现次数 | 推测含义 |
|------|----------|----------|
| **+0x46E920** | **1,946** | **全局对象基址（NtcMach 核心结构体）** |
| +0x10 | 829 | 结构体字段 |
| +0x14 | 769 | 结构体字段 |
| +0x18 | 688 | 结构体字段 |
| +0x24 | 596 | 结构体字段 |
| +0x1C | 525 | 结构体字段 |
| +0x20 | 510 | 结构体字段 |
| +0x8 | 454 | 结构体字段 |
| +0xC | 402 | 结构体字段 |
| +0x2C | 395 | 栈变量/结构体字段 |
| +0x30 | 394 | 栈变量/结构体字段 |
| +0x28 | 366 | 栈变量/结构体字段 |
| +0x4 | 341 | 结构体字段 |
| +0x34 | 295 | 栈变量/结构体字段 |
| +0x3C | 286 | 栈变量/结构体字段 |

### 关键发现：全局对象基址

**+0x46E920 出现 1,946 次**，远超其他偏移。这是 NtcMach 的一个全局对象/结构体指针：

```
mov ebx, [0x46E920]    ; ebx = g_globalObject
...
mov eax, [ebx+0x10]    ; eax = g_globalObject->field_10
```

当前 FOX 输出：
```c
eax_1 = <?memory operand: [ebx+0x10]>;
```

理想输出：
```c
eax_1 = g_globalObject->field_10;
```

---

## 5. Capability Matrix

| 能力 | 状态 | 证据 |
|------|------|------|
| 内存加载检测 | ✅ PASS | 144,256 个 Expression::Load |
| Base+offset 模式识别 | ✅ PASS | 21,595 个 SSA 操作数，100% 是 base+offset |
| 常量地址识别 | ⚪ N/A | NtcMach 中无裸常量地址 |
| 字段名恢复 | ❌ FAIL | 0，全部显示原始偏移 |
| 结构体/对象恢复 | ❌ FAIL | 0 |
| 指针类型推断 | ❌ FAIL | 0 |
| 跨函数类型传播 | ❌ FAIL | 0 |
| 栈变量恢复 | ⚠️ PARTIAL | esp/ebp+offset 存在，但未命名 |
| 全局对象识别 | ❌ FAIL | +0x46E920 未被标记为全局对象 |

---

## 6. GAP Registry

### GAP-P0-8-FIELD-NAMES（P0，最高优先级）
**问题**: 内存偏移显示为原始数字，如 `[esi+0x190b8]`，而非字段名。
**影响**: 21,595 个内存操作数全部受影响。
**最小修复**: 将 `[reg+offset]` 显示为 `reg->field_OFFSET`。

### GAP-P0-8-GLOBAL-OBJECT（P0）
**问题**: +0x46E920 出现 1,946 次，是全局对象基址，但未被识别。
**影响**: 大量 `[ebx+offset]` 实际上是 `g_object->field`。
**最小修复**: 识别高频常量基址，标记为全局对象。

### GAP-P0-8-STACK-VARS（P1）
**问题**: `[esp+0x2c]` 未命名为局部变量。
**影响**: 栈变量可读性差。
**最小修复**: 基于函数 prologue 分析，将 esp/ebp+offset 命名为 `local_XX` / `arg_XX`。

### GAP-P0-8-UNKNOWN-MEM（P1）
**问题**: 293,766 个 `<?memory operand>` 在 Expression 层无法恢复。
**影响**: 大量表达式包含 unknown memory operand。
**根因**: Expression Recovery 对复杂内存地址表达式（多级间接寻址）处理不足。

### GAP-P0-8-STRUCT-RECOVERY（P2）
**问题**: 无结构体边界检测。
**影响**: 无法区分不同对象的字段。

### GAP-P0-8-POINTER-TYPE（P2）
**问题**: 无指针 vs 值的区分。

### GAP-P0-8-CROSS-FUNC-TYPE（P3）
**问题**: 无跨函数类型传播。

---

## 7. 推荐的最小下一步

### P0-8.1: Memory Field Labeling + Global Object Identification

**目标**: 不建立类型系统，只改善显示层。

1. **字段标注**: `[esi+0x190b8]` → `esi->field_190B8`
2. **全局对象识别**: 高频基址（如 +0x46E920）→ `g_object->field_XX`
3. **栈变量命名**: `[esp+0x2c]` → `local_2c`（基于 prologue 分析）

**预期影响**:
- 21,595 个内存操作数可读性提升
- 1,946 个全局对象访问变得可识别
- 不需要修改 SSA / Memory SSA / Expression Recovery

**实现范围**:
- 只修改 emitter.rs（显示层）
- 可选：structured_ir.rs 中添加 MemoryAccess 元数据
- 不修改已封板模块

---

## 8. 明确不做

本阶段（Reality Audit）未做：
- ❌ 类型系统设计
- ❌ 结构体恢复算法
- ❌ C++ RTTI 分析
- ❌ vtable 分析
- ❌ 跨函数类型传播
- ❌ 修改任何生产代码

---

## 9. 结论

FOX 当前对内存访问的**底层识别能力已经完整**（100% base+offset 模式），但**显示层完全缺失**。

最大的三个可读性瓶颈：
1. **293,766 个 unknown memory operands** — Expression 层无法恢复复杂地址
2. **字段名全部缺失** — 21,595 个操作数显示原始偏移
3. **全局对象未识别** — +0x46E920 出现 1,946 次但未标记

**最小下一步 P0-8.1** 只做显示层改善（字段标注 + 全局对象 + 栈变量），预计可以显著提升反编译可读性，且不需要修改已封板的分析模块。

**状态**: Reality Audit COMPLETE → WAITING FOR ARCHITECT DECISION
