# GAP-RM-2 Memory Operand Recovery Foundation

**阶段**: GAP-RM-2（Reality Mission 第二轮）
**触发**: NtcMach objects=332 但 fields 仅 30，而 P0-8 emitter 历史统计 global_46E920 就有 156 unique fields
**日期**: 2026-09-12

---

## 1. 缺陷

大量 `mov eax,[ecx+0x24]` / `mov [esi+0x18],edx` / `lea eax,[edi+0x30]` 在 structured IR 里**没有**形成 `Binary{reg,const}` 表达式，而是作为 lift 原始文本留在：
```
Expression::Unknown { reason: "memory operand: [ecx+0x24]" }
AssignTarget::Memory { address: Unknown { reason: "memory address: [ecx+0x18]" } }
```
P0-15 ObjectRecovery 只 walk 结构化 Binary，所以这些字段访问全部漏掉。

---

## 2. 修复（Evidence-First）

新增 `memory_recovery.rs`：
```rust
pub struct ParsedMemory { base: Option<String>, offset: i64 }
pub fn parse_memory_operand(reason: &str) -> Option<ParsedMemory>
```
解析 **lift 层原始文本**（`SSAOperand::Memory{description}`，非 emitter C 输出）：
- `[ecx+0x24]` → (ecx, +0x24)
- `[esi-0x18]` → (esi, -0x18)
- `[0x46e920]` → (None, 0x46e920)
- `[ecx]` → (ecx, 0)
- 容忍 Zydis 前导 `+`、纯 scale `[esp*4]` 安全拒绝

ObjectRecovery 接入：
- FuncScan 新增 `reg_name_to_base: HashMap<String,u64>`（裸寄存器名→global base，因为 lift 文本不带 SSA version）
- Assign.lhs=reg, rhs=Constant(global) 时同时记录裸名映射
- consider 新增 `Expression::Unknown{reason}` 分支：parse → 查裸名映射 → record(base, offset)；纯常量 `[0x...]` 且 writable region 内 → pure global

**未解析 emitter 输出字符串**——解析的是 lift 产生的 `SSAOperand::Memory.description`。

---

## 3. 修改文件

| 文件 | 内容 |
|------|------|
| `src/memory_recovery.rs` | 新增：ParsedMemory + parse_memory_operand + 6 单测 |
| `src/object_recovery.rs` | FuncScan 加 reg_name_to_base；consider Unknown 分支 |
| `src/lib.rs` | `pub mod memory_recovery` |

---

## 4. 三 Reality 目标验证

| 目标 | RM-1 后 | RM-2 后 | OK率 |
|------|---------|---------|------|
| **NtcMach.exe** | objects=332, fields=30 | **objects=365, fields=829** | 339 (94.4%) 保持 |
| **KeyTable.exe** | objects=43, fields=19 | **objects=82, fields=134** | 146 (99.3%) 保持 |
| **NTCDLLV.DLL** | objects=41, fields=21 | **objects=58, fields=196** | 231 (96.7%) 保持 |

fields 跨三类 PE 全部数量级增长（30→829 / 19→134 / 21→196），无任一目标下降。

---

## 5. 回归 Gate

| 检查 | 结果 |
|------|------|
| lib 单测 | 78 passed |
| memory_recovery 单测 | 6 passed |
| object 单测 | 5 passed |
| 全量 cargo test | 13 suites ok |
| fmt / clippy -D warnings | clean |
| sealed modules | 未改 |

---

## 6. 意义

FOX 从"只看结构化 Binary 表达式"升级为"同时看到 lift 文本 memory operand"：
```
Binary → CFG / CallGraph / DataFlow / Signature / Type / Variable / Object(RM-1)
       + Unknown-reason [reg+off] memory operands (RM-2)
```
struct-layout 字段覆盖从个位数~30 跳到数百~829，逼近 P0-8 emitter 历史统计量级。

---

## 7. 已知 GAP（后续）

1. offset 为负 / `[esp+x]` stack 帧访问未记录（只收正 offset）
2. 字段 size / type 仍未恢复（FieldTypeFact 仍未接）
3. RM-3 Import/IAT symbol 边识别（NTCDLLV symbol=1 偏低）——独立 GAP，未混入
4. 连续 offset struct-layout 聚类仍稀疏（365 objects / 829 fields，多为分散访问）

**状态**: GAP-RM-2 IMPLEMENTATION COMPLETE → 待独立审计
