# P0-15 Independent Struct/Object Recovery Audit Report

**审计对象**: `c0b3401` (Struct/Object Recovery Engine)
**审计性质**: 只读代码路径 + 独立复跑
**日期**: 2026-09-12

---

## 裁决

# ✅ PASS（Foundation，非完整 Struct Recovery）

P0-15 真实验证 IR/Statement → Builder → ObjectMap → Emitter-read 链：
对象/字段来自真实 Expression/Memory 访问，无 offset→名字硬编码，emitter 只读。
FOX 骨架能力层全部就位。**但明确：这是 Object/Field Foundation，不是完整 C/C++ struct recovery。**

---

## Audit 1 — Git Reality

| 项 | 值 | 判定 |
|----|-----|------|
| HEAD | `c0b3401` | ✅ |
| Parent | `61a72af`（P0-14 audit） | ✅ |
| dirty | 0 | ✅ |
| sealed (analysis/arch/IR/parser/lift/SSA/runtime) | **无改动** | ✅ |
| 新增 | `object_recovery.rs` + 报告；改 emitter/lib/batch | ✅ |

## Audit 2 — 数据结构真实性

真实 struct storage：
- `FieldCandidate` (:32) {offset, accesses, type_label:Option<String>, touched_by}
- `ObjectCandidate` (:45) {id, base, name, fields, functions}
- `ObjectMap` (:60) {objects, by_base}
- `ObjectRecoveryBuilder` (:267)

**不是 String output parser**。✅

## Audit 3 — Field 来源（最高优先级）

field 仅来自真实 IR：
- `Expression::Binary{reg+const}` (:136)
- `Expression::Variable` bare pointer (:163)
- `Expression::Constant` pure global (:170)
- `AssignTarget::Memory{address}` (:216)、`Load{address}` (:187)

审计 grep：**无** `0x10=>health` / `0x20=>name` 硬编码。命中的 `0x46E920` 全在测试 fixture。✅

## Audit 4 — Object Identity

:279 `bases: BTreeSet<u64>`，按 base 聚合；:124 按 `(base,offset)` 入 entry。
同 base 多 offset → 一个 Object（单测 `test_same_base_offsets_merge_one_object` 守护：1 object / 2 fields）。
不是 3 个 object。✅

## Audit 5 — Field Merge

:124 `*self.access.entry((base,offset)).or_insert(0) += 1`——同 offset read+write 累加 accesses。
单测 `test_field_access_count_aggregates` 守护（两次访问 → accesses=2）。✅

## Audit 6 — Conflict Safety

`type_label` 始终 `None`（:298），无 join/conflict 逻辑。
byte vs pointer 冲突**不**强制 integer——直接无类型输出（fail-closed）。✅

---

## Audit 7 — Emitter 隔离

- :208 `set_object_map()` 注入
- :518 只读 `object_map.borrow()`
- :526/546/553 只读 `objects()` / `touched_by`
- emitter 命中的 `0x460000..0x480000`（976/999/1072/1161）是 **P0-8.2 已封板历史代码**，本次 diff 未改

**判定**: emitter 只消费。✅

## Audit 8 — P0-8 GAP 确认

审计 grep：`object_recovery.rs` **未**解析 reason 文本（335 行 `reason:String::new()` 是测试 fixture）。
确认：**Unknown-reason `[reg+off]` memory operand 未接入本层**——与施工报告 GAP 一致。
objects=26/fields=20 **不等于**完整 struct recovery（emitter 内部 global_46E920 有 156 unique fields）。✅

---

## Audit 9 — NtcMach Reality（独立复跑）

```
P0-15 Objects: objects=26, fields=20
```
非硬编码（由 walk statements 真实产出；单测换 base 产生 2 objects 证明输入敏感）。
134 函数带对象证据块，样本：`global_461540 (30 functions share, field_0x0 53 accesses)`。✅

## Audit 10 — 全链回归（独立复跑）

| 指标 | 复跑 | 基线 | 判定 |
|------|------|------|------|
| functions OK | 339 (94.4%) | 339 | ✅ |
| CallGraph edges | 2735 | 2735 | ✅ |
| DataFlow edges | 5654 | 5654 | ✅ |
| P0-12 callees | 183 | 183 | ✅ |
| P0-13 type keys | 390 | 390 | ✅ |
| P0-14 variables | 2784 @ 335 | 2784 @ 335 | ✅ |
| 全量 cargo test | 99 passed | 99 | ✅ |

---

## 证据链闭合确认

```
Binary
  ▼ CFG / Memory / CallGraph / DataFlow / Signature
  ▼ TypeCandidate / Variable
  ▼ Object / Field candidate   ← 本次审计通过
```

---

## 已知 GAP（如实记录，不阻塞启动 Reality Mission）

1. **最大**：Unknown-reason `[reg+off]` mem operand 未接入 analysis 层（只覆盖 Expression 化）；26/20 远小于真实 156 fields
2. offset 多为 0，struct-layout（连续 offset）证据不足
3. type_label 全 None（P0-13 FieldTypeFact batch 仍空）
4. 字段 size 未恢复
5. object 生命周期（create/update/query）未区分
6. 后续仍需：Memory Operand Recovery → Field Type Binding → Struct Layout Inference → Pointer Alias Analysis

---

## Verdict

**PASS**。允许进入 **FOX Reality Decompilation Mission**（真实测试项目：源码→编译→exe→FOX 反编译→重编译→运行对比）。

定位：这是 Object/Field **Foundation**，不是完整 C/C++ struct recovery；真实项目将暴露并逼 FOX 补齐上述 GAP。
