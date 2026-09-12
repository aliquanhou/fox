# P0-13 Independent Read-Only Audit Report

**审计对象**: `f24ac90` (Type Propagation Engine)
**审计性质**: 只读代码路径 + 独立复跑
**日期**: 2026-09-12

---

## 裁决

# ✅ PASS

P0-13 类型候选全部来自 P0-12 真实证据（ArgumentSourceKind / ReturnEvidence），
无 C 类型名，TypeJoin 冲突 fail-closed，emitter 只读。允许进入 P0-14 Variable Recovery。

---

## Phase 0 — Git Reality

| 项 | 值 | 判定 |
|----|-----|------|
| HEAD | `f24ac90` | ✅ |
| Parent | `dc14e38` (P0-12 Audit PASS) | ✅ |
| dirty | 0 | ✅ |
| 新增 | `type_propagation.rs`, 报告 | ✅ |
| sealed (fox-analysis/arch/IR/parser/lift/SSA/runtime) | **无改动** | ✅ |
| signature.rs 改动 | 仅加 iter()/insert() 访问器 | ✅ 合理 |

---

## Phase 1 — 数据结构真实性

TypeKind 变体（type_propagation.rs）：
```
Unknown / Integer{bits} / Pointer{target} / Struct{object} / Boolean / FunctionPointer
```
label() 输出：`unknown` / `integer-candidate(32b)` / `pointer-candidate` /
`struct-candidate(...)` / `boolean-candidate` / `function-pointer-candidate`。

**判定**: 无 `Int/String/Player` 这类 C/业务类型名。
命中的 `"int"` 字符串在 367 行，是 `test_join_conflict_collapses_to_unknown` 的
evidence fixture（非类型名输出），生产 label 仍为 `integer-candidate`。✅

---

## Phase 2 — Evidence 来源（最高优先级）

参数类型映射全部来自 `ArgumentSourceKind`（type_propagation.rs:171-187）：
```
Constant   -> Integer{32}
Computed   -> Integer{32}
MemoryLoad -> Pointer{None}
Register   -> Unknown (fail-closed)
Unknown    -> Unknown
```
审计命令确认：无 `eax`/函数名包含 `Create`/`offset==8`/`name.contains` 猜类型逻辑。
参数来源链 = ArgumentFlowEdge + ArgumentSourceKind（P0-12 已审计真实）。✅

## Phase 3 — Return Type

`ReturnEvidence::Condition -> Boolean, confidence=Low`（:210）。
**判定正确**：`test eax,eax; jne` 可能是 bool/status/pointer check，
故只给 boolean-candidate **LOW**，未给 `bool` 或 HIGH。Value/Unknown → Unknown。✅

## Phase 4 — TypeJoin fail-closed

:263 `fn join`：
- :264 `a.kind == b.kind` → 合并、confidence 取大
- 否则 → `Unknown` + evidence `"conflict: X vs Y"`（:281）
- 单测 `test_join_conflict_collapses_to_unknown` 守护（Integer+Pointer→Unknown）

**判定**: 冲突不强行选择。✅

## Phase 5 — Emitter 隔离

emitter.rs：
- :186 `set_type_map()` 注入
- :410 只读 `type_map.borrow()`
- :419/:431 只读 `param_type`/`return_type`
- 审计 grep：emitter 无 `TypeKind::Integer/Pointer`、无 `if offset==8` 造类型

**判定**: emitter 只消费，不推断。✅

---

## Phase 6 — NtcMach Reality（独立复跑）

```
P0-13 Type Candidates: keys=390, known=205, unknown=185
```
非硬编码（由 build() 遍历 sig_map 真实产出）。unknown≈47%，无 100% typed。✅

## Phase 7 — Regression（独立复跑）

| 指标 | 复跑 | 基线 | 判定 |
|------|------|------|------|
| functions OK | 339 (94.4%) | 339 | ✅ |
| CallGraph edges | 2735 (d=1417,s=109,u=1209) | 2735 | ✅ |
| DataFlow edges | 5654 (args=2919,ret=2735) | 5654 | ✅ |
| P0-12 callees | 183 | 183 | ✅ |
| batch test | 1 passed | — | ✅ |

类型传播未改变已有结构/callgraph/dataflow 结果。✅

## Phase 8 — GAP 验证

**GAP-1（确认存在，不阻塞 P0-13）**：`FieldTypeFact` 接口已建，但 P0-8 field access
统计在 emitter 内部（per-function clear），batch 传空——字段类型统计为 0。
裁决：**不阻塞 P0-13**，但 **P0-15 Struct Recovery 前必须解决**（把 P0-8 field evidence
从 emitter 提升到 analysis 层）。

其他 GAP：bits 固定 32；Pointer target 未关联 global object；FunctionPointer 未启用。

---

## Phase 9 — Audit Gate

- ✅ TypeMap 真实存在
- ✅ Builder 真实消费 Signature/DataFlow（ArgumentSourceKind）
- ✅ 无猜测类型（无 C 类型名、无名字/寄存器/offset 推断）
- ✅ Confidence 存在（None/Low/Medium）
- ✅ Emitter 只读
- ✅ 339 OK 保持
- ✅ tests PASS（89，含 5 新 type 单测）

**结论: PASS**。允许进入 P0-14 Variable Recovery Engine。
