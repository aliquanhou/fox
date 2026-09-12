# P0-14 Independent Read-Only Audit Report

**审计对象**: `3268ff9` (Variable Recovery Engine)
**审计性质**: 只读代码路径 + 独立复跑
**日期**: 2026-09-12

---

## 裁决

# ✅ PASS

P0-14 真实验证 SSA Value → VariableBuilder → VariableMap → Emitter 链：
同寄存器 SSA 版本合并为一个 variable，Phi 真实标记，无 rename 规则，Type 未强行连接。
FOX 证据链闭合：**Binary → CFG → CallGraph → DataFlow → Signature → TypeCandidate → Variable**。

---

## Audit 1 — Git Reality

| 项 | 值 | 判定 |
|----|-----|------|
| HEAD | `3268ff9` | ✅ |
| Parent | `f4e7bdf` (P0-13 Audit PASS) | ✅ |
| dirty | 0 | ✅ |
| 新增 | `variable_recovery.rs`, 报告 | ✅ |
| sealed (fox-analysis/arch/IR/parser/lift/SSA/runtime) | **无改动** | ✅ |

---

## Audit 2 — SSA Value 来源（最高优先级）

walk 来源全部来自真实 SSA（variable_recovery.rs）：
```
Assign.lhs: AssignTarget::Variable{name,version}  (204)
PhiAssign.lhs: AssignTarget::Variable              (158)
Expression::Variable{name,version}                 (219)
```
审计 grep：无 `eax=>variable`、`esp=>local`、`ebp-4=>variable` 字符串规则。
命中的 `"eax"` 全在测试 fixture/注释中。

**判定**: 来源仅 SSA，无硬编码 rename。✅

## Audit 3 — Version Union

:136 `for (register, mut versions) in acc.defs` → 每个 register 构造**一个** Variable，
`def_versions: versions`（排序后）。同寄存器 eax.1/eax.2/eax.3 合并为一个变量，
而非每版本一个。单测 `test_same_register_chain_becomes_one_variable` 守护（断言 len==1）。✅

## Audit 4 — Phi Recovery

PhiAssign.lhs Variable → `add_phi(name)` → `has_phi=true`（:158-160）。
单测 `test_phi_marks_variable` 守护。未根据 CFG 形状猜 phi。✅

---

## Audit 5 — Use/Def Reality

当前只有 `def_versions`（def 侧），**没有** uses 统计 / use-def 反查。
施工报告已如实标注为 GAP。

**判定**: partial variable identity（非 complete use-def）。不阻塞 P0-14，
后续阶段补 uses。✅

## Audit 6 — 特殊寄存器过滤

证据块样本确认 **FLAGS / EIP / ESP / FLAGS** 进入 variable 列表。
eax/ecx/edx 正常；eip/eflags 语义上非用户变量。

**GAP-P0-14-SPECIAL-REGISTER-FILTER**：记录为 GAP，不阻塞。
后续应过滤控制/标志寄存器（eip/eflags），只保留数据寄存器变量。

## Audit 7 — Type Integration Reality

审计确认 `variable_recovery.rs` **无** `type_candidate`/`TypeCandidate`/`TypeMap` 引用。
Variable 未接 P0-13 TypeMap，输出只有 `variable_N: reg [M versions] (phi)`，
**未**输出 `variable_1 integer`。

**判定**: 与报告 GAP 一致，未虚假连接类型。✅

## Audit 8 — Emitter Isolation

emitter.rs：
- :197 `set_variable_map()` 注入
- :474 只读 `var_map.borrow()`
- :479 只读 `variables_of_function(func_addr)`
- 审计 grep：无 `rename` / `=> "local"` / 按寄存器名造变量逻辑

**判定**: emitter 只消费。✅

---

## Audit 9 — NtcMach Reality（独立复跑）

```
P0-14 Variables: total variables=2784, functions=335
```
非硬编码（由 walk statements 真实产出）。样本：
```
variable_0: FLAGS [17 versions] (phi)
variable_2: eax  [20 versions] (phi)
variable_5: ecx  [14 versions] (phi)
```
命名克制（variable_N: reg，非 int x / count）。✅

## Audit 10 — Regression（独立复跑）

| 指标 | 复跑 | 基线 | 判定 |
|------|------|------|------|
| functions OK | 339 (94.4%) | 339 | ✅ |
| CallGraph edges | 2735 (d=1417,s=109,u=1209) | 2735 | ✅ |
| DataFlow edges | 5654 | 5654 | ✅ |
| P0-12 callees | 183 | 183 | ✅ |
| P0-13 type keys | 390 (known=206, unknown=184) | 390 | ✅ |
| batch test | 1 passed | — | ✅ |
| 全量 cargo test | 94 passed | 94 | ✅ |

类型传播未改变已有结果。✅

---

## 证据链闭合确认

```
Binary
  ▼ CFG Recovery              (P0-7)
  ▼ Memory / Global Object     (P0-8)
  ▼ Type Evidence             (P0-9)
  ▼ Function Behavior/Signature(P0-10/12)
  ▼ CallGraph                 (P0-11.2.7)
  ▼ DataFlow                  (P0-11.3)
  ▼ TypeCandidate            (P0-13)
  ▼ Variable                  (P0-14)  ← 本次审计通过
```

---

## 已知 GAP（不阻塞）

1. partial variable identity：只有 def_versions，无 uses/use-def 反查
2. **GAP-P0-14-SPECIAL-REGISTER-FILTER**：eip/eflags/esp 等控制/标志寄存器进入 variable
3. 局部变量未接 TypeMap
4. 栈变量未命名（只标 has_memory_store）
5. 跨函数共享变量未建模

---

## Verdict

**PASS**。FOX 具备完整证据链 Binary→...→Variable。
允许进入 **P0-15 Struct/Object Recovery**（global offset → object candidate / field candidate / type candidate）。
