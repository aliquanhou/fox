# FOX Reality Diary

工程日志：Reality Mission 期间每个真实项目驱动的关键节点。
规则：重大成果必须 Git + Evidence + 日记。

---

## 2026-09-12 — GAP-RM-2 Memory Operand Recovery（commit 3de0573）

**节点意义：第一次从 lift 原始 memory operand 恢复真实 field evidence。**

此前 analysis 层只认 structured `Binary{reg,const}` 表达式，大量 `[ecx+0x24]` /
`mov [esi+0x18],edx` 以 lift 文本形式留在 `Expression::Unknown{reason}` 里，
P0-15 完全看不到。这是 analysis 层长期存在的 blind spot——NtcMach 已有
332 objects，但 fields 仅 30，而 P0-8 emitter 历史统计 global_46E920 一个对象
就有 156 unique fields。

**做法**：新增 `memory_recovery.rs`，解析 lift 层原始 `SSAOperand::Memory.description`
（不是 emitter C 输出），`ObjectRecovery` 加 `reg_name_to_base` 裸名映射。

**Evidence**：
- NtcMach.exe  fields 30 → 829
- KeyTable.exe fields 19 → 134
- NTCDLLV.dll  fields 21 → 196
- OK 率无下降（339 / 146 / 231）

**教训**：NtcMach-only dogfood 永远测不出这个 blind spot。真实项目第一枪就击穿了
analysis 层假设。"看得懂 IR 结构" ≠ "看得懂真实机器内存布局"。

---

## 2026-09-12 — GAP-RM-1 Global Region Portability（commit 77374b3）

KeyTable.exe（不同 ImageBase）objects=0，暴露 P0-15 硬编码
`GLOBAL_BASE_MIN/MAX = NtcMach .data 范围`。改为 `GlobalRegionMap::from_binary`
从 PE section table 推可写全局区。NtcMach objects 26→332（旧窄窗口漏了大量对象），
KeyTable 0→43，DLL 独立工作。

## RM-7: KeyTable.exe -> compiled C (2026-09-12)
- NEW c_ast.rs: CExpr/CStmt/CFunction + IrToC (SSA IR -> C AST) + CRenderer.
- Proper reconstruction: structured Statement/Expression -> C AST, no emitter-text regex.
- Unknown degrades to literal 0 / tll_unknown_op(); no fabricated logic.
- KeyTable.exe 146 funcs -> keytable_recovered.c (436KB) -> MSVC cl /c PASS (0 error).
- Iterative fixes: free-var declaration, Deref cast (uint32_t*), no-prototype () call sig, extern fwd decls.
- MILESTONE: FOX first produced a C file accepted by a real compiler. Not round-trip yet.


## RM-7.1: Memory Access Reconstruction (2026-09-12)
- Audit caught 662 *(uint32_t*)(0): all memory access degraded to NULL because Load.address was Unknown{reason}.
- c_ast Unknown branch now parses lift reason text via memory_recovery:
  'memory operand: [ecx+0x24]' -> base+offset; 'stack pointer (Pop)' -> *(esp).
- KeyTable: deref-literal-0 662 -> 0, MSVC cl /c still PASS.
- No field-name/type guessing; raw address/register-offset preserved.


## RM-7.2: Function Prototype (2026-09-12)
- Forward decls and defs now carry variadic prototypes (uint32_t, ...) so call sites with differing arity compile.
- Empty calls render as call(0); collect_callees tracks max args.
- No SDK types / no guessed names; all uint32_t. MSVC cl /c PASS.


## RM-7.3: Control Flow Conditions (2026-09-12)
- Statement::If now renders real recovered conditions (CMP/TEST -> ==,!=,<,<=,>,>=).
- New CExpr::Compare; unresolved branches still degrade to Unknown (compile-safe).
- Sample: if ((tll_edi_1 <= tll_esi_1)) { ... } else { ... }. MSVC cl /c PASS.


## RM-7.4: Variable Naming (2026-09-12)
- tll_<reg>_<version> -> sequential tmp_N (source-style, no register leak).
- Same SSA value keeps same tmp across function. MSVC cl /c PASS.


## RM-8.2: SSA convergence guard (2026-09-12)
- MSVC /O2 rm8_roundtrip.exe caused analyze_function non-termination.
- Root cause 1: phi placement worklist (ssa/mod.rs) no iteration bound on broken CFG.
- Root cause 2: dominance-frontier walk (dominators/mod.rs) idom chain broken -> runner never advances.
- Fix: bounded phi iteration (blocks*20+200) + visited-set guard in DF walk.
- Result: rm8 729 functions analyzed in 55s, recovered.c 1.8MB generated. No hang.
- Known GAP: Function Discovery reports 729 functions for a small PE (false positives from data/jump tables), to fix next.


## RM-8 ROUND-TRIP SUCCESS (2026-09-12)
- rm8_roundtrip.c (/O2) -> FOX -> rm8_recovered.c -> MSVC -> rm8_recovered.exe
- Output: hits=60 misses=2 sum=10 q=-1 (identical to baseline)
- First FOX round-trip closure: source->exe->FOX->C->exe->match


## RM-8.9 Commercial PE Batch-1 Milestone (2026-09-13)
- 11/14 PE decompiled, 3232 functions, 3167 recovered, ~12.5MB C
- All MSVC cl /c 0 errors
- Remaining: NTCDLLG, M3, M4 hang on SSA convergence


## FOX v1.0 BASELINE (2026-09-13)
- Commit: 5542998
- 14/14 PEs decompiled, ~4111 functions, ~4036 recovered, ~16MB C
- All MSVC cl /c 0 errors
- Round-trip: rm8 output matches baseline
- This is the Binary Recovery Baseline. No future change may break this.

