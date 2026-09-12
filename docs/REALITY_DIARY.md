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

