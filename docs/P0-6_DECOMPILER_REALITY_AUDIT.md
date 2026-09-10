# P0-6 Decompiler Reality Audit

**Stage**: P0-6 — Decompiler Reality Audit
**Type**: Read-only architecture audit (no production code changes)
**Commit audited**: `dba483d` (P0-5.6B final)
**Verdict**: AUDIT COMPLETE

---

## 1. Executive Summary

**核心问题：FOX 今天距离把 NtcMach.exe 完整反编译成可读 C-like Source，还差哪几层？**

答案：**还差 6 层关键能力**。FOX 已经建成了强大的分析基础设施（Binary → Function → CFG → IR → SSA → Memory SSA → Value Flow），但从"分析"到"反编译"之间存在明确的断层：

```
已建成 (P0-0 ~ P0-5.6B)
  Binary → PE Parser → Function Discovery → CFG → CallGraph
  → IR (L1) → Register SSA → Memory SSA → Value Flow → Type Recovery (basic)
  → Evidence → Claim → Function Reality

缺失 (P0-6 及以后)
  IR L1 → L2 (expression tree)          ← 层1
  SSA → Expression Recovery              ← 层2
  CFG → Structured Control Flow          ← 层3
  Stack offset → Variable Recovery       ← 层4
  Primitive → Type Propagation           ← 层5
  AST → C-like Source Emitter            ← 层6
```

**fox-decompiler crate 当前是纯骨架**（18 行，空 struct），没有任何 AST、表达式、语句、变量、类型或代码生成实现。

---

## 2. Module-by-Module Audit

### 2.1 fox-decompiler

| 检查项 | 状态 | 证据 |
|---|---|---|
| 模块存在 | ✅ | `crates/fox-decompiler/src/lib.rs` |
| 真实实现 | ❌ | 仅 18 行，`pub struct Decompiler;` + new()/default() |
| AST | ❌ NOT IMPLEMENTED | 无 Expression/Statement/Function AST |
| Expression recovery | ❌ NOT IMPLEMENTED | 无 |
| Variable recovery | ❌ NOT IMPLEMENTED | 无 |
| Type recovery | ❌ NOT IMPLEMENTED | 无（在 fox-analysis 中） |
| Control structure | ❌ NOT IMPLEMENTED | 无 |
| Source emitter | ❌ NOT IMPLEMENTED | 无 |
| CLI decompile 命令 | ❌ NOT IMPLEMENTED | CLI 无 decompile 子命令 |
| Pipeline integration | ❌ NOT IMPLEMENTED | analyze_binary() 不调用 decompiler |

**判定**: **SKELETON**。模块仅为占位，注释明确写 "P0: placeholder. Full decompiler requires complete IR + analysis. Scheduled for P1."

### 2.2 fox-ir (Intermediate Representation)

| 能力 | 状态 | 证据 |
|---|---|---|
| IROp 枚举 | ✅ IMPLEMENTED | Mov/Load/Store/Add/Sub/Mul/Div/Cmp/Test/Jump/CondJump/Call/Return/Lea/Push/Pop 等 30+ opcodes |
| IROperand 语义 | ✅ IMPLEMENTED | Register(width,access), Immediate(value,width,is_signed), Memory(base,index,scale,disp,size,access,is_rip_relative), Variable, Phi, Flags |
| IRInstruction 元数据 | ✅ IMPLEMENTED | address, op, operands, reads_registers, writes_registers, implicit_reads/writes, reads_flags, writes_flags |
| IRBasicBlock | ✅ IMPLEMENTED | id, start/end address, instructions, successors, predecessors |
| IRFunction | ✅ IMPLEMENTED | name, address, basic_blocks, entry_block |
| IRModule | ✅ IMPLEMENTED | functions, architecture |
| L2 (expression-level) | ❌ NOT IMPLEMENTED | 无 expression tree，IR 仍是三地址指令级 |
| L3 (structured) | ❌ NOT IMPLEMENTED | 无 control structure / variable |
| 条件表达式 | ❌ NOT IMPLEMENTED | Cmp/Test 产生 flags，但无 flag→condition expression 转换 |
| Pointer arithmetic | ⚠️ PARTIAL | Memory operand 可表达 base+index*scale+disp，但无高级 pointer type |
| Signed/unsigned | ⚠️ PARTIAL | Immediate 有 is_signed，但操作本身不区分 signed/unsigned（如 Sar vs Shr 有区分） |
| Flag semantics | ⚠️ PARTIAL | reads_flags/writes_flags 布尔标记，但无具体 flag 位语义（ZF/CF/SF/OF） |

**判定**: **IMPLEMENTED (L1 only)**。IR 是高质量的指令级表示，有完整读写语义，但缺少表达式树和高级语义层。Instruction→IR 转换不丢失宽度/访问模式信息，但 flag 语义较粗。

### 2.3 fox-analysis CFG

| 能力 | 状态 | 证据 |
|---|---|---|
| BasicBlock | ✅ IMPLEMENTED | `cfg/mod.rs` |
| Edge (successors/predecessors) | ✅ IMPLEMENTED | |
| Conditional branch | ✅ IMPLEMENTED | CondJump IR op |
| Switch / jump table | ✅ IMPLEMENTED | `jump_table.rs`，真实 switch table recovery |
| Dominator Tree | ✅ IMPLEMENTED | `dominators/mod.rs`，dominators/idom/dominance frontier/tree children |
| Post-dominator | ❌ NOT IMPLEMENTED | 无 post_dominator 模块 |
| Loop detection (back edge, natural loop) | ❌ NOT IMPLEMENTED | 无 loop 检测 |
| If/Else recovery | ❌ NOT IMPLEMENTED | 无 control structure recovery |
| While/DoWhile recovery | ❌ NOT IMPLEMENTED | 无 |
| Switch recovery (structured) | ❌ NOT IMPLEMENTED | jump table 可解析，但不生成结构化 switch |
| Break/Continue | ❌ NOT IMPLEMENTED | 无 |
| Early return | ❌ NOT IMPLEMENTED | 无 |
| Irreducible CFG handling | ❌ NOT IMPLEMENTED | 无 |

**判定**: **PARTIAL**。CFG 基础 + Dominator 已实现，但无 post-dominator、无循环检测、无结构化控制流恢复。Dominator 是 SSA 的基础，也是未来控制流结构化的基础。

### 2.4 fox-analysis SSA (Register)

| 能力 | 状态 | 证据 |
|---|---|---|
| Phi placement | ✅ IMPLEMENTED | dominance frontier |
| Variable renaming | ✅ IMPLEMENTED | dominator-tree DFS with version stacks |
| Phi nodes | ✅ IMPLEMENTED | `PhiNode` struct |
| use-def chains | ✅ IMPLEMENTED | `use_def_chains: HashMap<(block,inst,op), (block,inst,version)>` |
| def-use chains | ✅ IMPLEMENTED | `def_use_chains: HashMap<(block,inst), Vec<(block,inst,op)>>` |
| SSAOperand | ✅ IMPLEMENTED | Register(version), Immediate, Memory, Phi |
| Expression tree from SSA | ❌ NOT IMPLEMENTED | 无 def→use 表达式重建 |
| Out-of-SSA (phi elimination) | ❌ NOT IMPLEMENTED | 无 phi removal / copy insertion |

**判定**: **IMPLEMENTED**。Register SSA 是完整的标准实现，有精确的 use-def/def-use 链。这是表达式恢复的关键基础。

### 2.5 fox-analysis Memory SSA

| 能力 | 状态 | 证据 |
|---|---|---|
| MemoryVariable | ✅ IMPLEMENTED | Stack/Global/Heap/Unknown |
| MemoryDef | ✅ IMPLEMENTED | |
| MemoryUse | ✅ IMPLEMENTED | |
| MemoryPhi | ✅ IMPLEMENTED | |
| MemoryVersion | ✅ IMPLEMENTED | |
| Use→Reaching Def | ✅ IMPLEMENTED | |
| Def→Use | ✅ IMPLEMENTED | |
| MemorySSA→Expression | ❌ NOT IMPLEMENTED | 无 Load→Register→Expression 重建 |

**判定**: **IMPLEMENTED**。Memory SSA 完整，是内存表达式恢复的基础。

### 2.6 fox-analysis Value Flow (Cross-Domain)

| 能力 | 状态 | 证据 |
|---|---|---|
| Register→Memory bridge | ✅ IMPLEMENTED | Store: RegisterDef→MemoryDef |
| Memory→Register bridge | ✅ IMPLEMENTED | Load: MemoryUse→RegisterDef |
| Basic Alias (Must/May/No) | ✅ IMPLEMENTED | |
| Function pointer propagation | ✅ IMPLEMENTED | LEA→Store→Load→call |
| Indirect call resolution | ⚠️ PARTIAL | 可解析部分，unresolved 保持 Unknown |

**判定**: **IMPLEMENTED**。跨域值流是 FOX 的独特优势，为表达式恢复提供了 Register↔Memory 的完整链路。

### 2.7 fox-analysis DataFlow

| 能力 | 状态 | 证据 |
|---|---|---|
| Reaching definitions | ✅ IMPLEMENTED | `dataflow/mod.rs` |
| Liveness | ✅ IMPLEMENTED | |
| Constant propagation | ✅ IMPLEMENTED | |

**判定**: **IMPLEMENTED**。

### 2.8 fox-analysis Type Recovery

| 能力 | 状态 | 证据 |
|---|---|---|
| Primitive types (u8/i8/.../u64/i64) | ✅ IMPLEMENTED | `FoxType` 枚举 |
| Pointer | ✅ IMPLEMENTED | |
| Float32/Float64 | ✅ IMPLEMENTED | |
| Type inference from memory width | ✅ IMPLEMENTED | mov eax,[x]→u32 |
| Type inference from arithmetic | ✅ IMPLEMENTED | |
| Type inference from LEA | ✅ IMPLEMENTED | pointer |
| Confidence + Evidence | ✅ IMPLEMENTED | |
| Struct recovery | ❌ NOT IMPLEMENTED | 无 struct field 分析 |
| Array recovery | ❌ NOT IMPLEMENTED | 无 |
| Enum recovery | ❌ NOT IMPLEMENTED | 无 |
| Function pointer type | ❌ NOT IMPLEMENTED | 无 |
| Type propagation (跨指令) | ⚠️ PARTIAL | 单指令推断，无跨指令传播 |
| Function signature recovery | ❌ NOT IMPLEMENTED | 无参数/返回值类型恢复 |
| Calling convention | ❌ NOT IMPLEMENTED | 无 |

**判定**: **PARTIAL**。基础原始类型推断已实现，但无复合类型、无类型传播、无函数签名。

### 2.9 fox-project

| 能力 | 状态 |
|---|---|
| Project save/load | ⚠️ SKELETON (仅 name/version/binary_path/analysis_data) |
| Project reconstruction | ❌ NOT IMPLEMENTED |

**判定**: **SKELETON**。

### 2.10 fox-cli

| 命令 | 状态 |
|---|---|
| info/analyze/functions/disasm/blocks/cfg/callgraph | ✅ |
| ir/evidence/imports/exports/strings/calls | ✅ |
| dataflow/dominators/ssa/types | ✅ |
| functions --reality | ✅ (P0-5.6B) |
| **decompile** | ❌ NOT IMPLEMENTED |

---

## 3. Capability Matrix

| 能力 | 状态 | 真实证据 |
|---|---|---|
| IR (L1) | **IMPLEMENTED** | `fox-ir/src/lib.rs` IROp/IROperand/IRInstruction 完整语义 |
| CFG | **IMPLEMENTED** | BasicBlock/Edge/successors/predecessors |
| Dominator | **IMPLEMENTED** | `dominators/mod.rs` idom/frontier/tree |
| Post-dominator | **NOT IMPLEMENTED** | 无模块 |
| Register SSA | **IMPLEMENTED** | `ssa/mod.rs` Phi/use-def/def-use |
| Memory SSA | **IMPLEMENTED** | `memory_ssa/mod.rs` Def/Use/Phi/Version |
| Value Flow (cross-domain) | **IMPLEMENTED** | `value_flow/mod.rs` Register↔Memory |
| Expression Recovery | **NOT IMPLEMENTED** | 无 SSA→expression tree |
| Variable Recovery | **NOT IMPLEMENTED** | 无 stack offset→C variable |
| Control Structure Recovery | **NOT IMPLEMENTED** | 无 if/else/while/switch |
| Loop Detection | **NOT IMPLEMENTED** | 无 back edge/natural loop |
| Type Recovery (primitive) | **PARTIAL** | `type_recovery/mod.rs` u8/i8/pointer/float |
| Type Recovery (struct/array) | **NOT IMPLEMENTED** | 无 |
| Function Signature | **NOT IMPLEMENTED** | 无参数/返回值/calling convention |
| Call Reconstruction | **PARTIAL** | direct/import thunk 解析，indirect 部分，无参数 |
| AST | **NOT IMPLEMENTED** | fox-decompiler 为空 |
| C-like Emitter | **NOT IMPLEMENTED** | 无 |
| Decompiler (整体) | **SKELETON** | 18 行空 struct |
| Project Reconstruction | **SKELETON** | fox-project 空壳 |

---

## 4. Key Architectural GAPs

### GAP-1: IR L1 → L2 Expression Tree (P0)

当前 IR 是三地址指令级：
```
mov eax, [rsp+8]    → IR: Mov, operands=[Register(eax,Write), Memory(rsp,8,Read)]
add eax, ebx        → IR: Add, operands=[Register(eax,ReadWrite), Register(ebx,Read)]
```

反编译需要表达式树：
```
eax = *(rsp+8) + ebx
```

**缺失**: 从 SSA def-use 链重建表达式树的算法。SSA 已有 use-def/def-use，但没有将链式定义折叠成表达式的 pass。

### GAP-2: CFG → Structured Control Flow (P0)

当前只有原始 CFG + Dominator。缺少：
- Post-dominator（if/else 合流点识别必需）
- Natural loop detection（back edge + loop header）
- If-then-else recovery
- While/do-while recovery
- Switch structuring（jump table 已解析，但不生成结构化 switch）
- Irreducible CFG 处理

### GAP-3: Stack Offset → Variable Recovery (P1)

当前 Memory SSA 能识别 `[rsp+0x20]` 是 StackLocation，但没有：
- Stack frame layout 分析
- 局部变量命名（local_20）
- 参数识别（[rsp+...] 在 call 之前）
- 返回值识别（rax）
- 变量生命周期

### GAP-4: Flag → Condition Expression (P1)

Cmp/Test 只设置 `writes_flags=true`，没有：
- 具体 flag 位（ZF/CF/SF/OF）语义
- CondJump → condition expression（`if (a > b)`）
- Setcc → boolean expression

### GAP-5: Type Propagation & Function Signature (P1)

当前只有单指令原始类型推断，缺少：
- 跨指令类型传播
- 函数参数/返回值类型恢复
- Calling convention 识别（cdecl/stdcall/thiscall/fastcall）
- Struct field recovery
- 外部 API signature（KERNEL32!CreateFileW → known signature）

### GAP-6: AST & C-like Emitter (P0)

完全缺失：
- Expression AST (BinaryOp, UnaryOp, Call, MemberAccess, ArrayIndex, Cast, ...)
- Statement AST (If, While, Return, Assign, Block, Switch, Break, Continue)
- Function AST (signature + body)
- C-like source emitter（缩进、括号、类型声明、变量声明）

---

## 5. Shortest Path: Minimum Viable Decompiler Vertical Slice

**目标**: 让一个真实函数从 Binary 变成可读 C-like Source。

```
P0-6.1: Expression Recovery (SSA → Expression Tree)
  ├── 从 Register SSA use-def 链重建表达式
  ├── 支持 Mov/Add/Sub/Mul/Div/And/Or/Xor/Cmp
  ├── 支持 Load (memory→register)
  ├── 支持 Immediate
  └── 输出: expression tree per instruction

P0-6.2: Flag → Condition + If/Else Recovery
  ├── Cmp/Test + CondJump → condition expression
  ├── Post-dominator (最小实现)
  ├── If-then-else structuring
  └── 输出: structured CFG

P0-6.3: Variable Recovery (minimal)
  ├── Stack offset → local_N
  ├── Register → register variable (temporary)
  ├── Return value (rax/eax)
  └── 输出: variable table

P0-6.4: AST + C-like Emitter
  ├── Expression AST
  ├── Statement AST (If/Return/Assign/Block)
  ├── Function AST
  ├── C-like emitter
  └── 输出: int foo() { ... }

P0-6.5: Call Reconstruction + Function Signature
  ├── Direct call → foo(a, b)
  ├── 参数位置 (stack/register)
  ├── 返回值
  └── 外部 API signature (已知 API)
```

**最小闭环验证函数**:
```asm
; int max(int a, int b)
push ebp
mov  ebp, esp
mov  eax, [ebp+8]
cmp  eax, [ebp+12]
jle  .else
mov  eax, [ebp+8]
jmp  .end
.else:
mov  eax, [ebp+12]
.end:
pop  ebp
ret
```

目标输出:
```c
int max(int a, int b) {
    if (a > b)
        return a;
    return b;
}
```

---

## 6. NtcMach.exe Dogfood Observation

对 NtcMach.exe 真实函数执行 `fox ir` / `fox ssa` / `fox dataflow`：

- **IR**: 成功生成 L1 IR，指令级语义完整
- **SSA**: 成功生成 Register SSA，有 Phi 和 use-def
- **Memory SSA**: 成功生成（通过 Pipeline）
- **Value Flow**: 成功生成跨域值流
- **断点**: 到 Value Flow 为止，没有 Expression Recovery、Control Structure、Variable Recovery、AST、Emitter

**真实函数在 Value Flow 之后无法继续形成高级语义**——这就是当前的能力边界。

---

## 7. Current Reality

FOX 已经建成的：
- 一个强大的 **二进制分析引擎**（Binary → Function → CFG → IR → SSA → Memory SSA → Value Flow → Evidence → Reality）
- 精确的 **数据流基础设施**（Register SSA + Memory SSA + Cross-domain Value Flow）
- 可追溯的 **Evidence 体系**（Evidence → Claim → Reality）

FOX 还没有的：
- **反编译器**（fox-decompiler 是空壳）
- **表达式恢复**（SSA→expression tree）
- **控制流结构化**（CFG→if/else/while/switch）
- **变量恢复**（stack offset→C variable）
- **AST 和代码生成**

---

## 8. Architectural GAP Summary

| GAP | Severity | Description |
|---|---|---|
| Expression Recovery | P0 | SSA→expression tree 缺失 |
| Control Structure Recovery | P0 | CFG→if/else/while/switch 缺失 |
| AST + Emitter | P0 | 无 AST，无 C-like 输出 |
| Post-dominator | P1 | if/else 合流点识别必需 |
| Variable Recovery | P1 | stack offset→variable |
| Flag semantics | P1 | Cmp→condition expression |
| Type propagation | P1 | 跨指令类型传播 |
| Function signature | P1 | 参数/返回值/calling convention |
| Loop detection | P2 | back edge/natural loop |
| Struct/array recovery | P2 | 复合类型 |
| Irreducible CFG | P3 | 高级控制流 |

---

## 9. Final Verdict

**FOX 今天距离把 NtcMach.exe 完整反编译成可读 C-like Source，还差 6 层：**

1. **Expression Recovery** — SSA def-use 链已有，但没有表达式树重建
2. **Control Structure Recovery** — CFG + Dominator 已有，但无 post-dominator / if-else / loop / switch 结构化
3. **Variable Recovery** — Memory SSA 能识别 stack location，但无局部变量/参数/返回值恢复
4. **Flag → Condition** — Cmp/Test 只标记 writes_flags，无条件表达式
5. **Type Propagation & Signature** — 只有单指令原始类型，无函数签名/复合类型
6. **AST + C-like Emitter** — 完全缺失，fox-decompiler 是空壳

**最短可行路线**: P0-6.1 Expression Recovery → P0-6.2 If/Else Recovery → P0-6.3 Variable Recovery → P0-6.4 AST+Emitter → P0-6.5 Call/Signature。先让一个简单函数变成 `int max(int a,int b){ if(a>b) return a; return b; }`，再逐步扩大。

**FOX 的分析基础设施已经足够支撑反编译器开发**——SSA、Memory SSA、Value Flow、Dominator、Evidence 都是反编译器的必要前提，且全部已封板。现在是时候从"分析引擎"迈向"反编译器"了。

---

*Truth > Confidence. Evidence > Guess. Reality > Metric.*
