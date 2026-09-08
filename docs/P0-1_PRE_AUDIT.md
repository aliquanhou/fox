# FOX P0-1 Pre-Implementation Audit

**审计对象**: P0-0 全部核心 crate
**审计日期**: 2026-09-08
**审计结论**: P0-0 基础设施可用，但 Binary Analysis Core 需从零构建真正的 BB/CFG/IR 管线

---

## 1. Function Discovery 真实算法

### 当前实现 (`fox-analysis/src/lib.rs`)
四步策略：
1. **入口点**: 硬编码 `binary.entry_point`，标记 EntryPoint evidence
2. **导出表**: 遍历 `binary.exports`，标记 ExportEntry evidence
3. **CALL 目标**: 线性扫描所有可执行节区，反汇编后收集所有 `instruction.call_target`
4. **Prologue 匹配**: 字节级扫描，匹配 `push rbp; mov rbp, rsp` 等模式

### 缺陷
- ❌ **无递归下降**: 不从入口点开始递归遍历，可能遗漏可达函数
- ❌ **无地址验证**: CALL 目标不验证是否在可执行节区内
- ❌ **无 Negative Evidence**: 不降低数据段中误报地址的置信度
- ❌ **无 Confidence 分级**: 所有函数统一处理，不区分 Confirmed/High/Probable/Unknown
- ❌ **Prologue 误报**: 字节级扫描可能匹配到数据中的巧合字节
- ❌ **end_address/size 全为 None**: 不确定函数边界

---

## 2. Basic Block 状态

**结论: 完全不存在。**

`cfg::ControlFlowGraph::build()` 仅为每个函数创建一个 BasicBlock：
```rust
BasicBlock {
    start_address: func.value.address,
    end_address: func.value.address,  // start == end，无实际内容
    successors: vec![],               // 空
    predecessors: vec![],             // 空
    instruction_count: 0,             // 零
}
```

没有指令分割，没有边界识别，没有边。

---

## 3. CFG 状态

**结论: 不是 CFG，仅是函数入口地址列表。**

- 无 successors / predecessors 边
- 无 Fallthrough / Conditional / Unconditional 边类型区分
- 无指令级证据
- `entry_block` 只是第一个函数的 block id，不是真正的函数入口块

---

## 4. CALL / JMP / Jcc / RET 处理

| 指令 | Instruction 标志 | fox-analysis 中的使用 |
|---|---|---|
| CALL | `is_call`, `call_target` | 仅用于函数发现（收集目标地址） |
| JMP (unconditional) | `is_jump`, `jump_target` | **完全未使用** |
| Jcc (conditional) | `is_conditional_jump`, `jump_target` | **完全未使用** |
| RET | `is_ret` | **完全未使用** |

**核心问题**: 反汇编层已经正确识别了控制流指令，但分析层完全没有消费这些信息。

---

## 5. 间接 CALL / JMP 处理

**结论: 静默丢弃。**

当 `call_target` 或 `jump_target` 为 `None` 时（间接跳转/调用）：
- 函数发现: `filter_map(|i| i.call_target)` 直接过滤掉
- CFG: 不存在，所以不处理
- 无 IndirectCall / IndirectJump 概念
- 无 Unknown target 标记

---

## 6. IR 实现程度

**结论: 零实现，仅有数据结构定义。**

- `IROp` 枚举: 定义了 30+ 操作码，但**无任何映射代码**
- `IROperand` 枚举: 定义了 Register/Immediate/Memory/Label/Variable/Constant
- `IRInstruction`, `IRBasicBlock`, `IRFunction`, `IRModule`: 纯数据结构
- **没有任何函数将机器 Instruction 转换为 IRInstruction**
- **没有 Instruction Mapping 表**

---

## 7. Evidence 聚合路径

**当前状态**:
```
Evidence → Function (仅在此级别)
```

**缺失**:
- ❌ Instruction 级 Evidence（每条指令的来源证据）
- ❌ BasicBlock 级 Evidence（块边界证据）
- ❌ CFG Edge 级 Evidence（边存在的证据）
- ❌ EvidenceKind 缺少: BranchTarget, Fallthrough, IndirectTarget, NegativeEvidence
- ❌ 无从下往上的聚合机制

---

## 8. Skeleton 清单（仅占位，无实现）

| Crate/Module | 状态 | 内容 |
|---|---|---|
| `fox-ir` | 🟡 数据结构 | 类型定义，零映射逻辑 |
| `fox-analysis/cfg` | ❌ 空壳 | 函数地址列表，无边 |
| `fox-analysis/callgraph` | ❌ 空壳 | 复制空的 calls 向量 |
| `fox-analysis/dataflow` | ❌ 空 | `pub struct DataFlowAnalysis;` |
| `fox-analysis/type_recovery` | ❌ 空 | `pub struct TypeRecovery;` |
| `fox-analysis/symbol` | ❌ 空 | `pub struct SymbolAnalysis;` |
| `fox-decompiler` | ❌ 空 | `pub struct Decompiler;` |
| `fox-project` | 🟡 最小 | 仅 name/version 字段 |

---

## 9. P0-1 施工优先级

按依赖关系排序：

1. **fox-core**: 扩展 EvidenceKind（CFG边、NegativeEvidence），增加 Edge 类型
2. **fox-disasm**: 增强 Instruction（结构化操作数、间接目标标记）
3. **fox-analysis/basic_block**: 新建 BasicBlock Engine（真正的分割算法）
4. **fox-analysis/cfg**: 重写 CFG（真正的边 + 边类型 + 证据）
5. **fox-analysis/callgraph**: 重写 CallGraph（Direct/Indirect/External/Unknown）
6. **fox-analysis/function_discovery**: 精化（递归下降 + Negative Evidence + Confidence 分级）
7. **fox-ir/l1**: 实现 Instruction → IR L1 映射
8. **Golden Samples**: 编译最小样本 + Ground Truth
9. **Fuzz**: Malformed PE 测试
10. **CLI**: 新增 disasm/blocks/cfg/callgraph/ir/evidence
11. **JSON Schema**: 冻结 v1
12. **CI**: no warnings + golden tests
