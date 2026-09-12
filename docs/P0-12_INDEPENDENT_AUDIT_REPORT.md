# P0-12 Independent Read-Only Audit Report

**审计对象**: `52e1bcc` (Function Signature Recovery Foundation)
**审计性质**: 只读代码路径 + 独立复跑回归
**日期**: 2026-09-12

---

## 裁决

# ✅ PASS

P0-12 在 P0-11.3 DataFlowGraph 之上，**真实按 (callee, argument-index) 聚合参数证据**，
而非按 call 次数猜参数。命名克制（Parameter Evidence，不宣称 Calling Convention Recovery）。

---

## Audit 1 — Git Reality

| 项 | 值 | 判定 |
|----|-----|------|
| HEAD | `52e1bcc` | ✅ |
| Parent | `295d65d` (P0-11.3 Audit PASS) | ✅ |
| dirty | 0 | ✅ |
| 新增 | `signature.rs`, 报告 | ✅ |
| sealed modules (fox-analysis/fox-arch/IR/parser/lift/SSA) | **无改动** | ✅ |
| dataflow.rs 改动 | 仅加 `edges()` 访问器 + `ArgumentSourceKind: Hash` | ✅ 合理扩展 |

---

## Audit 2 — 数据结构真实性

`signature.rs` 真实存在：
```
ParameterLocation{Stack,Register,Unknown}
FunctionParameter{index,location,source,call_sites}
ReturnEvidence{Condition,Value,Unknown}
SignatureConfidence{High,Medium,Low}
FunctionSignature{function,parameters,return_evidence,confidence}
SignatureMap{signatures}
  Query: get/len/is_empty/with_param_count
FunctionSignatureBuilder::build
```
**判定**: 真实结构体。✅

---

## Audit 3 — Builder 真实消费 DataFlowEdge（重点 GAP1）

代码证据（signature.rs）：
```
160: for flow in dataflow.edges() {          // 遍历真实 DataFlowEdge
162:     match flow.callee { Address(a)=>a, _=>continue }  // symbol/unknown 跳过
166:     match &flow.detail {
167:         Argument{index, source} => 按 (callee,index) 累加 source 计数
172:         Return{consumer}       => 聚合 return_seen
192:     每 index 取 source 众数 + call_sites
```

**关键判定**: 参数数量来自 `FlowDetail::Argument{index}` 的 index 维度，
**不是 call 次数统计**。symbol/unknown callee 不编造签名节点。✅

---

## Audit 4 — emitter 只读

emitter.rs：
```
175: set_signatures(map) 注入
356: emit_signature_evidence 只读 self.signatures
362: map.get(func_addr) 查询
```
**判定**: emitter 不自己分析签名。✅

---

## Audit 5 — 真实参数统计（独立复跑）

```
Total functions: 359
P0-12 Function Signatures: callees=183 (>=1 param: 113, >=2 params: 62)
OK (readable): 339 (94.4%)
```

输出 `ntcmach_decompilation_p0_12.c`：180 个签名证据块。
样本：`params: (none recovered)` / `arg0: stack (constant, N call sites)` / `return: value`。

**比例健康**：183/359 个被调用函数有签名，未出现 100% 全有参数、未编造 int/pointer。
fail-closed 有效。✅

---

## Audit 6 — 回归

| 检查 | 结果 |
|------|------|
| NtcMach OK | **339 / 359 (94.4%)**，复跑一致 ✅ |
| batch test | 1 passed, 0 failed ✅ |
| 全量 `cargo test -p fox-decompiler` | 84 passed, 0 failed（lib 52→57 含 5 新 signature 单测）✅ |
| fmt / clippy `-D warnings` | PASS ✅ |

---

## 命名克制性确认（用户提醒）

- 当前 `ParameterLocation` 只有 Stack/Register/Unknown，**未宣称** cdecl/stdcall/fastcall/thiscall
- `ReturnEvidence` 是行为证据（condition/value/ignored），**未宣称** int/pointer/bool 类型
- 这两点正是 P0-13 的活，本阶段命名保持准确。✅

---

## 已知 GAP（不阻塞 PASS）

1. Calling convention 未自动识别（参数 location 粗粒度）
2. callee 内部栈参数槽未验证（聚合自 caller PUSH）
3. ReturnEvidence 未到类型层
4. 参数名未恢复（仅 arg0/arg1 槽位）
5. P0-11.3 mem=0 继续影响 MemoryLoad 参数计数

---

## 结论

P0-12 **PASS**。FOX 第一次拥有函数接口事实（183 个被调用函数的参数个数/来源/返回值消费）。
允许进入下一阶段：**P0-13 Type Propagation**。
