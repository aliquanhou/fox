# P0-11 Cross Function Semantic Graph Foundation

**阶段**: P0-11
**目标**: 建立跨函数语义关系图基础
**基线**: `4c6beb0` (P0-10.5 Audit)
**日期**: 2026-09-12

---

## 1. 修改文件

| 文件 | 修改内容 |
|------|----------|
| `crates/fox-decompiler/src/emitter.rs` | 升级 Function Graph Evidence 输出，更新角色推断 |

**未修改**: SSA、Memory SSA、Expression Recovery、CFG、ConditionRecovery、CallGraph、DynamicPluginResolver、Structured IR 等所有已封板模块。

---

## 2. 实现方法

### 2.1 升级输出格式

```
*   P0-11 Function Graph Evidence: N objects, M fields, K accesses
*   Candidate Role: XXX (YYY confidence)
*   Evidence: ...
```

### 2.2 角色推断升级

| 条件 | 候选角色 | 置信度 |
|------|----------|--------|
| >20 accesses AND >=5 fields | state-manager-like | MEDIUM |
| >5 accesses AND >=2 fields | accessor-like | LOW |
| >10 accesses | worker-like | LOW |
| 其他 | UNKNOWN | NONE |

---

## 3. NtcMach 真实 Dogfood

| 指标 | 数值 |
|------|------|
| 339 OK | ✅ 保持 |
| 函数证据输出 | 97 个函数输出 |

---

## 4. 已知限制（GAP）

### GAP-P0-11-CROSS-FUNCTION-DETAILED（P1）
当前只基于本地访问频率推断角色，未建立真正的跨函数图：
- Caller/Callee 关系
- Global Ownership
- Function Cluster
- Return Value Flow

这些需要深入 SSA 分析层和 CallGraph 分析。

---

## 5. Tests

| 测试套件 | 结果 |
|----------|------|
| fox-decompiler lib tests | 42 PASS |
| 全部 integration tests | 27 PASS |
| **总计** | **69 PASS, 0 FAIL** |

- `cargo fmt`: PASS
- `cargo clippy --all-targets -- -D warnings`: PASS

---

## 6. 结论

P0-11 建立了跨函数语义关系图的基础框架，升级了角色推断。真正的跨函数图分析需要在分析层实现。

**状态**: IMPLEMENTATION COMPLETE → WAITING FOR AUDIT
