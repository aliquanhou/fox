# GAP-RM-1 Global Region Recovery & Portable Object Foundation

**阶段**: GAP-RM-1（Reality Mission 第一个修复）
**触发**: KeyTable.exe 全链 dogfood 暴露 objects=0
**日期**: 2026-09-12

---

## 1. 缺陷

P0-15 用硬编码常量识别全局对象：
```rust
const GLOBAL_BASE_MIN: u64 = 0x460000;
const GLOBAL_BASE_MAX: u64 = 0x480000;
```
这是 NtcMach.exe `.data` 段的反推范围。换到 KeyTable.exe（独立 PE、不同 ImageBase），全局变量落在别的地址，**objects=0**。

NtcMach dogfood 永远测不出这个——正是真实项目第一时间击穿。

---

## 2. 修复

新增 `GlobalRegionMap`：从 PE section table 推导可写全局区，**不再有任何硬编码地址**。

```rust
pub struct GlobalRegion { name, va_start, va_end }
pub struct GlobalRegionMap { regions: Vec<GlobalRegion> }

impl GlobalRegionMap {
    pub fn from_binary(bin: &Binary) -> Self {
        // writable && !executable sections (.data/.bss/writable .rdata)
        // va = image_base + RVA
    }
    pub fn contains(addr) -> bool
}
```

ObjectRecoveryBuilder 改造：
```rust
// before: ObjectRecoveryBuilder::build(&all_funcs)
// after:  ObjectRecoveryBuilder::build(&all_funcs, &regions)
```
- 删除 `GLOBAL_BASE_MIN/MAX` 常量
- `regions.contains(addr)` 替代硬编码区间判断

---

## 3. 修改文件

| 文件 | 内容 |
|------|------|
| `src/object_recovery.rs` | 新增 GlobalRegion/GlobalRegionMap；build 签名加 regions；删硬编码；+1 test_regions helper |
| `src/lib.rs` | re-export GlobalRegionMap |
| `tests/p0_6_7_batch_decompile.rs` | from_binary(&binary) → build(funcs,&regions) |
| `tests/remission_keytable_decompile.rs` | 同上（KeyTable 目标） |
| `tests/reality_mission_inventory.rs` | 新增：全目录 PE 清点（14 artifacts） |

---

## 4. 三目标验证（Phase 3）

### KeyTable.exe（修复前→后）
```
修复前: objects=0, fields=0
修复后: GAP-RM-1 GlobalRegions: 1 writable section
        objects=43, fields=19
        OK 146/147 = 99.3%（保持）
```

### NtcMach.exe（不下降，且更准）
```
修复前: objects=26, fields=20（窄硬编码窗口）
修复后: GAP-RM-1 GlobalRegions: 1 writable section
        objects=332, fields=30
        OK 339 (94.4%)（保持）
```
段表覆盖比旧窄窗口大，对象识别从 26 升到 332——证明旧硬编码还漏了大量真对象。

### 全目录（Phase 1 清点）
14/14 PE（1 EXE + 13 DLL）全部 loadable，零失败，共 4111 函数。

---

## 5. 回归 Gate

| 检查 | 结果 |
|------|------|
| KeyTable OK | 146/147 (99.3%) |
| NtcMach OK | 339/359 (94.4%) |
| object 单测 | 5 passed |
| 全量 cargo test | PASS |
| fmt / clippy -D warnings | PASS |
| sealed modules | 未改 |

---

## 6. 意义

Object Recovery 从 NtcMach-specific 变为**通用 PE 能力**：
```
Binary
  ▼ CFG / CallGraph / DataFlow / Signature / Type / Variable   (已跨 PE)
  ▼ Object Recovery   (此前 NtcMach 特化 → 现在 portable)
```

Reality Mission 第一个 finding 闭环：真实项目暴露硬编码 → 从段表推全局区 → 多 PE 验证。

---

## 7. 已知 GAP（后续）

1. objects=332/NtcMach 多为纯全局变量基址，连续 offset struct-layout 仍稀疏（offset 多为 0）
2. Unknown-reason `[reg+off]` mem operand 未接入（P0-15 主 GAP 仍在）
3. DLL 目标尚未跑完整全链（仅 inventory 证明可 load/analyze）
4. 字段 size/type 仍未恢复

**状态**: GAP-RM-1 FIXED → 待独立审计
