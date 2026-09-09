# FOX First Real Commercial DLL Dogfood Report

**Sample**: DevExpress.BonusSkins.v17.2.dll
**Date**: 2026-09-09
**FOX Commit**: `0bd0f90` (P0-4.4 SEAL candidate)
**Analyst**: 豆包A (施工方)
**Code Changes During Dogfood**: NONE (代码冻结)

---

## 1. Sample Identity

| Field | Value |
|-------|-------|
| Filename | DevExpress.BonusSkins.v17.2.dll |
| Size | 11,249,904 bytes (10.7 MB) |
| SHA-256 | `5626386303EAEF5D23F204933B80E5313904D85653FAF2C9A4381D03CA3CB698` |
| PE Format | PE32 (Windows 32-bit) |
| Machine | 0x014C (i386 / x86 32-bit) |
| ImageBase | 0x11000000 |
| EntryPoint | 0x11ABA70E |
| **CLR Header** | **RVA=0x2008, Size=72 — .NET CLR ASSEMBLY** |
| Sections | .text (11.2MB, RX), .rsrc (1.5KB, R), .reloc (512B, R) |
| Imports | 1 (mscoree.dll!_CorDllMain) |
| Exports | 0 |
| Relocations | 1 |
| Strings | 30,322 (mostly PNG image data: IHDR, PLTE, tRNS, pHYs) |
| .data section | **NONE** (no writable data section) |

### Critical Finding: This is a .NET Managed Assembly

独立验证 PE Data Directory[14] (CLI Header):
- RVA = 0x2008, Size = 72
- 唯一 import: `mscoree.dll!_CorDllMain`（.NET 运行时入口标准 thunk）
- 0 native exports
- Entry point: `jmp [0x11002000]`（跳转到 IAT 中的 _CorDllMain）
- .text 段 11MB 包含 IL 代码 + .NET 元数据 + 嵌入的 PNG 皮肤图片资源

**FOX 是原生 x86/x64 二进制分析工具，不支持 .NET IL。此样本超出 FOX 当前目标范围。**

---

## 2. Analysis Statistics

### 2.1 Commands That Succeeded

| Command | Result |
|---------|--------|
| `fox info` | ✅ PE metadata 正确解析（但未检测 CLR header） |
| `fox imports` | ✅ 正确识别 mscoree.dll!_CorDllMain |
| `fox strings` | ✅ 提取 30,322 strings |
| `fox disasm --address 0x11ABA70E` | ✅ 正确反汇编 entry thunk，但后续为垃圾 |

### 2.2 Commands That Failed / Hung

| Command | Result |
|---------|--------|
| `fox analyze --json` | ❌ **挂死**：45s 无输出，需 kill。stdout=0 bytes, stderr=空 |
| `fox functions` | ❌ **挂死**：>2min 无输出，需 kill |
| `fox cfg` | ⚠️ 未测试（依赖 analyze） |
| `fox ssa` | ⚠️ 未测试（依赖 analyze） |
| `fox dataflow` | ⚠️ 未测试（依赖 analyze） |

### 2.3 What FOX Actually Disassembles

Entry point (0x11ABA70E):
```
0x11ABA70E: FF 25 00 20 00 11   jmp [0x11002000]   ← 正确：_CorDllMain thunk
0x11ABA714: 00 00               add [eax], al       ← 垃圾：IL/元数据零字节
0x11ABA716: 00 00               add [eax], al       ← 垃圾
... (连续 50 条 add [eax], al)
```

FOX 将 .NET IL 代码和元数据中的零字节反汇编为 `add [eax], al`，将 PNG 图片数据反汇编为随机 x86 指令。

---

## 3. Capability Matrix

| Capability | Status | Notes |
|------------|--------|-------|
| PE Parsing | ✅ PASS | sections/imports/entrypoint/strings 正确 |
| .NET Detection | ❌ **FAIL** | 未解析 Data Directory[14] CLR Header，无法识别 .NET 程序集 |
| Function Discovery | ❌ **FAIL** | 对 11MB IL 数据挂死，无法完成 |
| CFG | N/A | 依赖 Function Discovery |
| Call Graph | N/A | 依赖 Function Discovery |
| IR | N/A | 依赖 Function Discovery |
| Register SSA | N/A | 依赖 Function Discovery |
| Memory Model | N/A | 依赖 Function Discovery |
| Memory SSA | N/A | 依赖 Function Discovery |
| Memory DataFlow | N/A | 依赖 Function Discovery |
| Cross-Domain Value Flow | N/A | 依赖 Function Discovery |
| Indirect Call Classification | N/A | 依赖 Function Discovery |
| Indirect Call Resolution | N/A | 依赖 Function Discovery |
| Evidence | ⚠️ PARTIAL | info/strings/disasm 有输出，但无分析级 Evidence |
| Robustness (no crash) | ⚠️ **PARTIAL** | 不 panic，但挂死（hang）属于可用性缺陷 |

---

## 4. Real Function Samples

**无法执行。** 原因：
1. 此 DLL 是 .NET 程序集，.text 段不包含原生 x86 函数
2. `fox functions` 挂死，无法获取函数列表
3. 唯一的原生代码是 entry point 的 6 字节 thunk（`jmp [0x11002000]`）

### 唯一可观察的原生代码片段

```
Address: 0x11ABA70E
Bytes:   FF 25 00 20 00 11
ASM:     jmp [0x11002000]
Type:    Indirect jump (IAT thunk for _CorDllMain)
Size:    6 bytes
```

这是 .NET DLL 的标准入口 thunk，不是真实业务函数。

---

## 5. Evidence Chains

**无法执行。** 完整分析链（Function → CFG → IR → SSA → Memory SSA → Value Flow）因 `fox analyze` 挂死而无法建立。

### 可观察的最短链（PE 层）

```
File (DevExpress.BonusSkins.v17.2.dll)
  ↓ PE Parser
Import: mscoree.dll!_CorDllMain
  ↓
EntryPoint: 0x11ABA70E
  ↓ Disasm
jmp [0x11002000]  (IAT thunk)
  ↓
Conclusion: .NET runtime entry, not native code
```

**但 FOX 自己不会得出这个结论** — 它没有 .NET 检测能力，会继续尝试将后续字节反汇编为 x86。

---

## 6. Memory SSA Findings

**无法执行。** `fox analyze` 挂死，无法进入 Memory SSA 阶段。

### 预期 GAP（基于样本性质）

即使 FOX 能完成分析，此 DLL 中也不存在：
- 原生 Stack Load/Store（IL 使用评估栈，不是 x86 栈帧）
- 原生 Global Variable（.NET 有自己的元数据格式）
- 原生 Function Pointer（.NET delegate 机制不同）

Memory SSA 对 .NET IL 不适用。

---

## 7. Indirect Call Findings

**无法执行完整统计。** 但 entry point 的 `jmp [0x11002000]` 是一个间接跳转（IAT thunk），FOX 的反汇编器能正确识别。

.NET DLL 中的真实"调用"是 IL `call` 指令，FOX 的 x86 反汇编器无法识别。

---

## 8. Failure / GAP List

### GAP-001: .NET CLR Assembly Detection Missing
- **Observed Behavior**: `fox info` 输出 architecture/sections/imports，但不报告 .NET CLR header
- **Expected Behavior**: 检测到 Data Directory[14] (CLI Header) 非零时，应明确标记为 ".NET CLR Assembly" 并警告不支持
- **Evidence**: 独立 PE 解析确认 CLI RVA=0x2008 Size=72；FOX info 输出无 .NET 信息
- **Severity**: **P0** — 导致后续所有分析挂死
- **Likely Root Cause**: PE parser 未实现 Data Directory 解析，特别是 CLR header
- **Suggested Future Phase**: P0-4.5 pre-work (PE parser enhancement) 或独立 robustness fix

### GAP-002: FOX Hangs on Unsupported / Non-Native Binaries
- **Observed Behavior**: `fox analyze` 和 `fox functions` 对 .NET DLL 挂死（>45s 无输出，无 panic，无错误）
- **Expected Behavior**: 检测到不支持的格式后，应输出结构化错误并退出（非零退出码），不应挂死
- **Evidence**: 45s 超时测试，stdout=0, stderr=空，需 SIGKILL
- **Severity**: **P0** — 挂死等于不可用，且无错误信息
- **Likely Root Cause**: Function Discovery 对 11MB 非代码数据进行线性扫描，零字节产生大量 `add [eax], al`，函数边界检测陷入大量伪函数
- **Suggested Future Phase**: 与 GAP-001 一起修复（检测 .NET 后提前退出）

### GAP-003: 32-bit x86 Support Not Validated
- **Observed Behavior**: FOX 主要开发和测试基于 x64 Ground Truth；此样本为 32-bit PE32
- **Expected Behavior**: 即使是原生 32-bit DLL，FOX 也应正确处理（EAX/ECX 等 32-bit 寄存器，不同调用约定）
- **Evidence**: 所有 Ground Truth 样本为 x64 (MSVC x64 O0/O2)；无 32-bit 测试样本
- **Severity**: **P1** — 32-bit 商业软件仍然大量存在
- **Likely Root Cause**: 开发聚焦 x64，32-bit 未建立 Ground Truth
- **Suggested Future Phase**: P0-5 (32-bit Ground Truth corpus)

### GAP-004: No Early Format Validation Gate
- **Observed Behavior**: FOX 对任何 PE 文件都尝试完整分析，不先检查是否为支持的子格式
- **Expected Behavior**: analyze 开始前应验证：native x86/x64? 有 .text 代码段? 有可执行入口?
- **Evidence**: .NET DLL 直接进入 Function Discovery 而无格式检查
- **Severity**: **P1**
- **Likely Root Cause**: 缺少 format validation gate
- **Suggested Future Phase**: 与 GAP-001 一起

### GAP-005: Disassembly of Non-Code Data Produces Garbage Without Warning
- **Observed Behavior**: `fox disasm` 将零字节和 PNG 数据反汇编为 `add [eax], al` 等，无任何"此地址可能不是代码"的警告
- **Expected Behavior**: 对明显非代码区域（全零、已知数据格式）应标记或警告
- **Evidence**: entry point 后 50 条指令全为 `add [eax], al`
- **Severity**: **P2** — 不阻断，但误导用户
- **Likely Root Cause**: 反汇编器无数据/代码区分能力
- **Suggested Future Phase**: P0-4.5+ (code/data discrimination)

### GAP-006: CI Efficiency (Registered Earlier)
- **Observed Behavior**: "Full test suite" 步骤重复运行已测测试，CI ~50min
- **Severity**: **P3**
- **Suggested Future Phase**: CI maintenance

---

## 9. False Positive / False Negative

### False Positives (可验证)

| FP | 说明 |
|----|------|
| `add [eax], al` 指令 | 零字节 (00 00) 被反汇编为有效指令，实际是 .NET 元数据填充 |
| 潜在伪函数 | Function Discovery 可能将 IL 代码中的字节模式误识别为函数入口（但因挂死无法量化） |

### False Negatives

| FN | 说明 |
|----|------|
| .NET CLR header | FOX 完全未检测到，属于"不知道自己不知道" |
| .NET 方法表/类型元数据 | 无法识别 .NET 特有结构 |

---

## 10. Final Verdict

### What FOX Can Prove
- PE32 头解析正确（machine, sections, imports, entrypoint, strings）
- 原生 x86 thunk 反汇编正确（`jmp [IAT]`）
- 字符串提取正确（30,322 条）

### What FOX Can Infer
- 唯一 import 是 mscoree.dll!_CorDllMain → 有经验的分析师可推断为 .NET
- 但 FOX **自己不会做出这个推断**

### What FOX Cannot Determine
- 这是 .NET 程序集（无 CLR header 检测）
- .text 段包含 IL 代码而非原生 x86
- 任何函数/CFG/SSA/Memory 分析结果（全部挂死）

### What FOX Currently Guesses
- 将 IL 字节和 PNG 数据"猜测"为 x86 指令（反汇编器不区分代码/数据）
- **这是最危险的**：FOX 不会说"我不知道"，而是输出垃圾反汇编结果

---

## 11. Recommended Next Phase

### 立即修复（不进入 P0-4.5）

**GAP-001 + GAP-002 应作为独立的 Robustness Fix 处理**，不属于 P0-4.5 范围：
1. PE parser 增加 Data Directory[14] (CLR Header) 解析
2. `fox info` 输出 ".NET CLR Assembly" 标记
3. `fox analyze` / `fox functions` 检测到 .NET 后输出结构化错误并退出
4. 增加 .NET DLL 到 robustness 测试集

这是 P0 级阻断问题：FOX 面对不支持的格式应该**优雅失败**，而不是挂死。

### P0-4.5 方向（待确认）

在修复 .NET 检测后，P0-4.5 应回到原生 DLL Dogfood：
- 需要一个**真正的原生 x86/x64 商业 DLL**（非 .NET）
- 建议候选：原生 Windows 系统 DLL（如 kernel32.dll 的子集）、或用户提供的其他原生 DLL
- 目标：验证 Function Discovery → CFG → SSA → Memory SSA → Value Flow 在真实原生代码上的表现

### 关于此样本

DevExpress.BonusSkins.v17.2.dll 是 .NET 程序集，**不适合作为 FOX（原生分析工具）的 Dogfood 样本**。
但它成功暴露了 FOX 的格式检测和鲁棒性缺陷，这本身就是有价值的 Dogfood 结果。

---

## 12. Summary

```
Sample: DevExpress.BonusSkins.v17.2.dll
SHA256: 5626386303EAEF5D23F204933B80E5313904D85653FAF2C9A4381D03CA3CB698
FOX Commit: 0bd0f90 (P0-4.4)

Analysis:
  PE Parsing:        PASS
  .NET Detection:    FAIL (P0 GAP)
  Full Analyze:      HANG (P0 GAP)
  Functions:         HANG
  Disasm (thunk):    PASS
  Disasm (IL data):  GARBAGE
  Strings:           PASS (30322)

Functions:   N/A (.NET, no native functions)
CFG:         N/A
IR:          N/A
SSA:         N/A
Memory SSA:  N/A
Value Flow:  N/A
Indirect:    N/A
Evidence:    PE-level only

PASS:    PE parsing, string extraction, thunk disasm
PARTIAL: Robustness (no panic but hangs)
FAIL:    .NET detection, full analyze, function discovery
N/A:     All downstream analysis (SSA/Memory/ValueFlow)

P0 GAP:  GAP-001 .NET detection missing
         GAP-002 FOX hangs on unsupported binaries
P1 GAP:  GAP-003 32-bit not validated
         GAP-004 No format validation gate
P2 GAP:  GAP-005 Non-code disassembly without warning
P3 GAP:  GAP-006 CI efficiency

Code Changes: NONE (代码冻结遵守)

Final Verdict:
  FOX 当前版本面对此 .NET 商业 DLL：
  - 能正确解析 PE 头和提取字符串
  - 不能识别 .NET 格式
  - 完整分析挂死
  - 反汇编输出垃圾但不警告
  
  此样本超出 FOX 原生 x86/x64 目标范围，
  但暴露了必须修复的格式检测和鲁棒性缺陷。

Recommended Next:
  1. 独立修复 GAP-001 + GAP-002 (.NET detection + graceful failure)
  2. 获取真正的原生 x86/x64 商业 DLL 进行第二次 Dogfood
  3. 然后决定 P0-4.5 (Object/VTable 或 Memory DataFlow 增强)
```
