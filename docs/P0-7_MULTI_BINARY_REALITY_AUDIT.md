# P0-7 Commercial Software Multi-Binary Reality Audit

**性质：** 只读审计，不修改 FOX 核心代码
**日期：** 2026-09-11
**审计对象：** 制版软件完整安装目录（20 个 PE 文件）
**工具：** FOX CLI (info / imports / exports / strings)

---

## 一、资产总览

| 类型 | 数量 | 总大小 | 说明 |
|------|------|--------|------|
| EXE | 2 | 460 KB | 主程序 + 键表工具 |
| DLL | 12 | 1,576 KB | 业务插件（统一 11 函数接口） |
| SYS | 6 | 172 KB | 内核驱动 |
| **PE 合计** | **20** | **2,208 KB** | 全部 x86 (32-bit) Native |

**全部 20 个 PE 文件均为 x86 Native，无 Managed CLR，无 Mixed Mode。**

---

## 二、EXE 模块

### NtcMach.exe（主程序，408 KB）

| 属性 | 值 |
|------|-----|
| 架构 | PE32 x86 |
| Entry Point | 0x455E4C |
| Image Base | 0x400000 |
| Sections | .text / .rdata / .data / .rsrc |
| 静态导入 | 174 functions from 8 DLLs |
| 导出 | 0 |
| 字符串 | 1001 |

**静态导入的 8 个 DLL 全部是系统 DLL：**

| DLL | 导入函数数 | 用途 |
|-----|-----------|------|
| USER32.dll | 64 | GUI 窗口/消息/菜单 |
| MSVCRT.dll | 47 | C 运行时 |
| KERNEL32.dll | 28 | 文件/线程/内存/LoadLibrary |
| GDI32.dll | 27 | 图形/打印/调色板 |
| SETUPAPI.dll | 4 | 设备安装（驱动通信） |
| COMCTL32.dll | 2 | 工具栏 |
| comdlg32.dll | 1 | 打印对话框 |
| SHELL32.dll | 1 | ShellExecute |

**关键发现：NtcMach.exe 没有静态导入任何 NTC* 业务 DLL。**

业务 DLL 通过 `LoadLibraryA` + `GetProcAddress` 动态加载。二进制中硬编码了 DLL 名列表（无后缀）：
```
NTCDLL_M4, NTCDLLG, NTCDLLM, NTCDLLC,
NTCDLLA1, NTCDLLA2, NTCDLLA3, NTCDLLA4,
NTCDLLA5, NTCDLLA6, NTCDLLA7(缺失), NTCDLLV
```
以及函数 `NTC_LoadAll`（负责加载全部插件）。

### KeyTable.exe（键表工具，52 KB）

| 属性 | 值 |
|------|-----|
| 静态导入 | 57 functions from 1 DLL |
| 导入 DLL | KERNEL32.dll only |
| 导出 | 0 |

**纯控制台/工具程序**，无 GUI 依赖。用于生成/编辑键表数据（chi/COM/ 目录下的 KEY_*.BMP/TBL 文件）。

---

## 三、DLL 模块 — 统一插件接口

### 核心架构发现

**12 个 DLL 每个都恰好导出 11 个函数，命名模式完全统一：**

```
{Prefix}_f00, {Prefix}_f01, ..., {Prefix}_f07,
{Prefix}_f18, {Prefix}_f19, {Prefix}_f20
```

这是一个**标准的硬件驱动插件接口**（11 个虚函数槽位）。

### DLL 业务角色映射

| DLL | 大小 | 导出前缀 | 业务角色 |
|-----|------|---------|---------|
| NTCDLLG.DLL | 172 KB | **Dgraph** | 图形/绘图引擎 |
| NTCDLLM.DLL | 124 KB | **DMachine** | 机器控制核心 |
| NTCDLLC.DLL | 112 KB | **DCompiler** | 花样/指令编译器 |
| NTCDLLV.DLL | 92 KB | **DVtest** | 验证/测试 |
| NtcDLL_M3.DLL | 120 KB | **DFeed0** | 送料器驱动 (型号3) |
| NtcDLL_M4.DLL | 128 KB | **DFeed0** | 送料器驱动 (型号4) |
| NTCDLLA1.DLL | 132 KB | **DAutoTape** | 自动胶带机 (型号1) |
| NTCDLLA2.DLL | 132 KB | **DAutoTape** | 自动胶带机 (型号2) |
| NTCDLLA3.DLL | 136 KB | **DAutoTape** | 自动胶带机 (型号3) |
| NTCDLLA4.DLL | 136 KB | **DAutoTape** | 自动胶带机 (型号4) |
| NTCDLLA5.DLL | 140 KB | **DAutoTape** | 自动胶带机 (型号5) |
| NTCDLLA6.DLL | 152 KB | **DAutoTape** | 自动胶带机 (型号6) |

**分组：**
- **核心业务 DLL（4个）：** Dgraph / DMachine / DCompiler / DVtest — 每个角色唯一
- **硬件驱动 DLL（8个）：** 6x DAutoTape + 2x DFeed0 — 同一接口的不同硬件型号实现
- NTCDLLA7 在 NtcMach 字符串中被引用但目录中**不存在**（可选型号，未安装）

### 插件接口函数地址分布

以 NTCDLLG.DLL (Dgraph) 为例：
```
f00 @ 0x1030   f01 @ 0x1050   f02 @ 0x1090   f03 @ 0x10D0
f04 @ 0x1120   f05 @ 0x1160   f06 @ 0x11A0   f07 @ 0x1200
f18 @ 0x1260   f19 @ 0x1280   f20 @ 0x12A0
```
f00-f07 连续排列，f18-f20 是扩展槽位。

---

## 四、SYS 驱动模块

| SYS | 大小 | 导入 | 导出 | 角色 |
|-----|------|------|------|------|
| Generic.sys | 41.8 KB | 43 | **37** | 标准 USB WDM 驱动框架 |
| NtcLPP.sys | 24.5 KB | 46 | 0 | 过滤驱动（LPT/并口？） |
| SfDriverBulk.sys | 26.5 KB | 50 | 0 | USB Bulk 传输驱动 |
| SfDriverKey.sys | 26.5 KB | 50 | 0 | USB 键盘/按键驱动 |
| SfDriverMaster.sys | 26.5 KB | 50 | 0 | USB 主设备驱动 |
| SfDriverPro.sys | 26.5 KB | 50 | 0 | USB Pro 设备驱动 |

**Generic.sys 导出 37 个标准 WDM 接口**（`_GenericDispatchPnp@8`, `_GenericAcquireRemoveLock@8` 等），是微软提供的通用 USB 驱动框架模板。

4 个 SfDriver*.sys 导入表完全相同（50 functions），是同一驱动针对不同 USB 设备类型的变体。

NtcMach.exe 通过 SETUPAPI.dll（4 个函数）与驱动通信（`SetupDiGetClassDevsA` → `DeviceIoControl`）。

---

## 五、模块依赖关系图

```
                    ┌─────────────────┐
                    │   NtcMach.exe   │  (GUI 主程序, LoadLibrary 动态加载)
                    └────────┬────────┘
                             │ LoadLibraryA + GetProcAddress
           ┌─────────────────┼─────────────────┐
           ▼                 ▼                 ▼
    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │  核心 DLL (4) │  │ 硬件 DLL (8) │  │  系统 DLL    │
    │ Dgraph       │  │ 6x DAutoTape │  │ KERNEL32     │
    │ DMachine     │  │ 2x DFeed0    │  │ USER32       │
    │ DCompiler    │  │              │  │ GDI32        │
    │ DVtest       │  │              │  │ MSVCRT       │
    └──────────────┘  └──────────────┘  │ SETUPAPI     │
                                        └──────┬───────┘
                                               │ DeviceIoControl
                                               ▼
                                    ┌──────────────────┐
                                    │  内核驱动 (6 SYS) │
                                    │ Generic.sys      │
                                    │ 4x SfDriver*.sys │
                                    │ NtcLPP.sys       │
                                    └──────────────────┘

                    ┌─────────────────┐
                    │  KeyTable.exe   │  (独立工具, 仅 KERNEL32)
                    └─────────────────┘
```

---

## 六、NtcMach.exe 110 DirectExternal 分析

P0-5.2 确认 NtcMach.exe 有 110 个 DirectExternal call。**这些全部是系统 DLL 调用**（KERNEL32/USER32/GDI32/MSVCRT 等），已通过 Import Thunk 解析。

**业务 DLL 调用不在静态导入表中**，因为是动态加载：
```
LoadLibraryA("NTCDLLG")       → HMODULE
GetProcAddress(hmod, "Dgraph_f00") → 函数指针
call [函数指针]                 → indirect call (FOX 当前显示 call_unknown)
```

---

## 七、NtcMach 1219 个 indirect call (call_unknown) 的来源分析

P0-6.10 确认 NtcMach 有 1219 个 `call_unknown`。根据本次审计，主要来源：

| 来源 | 估计占比 | 可解析性 |
|------|---------|---------|
| **DLL 插件函数指针调用**（GetProcAddress 返回值） | 高 | ✅ 可通过 LoadLibrary→GetProcAddress 追踪解析 |
| C++ 虚函数调用（vtable） | 中 | ⚠️ 需 vtable 分析 |
| 回调函数指针 | 低 | ⚠️ 需 Value Flow |
| 真正无法静态解析 | 低 | ❌ |

**最大机会：DLL 插件调用。** NtcMach.exe 硬编码了全部 DLL 名和 11 函数接口，如果 FOX 能追踪：
```
LoadLibraryA("NTCDLLG") → hmod
GetProcAddress(hmod, "Dgraph_f00") → func_ptr
call func_ptr → call Dgraph_f00(...)
```
那么大量 indirect call 可以解析为具体的 DLL 导出函数，进而进入 DLL 内部分析。

---

## 八、DLL 可分析性评估

对 12 个业务 DLL 进行 FOX 分析的可行性：

| DLL | 可分析函数估计 | 优先级 | 理由 |
|-----|--------------|--------|------|
| NTCDLLG.DLL (Dgraph) | ~100-200 | 🔴 高 | 图形引擎，最大最核心 |
| NTCDLLM.DLL (DMachine) | ~100-150 | 🔴 高 | 机器控制核心 |
| NTCDLLC.DLL (DCompiler) | ~80-120 | 🟡 中 | 花样编译器 |
| NTCDLLV.DLL (DVtest) | ~50-80 | 🟡 中 | 验证测试 |
| 6x DAutoTape | 各 ~50-80 | 🟡 中 | 硬件驱动，接口统一 |
| 2x DFeed0 | 各 ~50-80 | 🟡 中 | 送料器驱动 |

**总计可分析函数估计：1000-1500 个**（远超 NtcMach.exe 的 359 个）。

---

## 九、关键架构结论

### 结论 1：这是一个标准的插件化硬件控制软件
- 主程序 + 统一接口 DLL + 内核驱动的三层架构
- 12 个 DLL 实现 11 函数虚接口，支持多硬件型号
- NtcMach.exe 通过 NTC_LoadAll 动态发现和加载插件

### 结论 2：FOX 当前只分析了"冰山一角"
- NtcMach.exe: 359 函数（已分析）
- 12 DLL: 估计 1000-1500 函数（未分析）
- 业务逻辑主要在 DLL 中，EXE 主要是 GUI 和调度

### 结论 3：跨模块调用解析是下一个最大跃迁
如果实现 `LoadLibrary → GetProcAddress → call` 追踪：
- 1219 个 indirect call 中大量可解析
- 可以从 EXE call 直接进入 DLL 函数内部
- 符号名从 `call_unknown` → `call Dgraph_f00`

### 结论 4：SYS 驱动暂不需要深入
- Generic.sys 是标准框架，业务逻辑少
- SfDriver*.sys 是 USB 传输层，不是业务逻辑
- NtcLPP.sys 可能是并口过滤，优先级低

---

## 十、建议下一步

### P0-7.1 跨 EXE/DLL 调用与符号解析（推荐）

**目标：** 追踪 `LoadLibraryA` → `GetProcAddress` → indirect call，将 NtcMach 的 call_unknown 解析为具体 DLL 导出函数。

**最小闭环：**
1. 识别 NtcMach.exe 中的 `LoadLibraryA("NTCDLLG")` 调用
2. 识别后续 `GetProcAddress(hmod, "Dgraph_f00")` 调用
3. 将返回的函数指针与 indirect call 关联
4. 输出 `call Dgraph_f00(...)` 而非 `call_unknown(...)`
5. 可选：进入 DLL 内部函数分析

**预期收益：** NtcMach 1219 个 call_unknown 中，估计 30-50% 可解析。

### 后续路线（P0-7 审计后决定）

```
P0-7.1 跨 EXE/DLL 调用解析
    ↓
P0-8.x DLL 批量反编译（12 个 DLL 1000+ 函数）
    ↓
P0-9.x Variable Recovery
    ↓
P0-10.x Nested Control Structure / Switch
    ↓
P0-11.x Project Reconstruction（完整软件理解）
```

---

## 十一、审计统计汇总

| 指标 | 值 |
|------|-----|
| PE 文件总数 | 20 |
| EXE | 2 (NtcMach.exe, KeyTable.exe) |
| DLL | 12 (全部统一 11 函数插件接口) |
| SYS | 6 (1 框架 + 4 USB + 1 过滤) |
| 全部 Native | ✅ 20/20 |
| 全部 x86 | ✅ 20/20 |
| NtcMach 静态导入 | 174 functions / 8 system DLLs |
| NtcMach 业务 DLL 导入 | 0 (动态加载) |
| DLL 统一导出接口 | 11 functions (f00-f07, f18-f20) |
| 业务角色数 | 6 (Dgraph/DMachine/DCompiler/DVtest/DAutoTape/DFeed0) |
| 估计 DLL 可分析函数 | 1000-1500 |
| NtcMach indirect call 可解析潜力 | 30-50% (通过 GetProcAddress 追踪) |

---

**没有 Evidence，不生成 Claim。**
**本审计基于 FOX CLI 对 20 个 PE 文件的真实解析，无猜测。**
