# FOX P0-0 Reality Audit & Architecture Bootstrap — 施工报告

**项目**: FOX — Binary Reverse Engineering & Decompilation Platform
**阶段**: P0-0 (Reality Audit & Architecture Bootstrap)
**日期**: 2026-09-08
**状态**: ✅ SEALED (Evidence + Test + CI 全部就绪)

---

## 1. 行业现状

### 1.1 主流工具能力矩阵

| 工具 | 开源 | 反编译器 | IR | 多架构 | 证据链 | CLI优先 | 核心语言 |
|---|---|---|---|---|---|---|---|
| **Ghidra** (NSA) | ✅ Apache-2.0 | ✅ 高质量 | P-code | ✅ 广泛 | ❌ 无显式证据 | ❌ GUI优先 | Java |
| **IDA Pro** | ❌ 商业 | ✅ Hex-Rays | Microcode | ✅ 广泛 | ❌ | ❌ GUI优先 | C++ |
| **Binary Ninja** | ❌ 商业 | ✅ | BNIL (LLIL/MLIL/HLIL) | ✅ | ❌ | ❌ GUI优先 | C++ |
| **Cutter/Radare2** | ✅ LGPL | ❌ 弱 | ESIL | ✅ | ❌ | ✅ CLI | C |
| **angr** | ✅ BSD | ❌ | VEX | ✅ | ❌ | ✅ Python API | Python |
| **ILSpy** | ✅ MIT | ✅ .NET | ILAst | ❌ .NET only | ❌ | ❌ | C# |
| **dnSpyEx** | ✅ GPLv3 | ✅ .NET | ILAst | ❌ .NET only | ❌ | ❌ | C# |

### 1.2 各工具核心特征

- **Ghidra**: 反编译质量接近 IDA，P-code IR 设计成熟，但 Java 生态笨重，分析结果不可追溯，GUI 与核心紧耦合。
- **IDA Pro**: 业界标准，Hex-Rays 反编译器质量最高，但闭源昂贵，microcode IR 不公开完整规范。
- **Binary Ninja**: BNIL 多层 IR 设计优秀，API 现代化，但商业闭源，功能覆盖不如 IDA/Ghidra。
- **Radare2/Cutter**: 命令行强大，ESIL IR 可用于仿真，但 UI 弱，反编译能力弱，代码质量参差不齐。
- **angr**: 符号执行强，VEX IR 来自 Valgrind，但 Python 性能瓶颈，静态分析不是重点。
- **ILSpy/dnSpyEx**: .NET 专用，利用 MSIL 元数据反编译质量高，但完全不处理 native code。

---

## 2. Gaps (FOX 的机会)

### 2.1 已解决的问题（不需要重复造轮子）
- PE/ELF/Mach-O 格式解析 — 格式稳定，有成熟参考
- x86/x64 指令解码 — Zydis/Capstone 已解决
- 基础反汇编 — 成熟技术
- .NET 托管代码反编译 — ILSpy 已解决（FOX 不竞争此领域）

### 2.2 FOX 真正的缺口（必须自主实现）

| Gap | 描述 | 为什么现有工具没解决 |
|---|---|---|
| **Evidence System** | 每个分析结论必须可追溯到具体证据 | 所有工具输出结论但不解释"为什么" |
| **CLI-First 架构** | 核心引擎与 GUI 完全解耦，CLI 一等公民 | Ghidra/IDA/Binary Ninja 都是 GUI-first |
| **现代内存安全核心** | Rust 编写，处理不可信二进制输入无内存安全风险 | 所有主流工具都是 C/C++/Java |
| **可审计的分析管线** | Binary→Instruction→BB→CFG→IR 每一步可验证 | 现有工具的分析管线是黑盒 |
| **项目重建** | 从二进制恢复完整项目结构（非仅函数列表） | 没有工具以此为核心目标 |
| **AI 辅助的正确定位** | AI 作为分析助手，输出必须带证据，不作为 Ground Truth | 现有 AI 逆向工具直接输出猜测 |

### 2.3 应该复用的能力
- **Zydis**: x86/x64 反汇编引擎（P0）
- **Capstone**: 多架构反汇编（P0-2+，ARM64 时引入）
- **serde**: 证据和分析结果的序列化
- **Tauri**: GUI 框架（P1）

---

## 3. FOX 产品定位

**FOX — Binary Reverse Engineering & Decompilation Platform**
**中文**: FOX 逆向工程与反编译平台

### 3.1 FOX 是什么
- 一个真正独立的、现代化的逆向工程平台
- 从编译后的软件中恢复尽可能高质量、可验证、可理解的软件结构与源码表示
- 以 Evidence System 为核心，每个结论都可审计

### 3.2 FOX 不是什么
- ❌ DLL 查看器
- ❌ Hex Editor
- ❌ 简单反汇编器
- ❌ Ghidra/IDA 的 UI 克隆
- ❌ AI 猜代码工具

### 3.3 架构约束
- **从架构层面禁止绑定 DLL** — 核心模型必须支持 PE/ELF/Mach-O/.NET Native
- **Core/Binary/Architecture/IR/Analysis 必须与 UI 解耦**
- **不能把整个产品做成一个 GUI 程序**

---

## 4. 技术栈比较

### 4.1 核心语言

| 维度 | Rust | C++ | C |
|---|---|---|---|
| 内存安全 | ✅ 编译期保证 | ❌ | ❌ |
| 性能 | ✅ 与 C++ 持平 | ✅ 最优 | ✅ 最优 |
| 构建系统 | ✅ Cargo (原生) | ❌ CMake/混乱 | ❌ Make |
| 多 crate 架构 | ✅ 原生支持 | ⚠️ 需手动配置 | ⚠️ 需手动配置 |
| Tauri 集成 | ✅ 原生 | ❌ 需 FFI | ❌ 需 FFI |
| 生态成熟度 | ✅ 快速增长 | ✅ 最成熟 | ✅ 成熟 |
| **决策** | **✅ 选择** | | |

### 4.2 Disassembler

| 维度 | Zydis | Capstone | LLVM MC |
|---|---|---|---|
| x86/x64 质量 | ✅ 最优 | ✅ 好 | ✅ 最好 |
| 多架构 | ❌ 仅 x86 | ✅ 广泛 | ✅ 最广 |
| 性能 | ✅ 最快 | ⚠️ 较慢 | ⚠️ 重 |
| 内存分配 | ✅ 零分配 | ❌ 每指令动态分配 | ⚠️ 重 |
| Rust 绑定 | ✅ 官方 | ✅ 成熟 | ❌ 复杂 |
| **P0 决策** | **✅ 选择** | P0-2 引入 | ❌ 过重 |

### 4.3 Binary Parser

| 维度 | 自研 | goblin | object | LLVM Object |
|---|---|---|---|---|
| 证据集成 | ✅ 深度集成 | ❌ 通用 | ❌ 通用 | ❌ 通用 |
| PE 完整度 | ✅ P0 全量 | ✅ | ✅ | ✅ |
| 依赖体积 | ✅ 零 | ⚠️ 小 | ⚠️ 小 | ❌ 巨大 |
| 错误可追溯 | ✅ offset+message | ⚠️ 一般 | ⚠️ 一般 | ❌ |
| **决策** | **✅ 自研 PE** | 参考验证 | | |

### 4.4 GUI (P1)

| 维度 | Tauri + React | Qt | Electron |
|---|---|---|---|
| 后端语言 | ✅ Rust (原生) | ❌ C++ (需FFI) | ❌ JS (需FFI) |
| 包体积 | ✅ 5-15MB | ⚠️ 20-150MB | ❌ 100MB+ |
| 内存占用 | ✅ 50-100MB | ⚠️ 50-150MB | ❌ 200-500MB |
| 生态 | ✅ React 丰富 | ✅ Qt 成熟 | ✅ 最成熟 |
| 安全 | ✅ Rust+WebView沙箱 | ⚠️ C++ | ⚠️ |
| **决策** | **✅ Tauri + React** | | |

### 4.5 IR

| 维度 | 自研 FOX IR | LLVM IR | MLIR | VEX |
|---|---|---|---|---|
| 设计目标 | 反编译 | 编译 | 多层编译 | 仿真 |
| 证据集成 | ✅ 原生 | ❌ | ❌ | ❌ |
| 多层设计 | ✅ L1/L2/L3 | ❌ 单层 | ✅ 多层 | ❌ |
| 依赖体积 | ✅ 零 | ❌ 巨大 | ❌ 巨大 | ⚠️ 中 |
|  stripped binary 适配 | ✅ 从头设计 | ❌ 假设有类型 | ⚠️ | ✅ |
| **决策** | **✅ 自研** | | | |

---

## 5. 最终技术选型

| 组件 | 选择 | 核心理由 |
|---|---|---|
| 核心语言 | **Rust 1.98+** | 内存安全 + Cargo workspace + Tauri 原生集成 |
| Disassembler (P0) | **Zydis 4.1** | x86/x64 最快最准，零动态分配 |
| Disassembler (P0-2+) | **Capstone** | ARM64 等多架构扩展 |
| Binary Parser | **自研 PE Parser** | 证据深度集成，全量错误追溯 |
| GUI (P1) | **Tauri 2.x + React** | Rust 后端原生，轻量，安全 |
| IR | **自研 FOX IR** | 为反编译设计，多层，证据原生 |
| 序列化 | **serde + serde_json** | 证据/分析结果持久化 |
| CLI | **clap 4.x** | 标准 Rust CLI 框架 |
| 日志 | **log + env_logger** | 轻量日志 |
| 构建 | **Cargo Workspace** | 原生分层，编译期强制边界 |
| CI | **GitHub Actions** | Linux/Windows/macOS 矩阵 |
| License | **MIT** | 兼容开源与商业 |

---

## 6. Architecture

### 6.1 分层架构

```
┌─────────────────────────────────────────────────────────┐
│  UI Layer (P1+)  —  Tauri + React Desktop               │
├─────────────────────────────────────────────────────────┤
│  CLI Layer  —  fox info/analyze/functions/imports/...   │
├─────────────────────────────────────────────────────────┤
│  Project Layer  —  项目管理与重建                        │
├─────────────────────────────────────────────────────────┤
│  Decompiler Layer (P1+)  —  IR → Readable Source        │
├─────────────────────────────────────────────────────────┤
│  Analysis Layer  —  CFG / CallGraph / DataFlow / ...    │
├─────────────────────────────────────────────────────────┤
│  IR Layer  —  FOX IR (L1 Instruction → L2 Op → L3)     │
├─────────────────────────────────────────────────────────┤
│  Disassembly Layer  —  Trait + Zydis Backend            │
├─────────────────────────────────────────────────────────┤
│  Architecture Layer  —  x86 / x64 / ARM64 定义          │
├─────────────────────────────────────────────────────────┤
│  Binary Layer  —  PE (P0) / ELF (P0-2) / Mach-O (P0-3) │
├─────────────────────────────────────────────────────────┤
│  Core Layer  —  Evidence System / Error / Address       │
└─────────────────────────────────────────────────────────┘
```

### 6.2 依赖规则（编译期强制）
- Core 不依赖任何 FOX crate
- Binary 依赖 Core + Arch
- Arch 依赖 Core
- Disasm 依赖 Core + Arch
- IR 依赖 Core + Arch
- Analysis 依赖 Core + Binary + Arch + Disasm + IR
- Decompiler 依赖 Core + IR + Analysis
- Project 依赖 Core + Binary + Analysis
- CLI 依赖全部
- **任何层不得依赖上层**

### 6.3 Crate 清单

| Crate | 职责 | 状态 |
|---|---|---|
| `fox-core` | Evidence System, Error, Address | ✅ 完成 |
| `fox-binary` | PE/ELF/Mach-O 解析 | ✅ PE完成 |
| `fox-arch` | x86/x64/ARM64 定义, 调用约定 | ✅ 完成 |
| `fox-disasm` | 反汇编抽象 + Zydis 后端 | ✅ 完成 |
| `fox-ir` | FOX IR 定义 (L1/L2/L3) | 🟡 骨架 |
| `fox-analysis` | CFG/CallGraph/FunctionDiscovery | ✅ 基础完成 |
| `fox-decompiler` | IR→源码反编译器 | 🟡 占位 (P1) |
| `fox-project` | 项目管理 | 🟡 骨架 |
| `fox-cli` | 命令行接口 | ✅ 完成 |

---

## 7. Binary → IR Pipeline (P0)

```
Raw Bytes
    ↓  [Format Detection]  MZ/PE magic, ELF magic, Mach-O magic
Binary Format (PE32 / PE32+ / ELF32 / ELF64 / Mach-O)
    ↓  [Binary Parsing]  DOS Header → NT Headers → Sections → Imports → Exports → Relocs → Strings
Binary Object (架构, 入口点, 节区, 导入, 导出, 重定位, 字符串)
    ↓  [Architecture Detection]  Machine field → Architecture enum
Architecture (x86 / x64 / ARM64)
    ↓  [Function Discovery]  入口点 + 导出表 + CALL目标 + Prologue匹配  [每个函数带Evidence]
Functions (WithEvidence<Function> 列表)
    ↓  [Disassembly]  Zydis 解码可执行节区
Instructions (地址, 长度, 助记符, 操作数, 原始字节, 控制流标志)
    ↓  [Basic Block Identification]  分支目标 + RET边界  [P0-1 深化]
Basic Blocks
    ↓  [CFG Construction]  块 + 边  [P0-1 深化]
Control Flow Graph
    ↓  [IR L1 Generation]  Instruction → IROp 映射  [P0-1 实现]
FOX IR (L1)
    ↓  [Call Graph]  函数→函数边
Call Graph
```

**P0 已打通**: Raw Bytes → Binary → Functions → Instructions → CFG (骨架)
**P0-1 目标**: 完整 Basic Block → CFG → IR L1

---

## 8. Evidence Architecture

### 8.1 核心类型

```rust
pub struct WithEvidence<T> {
    pub value: T,
    pub confidence: Confidence,  // 0.0 - 1.0
    pub evidence: EvidenceList,  // 有序证据列表
}

pub struct Evidence {
    pub kind: EvidenceKind,      // 证据类型
    pub address: Option<u64>,    // 观测地址
    pub detail: Option<String>,  // 详情
    pub weight: f64,             // 单证据权重 0.0-1.0
}
```

### 8.2 证据类型 (EvidenceKind)
- `FunctionPrologue` — 有效函数序言
- `FunctionEpilogue` — 有效函数尾声
- `CallReference { count }` — 被 N 条 CALL 引用
- `ValidReturn` — 以有效 RET 结尾
- `StackFramePattern` — 栈帧模式
- `CalledApi { api_name }` — 调用已知 API
- `ImportEntry` / `ExportEntry` / `RelocationEntry`
- `StringReference { string }` — 字符串引用
- `EntryPoint` — 二进制入口点
- `ExecutableSection` — 可执行节区
- `PatternMatch { pattern }` — 模式匹配
- `CrossReference { from }` — 交叉引用
- `Heuristic { description }` — 启发式
- `UserAnnotation` — 用户标注
- `SymbolInfo` — 符号表/调试信息
- `CallingConvention` — 调用约定匹配
- `TypeUsagePattern` — 类型使用模式

### 8.3 置信度聚合算法
```
confidence = max_weight + 0.1 * (n-1) * (1 - max_weight)
```
- 单证据最高置信度 = 该证据 weight（不超过 0.7 对于启发式）
- 每增加一条独立证据，填补剩余置信度缺口的 10%
- 确保**没有单一启发式能给出 100% 置信度**
- 多条独立证据源才能推高置信度

### 8.4 证据链示例（真实输出）
```
Function: sub_0000000140001008 @ 0x0000000140001008
  Confidence: 0.55
  Evidence:
    - Referenced by 1 CALL instructions [weight=0.50]
```

### 8.5 铁律
- **禁止 "AI说它是XXX" 直接作为事实**
- 所有分析结果必须包装在 `WithEvidence<T>` 中
- 空证据列表 = 置信度 0 = 不可信结论

---

## 9. Golden Sample Strategy

### 9.1 样本清单 (10 个)

| ID | 名称 | 描述 | 预期重点 |
|---|---|---|---|
| 01 | hello | 最小 hello world | 入口点, printf import, 字符串 |
| 02 | functions | 多函数调用 | 函数发现, CALL 边 |
| 03 | branch | if/else 分支 | CFG 分支边 |
| 04 | loop | for/while 循环 | 回边, 循环结构 |
| 05 | pointer | 指针运算 | 内存操作识别 |
| 06 | struct | 结构体访问 | 字段访问模式 |
| 07 | function_pointer | 函数指针 | 间接调用识别 |
| 08 | cpp_class | C++ 类/虚表 | vtable, thiscall |
| 09 | import_export | DLL 导入导出 | 导出表, IAT |
| 10 | optimized | -O2 优化代码 | 内联, 指令调度 |

### 9.2 回归测试规则
1. 每个新核心能力必须添加至少一个 golden sample
2. 每个样本必须可编译并产生预期输出
3. CI 在 Linux/Windows/macOS 上运行 golden tests
4. 预期值为最低值（除非指定 exact_match）
5. **AI 输出永远不作为 Ground Truth**

### 9.3 P0 状态
- ✅ 样本规范定义 (`golden/samples.yaml`)
- ⏳ 样本源码和编译: P0-1 实施（需要 C 编译器）

---

## 10. License Audit

### 10.1 已审计依赖

| 名称 | 版本 | License | 用途 | 链接方式 |
|---|---|---|---|---|
| anyhow | 1.0 | MIT/Apache-2.0 | 错误处理 | 静态 |
| thiserror | 1.0 | MIT/Apache-2.0 | 错误类型派生 | 静态 |
| serde | 1.0 | MIT/Apache-2.0 | 序列化 | 静态 |
| serde_json | 1.0 | MIT/Apache-2.0 | JSON 输出 | 静态 |
| log | 0.4 | MIT/Apache-2.0 | 日志门面 | 静态 |
| env_logger | 0.11 | MIT/Apache-2.0 | 日志实现 | 静态 |
| clap | 4.5 | MIT/Apache-2.0 | CLI 参数解析 | 静态 |
| zydis | 4.1 | MIT | x86/x64 反汇编 | 静态 |
| goblin | 0.8 | MIT | 参考验证（未链接） | 未链接 |

### 10.2 合规状态
- ✅ 所有当前依赖为 MIT 或 Apache-2.0
- ✅ 兼容开源与商业分发
- ✅ 核心 crate 无 GPL/LGPL 依赖
- ✅ FOX 自身采用 MIT License
- 📋 完整记录见 `THIRD_PARTY.md`

---

## 11. Repository Bootstrap

### 11.1 目录结构

```
fox/
├── apps/
│   ├── cli/                    # fox 命令行工具
│   │   ├── src/main.rs
│   │   └── tests/              # 集成测试
│   └── desktop/                # Tauri GUI (P1)
├── crates/
│   ├── fox-core/               # Evidence System, Error, Address
│   ├── fox-binary/             # PE/ELF/Mach-O parsers
│   │   └── src/{pe,elf,macho}/
│   ├── fox-arch/               # x86/x64/ARM64 definitions
│   │   └── src/{x86,x64,arm64}/
│   ├── fox-disasm/             # Disassembler trait + Zydis backend
│   ├── fox-ir/                 # FOX Intermediate Representation
│   ├── fox-analysis/           # CFG/CallGraph/DataFlow/TypeRecovery/Symbol
│   ├── fox-decompiler/         # IR → Source (P1)
│   └── fox-project/            # Project management
├── samples/                    # 样本源码
├── tests/                      # 测试资源
├── golden/                     # Golden Sample 规范
│   └── samples.yaml
├── docs/
│   ├── ARCHITECTURE.md
│   └── TDR.md
├── tools/
├── .github/workflows/ci.yml    # CI 配置
├── Cargo.toml                  # Workspace root
├── LICENSE                     # MIT
├── THIRD_PARTY.md              # 第三方 License 审计
├── CONTRIBUTING.md
└── README.md
```

### 11.2 代码统计
- **9 个 crate** (8 库 + 1 二进制)
- **14 个测试** 全部通过 (9 单元 + 5 集成)
- **CLI 7 个命令** 全部可用
- **零 unsafe 代码** (fox-core, fox-binary, fox-arch, fox-ir, fox-analysis)

---

## 12. CI 状态

### 12.1 已配置
- **平台矩阵**: Ubuntu-latest, Windows-latest, macOS-latest
- **检查项**:
  - `cargo fmt --all -- --check` (格式)
  - `cargo clippy --all-targets -- -D warnings` (lint)
  - `cargo check --workspace` (编译检查)
  - `cargo build --workspace` (构建)
  - `cargo test --workspace` (单元测试)
  - 集成测试
  - Golden tests (P0 标记 continue-on-error，待样本编译)

### 12.2 本地验证 (Windows)
- ✅ `cargo check --workspace` — 通过
- ✅ `cargo build --release -p fox-cli` — 通过
- ✅ `cargo test --workspace` — 14 passed, 0 failed
- ✅ 真实 PE 文件验证 (whoami.exe) — 全部命令正常

### 12.3 后续扩展 (P0-1+)
- fuzz 测试
- sanitizer (ASan/MSan)
- 性能基准 (benchmark)
- Golden sample 编译与回归

---

## 13. 已实现能力 (P0)

### 13.1 PE 解析 ✅
- ✅ DOS Header + PE Signature 检测
- ✅ COFF File Header (Machine, Sections, Characteristics)
- ✅ Optional Header (PE32 / PE32+)
- ✅ Entry Point + Image Base
- ✅ Section Table (名称, 虚拟地址, 原始偏移, 权限标志)
- ✅ Import Table (DLL 名称, 函数名/序号, Hint, IAT 地址)
- ✅ Export Table (名称, 序号, 地址, 转发)
- ✅ Base Relocations (类型, 虚拟地址)
- ✅ String Extraction (最小长度 4, ASCII 可打印)
- ✅ Architecture Detection (x86 / x64 / ARM64)

### 13.2 反汇编 ✅
- ✅ Zydis 4.x 后端 (x86/x64)
- ✅ 架构无关 `Disassembler` trait
- ✅ 指令元数据 (CALL/RET/JMP 标志, 目标地址)
- ✅ 线性扫描反汇编

### 13.3 函数发现 ✅ (带 Evidence)
- ✅ 入口点函数 (EntryPoint evidence)
- ✅ 导出函数 (ExportEntry evidence)
- ✅ CALL 目标函数 (CallReference evidence)
- ✅ Prologue 模式匹配 (FunctionPrologue evidence)
- ✅ 置信度聚合算法

### 13.4 分析框架 ✅
- ✅ CFG 骨架 (基本块列表)
- ✅ Call Graph 骨架 (节点 + 边计数)
- ✅ `analyze_binary` 全管线入口

### 13.5 CLI ✅
- ✅ `fox info <file>` — 二进制信息
- ✅ `fox analyze <file>` — 完整分析
- ✅ `fox functions <file>` — 函数列表 + 证据详情
- ✅ `fox imports <file>` — 导入表
- ✅ `fox exports <file>` — 导出表
- ✅ `fox strings <file>` — 字符串提取
- ✅ `fox cfg <file>` — CFG 摘要
- ✅ `--json` 机器可读输出
- ✅ `--verbose` 调试日志

### 13.6 Evidence System ✅
- ✅ `WithEvidence<T>` 泛型包装
- ✅ 18 种 EvidenceKind
- ✅ 置信度聚合 (max_weight + 递减 bonus)
- ✅ 序列化支持 (serde)

### 13.7 真实验证 (whoami.exe)
- PE32+ 解析: ✅ 6 sections, 128 imports, 35 relocs, 192 strings
- 函数发现: ✅ 239 functions, 全部带证据
- 架构检测: ✅ x86-64
- 入口点: ✅ 0x14000D2B0

---

## 14. 未实现能力

| 能力 | 状态 | 计划阶段 |
|---|---|---|
| 完整 Basic Block 识别 (分支边界) | 🟡 骨架 | P0-1 |
| 完整 CFG 边 (successors/predecessors) | 🟡 骨架 | P0-1 |
| IR L1 生成 (Instruction → IROp) | 🟡 骨架 | P0-1 |
| 函数大小/结束地址计算 | ❌ | P0-1 |
| Call Graph 边填充 | 🟡 骨架 | P0-1 |
| Data Flow Analysis | ❌ | P0-2 |
| Type Recovery | ❌ | P0-3 |
| Symbol Analysis (FID) | ❌ | P0-2 |
| ELF Parser | ❌ | P0-2 |
| Mach-O Parser | ❌ | P0-3 |
| ARM64 反汇编 | ❌ | P0-2 |
| Decompiler | ❌ | P1 |
| GUI (Tauri) | ❌ | P1 |
| AI 辅助分析 | ❌ | P2 |
| 项目重建 | ❌ | P1+ |
| Golden Sample 编译 | ❌ | P0-1 |

---

## 15. 风险

| 风险 | 等级 | 缓解措施 |
|---|---|---|
| Zydis Rust 绑定 API 不稳定 | 中 | 抽象在 Disassembler trait 后，可切换 Capstone |
| PE parser 边界情况 (加壳/损坏文件) | 中 | 集成测试覆盖 + goblin 交叉验证 |
| 函数发现误报 (数据被当代码) | 中 | Evidence System 置信度标记，不做绝对断言 |
| Rust 编译时间长 | 低 | Workspace 拆分 + 增量编译 |
| Golden Sample 需要 C 编译器 | 低 | P0-1 引入 MinGW/GCC，CI 预装 |
| 反编译复杂度极高 | 高 | 分阶段：先 IR→结构化→伪代码，不追求一步到位 |
| 多架构扩展工作量 | 中 | 架构抽象层已就绪，按 P0-2/P0-3 推进 |

---

## 16. P0-1 施工计划

### 阶段目标
**打通 Binary → Instruction → Basic Block → CFG → IR L1 完整链路，每条边都带证据。**

### 具体任务

#### T1: Basic Block 识别器
- 线性扫描反汇编，按以下规则切分基本块：
  - 无条件 JMP 结束当前块
  - 条件 JMP 结束当前块，目标地址开始新块
  - RET 结束当前块
  - CALL 目标地址开始新块
  - 函数入口开始新块
- 每个 BasicBlock 携带：start_address, end_address, instruction_count, 终止指令类型

#### T2: 完整 CFG 构建
- 计算每个块的 successors (无条件跳转目标 + 条件跳转 fall-through + 条件跳转目标)
- 计算 predecessors (反向边)
- 识别循环回边
- CFG 序列化输出 (JSON/DOT)

#### T3: IR L1 生成
- Instruction → IROp 映射表 (x86/x64 常用指令 ~100 条)
- 操作数解码 (Register/Immediate/Memory)
- IRBasicBlock 构建
- IRFunction 组装

#### T4: 函数边界精化
- 从入口开始递归下降，遇到 RET 确定函数结束
- 计算函数大小
- 标记函数内基本块归属

#### T5: Call Graph 填充
- 扫描所有 CALL 指令，解析目标地址
- 建立 Function → Function 边
- 区分直接调用/间接调用
- 导入函数调用识别

#### T6: Golden Sample 编译
- 编写 10 个样本的 C/C++ 源码
- 配置 CI 编译 (x86/x64, Windows)
- 编写 golden 断言测试
- 所有样本进入回归测试

#### T7: CLI 增强
- `fox disasm <file> [--address <addr>]` — 反汇编指定地址
- `fox cfg <file> --dot` — 输出 DOT 格式 CFG
- `fox ir <file>` — 输出 IR L1
- `fox evidence <file> --function <addr>` — 单函数证据详情

#### T8: 测试覆盖
- 每个 T1-T5 任务必须有单元测试
- Golden sample 回归测试
- 证据链完整性测试 (每个分析结果必须有非空 evidence)

### 验收标准
1. `cargo test --workspace` 全部通过
2. Golden Sample 01-05 编译并通过断言
3. `fox cfg` 输出正确的 successors/predecessors
4. `fox ir` 输出有效的 IR L1
5. 每个函数的 CFG 边都可追溯到具体指令证据
6. 无新增编译警告
7. CLI 所有命令在真实 PE 文件上验证通过

### P0-1 禁止事项
- ❌ 不开发 GUI
- ❌ 不开发反编译器
- ❌ 不引入 AI
- ❌ 不扩展 ELF/Mach-O/ARM64
- ❌ 不宣称"已实现反编译"

---

## 封板声明

**FOX P0-0 阶段已完成 AUDIT → GAP → ARCHITECTURE → IMPLEMENTATION → TEST → EVIDENCE → CI 全流程。**

- ✅ Evidence: 所有分析结果携带证据链
- ✅ Test: 14 个测试全部通过 (9 单元 + 5 集成)
- ✅ CI: GitHub Actions 三平台矩阵已配置
- ✅ Build: Release 构建成功，CLI 可执行
- ✅ Verify: 真实 PE 文件 (whoami.exe) 全命令验证通过

**P0-0 SEALED.** 等待独立架构审计后进入 P0-1。
