# FOX — Binary Reverse Engineering & Decompilation Platform

> FOX 逆向工程与反编译平台

FOX is a modern, independent reverse engineering platform built from first principles.
It is **not** a DLL viewer, hex editor, simple disassembler, or a UI clone of Ghidra/IDA.

## Architecture Principle

FOX is **layered and decoupled**. Core / Binary / Architecture / IR / Analysis are
completely independent of the UI. The product is **not** a GUI program — it is an
analysis engine with CLI first, GUI later.

```
FOX
├── Core              (Evidence System, Error Types, Address)
├── Binary            (PE / ELF / Mach-O parsers)
├── Architecture      (x86 / x64 / ARM64 definitions)
├── Disassembly       (Zydis backend, architecture-agnostic trait)
├── IR                (FOX Intermediate Representation)
├── Analysis          (CFG / Call Graph / Data Flow / Type Recovery / Symbol)
├── Decompiler        (IR → Readable Source)
├── Project           (Project management & reconstruction)
├── CLI               (fox analyze / info / functions / ...)
└── UI                (Tauri + React, P1+)
```

## The Evidence System (Most Important)

Every analysis result in FOX **must** carry evidence. No conclusion is accepted
without a traceable chain:

```
Instruction → Basic Block → Function → CFG → Analysis Result → Evidence
```

Example:
```
Function: sub_140001230
Confidence: 0.93
Evidence:
  - Valid function prologue @ 0x140001230 [weight=0.60]
  - Referenced by 4 CALL instructions [weight=0.50]
  - Ends with valid RET [weight=0.50]
  - Stack frame pattern detected [weight=0.40]
  - Called API: BCryptOpenAlgorithmProvider [weight=0.70]
```

**AI output is never accepted as fact.** It must be backed by evidence.

## P0 Status (Native Windows)

Target: PE32 / PE32+, x86 / x64

| Capability | Status |
|---|---|
| PE Header | ✅ Implemented |
| Sections | ✅ Implemented |
| Imports | ✅ Implemented |
| Exports | ✅ Implemented |
| Relocations | ✅ Implemented |
| Strings | ✅ Implemented |
| Entry Point | ✅ Implemented |
| Architecture Detection | ✅ Implemented |
| Function Discovery | ✅ Implemented (with evidence) |
| Disassembly | ✅ Implemented (Zydis) |
| Basic CFG | 🟡 Skeleton |
| Basic Call Graph | 🟡 Skeleton |
| Basic IR | 🟡 Skeleton |

## CLI Usage

```bash
fox info <file>        # Binary header and metadata
fox analyze <file>     # Full analysis pipeline
fox functions <file>   # List discovered functions (with evidence)
fox imports <file>     # List imports
fox exports <file>     # List exports
fox strings <file>     # List extracted strings
fox cfg <file>         # CFG summary
```

All commands support `--json` for machine-readable output and `--verbose` for debug logging.

## Building

```bash
cargo build --workspace
cargo test --workspace
```

## Engineering Discipline

Every FOX phase follows:

```
AUDIT → GAP → ARCHITECTURE → IMPLEMENTATION → TEST → EVIDENCE → CI → COMMIT → SEAL
```

No phase is sealed without Evidence + Test + CI.

## License

MIT — see [LICENSE](LICENSE). All dependencies are MIT/Apache-2.0.
See [THIRD_PARTY.md](THIRD_PARTY.md) for full audit.
