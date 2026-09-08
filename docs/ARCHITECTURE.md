# FOX Architecture

## Layered Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     UI Layer (P1+)                       │
│              Tauri + React Desktop App                   │
├─────────────────────────────────────────────────────────┤
│                     CLI Layer                            │
│         fox info / analyze / functions / ...            │
├─────────────────────────────────────────────────────────┤
│                  Project Layer                           │
│         Project save/load, Reconstruction               │
├─────────────────────────────────────────────────────────┤
│                Decompiler Layer (P1+)                    │
│            IR → Structured → Readable Source             │
├─────────────────────────────────────────────────────────┤
│                 Analysis Layer                           │
│  CFG │ CallGraph │ DataFlow │ TypeRecovery │ Symbol     │
├─────────────────────────────────────────────────────────┤
│                    IR Layer                              │
│         FOX IR (L1 Instruction → L2 Operation → L3)     │
├─────────────────────────────────────────────────────────┤
│                Disassembly Layer                         │
│    Architecture-agnostic trait │ Zydis (x86/x64)        │
├─────────────────────────────────────────────────────────┤
│               Architecture Layer                         │
│           x86 │ x64 │ ARM64 (definitions, CC)           │
├─────────────────────────────────────────────────────────┤
│                Binary Layer                              │
│            PE (P0) │ ELF (P0-2) │ Mach-O (P0-3)         │
├─────────────────────────────────────────────────────────┤
│                   Core Layer                             │
│        Evidence System │ Error Types │ Address          │
└─────────────────────────────────────────────────────────┘
```

## Dependency Rules

- Core depends on nothing (except std + serde)
- Binary depends on Core
- Architecture depends on Core
- Disassembly depends on Core + Architecture
- IR depends on Core + Architecture
- Analysis depends on Core + Binary + Architecture + Disassembly + IR
- Decompiler depends on Core + IR + Analysis
- Project depends on Core + Binary + Analysis
- CLI depends on everything
- UI depends on CLI/core (via Tauri commands)

**No layer may depend on a layer above it.**

## Binary → IR Pipeline (P0)

```
Raw Bytes
    ↓
Format Detection (MZ/PE, ELF magic, Mach-O magic)
    ↓
Binary Parsing (Header, Sections, Imports, Exports, Relocs, Strings)
    ↓
Architecture Detection (Machine field → Architecture enum)
    ↓
Function Discovery (Entry point + Exports + Call targets + Prologues)
    ↓  [Every function carries Evidence]
Disassembly (Zydis for x86/x64)
    ↓
Basic Block Identification (Branch targets, RET boundaries)
    ↓
CFG Construction (Blocks + Edges)
    ↓
IR L1 Generation (Instruction → IROp mapping)
    ↓
Call Graph (Function → Function edges)
```

## Evidence Architecture

Every analysis result is wrapped in `WithEvidence<T>`:

```rust
pub struct WithEvidence<T> {
    pub value: T,
    pub confidence: Confidence,  // 0.0 - 1.0
    pub evidence: EvidenceList,  // Ordered list of evidence items
}
```

Evidence flows bottom-up:
- Instructions carry raw bytes and address
- Basic blocks reference instruction ranges
- Functions reference basic blocks + discovery evidence
- CFG nodes reference functions
- Analysis results reference all of the above

This creates a fully auditable chain: **"Why does FOX believe X?"** is always answerable.

## Technology Decision Record (TDR)

See `docs/TDR.md` for full technology selection rationale.
