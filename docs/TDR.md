# FOX Technology Decision Record (TDR)

## 1. Core Language: Rust

### Candidates
- **Rust** — memory-safe, zero-cost abstractions, modern toolchain, Cargo workspace
- **C++** — mature ecosystem, LLVM integration, but memory safety issues
- **C** — maximum control, but no modern abstractions, unsafe by default

### Decision: Rust

### Rationale
1. **Memory safety is non-negotiable** for a binary analysis platform that processes untrusted input. Rust's ownership system eliminates entire classes of vulnerabilities.
2. **Cargo workspace** provides native multi-crate architecture matching FOX's layered design.
3. **Zero-cost abstractions** match C++ performance without the safety debt.
4. **Tauri integration** is native — GUI backend will be Rust, no FFI bridge needed.
5. **serde** provides first-class serialization for Evidence System and project files.
6. Cross-platform compilation (Linux/Windows/macOS) is first-class.

### Risks
- Compile times are slower than C++ (mitigated by incremental compilation and workspace splitting)
- Smaller talent pool than C++ (mitigated by growing adoption)

---

## 2. Disassembler: Zydis (P0) → Capstone (P0-2+)

### Candidates
- **Zydis** — x86/x64 only, fastest, lightweight, no dynamic allocation
- **Capstone** — multi-architecture, mature, but slower and heavier
- **LLVM MC** — most complete, but heavy dependency and complex API

### Decision: Zydis for P0, Capstone for multi-arch expansion

### Rationale
1. P0 targets **x86/x64 only**. Zydis is the best-in-class x86 disassembler.
2. Zydis is **fast and lightweight** — critical for large binary analysis.
3. Zydis has **no dynamic memory allocation** per instruction — predictable performance.
4. The `Disassembler` trait abstracts the backend, so switching/adding Capstone later is clean.
5. Capstone will be added when ARM64 support is needed (P0-2).

### Risks
- Zydis Rust binding (0.0.5) is relatively young — API may change
- Mitigation: abstract behind trait, pin version

---

## 3. Binary Parser: Self-written PE Parser (P0)

### Candidates
- **Self-written** — full control, no dependency, evidence-friendly
- **goblin** — popular Rust binary parser, PE/ELF/Mach-O
- **object** — Rust crate, used by many tools
- **LLVM Object** — most complete, but heavy

### Decision: Self-written PE parser for P0

### Rationale
1. **Evidence System requires deep integration** — a generic parser doesn't attach evidence to parse decisions.
2. PE format is **stable and well-documented** — writing a parser is straightforward and low-risk.
3. Full control over **error handling and offset tracking** for ParseError evidence.
4. No dependency on external crate that may not match FOX's abstraction needs.
5. goblin/object can be used for **cross-validation** in tests, not as the primary parser.
6. ELF and Mach-O parsers will be written in P0-2/P0-3 following the same pattern.

### Risks
- More code to maintain
- Mitigation: comprehensive tests + cross-validation against goblin

---

## 4. GUI: Tauri + React (P1)

### Candidates
- **Tauri + React** — Rust backend, system WebView, tiny binaries, low memory
- **Qt** — mature, C++ native, but requires C++ bridge and large dependency
- **Electron** — mature ecosystem, but 100MB+ binaries, high memory

### Decision: Tauri + React

### Rationale
1. **Rust backend native integration** — FOX core is Rust, Tauri commands call Rust directly. No FFI.
2. **Tiny binaries** (5-15MB vs 100MB+ for Electron) — fits a developer tool.
3. **Low memory** — system WebView vs bundled Chromium.
4. **React ecosystem** — rich component libraries for complex UI (CFG viewer, disassembly listing).
5. **Security** — Rust backend + WebView sandbox.
6. Cross-platform: Windows, macOS, Linux.

### Risks
- System WebView version differences (mitigation: feature detection, fallback)
- Tauri 2.0 API still evolving (mitigation: pin version, GUI is P1 not P0)

---

## 5. IR: Custom FOX IR

### Candidates
- **LLVM IR** — mature, optimized, but designed for compilation not decompilation
- **MLIR** — flexible, multi-level, but complex and heavy
- **Custom IR** — full control, designed for reverse engineering
- **VEX IR** (angr) — proven for binary analysis, but C library, Python-centric

### Decision: Custom FOX IR

### Rationale
1. **Decompilation IR has different requirements than compilation IR.** LLVM IR assumes source-level constructs (types, functions with signatures) that don't exist in stripped binaries.
2. **Evidence integration** — custom IR can carry evidence at every level.
3. **Multi-level design** — L1 (instruction-level), L2 (operation-level), L3 (structured). This matches the decompilation pipeline naturally.
4. **No heavy dependency** — LLVM/MLIR would add enormous build complexity.
5. **Architecture-neutral** — designed from the start to support x86, ARM, etc.
6. Binary Ninja's BNIL and Ghidra's P-code prove that **custom IR for RE is the right approach**.

### Risks
- More design work
- Mitigation: study P-code, BNIL, VEX, ESIL designs; start simple (L1 only in P0)

---

## 6. Build System: Cargo Workspace

### Decision: Cargo workspace with per-layer crates

### Rationale
1. Native to Rust, no extra build system.
2. Crate boundaries enforce **layer separation** at compile time.
3. Parallel compilation across crates.
4. Each crate can be tested independently.
5. Dependency tracking is per-crate — GUI deps don't pollute core.

---

## 7. Testing: Golden Sample System + Unit Tests

### Decision: Two-tier testing

1. **Unit tests** — per-crate, per-function.
2. **Golden samples** — compiled binaries with expected analysis results, used for regression.

### Rationale
- Unit tests catch implementation errors.
- Golden samples catch **regression across the full pipeline** and prove real-world capability.
- No single DLL sample proves generality — the suite of 10+ samples does.

---

## 8. CI: GitHub Actions (Linux/Windows/macOS)

### Decision: GitHub Actions matrix build

### Rationale
- FOX must be cross-platform.
- Free for open source.
- Matrix strategy tests all three OSes.
- Future: fuzz, sanitizer, benchmark jobs.

---

## Summary Table

| Component | Choice | Why |
|---|---|---|
| Core Language | Rust | Memory safety + Cargo + Tauri |
| Disassembler (P0) | Zydis | Best x86/x64, fast, lightweight |
| Disassembler (future) | Capstone | Multi-arch expansion |
| Binary Parser | Self-written | Evidence integration, full control |
| GUI (P1) | Tauri + React | Rust-native, tiny, low memory |
| IR | Custom FOX IR | Designed for decompilation, evidence |
| Build | Cargo Workspace | Native, layer-enforcing |
| Testing | Unit + Golden Samples | Regression + real-world proof |
| CI | GitHub Actions | Cross-platform matrix |
