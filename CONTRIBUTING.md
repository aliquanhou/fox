# Contributing to FOX

## Engineering Discipline

Every change to FOX must follow the phase seal process:

```
AUDIT → GAP → ARCHITECTURE → IMPLEMENTATION → TEST → EVIDENCE → CI → COMMIT → SEAL
```

## Hard Rules

1. **No analysis result without evidence.** Every `WithEvidence<T>` must have at least one evidence item.
2. **No AI output as ground truth.** AI suggestions must be verified and backed by evidence.
3. **No DLL-specific core abstractions.** Core must be format-agnostic.
4. **No GUI in core.** Core/Binary/Arch/IR/Analysis must compile without any GUI dependency.
5. **No untested completion.** Every capability must have a test before being marked done.
6. **No GPL/LGPL in core.** All core dependencies must be MIT/Apache-2.0/BSD.
7. **No single-sample proof.** Capabilities must be validated against the Golden Sample suite.

## Adding a New Capability

1. Add a golden sample to `golden/samples.yaml`
2. Implement in the appropriate crate
3. Add unit tests
4. Add evidence to all analysis outputs
5. Run `cargo test --workspace`
6. Update `THIRD_PARTY.md` if adding dependencies
7. Update this README's capability table

## Code Style

- `cargo fmt --all`
- `cargo clippy --all-targets -- -D warnings`
- All public APIs must have doc comments
- Evidence types must derive Serialize/Deserialize
