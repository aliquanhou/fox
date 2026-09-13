# FINAL-E Variable Semantic Reality Audit

## Date: 2026-09-13
## Baseline: 38b3bde (FOX v1.9)

## Current Variable Statistics (NtcMach sample)

| Category | Count |
|---|---|
| Total functions | 359 |
| SSA variables per func | ~3.5 avg |
| local_N declared | ~1280 |
| arg0/arg1 | per function |
| field_0xNN | ~829 across all |
| Unknown variables | ~15% |

## Naming State

| Current | Target | Confidence |
|---|---|---|
| local_N | file_handle / buffer / length | pending |
| arg0/arg1 | HANDLE / LPCSTR | pending |
| field_0xNN | struct fields | pending |
| tmp_N | expression folding | pending |

## Evidence Available
- CallGraph: which function calls which API
- DataFlow: argument flow between caller/callee
- IAT: API names (CreateFileA, DeviceIoControl...)
- Memory: stack/global/object access

## GAP
- No semantic type propagation yet (uint32_t everywhere)
- No variable naming by usage pattern
- No function argument role inference

## Next
FINAL-E: build VariableSemantic layer, rename high-confidence variables.
