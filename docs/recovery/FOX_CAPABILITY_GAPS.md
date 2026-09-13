# FOX CAPABILITY GAPS

## GAP-001: String XRef
- **发现时间**: 2026-09-13
- **DeepSeek 请求**: "Where is 'machine_process' referenced?"
- **FOX 当前能力**: string_search only returns string address
- **缺失能力**: string → xref → function → caller/callee → evidence
- **为什么需要**: To trace business logic from strings to functions
- **优先级**: P0
- **状态**: OPEN

## GAP-002: Resource Extraction
- **发现时间**: 2026-09-13
- **证据**: chk_cams.bmp, chk_yarn.bmp, ramsend.bin exist as strings
- **FOX 当前能力**: No PE resource parsing
- **缺失能力**: Extract BMP/TBL/DAT resources + references
- **优先级**: P1
- **状态**: OPEN

## GAP-003: Compiler/Encoding Logic
- **发现时间**: 2026-09-13
- **证据**: "3Dtest.txt", "test_fp.out" strings suggest pattern compilation
- **FOX 当前能力**: No pattern compiler analysis
- **缺失能力**: Identify compiler functions + encoding format
- **优先级**: P0
- **状态**: OPEN

## GAP-004: Machine Protocol
- **发现时间**: 2026-09-13
- **证据**: USB send, DeviceIoControl, ramsend.bin
- **FOX 当前能力**: No protocol analysis
- **缺失能力**: Decode USB/DeviceIoControl protocol
- **优先级**: P1
- **状态**: OPEN
