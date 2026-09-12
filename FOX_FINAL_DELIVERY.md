# FOX v1.1 Final Delivery Report

## 基线
- Git: 33d361a
- Date: 2026-09-13

## 能力矩阵

| 能力 | 状态 |
|---|---|
| PE Loader | ✅ |
| CFG Recovery | ✅ |
| SSA | ✅ |
| CallGraph | ✅ |
| DataFlow | ✅ |
| Signature | ✅ |
| Type Candidate | ✅ |
| Variable Recovery | ✅ |
| Object/Field Recovery | ✅ |
| Memory Operand Recovery | ✅ |
| IAT/API Recovery | ✅ |
| C AST | ✅ |
| C Compiler (MSVC) | ✅ |
| Round Trip (rm8) | ✅ |
| Struct.field Access | ✅ |
| Type Recovery (semantic) | ⬜ |
| Struct Definition | ⬜ |
| Function Naming | ⬜ |
| C++ Recovery | ⬜ |

## 14/14 PE Decompile Results

| PE | Functions | OK | C Size | cl /c |
|---|---|---|---|---|
| NtcMach.exe | 359 | 341 | 1.8MB | 0 err |
| KeyTable.exe | 147 | 146 | 397KB | 0 err |
| NTCDLLA1.DLL | 304 | 300 | 1.29MB | 0 err |
| NTCDLLA2.DLL | 304 | 300 | 1.29MB | 0 err |
| NTCDLLA3.DLL | 307 | 303 | 1.23MB | 0 err |
| NTCDLLA4.DLL | 306 | 302 | 1.24MB | 0 err |
| NTCDLLA5.DLL | 307 | 304 | 1.30MB | 0 err |
| NTCDLLA6.DLL | 349 | 341 | 1.39MB | 0 err |
| NTCDLLC.DLL | 261 | 258 | 741KB | 0 err |
| NTCDLLG.DLL | 343 | 336 | 1.37MB | 0 err |
| NTCDLLM.DLL | 349 | 341 | 1.13MB | 0 err |
| NTCDLLV.DLL | 239 | 231 | 767KB | 0 err |
| NtcDLL_M3.DLL | 246 | 242 | 899KB | 0 err |
| NtcDLL_M4.DLL | 290 | 279 | 976KB | 0 err |

**合计：~4111 函数，~4036 OK，~16MB C，全部 0 编译错误。**

## Round-trip
- rm8 test: `hits=60 misses=2 sum=10 q=-1` (identical)

## Known Limitations
1. Type Recovery: still uint32_t (semantic types pending)
2. Function names: sub_401000 (semantic names pending)
3. Variable names: tmp_N (semantic names pending)
4. Struct definitions: field_0x24 (full struct layout pending)
5. C++: not detected (vtable/RTTI pending)
6. Control flow: goto still present in complex blocks
