# SOFTWARE DOMAIN TRUTH MAP

## 1. Software Identity
- **Domain**: Industrial textile knitting machine control software
- **Purpose**: Control and monitor a computerized flat knitting machine via USB, with pattern editing, memory management, and camera-based stitch inspection
- **Confidence**: medium (based on string evidence from NtcMach.exe)

## 2. User Roles (Evidence-based)
- Operator (machine control, send data)
- Service engineer (machine test, diagnostics)
- Unknown: pattern designer (no direct evidence yet)

## 3. End-to-End Workflow
```
Pattern Edit
  ↓ (NtcMach.exe GUI)
Memory Storage
  ↓ (MemoryIndex / IsMemorySave)
USB Send to Machine
  ↓ (ramsend.bin / net send)
Machine Execution
  ↓ (machine_process)
Stitch Inspection
  ↓ (mchk / chk_cams.bmp)
```

## 4. Major Components
| Module | Role | Evidence |
|---|---|---|
| NtcMach.exe | GUI main program | CreateWindow, LoadMenu, BitBlt |
| NTCDLLG.DLL | Device I/O core | DeviceIoControl × 30, CreateService |
| NTCDLLC.DLL | Unknown | Needs investigation |
| NTCDLLM.DLL | Unknown | Needs investigation |
| KeyTable.exe | Hotkey config | LoadAccelerators |

## 5. Key Domain Objects (Candidate)
- Pattern (花样)
- Stitch (线圈)
- Yarn (纱线)
- Machine (机器)
- Memory (内存)
- Send (发送)
- Camera Check (相机检查)

## 7. Business Core Candidates (R2-3 Discovery)
| Candidate | Evidence | Role | Confidence |
|---|---|---|---|
| MACH_DATA2 | string constant | machine data identifier | medium |
| data\%s | path pattern | pattern data file | medium |
| MemoryIndex / IsMemorySave | API functions | pattern memory management | medium |
| ramsend.bin / net send | strings | USB data transfer to machine | high |
| TRANSFER | knitting term | stitch transfer operation | medium |
| stitch | knitting term | loop/coil | medium |
| machine_process | main loop string | machine control loop | medium |
| DMachine_f00~f06 | frame names | machine control data frames | medium |

**Business Domain**: industrial knitting machine control and data transfer
**Confidence**: medium
- **fn_41EDF0**:
  - FACT: references "machine_process" string, calls LoadStringA/LoadIconA/LoadCursorA
  - HYPOTHESIS: window class preparation
  - UNKNOWN: whether it ultimately calls RegisterClassEx (not found in direct calls)
- **machine_process**:
  - FACT: string at VA 0x4591B8, referenced by fn_41EDF0
  - HYPOTHESIS: window class name
  - UNKNOWN: actual data flow into lpszClassName

## 6. Known GAPs
- String → function cross-reference not implemented
- Resource extraction (BMP/TBL/DAT) not implemented
- Compiler/encoding logic not investigated
- Machine protocol not decoded
