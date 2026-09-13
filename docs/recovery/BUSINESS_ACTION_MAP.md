# BUSINESS ACTION MAP

## 1. Software Domain
- **FACT**: Industrial knitting machine control software
- **FACT**: NtcMach.exe + 12 DLLs + KeyTable.exe
- **Confidence**: medium (based on strings: stitch, TRANSFER, DMachine, machine_process)

## 2. Business Actions (Candidate)

| Action | Evidence | Status | Confidence |
|---|---|---|---|
| Machine Control Loop | machine_process string | HYPOTHESIS | low |
| Pattern Memory Management | MemoryIndex, IsMemorySave | HYPOTHESIS | medium |
| Data Transfer to Machine | ramsend.bin, net send | HYPOTHESIS | medium |
| Stitch Inspection | chk_cams.bmp, chk_yarn.bmp | HYPOTHESIS | medium |
| Window/GUI | LoadString, LoadIcon, LoadCursor | FACT | high |

## 3. Function Clusters

### BC-001: GUI / Window Class
- **Entry**: fn_41EDF0
- **FACT**: references "machine_process", calls LoadStringA/LoadIconA/LoadCursorA
- **HYPOTHESIS**: window class preparation
- **UNKNOWN**: RegisterClassEx wrapper
- **Confidence**: medium

### BC-002: Memory Management
- **Strings**: MemoryIndex, IsMemorySave, IsMemory
- **FACT**: strings exist
- **HYPOTHESIS**: pattern/machine data memory management
- **UNKNOWN**: actual functions, data flow

### BC-003: Data Send
- **Strings**: ramsend.bin, net send, send data
- **FACT**: strings exist
- **HYPOTHESIS**: sending data to machine via USB
- **UNKNOWN**: actual protocol, functions

### BC-004: Machine Control Frames
- **Strings**: DMachine_f00 ~ DMachine_f06
- **FACT**: strings exist
- **HYPOTHESIS**: machine operation frames
- **UNKNOWN**: actual functions, data structure

### BC-005: Stitch/Camera Inspection
- **Strings**: chk_cams.bmp, chk_yarn.bmp, stitch
- **FACT**: strings exist
- **HYPOTHESIS**: visual inspection of stitches
- **UNKNOWN**: actual functions

## 4. Compiler Candidates
- **UNKNOWN**: No clear compiler function found yet
- **Search terms**: compiler, compile, convert, encode
- **Next step**: trace data flow from pattern file to machine data

## 5. Machine Model Candidates
- **UNKNOWN**: No clear machine type selection found yet
- **Search terms**: machine type, machine model, type selector

## 6. User Workflow (Hypothesis)
```
User edits pattern
  ↓ Pattern saved to memory
  ↓ Pattern data sent to machine
  ↓ Machine executes knitting
  ↓ Stitch inspection (camera)
```

## 7. Recovery Priority
1. **BC-003 Data Send** - highest business value
2. **BC-002 Memory Management** - pattern data
3. **BC-004 Machine Control Frames** - machine I/O
4. **BC-001 GUI** - lowest priority (just interface)
5. **BC-005 Inspection** - diagnostic feature

## 9. Autonomous Investigation Progress
- **CreateFileA**: 2 calls, filename @ 0x461040 (not ASCII string - dynamic path?)
- **ReadFile**: 1 call found
- **Next**: trace which function calls CreateFileA → pattern file load candidate
