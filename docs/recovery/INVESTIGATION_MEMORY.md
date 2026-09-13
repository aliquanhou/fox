# FOX Investigation Memory - Persistent Notes
# Binary: NtcMach.exe (制版软件)
# Started: 2026-09-13

## Investigation Log

### INV-001: fn_40A590
- Question: What does this function do?
- Tool calls: get_function, get_callees, get_callers
- Evidence: E-FUNC-0001, E-CALLEES-0002, E-CALLERS-0003
- Conclusion:
  FACT: 1322 lines, 8 callees, CloseHandle+MessageBoxA+SendMessageA, 1 caller (fn_455E4C)
  HYPOTHESIS: UI-related routine (dialog/message handler)
  UNKNOWN: exact purpose, control flow
- Confidence: medium
- Next: investigate fn_455E4C (the only caller)

### INV-002: fn_41EDF0
- Known: machine_process string @ 0x4591B8 → push @ 0x1FF4A
- APIs: LoadStringA, LoadIconA, LoadCursorA
- Conclusion:
  FACT: references machine_process, calls Load* APIs
  HYPOTHESIS: window class preparation
  UNKNOWN: no RegisterClassEx evidence yet
- Confidence: medium

### INV-003: fn_41A870
- Known: CreateFileA call
- Hypothesis: file open (Pattern Load?)
- Confidence: low
- Next: verify what files it opens

### INV-004: fn_1000F2F0 (NTCDLLG.DLL) ⭐ DEVICE I/O CORE
- Question: What does this function do?
- Evidence: 667 lines, 29x DeviceIoControl, 1x WriteFile, 4x CloseHandle
- Evidence ID: E-DEVICE-0004
- Conclusion:
  FACT: NTCDLLG.DLL device communication core
  FACT: 29 DeviceIoControl calls in one function
  FACT: Called by 2 functions (fn_100014A0, fn_10011210)
  HYPOTHESIS: Machine protocol layer (knitting machine I/O)
  UNKNOWN: IOCTL codes, data structures, protocol format
- Confidence: HIGH
- Next: find callers of this function
- Priority: P0 - this is the hardware boundary
