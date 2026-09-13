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

### INV-005: NTCDLLG Architecture Analysis (DeepSeek)
- Question: What is the overall architecture?
- Evidence: 3 callers of fn_1000F2F0, 6 real IOCTL codes
- Evidence ID: E-ARCH-0005
- DeepSeek conclusion:
  FACT: fn_1000F2F0 = Device I/O HAL (29x DeviceIoControl)
  FACT: 3 callers = narrow interface design
  HYPOTHESIS: fn_100187E1 (41k lines) = main orchestration/knitting state machine
  HYPOTHESIS: fn_10001280 = init/configuration
  HYPOTHESIS: fn_10011210 = control/command channel
  HYPOTHESIS: Pattern Compiler sits above fn_100187E1
  UNKNOWN: exact location of compiler
- Confidence: high (architecture), medium (compiler location)
- Data flow: App → Orchestrator → HAL → Driver → Hardware
- Priority: P0 - architecture now clear
