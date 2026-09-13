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

### INV-006: NtcMach.exe File I/O Analysis
- Question: Where is the file I/O core?
- Evidence: Only fn_41A870 has CreateFileA (2 calls, 42 lines)
- Evidence ID: E-FILEIO-0006
- Conclusion:
  FACT: fn_41A870 = file open wrapper (2x CreateFileA)
  FACT: No file name strings (dynamic construction)
  HYPOTHESIS: Generic file open utility, called by pattern load/save
  UNKNOWN: which files it opens
- Confidence: medium
- Priority: P1

### INV-010: File Processing Call Chain
- Question: What happens after file is read?
- Evidence: Deep call chain from fn_41AB70
- Evidence ID: E-CHAIN-0010
- Chain discovered:
  fn_41AB70 (177 lines, ReadFile)
    → fn_4280A0 (106 lines)
      → fn_428160 (65 lines)
        → fn_4281F0 (35 lines)
          → fn_429F00 (1504 lines! 2nd largest function)
          → fn_428240
- Conclusion:
  FACT: File data flows through 5 levels of function calls
  FACT: fn_429F00 is the 2nd largest function (1504 lines)
  HYPOTHESIS: fn_429F00 is the actual Pattern Parser/Decoder
  UNKNOWN: exact transformation
- Confidence: high
- Priority: P0 - fn_429F00 is the next investigation target
