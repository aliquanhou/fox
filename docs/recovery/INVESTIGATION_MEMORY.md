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

### INV-009: File Read Core Found
- Question: Which function reads pattern files?
- Evidence: fn_41AB70 = 177 lines, 1x ReadFile, 1x CloseHandle
- Evidence ID: E-READER-0009
- Key findings:
  FACT: fn_41AB70 calls wsprintfA (path string formatting)
  FACT: fn_41AB70 calls fn_4280A0(4639008) - 0x46CC60
  FACT: Only caller = fn_455E4C
  FACT: fn_455E4C is the entry point with CreateFileA
- Conclusion:
  FACT: Path string is dynamically formatted via wsprintfA
  FACT: File open → read chain: fn_455E4C → fn_41AB70 → ReadFile
  HYPOTHESIS: fn_4280A0 processes file content after read
  UNKNOWN: exact file path format
- Confidence: high
- Priority: P0 - Pattern Reader confirmed
