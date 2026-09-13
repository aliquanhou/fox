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

### INV-008: Pattern File Format Analysis
- Question: What do the pattern files look like?
- Evidence: Real data files in data/ directory
- Evidence ID: E-FORMAT-0008
- Files found:
  - AT.FSZ (89377 bytes) - compressed/encrypted (random bytes)
  - AT.BMZ (1690 bytes) - auxiliary
  - patternset.dat (40512 bytes) - structured!
  - P_NTC.SET (205524 bytes) - settings
  - tension.dat (2048 bytes)
  - Wt_dvc.dat (47500 bytes)
  - MD_EDIT.fs (2429540 bytes) - large pattern editor data
- patternset.dat header analysis:
  offset 0x00: 00 00 00 00
  offset 0x04: 0x0200 = 512 (likely needle count or pattern width)
  offset 0x08: 0x3E8 = 1000 (likely course count or pattern height)
  offset 0x10: 0x28 = 40 (likely color count?)
  offset 0x14: 0x06 = 6
- Conclusion:
  FACT: patternset.dat has structured header with numeric fields
  FACT: AT.FSZ is compressed/encrypted
  HYPOTHESIS: patternset.dat = pattern set index/metadata
  HYPOTHESIS: AT.FSZ = actual pattern data (compressed)
  UNKNOWN: exact format details
- Confidence: medium
- Priority: P0 - this is the Pattern Compiler input
