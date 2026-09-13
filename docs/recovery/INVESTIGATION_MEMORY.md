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

### INV-012: Parser Subfunctions Analysis
- Question: What do the parser subfunctions do?
- Evidence: fn_429F00 has 7 callees analyzed
- Evidence ID: E-PARSE-0012
- Findings:
  fn_428FE0 (504 lines) - largest subparser
  fn_427B00 (204 lines)
  fn_4292E0 (169 lines)
  fn_428B60 (151 lines)
  fn_429880 (146 lines)
  fn_4299E0 (151 lines)
  fn_429710 (34 lines)
- Conclusion:
  FACT: 7 subparsers form a hierarchy
  FACT: No string literals in subparsers (pure binary parsing)
  HYPOTHESIS: Each subparser handles different record types
  UNKNOWN: exact record format
- Confidence: medium
- Priority: P1

### INV-013: Pattern Parser Callers
- Question: Who calls the Pattern Parser?
- Evidence: fn_429F00 has 2 callers
- Evidence ID: E-PARSER-CALLERS-0013
- Findings:
  FACT: fn_455E4C (main entry)
  FACT: fn_428240 (15 lines thin wrapper)
- Conclusion:
  FACT: Parser is called from main entry and from a wrapper
  HYPOTHESIS: fn_428240 may be used for re-parse or reload
  UNKNOWN: Pattern Compiler location
- Confidence: medium
- Priority: P1 - need to find where parsed data goes

### INV-014: Cross-module Analysis
- Question: Where is the business logic?
- Evidence: NtcMach has 0 machine-related strings, 0 direct NTCDLLG calls
- Evidence ID: E-CROSS-0014
- Findings:
  FACT: NtcMach.exe = GUI shell only
  FACT: Business strings are in resources or other DLLs
  HYPOTHESIS: Pattern Compiler and Machine Logic are in separate DLLs
  UNKNOWN: which DLL does what
- Confidence: medium
- Priority: P1 - need to analyze other DLLs
