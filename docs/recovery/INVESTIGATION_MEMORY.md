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

### INV-015: DLL Inventory
- Question: What do other DLLs contain?
- Evidence: File sizes and function counts
- Evidence ID: E-INVENTORY-0015
- Findings:
  NTCDLLC: 740KB C output
  NTCDLLG: 29x DeviceIoControl (confirmed)
  Other DLLs: to be analyzed
- Conclusion:
  FACT: Each DLL is ~700-1000KB C output
  HYPOTHESIS: Different DLLs handle different business domains
  UNKNOWN: exact module responsibilities
- Confidence: low
- Priority: P1

### INV-016: Business DLL Scan
- Question: What do business DLLs contain?
- Evidence: String scan results
- Evidence ID: E-DLL-SCAN-0016
- Findings:
  NTCDLLC: 0 matching functions/strings (may be exported only)
  NTCDLLM: 0 matching
  NTCDLLV: 0 matching
  NTCDLL_M3: 242 functions
  NTCDLL_M4: 279 functions
- Conclusion:
  FACT: M3/M4 have real functions
  FACT: C/M/V may be export-only wrappers
  UNKNOWN: full module mapping
- Confidence: low
- Priority: P1

### INV-017: M3/M4 String Analysis
- Question: What strings exist in business DLLs?
- Evidence: String scan
- Evidence ID: E-M3M4-STR-0017
- Findings:
  M3: 0 string literals
  M4: to be checked
- Conclusion:
  FACT: Business logic DLLs have no embedded strings
  HYPOTHESIS: All strings come from NtcMach resources
  HYPOTHESIS: M3/M4 are pure computation/algorithm DLLs
  UNKNOWN: exact algorithm domain
- Confidence: medium
- Priority: P1 - M3/M4 = algorithm core

### INV-018: M4 Core Algorithm Functions
- Question: Where is the knitting algorithm?
- Evidence: Largest functions in M4
- Evidence ID: E-M4-CORE-0018
- Findings:
  fn_1000A560: 1542 lines
  fn_1000B4E0: 1536 lines
  fn_10008620: 1427 lines
  fn_100065C0: 1171 lines
  fn_100075A0: 1140 lines
- Conclusion:
  FACT: 5 core functions >1000 lines
  HYPOTHESIS: These are the knitting algorithm cores
  HYPOTHESIS: One may be Pattern Compiler
  UNKNOWN: exact role of each
- Confidence: medium
- Priority: P0 - these are the algorithm heart

### INV-019: Core Algorithm Function Analysis
- Question: What do the 5 core functions do?
- Evidence: API call scan
- Evidence ID: E-CORE-ANALYSIS-0019
- Findings:
  All 5 functions: 0 API calls, pure computation
  fn_100065C0: 16 internal calls (most complex orchestrator)
  fn_1000A560: 12 internal calls
  fn_10008620: 12 internal calls
  fn_100075A0: 9 internal calls
  fn_1000B4E0: 6 internal calls (leaf computation)
- Conclusion:
  FACT: All core functions are pure computation (no I/O)
  HYPOTHESIS: fn_100065C0 = main algorithm orchestrator
  HYPOTHESIS: fn_1000B4E0 = leaf computation kernel
  UNKNOWN: exact algorithm semantics
- Confidence: medium
- Priority: P0

### INV-020: Algorithm Orchestrator Signature
- Question: What does fn_100065C0 take as input?
- Evidence: Function signature
- Evidence ID: E-ORCH-SIG-0020
- Findings:
  FACT: fn_100065C0(uint32_t arg0 /* HANDLE? */, ...)
  FACT: Calls fn_10001180(268569696)
  FACT: Calls wsprintfA
  FACT: 750+ local variables
- Conclusion:
  FACT: arg0 is likely a context/state pointer
  HYPOTHESIS: This function processes pattern state machine
  HYPOTHESIS: 750 locals = complex state tracking
  UNKNOWN: exact state machine
- Confidence: medium
- Priority: P0

### INV-021: Helper Function Chain
- Question: What does fn_10001180 do?
- Evidence: 53 lines, 1 callee
- Evidence ID: E-HELPER-0021
- Findings:
  FACT: fn_10001180: 53 lines, calls fn_10001210
  HYPOTHESIS: This is a small initialization/setup helper
  UNKNOWN: exact purpose
- Confidence: low
- Priority: P2

### INV-022: Compute Kernel Arithmetic Analysis
- Question: What does the compute kernel do?
- Evidence: Operator frequency
- Evidence ID: E-KERNEL-ARITH-0022
- Findings:
  FACT: + : 425 operations
  FACT: ^ : 105 XOR operations
  FACT: - : 63 subtractions
  FACT: | : 54 bitwise OR
  FACT: * : 36 multiplications
- Conclusion:
  FACT: Heavy arithmetic + bitwise operations
  HYPOTHESIS: This is data transformation / encoding algorithm
  HYPOTHESIS: XOR suggests encoding/obfuscation
  UNKNOWN: exact algorithm type
- Confidence: medium
- Priority: P0
