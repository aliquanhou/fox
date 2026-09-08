# FOX Third-Party License Audit
#
# Every dependency MUST be recorded.
# FOX must be legally open-sourceable and commercializable.

dependencies:
  # --- Core ---
  - name: anyhow
    version: "1.0"
    license: "MIT OR Apache-2.0"
    purpose: "Error handling"
    linking: "static"
    redistribution: "Yes - include license text"
    source: "https://crates.io/crates/anyhow"

  - name: thiserror
    version: "1.0"
    license: "MIT OR Apache-2.0"
    purpose: "Error type derivation"
    linking: "static"
    redistribution: "Yes - include license text"
    source: "https://crates.io/crates/thiserror"

  - name: serde
    version: "1.0"
    license: "MIT OR Apache-2.0"
    purpose: "Serialization/deserialization for evidence and analysis results"
    linking: "static"
    redistribution: "Yes - include license text"
    source: "https://crates.io/crates/serde"

  - name: serde_json
    version: "1.0"
    license: "MIT OR Apache-2.0"
    purpose: "JSON output for CLI and project files"
    linking: "static"
    redistribution: "Yes - include license text"
    source: "https://crates.io/crates/serde_json"

  - name: log
    version: "0.4"
    license: "MIT OR Apache-2.0"
    purpose: "Logging facade"
    linking: "static"
    redistribution: "Yes - include license text"
    source: "https://crates.io/crates/log"

  - name: env_logger
    version: "0.11"
    license: "MIT OR Apache-2.0"
    purpose: "Logging implementation"
    linking: "static"
    redistribution: "Yes - include license text"
    source: "https://crates.io/crates/env_logger"

  # --- CLI ---
  - name: clap
    version: "4.5"
    license: "MIT OR Apache-2.0"
    purpose: "Command-line argument parsing"
    linking: "static"
    redistribution: "Yes - include license text"
    source: "https://crates.io/crates/clap"

  # --- Disassembly ---
  - name: zydis
    version: "0.0.5"
    license: "MIT"
    purpose: "x86/x64 disassembler engine"
    linking: "static"
    redistribution: "Yes - include license text"
    source: "https://crates.io/crates/zydis"
    notes: "Zydis is the fastest x86 disassembler. P0 only. Multi-arch expansion will add Capstone."

  # --- Binary Parsing (reference, not yet linked) ---
  - name: goblin
    version: "0.8"
    license: "MIT"
    purpose: "Reference binary parser (PE/ELF/Mach-O). FOX uses self-written PE parser in P0; goblin is listed for future cross-validation."
    linking: "not linked (reference only)"
    redistribution: "N/A"
    source: "https://crates.io/crates/goblin"

# License compliance status:
# All current dependencies are MIT or Apache-2.0, compatible with both
# open-source and commercial distribution.
#
# P0-0 decision: FOX core is MIT licensed.
# No GPL/LGPL dependencies are allowed in core crates.
# GUI (Tauri) dependencies will be audited in P1.
