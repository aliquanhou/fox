//! FOX FLAGS Semantic Model (P0-3.9)
//!
//! Fine-grained x86 FLAGS modeling: ZF, CF, SF, OF, PF, AF.
//! Each flag can be: READ, WRITE, PRESERVE, UNDEFINED after an instruction.
//!
//! This is critical for Decompiler: CMP -> Jcc must trace ZF definition
//! to branch condition, not just "writes_flags=true".

use serde::{Deserialize, Serialize};

/// Individual x86 FLAGS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Flag {
    /// Zero Flag
    ZF,
    /// Carry Flag
    CF,
    /// Sign Flag
    SF,
    /// Overflow Flag
    OF,
    /// Parity Flag
    PF,
    /// Auxiliary Carry Flag
    AF,
}

impl Flag {
    pub fn all() -> [Flag; 6] {
        [Flag::ZF, Flag::CF, Flag::SF, Flag::OF, Flag::PF, Flag::AF]
    }

    pub fn name(&self) -> &'static str {
        match self {
            Flag::ZF => "ZF",
            Flag::CF => "CF",
            Flag::SF => "SF",
            Flag::OF => "OF",
            Flag::PF => "PF",
            Flag::AF => "AF",
        }
    }
}

/// How an instruction affects a specific flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlagEffect {
    /// Flag is read by this instruction (e.g., Jcc reads ZF)
    Read,
    /// Flag is written/defined by this instruction (e.g., CMP writes ZF)
    Write,
    /// Flag is read and written (e.g., ADC reads CF, writes CF)
    ReadWrite,
    /// Flag is preserved (unchanged) by this instruction
    Preserve,
    /// Flag becomes undefined after this instruction
    Undefined,
}

/// Complete FLAGS semantics for one instruction.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FlagsSemantics {
    /// Per-flag effects
    pub effects: std::collections::HashMap<Flag, FlagEffect>,
}

impl FlagsSemantics {
    pub fn new() -> Self {
        Self {
            effects: std::collections::HashMap::new(),
        }
    }

    pub fn set(&mut self, flag: Flag, effect: FlagEffect) {
        self.effects.insert(flag, effect);
    }

    pub fn get(&self, flag: Flag) -> FlagEffect {
        self.effects
            .get(&flag)
            .copied()
            .unwrap_or(FlagEffect::Preserve)
    }

    pub fn reads(&self, flag: Flag) -> bool {
        matches!(self.get(flag), FlagEffect::Read | FlagEffect::ReadWrite)
    }

    pub fn writes(&self, flag: Flag) -> bool {
        matches!(
            self.get(flag),
            FlagEffect::Write | FlagEffect::ReadWrite | FlagEffect::Undefined
        )
    }

    pub fn any_read(&self) -> bool {
        Flag::all().iter().any(|f| self.reads(*f))
    }

    pub fn any_write(&self) -> bool {
        Flag::all().iter().any(|f| self.writes(*f))
    }

    pub fn read_flags(&self) -> Vec<Flag> {
        Flag::all()
            .iter()
            .filter(|f| self.reads(**f))
            .copied()
            .collect()
    }

    pub fn written_flags(&self) -> Vec<Flag> {
        Flag::all()
            .iter()
            .filter(|f| self.writes(**f))
            .copied()
            .collect()
    }
}

/// Look up FLAGS semantics for an x86 instruction mnemonic.
///
/// Based on Intel SDM flag effect tables.
pub fn lookup_flags(mnemonic: &str) -> FlagsSemantics {
    let mut s = FlagsSemantics::new();
    let m = mnemonic.to_uppercase();

    match m.as_str() {
        // === Arithmetic: writes all status flags ===
        "ADD" | "SUB" | "ADC" | "SBB" | "CMP" => {
            for f in [Flag::ZF, Flag::CF, Flag::SF, Flag::OF, Flag::PF, Flag::AF] {
                s.set(f, FlagEffect::Write);
            }
            if m == "ADC" || m == "SBB" {
                s.set(Flag::CF, FlagEffect::ReadWrite);
            }
        }
        // === Logical: writes ZF/SF/PF, CF=0, OF=0, AF undefined ===
        "AND" | "OR" | "XOR" | "TEST" => {
            s.set(Flag::ZF, FlagEffect::Write);
            s.set(Flag::SF, FlagEffect::Write);
            s.set(Flag::PF, FlagEffect::Write);
            s.set(Flag::CF, FlagEffect::Write); // always 0
            s.set(Flag::OF, FlagEffect::Write); // always 0
            s.set(Flag::AF, FlagEffect::Undefined);
        }
        // === INC/DEC: preserves CF, writes others ===
        "INC" | "DEC" => {
            s.set(Flag::ZF, FlagEffect::Write);
            s.set(Flag::SF, FlagEffect::Write);
            s.set(Flag::OF, FlagEffect::Write);
            s.set(Flag::PF, FlagEffect::Write);
            s.set(Flag::AF, FlagEffect::Write);
            s.set(Flag::CF, FlagEffect::Preserve);
        }
        // === Shifts/rotates ===
        "SHL" | "SAL" => {
            s.set(Flag::CF, FlagEffect::Write);
            s.set(Flag::ZF, FlagEffect::Write);
            s.set(Flag::SF, FlagEffect::Write);
            s.set(Flag::PF, FlagEffect::Write);
            s.set(Flag::OF, FlagEffect::Undefined); // defined only for 1-bit shift
            s.set(Flag::AF, FlagEffect::Undefined);
        }
        "SHR" => {
            s.set(Flag::CF, FlagEffect::Write);
            s.set(Flag::ZF, FlagEffect::Write);
            s.set(Flag::SF, FlagEffect::Write);
            s.set(Flag::PF, FlagEffect::Write);
            s.set(Flag::OF, FlagEffect::Undefined);
            s.set(Flag::AF, FlagEffect::Undefined);
        }
        "SAR" => {
            s.set(Flag::CF, FlagEffect::Write);
            s.set(Flag::ZF, FlagEffect::Write);
            s.set(Flag::SF, FlagEffect::Write);
            s.set(Flag::PF, FlagEffect::Write);
            s.set(Flag::OF, FlagEffect::Write); // OF=0 for SAR
            s.set(Flag::AF, FlagEffect::Undefined);
        }
        "ROL" | "ROR" | "RCL" | "RCR" => {
            s.set(Flag::CF, FlagEffect::Write);
            s.set(Flag::OF, FlagEffect::Undefined);
            // ZF, SF, PF, AF preserved
        }
        // === Multiplication ===
        "MUL" | "IMUL" => {
            s.set(Flag::CF, FlagEffect::Write);
            s.set(Flag::OF, FlagEffect::Write);
            s.set(Flag::ZF, FlagEffect::Undefined);
            s.set(Flag::SF, FlagEffect::Undefined);
            s.set(Flag::PF, FlagEffect::Undefined);
            s.set(Flag::AF, FlagEffect::Undefined);
        }
        // === Division ===
        "DIV" | "IDIV" => {
            for f in Flag::all() {
                s.set(f, FlagEffect::Undefined);
            }
        }
        // === Conditional jumps: read specific flags ===
        "JE" | "JZ" => {
            s.set(Flag::ZF, FlagEffect::Read);
        }
        "JNE" | "JNZ" => {
            s.set(Flag::ZF, FlagEffect::Read);
        }
        "JC" | "JB" | "JNAE" => {
            s.set(Flag::CF, FlagEffect::Read);
        }
        "JNC" | "JAE" | "JNB" => {
            s.set(Flag::CF, FlagEffect::Read);
        }
        "JS" => {
            s.set(Flag::SF, FlagEffect::Read);
        }
        "JNS" => {
            s.set(Flag::SF, FlagEffect::Read);
        }
        "JO" => {
            s.set(Flag::OF, FlagEffect::Read);
        }
        "JNO" => {
            s.set(Flag::OF, FlagEffect::Read);
        }
        "JP" | "JPE" => {
            s.set(Flag::PF, FlagEffect::Read);
        }
        "JNP" | "JPO" => {
            s.set(Flag::PF, FlagEffect::Read);
        }
        "JA" | "JNBE" => {
            s.set(Flag::CF, FlagEffect::Read);
            s.set(Flag::ZF, FlagEffect::Read);
        }
        "JNA" | "JBE" => {
            s.set(Flag::CF, FlagEffect::Read);
            s.set(Flag::ZF, FlagEffect::Read);
        }
        "JG" | "JNLE" => {
            s.set(Flag::ZF, FlagEffect::Read);
            s.set(Flag::SF, FlagEffect::Read);
            s.set(Flag::OF, FlagEffect::Read);
        }
        "JGE" | "JNL" => {
            s.set(Flag::SF, FlagEffect::Read);
            s.set(Flag::OF, FlagEffect::Read);
        }
        "JL" | "JNGE" => {
            s.set(Flag::SF, FlagEffect::Read);
            s.set(Flag::OF, FlagEffect::Read);
        }
        "JLE" | "JNG" => {
            s.set(Flag::ZF, FlagEffect::Read);
            s.set(Flag::SF, FlagEffect::Read);
            s.set(Flag::OF, FlagEffect::Read);
        }
        // === SETcc: read flags ===
        "SETE" | "SETZ" => {
            s.set(Flag::ZF, FlagEffect::Read);
        }
        "SETNE" | "SETNZ" => {
            s.set(Flag::ZF, FlagEffect::Read);
        }
        // === CMOVcc: read flags ===
        "CMOVE" | "CMOVZ" => {
            s.set(Flag::ZF, FlagEffect::Read);
        }
        "CMOVNE" | "CMOVNZ" => {
            s.set(Flag::ZF, FlagEffect::Read);
        }
        // === Flag manipulation ===
        "CLC" => {
            s.set(Flag::CF, FlagEffect::Write);
        }
        "STC" => {
            s.set(Flag::CF, FlagEffect::Write);
        }
        "CMC" => {
            s.set(Flag::CF, FlagEffect::ReadWrite);
        }
        "CLD" => { /* DF, not modeled */ }
        "STD" => { /* DF */ }
        // === MOV: preserves all flags ===
        "MOV" | "MOVZX" | "MOVSX" | "LEA" | "PUSH" | "POP" | "NOP" => {
            // All flags preserved
        }
        // === CALL/RET: preserves flags (in practice) ===
        "CALL" | "RET" => {
            // Flags preserved across call/ret boundary
        }
        // === Default: assume undefined for unknown instructions ===
        _ => {
            // Conservative: don't assume anything
        }
    }

    s
}

/// Verify CMP -> Jcc flag dependency chain.
///
/// Returns true if the Jcc instruction's required flags are defined
/// by the most recent flag-writing instruction (typically CMP/TEST).
pub fn verify_flag_chain(flag_writer_mnemonic: &str, flag_reader_mnemonic: &str) -> bool {
    let writer = lookup_flags(flag_writer_mnemonic);
    let reader = lookup_flags(flag_reader_mnemonic);

    for flag in Flag::all() {
        if reader.reads(flag) && !writer.writes(flag) {
            return false; // reader needs a flag writer doesn't provide
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cmp_writes_all_flags() {
        let s = lookup_flags("CMP");
        assert!(s.writes(Flag::ZF));
        assert!(s.writes(Flag::CF));
        assert!(s.writes(Flag::SF));
        assert!(s.writes(Flag::OF));
        assert!(s.writes(Flag::PF));
        assert!(s.writes(Flag::AF));
    }

    #[test]
    fn test_jne_reads_zf() {
        let s = lookup_flags("JNE");
        assert!(s.reads(Flag::ZF));
        assert!(!s.writes(Flag::ZF));
    }

    #[test]
    fn test_inc_preserves_cf() {
        let s = lookup_flags("INC");
        assert_eq!(s.get(Flag::CF), FlagEffect::Preserve);
        assert!(s.writes(Flag::ZF));
    }

    #[test]
    fn test_cmp_jne_chain() {
        assert!(verify_flag_chain("CMP", "JNE"));
    }

    #[test]
    fn test_test_je_chain() {
        assert!(verify_flag_chain("TEST", "JE"));
    }

    #[test]
    fn test_adc_reads_cf() {
        let s = lookup_flags("ADC");
        assert!(s.reads(Flag::CF));
        assert!(s.writes(Flag::CF));
    }

    #[test]
    fn test_mov_preserves_flags() {
        let s = lookup_flags("MOV");
        assert!(!s.any_write());
        assert!(!s.any_read());
    }

    #[test]
    fn test_jg_reads_zf_sf_of() {
        let s = lookup_flags("JG");
        assert!(s.reads(Flag::ZF));
        assert!(s.reads(Flag::SF));
        assert!(s.reads(Flag::OF));
    }
}
