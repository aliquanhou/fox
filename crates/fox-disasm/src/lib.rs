//! FOX Disassembler Abstraction Layer
//!
//! P0: Zydis for x86/x64.
//! Architecture-agnostic trait allows future expansion.

pub mod zydis_backend;

use fox_arch::Architecture;
use fox_core::{FoxError, FoxResult};
use serde::{Deserialize, Serialize};

/// Operand kind classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperandKind {
    Register,
    Immediate,
    Memory,
}

/// Structured memory operand.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryOperand {
    pub base: Option<String>,
    pub index: Option<String>,
    pub scale: u8,
    pub displacement: i64,
    /// Size in bytes (0 if unknown)
    pub size: u8,
    /// Whether this is RIP-relative (x64)
    pub is_rip_relative: bool,
    /// Effective address if computable (for RIP-relative)
    pub effective_address: Option<u64>,
}

/// Structured operand with semantic metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operand {
    pub kind: OperandKind,
    pub register: Option<String>,
    pub immediate: Option<u64>,
    pub memory: Option<MemoryOperand>,
    /// Width in bits (0 if unknown)
    pub width: u16,
    /// Whether this operand is read
    pub is_read: bool,
    /// Whether this operand is written
    pub is_write: bool,
    /// Whether this is an implicit operand (not in instruction text)
    pub is_implicit: bool,
}

/// A decoded instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    pub address: u64,
    pub length: usize,
    pub mnemonic: String,
    pub operands: String,
    pub raw_bytes: Vec<u8>,
    pub is_call: bool,
    pub is_ret: bool,
    pub is_jump: bool,
    pub is_conditional_jump: bool,
    pub jump_target: Option<u64>,
    pub call_target: Option<u64>,
    /// Structured operands (P0-2: semantic model)
    pub operands_structured: Vec<Operand>,
    /// Implicit registers read (e.g., FLAGS for CMP)
    pub implicit_reads: Vec<String>,
    /// Implicit registers written (e.g., FLAGS for ADD)
    pub implicit_writes: Vec<String>,
    /// Whether this instruction writes FLAGS
    pub writes_flags: bool,
    /// Whether this instruction reads FLAGS
    pub reads_flags: bool,
}

/// Disassembler trait - architecture-agnostic.
pub trait Disassembler: Send + Sync {
    fn architecture(&self) -> Architecture;
    fn disassemble(&self, data: &[u8], address: u64) -> FoxResult<Vec<Instruction>>;
    fn disassemble_one(&self, data: &[u8], address: u64) -> FoxResult<Option<Instruction>>;
}

/// Create a disassembler for the given architecture.
pub fn create_disassembler(arch: Architecture) -> FoxResult<Box<dyn Disassembler>> {
    match arch {
        Architecture::X86 | Architecture::X64 => {
            Ok(Box::new(zydis_backend::ZydisDisassembler::new(arch)?))
        }
        other => Err(FoxError::UnsupportedArchitecture(
            other.display_name().to_string(),
        )),
    }
}
