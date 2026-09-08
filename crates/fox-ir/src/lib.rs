//! FOX Intermediate Representation (IR)
//!
//! FOX uses a custom IR designed specifically for reverse engineering.
//! Not LLVM IR (which is designed for compilation, not decompilation).
//!
//! IR levels:
//! - L1: Instruction-level (close to machine code, architecture-specific)
//! - L2: Operation-level (architecture-neutral, RISC-like)
//! - L3: Structured (control flow structures, variables)
//!
//! P0-2: L1 with full semantic model (width, read/write, flags, memory).

pub mod flags;
pub mod l1;
pub mod memory;

use fox_core::Address;
use serde::{Deserialize, Serialize};

/// IR operation opcode (architecture-neutral).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IROp {
    // Data movement
    Mov,
    Load,
    Store,
    Push,
    Pop,
    Lea,

    // Arithmetic
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Neg,
    Inc,
    Dec,

    // Bitwise
    And,
    Or,
    Xor,
    Not,
    Shl,
    Shr,
    Sar,
    Rotl,
    Rotr,

    // Comparison
    Cmp,
    Test,

    // Control flow
    Jump,
    CondJump,
    Call,
    Return,
    Nop,
    Halt,

    // Flag operations
    SetFlag,
    ClearFlag,

    // Stack
    Enter,
    Leave,

    // System
    Int,
    Syscall,

    // Unknown / untranslated
    Unknown(String),
}

/// Operand access mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperandAccess {
    Read,
    Write,
    ReadWrite,
}

/// IR operand with full semantic information.
///
/// P0-2: Every operand carries width (bits), access mode, and signedness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IROperand {
    /// Register operand.
    Register {
        name: String,
        /// Width in bits (8, 16, 32, 64, 128, 256, 512)
        width: u16,
        access: OperandAccess,
    },
    /// Immediate value.
    Immediate {
        value: u64,
        /// Width in bits
        width: u16,
        is_signed: bool,
    },
    /// Memory operand: [base + index*scale + displacement]
    Memory {
        base: Option<String>,
        index: Option<String>,
        scale: u8,
        displacement: i64,
        /// Access size in bytes
        size: u8,
        access: OperandAccess,
        /// RIP-relative addressing (x64)
        is_rip_relative: bool,
        /// Computed effective address (if known)
        effective_address: Option<u64>,
    },
    /// Label / branch target.
    Label(String),
    /// SSA variable (P0-2.5).
    Variable { name: String, version: u32 },
    /// Phi node (P0-2.5).
    Phi {
        incoming: Vec<(String, u32)>, // (block_name, variable_version)
    },
    /// Constant (after constant propagation).
    Constant(u64),
    /// Flags register (EFLAGS/RFLAGS).
    Flags { access: OperandAccess },
}

impl IROperand {
    /// Get operand width in bits.
    pub fn width(&self) -> u16 {
        match self {
            IROperand::Register { width, .. } => *width,
            IROperand::Immediate { width, .. } => *width,
            IROperand::Memory { size, .. } => (*size as u16) * 8,
            IROperand::Flags { .. } => 64,
            _ => 0,
        }
    }

    /// Check if operand is a register read.
    pub fn is_register_read(&self) -> bool {
        matches!(
            self,
            IROperand::Register {
                access: OperandAccess::Read | OperandAccess::ReadWrite,
                ..
            }
        )
    }

    /// Check if operand is a register write.
    pub fn is_register_write(&self) -> bool {
        matches!(
            self,
            IROperand::Register {
                access: OperandAccess::Write | OperandAccess::ReadWrite,
                ..
            }
        )
    }
}

/// A single IR instruction with full semantic metadata.
///
/// P0-2: Every IR instruction records explicit reads/writes, flags,
/// and implicit operands for data flow analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IRInstruction {
    pub address: Address,
    pub op: IROp,
    pub operands: Vec<IROperand>,
    pub original_mnemonic: Option<String>,
    pub original_operands: Option<String>,
    pub size: u8,
    /// Registers explicitly read by this instruction
    pub reads_registers: Vec<String>,
    /// Registers explicitly written by this instruction
    pub writes_registers: Vec<String>,
    /// Implicit registers read (e.g., RSP for PUSH, RIP for JMP)
    pub implicit_reads: Vec<String>,
    /// Implicit registers written (e.g., RSP for PUSH, RIP for JMP)
    pub implicit_writes: Vec<String>,
    /// Whether this instruction reads FLAGS
    pub reads_flags: bool,
    /// Whether this instruction writes FLAGS
    pub writes_flags: bool,
}

impl IRInstruction {
    /// All registers read (explicit + implicit).
    pub fn all_reads(&self) -> Vec<&str> {
        let mut reads: Vec<&str> = self.reads_registers.iter().map(|s| s.as_str()).collect();
        reads.extend(self.implicit_reads.iter().map(|s| s.as_str()));
        reads
    }

    /// All registers written (explicit + implicit).
    pub fn all_writes(&self) -> Vec<&str> {
        let mut writes: Vec<&str> = self.writes_registers.iter().map(|s| s.as_str()).collect();
        writes.extend(self.implicit_writes.iter().map(|s| s.as_str()));
        writes
    }
}

/// A basic block in the IR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IRBasicBlock {
    pub id: usize,
    pub start_address: Address,
    pub end_address: Address,
    pub instructions: Vec<IRInstruction>,
    pub successors: Vec<usize>,
    pub predecessors: Vec<usize>,
}

/// An IR function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IRFunction {
    pub name: String,
    pub address: Address,
    pub basic_blocks: Vec<IRBasicBlock>,
    pub entry_block: usize,
}

/// IR module - contains all functions for a binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IRModule {
    pub functions: Vec<IRFunction>,
    pub architecture: String,
}

impl IRModule {
    pub fn new(architecture: &str) -> Self {
        IRModule {
            functions: Vec::new(),
            architecture: architecture.to_string(),
        }
    }
}
