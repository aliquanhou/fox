//! FOX Architecture Definitions
//!
//! Defines supported CPU architectures and their properties.
//! P0: x86, x64. Extensible to ARM64 and beyond.

pub mod arm64;
pub mod x64;
pub mod x86;

use serde::{Deserialize, Serialize};

/// Supported CPU architectures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Architecture {
    X86,
    X64,
    ARM64,
    // Reserved for future expansion
    MIPS,
    PowerPC,
    RISCv,
}

impl Architecture {
    /// Pointer size in bytes.
    pub fn pointer_size(&self) -> usize {
        match self {
            Architecture::X86 => 4,
            Architecture::X64 => 8,
            Architecture::ARM64 => 8,
            Architecture::MIPS => 4,
            Architecture::PowerPC => 4,
            Architecture::RISCv => 8,
        }
    }

    /// Default instruction alignment in bytes.
    pub fn instruction_alignment(&self) -> usize {
        match self {
            Architecture::X86 | Architecture::X64 => 1, // x86 is variable-length
            Architecture::ARM64 => 4,
            Architecture::MIPS => 4,
            Architecture::PowerPC => 4,
            Architecture::RISCv => 2, // RISC-V supports 16-bit compressed
        }
    }

    /// Whether this architecture uses variable-length instructions.
    pub fn is_variable_length(&self) -> bool {
        matches!(self, Architecture::X86 | Architecture::X64)
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Architecture::X86 => "x86 (32-bit)",
            Architecture::X64 => "x86-64 (64-bit)",
            Architecture::ARM64 => "ARM64 (AArch64)",
            Architecture::MIPS => "MIPS",
            Architecture::PowerPC => "PowerPC",
            Architecture::RISCv => "RISC-V",
        }
    }
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Calling convention descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallingConvention {
    pub name: String,
    pub argument_registers: Vec<String>,
    pub return_register: String,
    pub stack_direction: StackDirection,
    pub callee_saved_registers: Vec<String>,
    pub caller_saved_registers: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StackDirection {
    GrowsDown,
    GrowsUp,
}

impl Default for CallingConvention {
    fn default() -> Self {
        CallingConvention {
            name: "unknown".to_string(),
            argument_registers: vec![],
            return_register: "unknown".to_string(),
            stack_direction: StackDirection::GrowsDown,
            callee_saved_registers: vec![],
            caller_saved_registers: vec![],
        }
    }
}
