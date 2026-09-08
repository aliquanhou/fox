//! FOX CFG Edge Types
//!
//! Edges are classified by control flow semantics.
//! Different semantics are NOT mixed into a single edge type.

use crate::evidence::{Evidence, EvidenceList};
use serde::{Deserialize, Serialize};

/// The type of a CFG edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdgeKind {
    /// Fallthrough to next instruction (after non-branch or conditional not-taken)
    Fallthrough,
    /// Conditional branch taken (true)
    ConditionalTrue,
    /// Conditional branch not taken (false / fallthrough)
    ConditionalFalse,
    /// Unconditional jump (JMP)
    UnconditionalJump,
    /// Function call (CALL) — note: CALL is NOT a block terminator by default
    Call,
    /// Function return (RET)
    Return,
    /// Indirect jump (target unknown or computed)
    IndirectJump,
    /// Jump table edge (resolved from switch dispatch)
    JumpTable,
    /// Indirect call (target unknown or computed)
    IndirectCall,
    /// Unknown control flow (cannot classify)
    Unknown,
}

impl EdgeKind {
    pub fn display_name(&self) -> &'static str {
        match self {
            EdgeKind::Fallthrough => "Fallthrough",
            EdgeKind::ConditionalTrue => "ConditionalTrue",
            EdgeKind::ConditionalFalse => "ConditionalFalse",
            EdgeKind::UnconditionalJump => "UnconditionalJump",
            EdgeKind::Call => "Call",
            EdgeKind::Return => "Return",
            EdgeKind::IndirectJump => "IndirectJump",
            EdgeKind::JumpTable => "JumpTable",
            EdgeKind::IndirectCall => "IndirectCall",
            EdgeKind::Unknown => "Unknown",
        }
    }

    /// Whether this edge represents a real control flow transfer
    /// (as opposed to a fallthrough which is implicit).
    pub fn is_explicit_transfer(&self) -> bool {
        matches!(
            self,
            EdgeKind::ConditionalTrue
                | EdgeKind::UnconditionalJump
                | EdgeKind::Call
                | EdgeKind::Return
                | EdgeKind::IndirectJump
                | EdgeKind::IndirectCall
        )
    }

    /// Whether this edge's target is known (resolved to an address).
    pub fn has_known_target(&self) -> bool {
        !matches!(
            self,
            EdgeKind::IndirectJump | EdgeKind::IndirectCall | EdgeKind::Unknown
        )
    }
}

impl std::fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// A directed edge in the CFG, carrying evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgEdge {
    pub kind: EdgeKind,
    pub source_block: usize,
    pub target_block: Option<usize>,
    /// Target address if known (for indirect/unknown, this is None)
    pub target_address: Option<u64>,
    /// Address of the instruction that produces this edge
    pub source_instruction: u64,
    /// Evidence explaining why this edge exists
    pub evidence: EvidenceList,
}

impl CfgEdge {
    pub fn new(kind: EdgeKind, source_block: usize, source_instruction: u64) -> Self {
        CfgEdge {
            kind,
            source_block,
            target_block: None,
            target_address: None,
            source_instruction,
            evidence: EvidenceList::new(),
        }
    }

    pub fn with_target(mut self, block: usize, address: u64) -> Self {
        self.target_block = Some(block);
        self.target_address = Some(address);
        self
    }

    pub fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }
}

/// Call edge type for the call graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CallEdgeKind {
    /// Direct call to a known function within the binary
    Direct,
    /// Indirect call (function pointer, vtable, etc.)
    Indirect,
    /// Call to an external imported function
    External,
    /// Call target cannot be resolved
    Unknown,
}

impl CallEdgeKind {
    pub fn display_name(&self) -> &'static str {
        match self {
            CallEdgeKind::Direct => "Direct",
            CallEdgeKind::Indirect => "Indirect",
            CallEdgeKind::External => "External",
            CallEdgeKind::Unknown => "Unknown",
        }
    }
}

impl std::fmt::Display for CallEdgeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Classification of indirect call operands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndirectCallKind {
    /// Register indirect call: `call rax`
    Register,
    /// Memory indirect call: `call [rax]` or `call [rsp+0x20]`
    Memory,
    /// Vtable candidate: `call [reg+disp]` (object pointer + vtable offset)
    VtableCandidate,
    /// IAT call: `call [rip+disp]` resolved to external import
    Iat,
    /// Unknown indirect call pattern
    Unknown,
}

impl IndirectCallKind {
    pub fn display_name(&self) -> &'static str {
        match self {
            IndirectCallKind::Register => "Register",
            IndirectCallKind::Memory => "Memory",
            IndirectCallKind::VtableCandidate => "VtableCandidate",
            IndirectCallKind::Iat => "IAT",
            IndirectCallKind::Unknown => "Unknown",
        }
    }
}

/// An edge in the call graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphEdge {
    pub kind: CallEdgeKind,
    pub caller: u64,
    pub callee: Option<u64>,
    pub call_instruction: u64,
    /// Resolved symbol name for external calls (e.g., "kernel32.dll!CreateFileW")
    pub resolved_symbol: Option<String>,
    /// For indirect calls, the specific kind of indirect call
    pub indirect_kind: Option<IndirectCallKind>,
    /// Evidence explaining why this edge exists
    pub evidence: EvidenceList,
}
