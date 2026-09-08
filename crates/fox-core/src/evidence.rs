//! FOX Evidence System
//!
//! Every analysis result in FOX must carry evidence.
//! This answers: "Why does FOX believe this is a function / call / struct / API?"
//!
//! Evidence chain:
//!   Instruction -> Basic Block -> Function -> CFG -> Analysis Result -> Evidence

use serde::{Deserialize, Serialize};
use std::fmt;

/// Confidence score for an analysis result. 0.0 = no confidence, 1.0 = certain.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Confidence(pub f64);

impl Confidence {
    pub const ZERO: Confidence = Confidence(0.0);
    pub const LOW: Confidence = Confidence(0.3);
    pub const MEDIUM: Confidence = Confidence(0.6);
    pub const HIGH: Confidence = Confidence(0.85);
    pub const CERTAIN: Confidence = Confidence(1.0);

    pub fn new(value: f64) -> Self {
        Confidence(value.clamp(0.0, 1.0))
    }

    pub fn is_high(&self) -> bool {
        self.0 >= 0.8
    }

    pub fn is_certain(&self) -> bool {
        (self.0 - 1.0).abs() < f64::EPSILON
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.2}", self.0)
    }
}

/// The kind of evidence supporting an analysis conclusion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceKind {
    /// Valid function prologue detected (e.g., push rbp; mov rbp, rsp)
    FunctionPrologue,
    /// Valid function epilogue detected (e.g., leave; ret)
    FunctionEpilogue,
    /// Referenced by N CALL instructions
    CallReference { count: usize },
    /// Ends with a valid RET instruction
    ValidReturn,
    /// Stack frame pattern detected
    StackFramePattern,
    /// Called a known API (name provided)
    CalledApi { api_name: String },
    /// Import table entry
    ImportEntry,
    /// Export table entry
    ExportEntry,
    /// Relocation entry
    RelocationEntry,
    /// String reference
    StringReference { string: String },
    /// Control flow transfer (jmp/call)
    ControlFlowTransfer,
    /// Basic block boundary (conditional branch target)
    BranchTarget,
    /// Entry point from binary header
    EntryPoint,
    /// Section is executable
    ExecutableSection,
    /// Pattern match (signature/bytes)
    PatternMatch { pattern: String },
    /// Cross-reference from another location
    CrossReference { from: u64 },
    /// Heuristic analysis result
    Heuristic { description: String },
    /// User annotation
    UserAnnotation,
    /// From symbol table / debug info
    SymbolInfo,
    /// Architecture-specific convention
    CallingConvention,
    /// Data type inferred from usage
    TypeUsagePattern,
    /// CFG edge: fallthrough to next instruction
    FallthroughEdge,
    /// CFG edge: conditional branch taken (true)
    ConditionalTrueEdge,
    /// CFG edge: conditional branch not taken (false / fallthrough)
    ConditionalFalseEdge,
    /// CFG edge: unconditional jump
    UnconditionalJumpEdge,
    /// CFG edge: function call
    CallEdge,
    /// CFG edge: function return
    ReturnEdge,
    /// CFG edge: indirect jump (target unknown)
    IndirectJumpEdge,
    /// CFG edge: indirect call (target unknown)
    IndirectCallEdge,
    /// CFG edge: unknown control flow
    UnknownEdge,
    /// Instruction is a basic block terminator
    BlockTerminator { mnemonic: String },
    /// Address is a branch target (starts a new block)
    BranchTargetAddress { target: u64 },
    /// Instruction successfully decoded (valid instruction boundary)
    ValidInstructionDecoded,
    /// Function is reachable from entry point via recursive descent
    ReachableFromEntry,
    /// Negative evidence: address is in a non-executable section
    NegativeNonExecutableSection,
    /// Negative evidence: address does not start with a valid instruction
    NegativeInvalidInstructionBoundary,
    /// Negative evidence: no reachable path to this address
    NegativeUnreachable,
    /// Negative evidence: address identified as data (jump table, etc.)
    NegativeDataAddress,
    /// Data flow analysis result (reaching definitions, liveness, constants)
    DataFlowAnalysis,
    /// Dominator analysis result
    DominatorAnalysis,
    /// SSA construction (phi placement, renaming)
    SSAConstruction,
    /// Type inference result
    TypeInference,
    /// External call resolved via IAT
    ExternalCallResolved { symbol: String },
    /// Function body validated: valid instructions + RET/tail-call + no overlap
    ValidFunctionBody,
    /// Function body validation failed
    InvalidFunctionBody { reason: String },
    /// Tail call detected (JMP to another function)
    TailCall,
    /// Function found in .pdata exception metadata (x64 authoritative)
    PdataEntry,
    /// Jump table pattern detected (switch dispatch)
    JumpTablePattern,
    /// Jump table target resolved
    JumpTableTarget,
    /// Function reached via thunk/JMP chain
    ThunkTarget,
}

impl fmt::Display for EvidenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvidenceKind::FunctionPrologue => write!(f, "Valid function prologue"),
            EvidenceKind::FunctionEpilogue => write!(f, "Valid function epilogue"),
            EvidenceKind::CallReference { count } => {
                write!(f, "Referenced by {} CALL instructions", count)
            }
            EvidenceKind::ValidReturn => write!(f, "Ends with valid RET"),
            EvidenceKind::StackFramePattern => write!(f, "Stack frame pattern detected"),
            EvidenceKind::CalledApi { api_name } => write!(f, "Called API: {}", api_name),
            EvidenceKind::ImportEntry => write!(f, "Import table entry"),
            EvidenceKind::ExportEntry => write!(f, "Export table entry"),
            EvidenceKind::RelocationEntry => write!(f, "Relocation entry"),
            EvidenceKind::StringReference { string } => {
                write!(f, "String reference: \"{}\"", string)
            }
            EvidenceKind::ControlFlowTransfer => write!(f, "Control flow transfer"),
            EvidenceKind::BranchTarget => write!(f, "Branch target (basic block boundary)"),
            EvidenceKind::EntryPoint => write!(f, "Binary entry point"),
            EvidenceKind::ExecutableSection => write!(f, "Executable section"),
            EvidenceKind::PatternMatch { pattern } => write!(f, "Pattern match: {}", pattern),
            EvidenceKind::CrossReference { from } => write!(f, "Cross-reference from 0x{:X}", from),
            EvidenceKind::Heuristic { description } => write!(f, "Heuristic: {}", description),
            EvidenceKind::UserAnnotation => write!(f, "User annotation"),
            EvidenceKind::SymbolInfo => write!(f, "Symbol table / debug info"),
            EvidenceKind::CallingConvention => write!(f, "Calling convention match"),
            EvidenceKind::TypeUsagePattern => write!(f, "Type usage pattern"),
            EvidenceKind::FallthroughEdge => write!(f, "CFG edge: fallthrough"),
            EvidenceKind::ConditionalTrueEdge => write!(f, "CFG edge: conditional true"),
            EvidenceKind::ConditionalFalseEdge => {
                write!(f, "CFG edge: conditional false (fallthrough)")
            }
            EvidenceKind::UnconditionalJumpEdge => write!(f, "CFG edge: unconditional jump"),
            EvidenceKind::CallEdge => write!(f, "CFG edge: call"),
            EvidenceKind::ReturnEdge => write!(f, "CFG edge: return"),
            EvidenceKind::IndirectJumpEdge => write!(f, "CFG edge: indirect jump"),
            EvidenceKind::IndirectCallEdge => write!(f, "CFG edge: indirect call"),
            EvidenceKind::UnknownEdge => write!(f, "CFG edge: unknown control flow"),
            EvidenceKind::BlockTerminator { mnemonic } => {
                write!(f, "Block terminator: {}", mnemonic)
            }
            EvidenceKind::BranchTargetAddress { target } => {
                write!(f, "Branch target @ 0x{:X}", target)
            }
            EvidenceKind::ValidInstructionDecoded => write!(f, "Valid instruction decoded"),
            EvidenceKind::ReachableFromEntry => write!(f, "Reachable from entry point"),
            EvidenceKind::NegativeNonExecutableSection => {
                write!(f, "NEGATIVE: non-executable section")
            }
            EvidenceKind::NegativeInvalidInstructionBoundary => {
                write!(f, "NEGATIVE: invalid instruction boundary")
            }
            EvidenceKind::NegativeUnreachable => write!(f, "NEGATIVE: unreachable from entry"),
            EvidenceKind::NegativeDataAddress => write!(f, "NEGATIVE: identified as data address"),
            EvidenceKind::DataFlowAnalysis => write!(f, "Data flow analysis"),
            EvidenceKind::DominatorAnalysis => write!(f, "Dominator analysis"),
            EvidenceKind::SSAConstruction => write!(f, "SSA construction"),
            EvidenceKind::TypeInference => write!(f, "Type inference"),
            EvidenceKind::ExternalCallResolved { symbol } => {
                write!(f, "External call resolved: {}", symbol)
            }
            EvidenceKind::ValidFunctionBody => write!(f, "Valid function body"),
            EvidenceKind::InvalidFunctionBody { reason } => {
                write!(f, "Invalid function body: {}", reason)
            }
            EvidenceKind::TailCall => write!(f, "Tail call detected"),
            EvidenceKind::PdataEntry => write!(f, "Function in .pdata exception metadata"),
            EvidenceKind::JumpTablePattern => write!(f, "Jump table pattern detected"),
            EvidenceKind::JumpTableTarget => write!(f, "Jump table target resolved"),
            EvidenceKind::ThunkTarget => write!(f, "Function reached via thunk/JMP chain"),
        }
    }
}

/// A single piece of evidence supporting an analysis conclusion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: EvidenceKind,
    /// Address where this evidence was observed
    pub address: Option<u64>,
    /// Optional detail text
    pub detail: Option<String>,
    /// How much this single piece of evidence contributes (0.0 - 1.0)
    pub weight: f64,
}

impl Evidence {
    pub fn new(kind: EvidenceKind) -> Self {
        Evidence {
            kind,
            address: None,
            detail: None,
            weight: 0.5,
        }
    }

    pub fn with_address(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with_weight(mut self, weight: f64) -> Self {
        self.weight = weight.clamp(0.0, 1.0);
        self
    }
}

impl fmt::Display for Evidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "- {}", self.kind)?;
        if let Some(addr) = self.address {
            write!(f, " @ 0x{:X}", addr)?;
        }
        if let Some(detail) = &self.detail {
            write!(f, " ({})", detail)?;
        }
        write!(f, " [weight={:.2}]", self.weight)
    }
}

/// A list of evidence supporting an analysis conclusion.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvidenceList {
    pub items: Vec<Evidence>,
}

impl EvidenceList {
    pub fn new() -> Self {
        EvidenceList { items: Vec::new() }
    }

    pub fn push(&mut self, evidence: Evidence) {
        self.items.push(evidence);
    }

    pub fn add(&mut self, kind: EvidenceKind) {
        self.items.push(Evidence::new(kind));
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Compute aggregate confidence from weighted evidence.
    ///
    /// Algorithm:
    /// - Base = maximum single evidence weight (strongest piece of evidence)
    /// - Each additional evidence adds diminishing bonus: 0.1 * (1 - base) per extra piece
    /// - This ensures no single heuristic gives 100% confidence,
    ///   and multiple independent evidence sources increase confidence.
    pub fn confidence(&self) -> Confidence {
        if self.items.is_empty() {
            return Confidence::ZERO;
        }
        let max_weight = self.items.iter().map(|e| e.weight).fold(0.0f64, f64::max);
        let extra_count = (self.items.len() - 1) as f64;
        // Diminishing returns: each extra evidence adds 10% of remaining gap
        let bonus = 0.1 * extra_count * (1.0 - max_weight);
        Confidence::new(max_weight + bonus)
    }
}

impl fmt::Display for EvidenceList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for item in &self.items {
            writeln!(f, "{}", item)?;
        }
        Ok(())
    }
}

/// Wrapper that attaches evidence and confidence to any analysis result.
///
/// This enforces the FOX principle: no conclusion without evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithEvidence<T> {
    pub value: T,
    pub confidence: Confidence,
    pub evidence: EvidenceList,
}

impl<T> WithEvidence<T> {
    pub fn new(value: T) -> Self {
        WithEvidence {
            value,
            confidence: Confidence::ZERO,
            evidence: EvidenceList::new(),
        }
    }

    pub fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self.confidence = self.evidence.confidence();
        self
    }

    pub fn with_evidence_kind(mut self, kind: EvidenceKind) -> Self {
        self.evidence.add(kind);
        self.confidence = self.evidence.confidence();
        self
    }

    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> WithEvidence<U> {
        WithEvidence {
            value: f(self.value),
            confidence: self.confidence,
            evidence: self.evidence,
        }
    }
}

impl<T: fmt::Display> fmt::Display for WithEvidence<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.value)?;
        writeln!(f, "  Confidence: {}", self.confidence)?;
        writeln!(f, "  Evidence:")?;
        for item in &self.evidence.items {
            writeln!(f, "    {}", item)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_confidence_aggregation() {
        let mut ev = EvidenceList::new();
        assert_eq!(ev.confidence().0, 0.0);

        ev.add(EvidenceKind::FunctionPrologue);
        assert!(ev.confidence().0 > 0.0);

        ev.add(EvidenceKind::ValidReturn);
        ev.add(EvidenceKind::CallReference { count: 4 });
        assert!(ev.confidence().0 > 0.5);
    }

    #[test]
    fn test_with_evidence_chain() {
        let func = WithEvidence::new("sub_140001230")
            .with_evidence_kind(EvidenceKind::FunctionPrologue)
            .with_evidence_kind(EvidenceKind::ValidReturn)
            .with_evidence_kind(EvidenceKind::CallReference { count: 4 });

        assert_eq!(func.evidence.len(), 3);
        assert!(func.confidence.0 > 0.0);
    }

    #[test]
    fn test_confidence_clamping() {
        let c = Confidence::new(1.5);
        assert_eq!(c.0, 1.0);
        let c = Confidence::new(-0.5);
        assert_eq!(c.0, 0.0);
    }
}
