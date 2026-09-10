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
    /// Function address taken (loaded via LEA or stored in data)
    AddressTaken,
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
            EvidenceKind::AddressTaken => write!(f, "Function address taken (pointer reference)"),
        }
    }
}

// ============================================================================
// P0-5.5: Evidence Claim Layer
//
// Evidence is not Truth. Evidence supports a specific Claim.
// A Claim has a type (what is proven), a subject (what it applies to),
// and a strength (how strongly it supports the claim).
//
// This layer is a non-breaking extension: Evidence.claim is Option,
// existing evidence construction is unchanged, and confidence() is untouched.
// ============================================================================

/// The type of semantic claim an evidence supports.
///
/// This answers: "What does this evidence actually prove?"
/// An EvidenceKind may support zero, one, or multiple ClaimTypes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClaimType {
    /// This address is a function entry point.
    FunctionStart,
    /// The bytes at this location form a valid function body.
    FunctionBody,
    /// The function ends at this address.
    FunctionEnd,
    /// This address has a specific function identity (Canonical/Thunk/etc.).
    FunctionIdentity,
    /// This address is reachable from another location (e.g., entry point).
    Reachability,
    /// This address is an external identity (import thunk → DLL!symbol).
    ExternalIdentity,
    /// This address is NOT a function boundary (negative claim).
    NegativeBoundary,
    /// This address is part of an exception handling region.
    ExceptionRegion,
    /// The claim type is not yet determined / not applicable.
    Unknown,
}

impl fmt::Display for ClaimType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClaimType::FunctionStart => write!(f, "FunctionStart"),
            ClaimType::FunctionBody => write!(f, "FunctionBody"),
            ClaimType::FunctionEnd => write!(f, "FunctionEnd"),
            ClaimType::FunctionIdentity => write!(f, "FunctionIdentity"),
            ClaimType::Reachability => write!(f, "Reachability"),
            ClaimType::ExternalIdentity => write!(f, "ExternalIdentity"),
            ClaimType::NegativeBoundary => write!(f, "NegativeBoundary"),
            ClaimType::ExceptionRegion => write!(f, "ExceptionRegion"),
            ClaimType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// The subject a claim applies to.
///
/// Must be address-stable, not a free-form string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClaimSubject {
    /// A raw address in the binary.
    Address(u64),
    /// A function identified by its start address.
    Function(u64),
    /// A thunk (internal or import) identified by its address.
    Thunk(u64),
    /// Subject not determined.
    Unknown,
}

impl fmt::Display for ClaimSubject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClaimSubject::Address(a) => write!(f, "Address(0x{:X})", a),
            ClaimSubject::Function(a) => write!(f, "Function(0x{:X})", a),
            ClaimSubject::Thunk(a) => write!(f, "Thunk(0x{:X})", a),
            ClaimSubject::Unknown => write!(f, "Unknown"),
        }
    }
}

/// The strength of a claim.
///
/// This is independent of Evidence.weight. Strength describes the
/// semantic role of the evidence relative to its claim, not a numeric score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClaimStrength {
    /// Authoritative: independently proves the claim (e.g., PE header, .pdata).
    Strong,
    /// Supports the claim but does not independently prove it (e.g., CALL target).
    Supporting,
    /// Provides context but is weak evidence for the claim (e.g., prologue pattern).
    Contextual,
    /// Refutes the claim (negative evidence).
    Negative,
    /// Strength not determined.
    Unknown,
}

impl fmt::Display for ClaimStrength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClaimStrength::Strong => write!(f, "Strong"),
            ClaimStrength::Supporting => write!(f, "Supporting"),
            ClaimStrength::Contextual => write!(f, "Contextual"),
            ClaimStrength::Negative => write!(f, "Negative"),
            ClaimStrength::Unknown => write!(f, "Unknown"),
        }
    }
}

/// A semantic claim supported by one or more pieces of evidence.
///
/// Every claim is traceable back to its source evidence via `source_evidence`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceClaim {
    /// What this claim asserts.
    pub claim_type: ClaimType,
    /// What the claim applies to.
    pub subject: ClaimSubject,
    /// How strongly the source evidence supports this claim.
    pub strength: ClaimStrength,
    /// The EvidenceKind that produced this claim (for traceability).
    pub source_evidence: EvidenceKind,
}

impl fmt::Display for EvidenceClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Claim({} @ {} [{}] from {})",
            self.claim_type, self.subject, self.strength, self.source_evidence
        )
    }
}

impl EvidenceClaim {
    pub fn new(
        claim_type: ClaimType,
        subject: ClaimSubject,
        strength: ClaimStrength,
        source_evidence: EvidenceKind,
    ) -> Self {
        EvidenceClaim {
            claim_type,
            subject,
            strength,
            source_evidence,
        }
    }
}

/// Default claim mapping for each EvidenceKind.
///
/// This is the canonical mapping derived from P0-5.4 Architecture Audit
/// and P0-5.3A Validation. It is intentionally conservative:
/// - ValidFunctionBody → FunctionBody (NOT FunctionStart)
/// - ReachableFromEntry → Reachability (NOT FunctionStart)
/// - AddressTaken → no auto-mapping (per P0-5.3A, may be BB label)
/// - Negative evidence → NegativeBoundary
///
/// `subject_addr` is the address the evidence was observed at, if known.
impl EvidenceKind {
    pub fn default_claims(&self, subject_addr: Option<u64>) -> Vec<EvidenceClaim> {
        let sub = match subject_addr {
            Some(a) => ClaimSubject::Address(a),
            None => ClaimSubject::Unknown,
        };
        match self {
            // --- Strong FunctionStart evidence ---
            EvidenceKind::EntryPoint => vec![EvidenceClaim::new(
                ClaimType::FunctionStart,
                sub,
                ClaimStrength::Strong,
                self.clone(),
            )],
            EvidenceKind::ExportEntry => vec![EvidenceClaim::new(
                ClaimType::FunctionStart,
                sub,
                ClaimStrength::Strong,
                self.clone(),
            )],
            EvidenceKind::PdataEntry => vec![
                EvidenceClaim::new(
                    ClaimType::FunctionStart,
                    sub,
                    ClaimStrength::Strong,
                    self.clone(),
                ),
                EvidenceClaim::new(
                    ClaimType::FunctionEnd,
                    sub,
                    ClaimStrength::Strong,
                    self.clone(),
                ),
            ],

            // --- Supporting FunctionStart evidence ---
            EvidenceKind::CallReference { .. } => vec![EvidenceClaim::new(
                ClaimType::FunctionStart,
                sub,
                ClaimStrength::Supporting,
                self.clone(),
            )],
            EvidenceKind::ThunkTarget => vec![
                EvidenceClaim::new(
                    ClaimType::FunctionStart,
                    sub,
                    ClaimStrength::Supporting,
                    self.clone(),
                ),
                EvidenceClaim::new(
                    ClaimType::FunctionIdentity,
                    sub,
                    ClaimStrength::Supporting,
                    self.clone(),
                ),
            ],

            // --- FunctionBody evidence (NOT FunctionStart) ---
            EvidenceKind::ValidFunctionBody => vec![EvidenceClaim::new(
                ClaimType::FunctionBody,
                sub,
                ClaimStrength::Supporting,
                self.clone(),
            )],
            EvidenceKind::ValidInstructionDecoded => vec![EvidenceClaim::new(
                ClaimType::FunctionBody,
                sub,
                ClaimStrength::Contextual,
                self.clone(),
            )],
            EvidenceKind::ValidReturn => vec![EvidenceClaim::new(
                ClaimType::FunctionEnd,
                sub,
                ClaimStrength::Contextual,
                self.clone(),
            )],
            EvidenceKind::FunctionEpilogue => vec![EvidenceClaim::new(
                ClaimType::FunctionEnd,
                sub,
                ClaimStrength::Contextual,
                self.clone(),
            )],

            // --- Contextual evidence ---
            EvidenceKind::FunctionPrologue => vec![EvidenceClaim::new(
                ClaimType::FunctionStart,
                sub,
                ClaimStrength::Contextual,
                self.clone(),
            )],
            EvidenceKind::StackFramePattern => vec![EvidenceClaim::new(
                ClaimType::FunctionBody,
                sub,
                ClaimStrength::Contextual,
                self.clone(),
            )],
            EvidenceKind::TailCall => vec![EvidenceClaim::new(
                ClaimType::FunctionEnd,
                sub,
                ClaimStrength::Contextual,
                self.clone(),
            )],

            // --- Reachability (NOT FunctionStart) ---
            EvidenceKind::ReachableFromEntry => vec![EvidenceClaim::new(
                ClaimType::Reachability,
                sub,
                ClaimStrength::Supporting,
                self.clone(),
            )],

            // --- External Identity ---
            EvidenceKind::ExternalCallResolved { .. } => vec![EvidenceClaim::new(
                ClaimType::ExternalIdentity,
                sub,
                ClaimStrength::Strong,
                self.clone(),
            )],
            EvidenceKind::ImportEntry => vec![EvidenceClaim::new(
                ClaimType::ExternalIdentity,
                sub,
                ClaimStrength::Strong,
                self.clone(),
            )],

            // --- Identity ---
            EvidenceKind::AddressTaken => {
                // Per P0-5.3A: AddressTaken may point to BB label, jump table,
                // or function entry. Must NOT auto-map to FunctionStart.
                // No default claim — requires additional context.
                vec![]
            }

            // --- Negative evidence ---
            EvidenceKind::NegativeNonExecutableSection
            | EvidenceKind::NegativeInvalidInstructionBoundary
            | EvidenceKind::NegativeUnreachable
            | EvidenceKind::NegativeDataAddress
            | EvidenceKind::InvalidFunctionBody { .. } => vec![EvidenceClaim::new(
                ClaimType::NegativeBoundary,
                sub,
                ClaimStrength::Negative,
                self.clone(),
            )],

            // --- CFG / control flow evidence (no function-boundary claim) ---
            EvidenceKind::BranchTarget
            | EvidenceKind::BranchTargetAddress { .. }
            | EvidenceKind::ControlFlowTransfer
            | EvidenceKind::FallthroughEdge
            | EvidenceKind::ConditionalTrueEdge
            | EvidenceKind::ConditionalFalseEdge
            | EvidenceKind::UnconditionalJumpEdge
            | EvidenceKind::CallEdge
            | EvidenceKind::ReturnEdge
            | EvidenceKind::IndirectJumpEdge
            | EvidenceKind::IndirectCallEdge
            | EvidenceKind::UnknownEdge
            | EvidenceKind::BlockTerminator { .. }
            | EvidenceKind::JumpTablePattern
            | EvidenceKind::JumpTableTarget => {
                // These are CFG-level claims, not function boundary claims.
                // No default function-boundary claim.
                vec![]
            }

            // --- Analysis / other evidence (no default claim) ---
            EvidenceKind::CalledApi { .. }
            | EvidenceKind::RelocationEntry
            | EvidenceKind::StringReference { .. }
            | EvidenceKind::ExecutableSection
            | EvidenceKind::PatternMatch { .. }
            | EvidenceKind::CrossReference { .. }
            | EvidenceKind::Heuristic { .. }
            | EvidenceKind::UserAnnotation
            | EvidenceKind::SymbolInfo
            | EvidenceKind::CallingConvention
            | EvidenceKind::TypeUsagePattern
            | EvidenceKind::DataFlowAnalysis
            | EvidenceKind::DominatorAnalysis
            | EvidenceKind::SSAConstruction
            | EvidenceKind::TypeInference => {
                // These require context-specific claim assignment.
                // No default function-boundary claim.
                vec![]
            }
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
    /// P0-5.5: Explicit semantic claim. If None, claims are derived
    /// from EvidenceKind::default_claims() at query time.
    #[serde(default)]
    pub claim: Option<EvidenceClaim>,
}

impl Evidence {
    pub fn new(kind: EvidenceKind) -> Self {
        Evidence {
            kind,
            address: None,
            detail: None,
            weight: 0.5,
            claim: None,
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

    /// Set an explicit semantic claim on this evidence.
    /// If not set, claims are derived from EvidenceKind::default_claims().
    pub fn with_claim(mut self, claim: EvidenceClaim) -> Self {
        self.claim = Some(claim);
        self
    }

    /// Get the claims this evidence supports.
    ///
    /// Priority: explicit `claim` field > default_claims() derivation.
    /// One evidence may produce multiple claims (e.g., PdataEntry → Start + End).
    pub fn claims(&self) -> Vec<EvidenceClaim> {
        if let Some(c) = &self.claim {
            vec![c.clone()]
        } else {
            self.kind.default_claims(self.address)
        }
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
        write!(f, " [weight={:.2}]", self.weight)?;
        if let Some(claim) = &self.claim {
            write!(f, " claim={}", claim)?;
        }
        Ok(())
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

    /// P0-5.5: Collect all semantic claims from all evidence in this list.
    ///
    /// Multiple evidence items may produce the same claim type; this method
    /// returns all claims (deduplicated by claim_type + subject).
    /// Does NOT modify confidence or weights.
    pub fn claims(&self) -> Vec<EvidenceClaim> {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        for ev in &self.items {
            for claim in ev.claims() {
                let key = (claim.claim_type, claim.subject);
                if seen.insert(key) {
                    result.push(claim);
                }
            }
        }
        result
    }

    /// Get claims filtered by a specific ClaimType.
    pub fn claims_of_type(&self, claim_type: ClaimType) -> Vec<EvidenceClaim> {
        self.claims()
            .into_iter()
            .filter(|c| c.claim_type == claim_type)
            .collect()
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

    // ========================================================================
    // P0-5.5 Claim Layer tests
    // ========================================================================

    #[test]
    fn test_claim_type_display() {
        assert_eq!(format!("{}", ClaimType::FunctionStart), "FunctionStart");
        assert_eq!(format!("{}", ClaimType::FunctionBody), "FunctionBody");
        assert_eq!(format!("{}", ClaimType::Reachability), "Reachability");
    }

    #[test]
    fn test_claim_subject_display() {
        assert_eq!(
            format!("{}", ClaimSubject::Address(0x401000)),
            "Address(0x401000)"
        );
        assert_eq!(
            format!("{}", ClaimSubject::Function(0x401000)),
            "Function(0x401000)"
        );
    }

    #[test]
    fn test_valid_function_body_maps_to_body_not_start() {
        // Critical: ValidFunctionBody must NOT produce FunctionStart claim
        let ev = Evidence::new(EvidenceKind::ValidFunctionBody).with_address(0x401000);
        let claims = ev.claims();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].claim_type, ClaimType::FunctionBody);
        assert_eq!(claims[0].strength, ClaimStrength::Supporting);
        // Must NOT be FunctionStart
        assert!(!claims
            .iter()
            .any(|c| c.claim_type == ClaimType::FunctionStart));
    }

    #[test]
    fn test_call_reference_maps_to_function_start() {
        let ev = Evidence::new(EvidenceKind::CallReference { count: 3 })
            .with_address(0x401000)
            .with_weight(0.7);
        let claims = ev.claims();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].claim_type, ClaimType::FunctionStart);
        assert_eq!(claims[0].strength, ClaimStrength::Supporting);
    }

    #[test]
    fn test_entry_point_maps_to_strong_function_start() {
        let ev = Evidence::new(EvidenceKind::EntryPoint)
            .with_address(0x455E4C)
            .with_weight(0.95);
        let claims = ev.claims();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].claim_type, ClaimType::FunctionStart);
        assert_eq!(claims[0].strength, ClaimStrength::Strong);
    }

    #[test]
    fn test_pdata_maps_to_start_and_end() {
        let ev = Evidence::new(EvidenceKind::PdataEntry)
            .with_address(0x140001000)
            .with_weight(0.85);
        let claims = ev.claims();
        assert_eq!(claims.len(), 2);
        assert!(claims
            .iter()
            .any(|c| c.claim_type == ClaimType::FunctionStart));
        assert!(claims
            .iter()
            .any(|c| c.claim_type == ClaimType::FunctionEnd));
        assert!(claims.iter().all(|c| c.strength == ClaimStrength::Strong));
    }

    #[test]
    fn test_reachable_from_entry_maps_to_reachability_not_start() {
        // Critical: ReachableFromEntry must NOT produce FunctionStart
        let ev = Evidence::new(EvidenceKind::ReachableFromEntry).with_address(0x401000);
        let claims = ev.claims();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].claim_type, ClaimType::Reachability);
        assert!(!claims
            .iter()
            .any(|c| c.claim_type == ClaimType::FunctionStart));
    }

    #[test]
    fn test_address_taken_has_no_default_claim() {
        // Per P0-5.3A: AddressTaken may be BB label, must NOT auto-map to FunctionStart
        let ev = Evidence::new(EvidenceKind::AddressTaken).with_address(0x401000);
        let claims = ev.claims();
        assert!(
            claims.is_empty(),
            "AddressTaken must not auto-map to any claim"
        );
    }

    #[test]
    fn test_import_thunk_maps_to_external_identity() {
        let ev = Evidence::new(EvidenceKind::ExternalCallResolved {
            symbol: "MSVCRT.dll!printf".to_string(),
        })
        .with_address(0x455E40);
        let claims = ev.claims();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].claim_type, ClaimType::ExternalIdentity);
        assert_eq!(claims[0].strength, ClaimStrength::Strong);
    }

    #[test]
    fn test_negative_evidence_maps_to_negative_boundary() {
        let ev = Evidence::new(EvidenceKind::NegativeNonExecutableSection).with_address(0x402000);
        let claims = ev.claims();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].claim_type, ClaimType::NegativeBoundary);
        assert_eq!(claims[0].strength, ClaimStrength::Negative);
    }

    #[test]
    fn test_explicit_claim_overrides_default() {
        let explicit = EvidenceClaim::new(
            ClaimType::FunctionStart,
            ClaimSubject::Address(0x401000),
            ClaimStrength::Strong,
            EvidenceKind::EntryPoint,
        );
        let ev = Evidence::new(EvidenceKind::ValidFunctionBody)
            .with_address(0x401000)
            .with_claim(explicit.clone());
        let claims = ev.claims();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0], explicit);
        // Explicit claim overrides default (which would be FunctionBody)
        assert_eq!(claims[0].claim_type, ClaimType::FunctionStart);
    }

    #[test]
    fn test_evidence_list_claims_dedup() {
        let mut list = EvidenceList::new();
        list.push(
            Evidence::new(EvidenceKind::CallReference { count: 3 })
                .with_address(0x401000)
                .with_weight(0.7),
        );
        list.push(
            Evidence::new(EvidenceKind::FunctionPrologue)
                .with_address(0x401000)
                .with_weight(0.4),
        );
        // Both produce FunctionStart @ 0x401000 — should dedup to one
        let start_claims = list.claims_of_type(ClaimType::FunctionStart);
        assert_eq!(start_claims.len(), 1);
    }

    #[test]
    fn test_evidence_list_claims_multiple_types() {
        let mut list = EvidenceList::new();
        list.push(
            Evidence::new(EvidenceKind::CallReference { count: 3 })
                .with_address(0x401000)
                .with_weight(0.7),
        );
        list.push(
            Evidence::new(EvidenceKind::ValidFunctionBody)
                .with_address(0x401000)
                .with_weight(0.6),
        );
        list.push(
            Evidence::new(EvidenceKind::ValidReturn)
                .with_address(0x401100)
                .with_weight(0.3),
        );
        let all_claims = list.claims();
        assert!(all_claims.len() >= 3); // Start + Body + End
        assert!(all_claims
            .iter()
            .any(|c| c.claim_type == ClaimType::FunctionStart));
        assert!(all_claims
            .iter()
            .any(|c| c.claim_type == ClaimType::FunctionBody));
        assert!(all_claims
            .iter()
            .any(|c| c.claim_type == ClaimType::FunctionEnd));
    }

    #[test]
    fn test_claim_does_not_change_confidence() {
        // Adding claims must NOT change the confidence formula
        let mut list = EvidenceList::new();
        list.push(
            Evidence::new(EvidenceKind::CallReference { count: 3 })
                .with_address(0x401000)
                .with_weight(0.7),
        );
        let conf_before = list.confidence();
        let _claims = list.claims(); // calling claims() must not mutate
        let conf_after = list.confidence();
        assert_eq!(conf_before.0, conf_after.0);
    }

    #[test]
    fn test_claim_traceability_to_source_evidence() {
        let ev = Evidence::new(EvidenceKind::ValidFunctionBody).with_address(0x401000);
        let claims = ev.claims();
        assert_eq!(claims.len(), 1);
        // Claim must trace back to source evidence kind
        assert_eq!(claims[0].source_evidence, EvidenceKind::ValidFunctionBody);
        assert_eq!(claims[0].subject, ClaimSubject::Address(0x401000));
    }

    #[test]
    fn test_cfg_evidence_has_no_function_boundary_claim() {
        // CFG edges should NOT produce function boundary claims
        let ev = Evidence::new(EvidenceKind::BranchTarget).with_address(0x401050);
        assert!(ev.claims().is_empty());

        let ev = Evidence::new(EvidenceKind::FallthroughEdge).with_address(0x401050);
        assert!(ev.claims().is_empty());

        let ev = Evidence::new(EvidenceKind::JumpTableTarget).with_address(0x401050);
        assert!(ev.claims().is_empty());
    }

    #[test]
    fn test_evidence_without_claim_field_is_backward_compatible() {
        // Evidence constructed the old way (without claim) still works
        let ev = Evidence::new(EvidenceKind::EntryPoint);
        assert!(ev.claim.is_none());
        // But claims() still derives from default_claims
        assert_eq!(ev.claims().len(), 1);
        assert_eq!(ev.claims()[0].claim_type, ClaimType::FunctionStart);
    }

    #[test]
    fn test_claim_strength_display() {
        assert_eq!(format!("{}", ClaimStrength::Strong), "Strong");
        assert_eq!(format!("{}", ClaimStrength::Supporting), "Supporting");
        assert_eq!(format!("{}", ClaimStrength::Negative), "Negative");
    }
}
