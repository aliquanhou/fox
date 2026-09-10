//! FOX Analysis Framework
//!
//! P0-1 capabilities:
//! - Function Discovery (recursive descent + Negative Evidence + Confidence tiers)
//! - Basic Block Engine (real segmentation via recursive descent)
//! - CFG (typed edges with evidence)
//! - Call Graph (Direct/Indirect/External/Unknown)
//!
//! All analysis results MUST carry evidence.

pub mod basic_block;
pub mod callgraph;
pub mod cfg;
pub mod dataflow;
pub mod dominators;
pub mod golden;
pub mod jump_table;
pub mod memory_ssa;
pub mod pipeline;
pub mod ssa;
pub mod symbol;
pub mod type_recovery;
pub mod value_flow;

use fox_binary::Binary;
use fox_core::{
    adjudicate_reality, Address, BodyReality, BoundaryReality, ClaimStrength, ClaimType,
    Confidence, Evidence, EvidenceClaim, EvidenceKind, FoxError, FoxResult, FunctionRange,
    FunctionReality, IdentityReality, RealityStatus, WithEvidence,
};
use fox_disasm::create_disassembler;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Function confidence tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FunctionConfidence {
    /// Confirmed by multiple strong evidence sources (entry point, export, + reachable + validated body)
    Confirmed,
    /// High confidence (export or multiple call references + valid prologue + validated body)
    High,
    /// Probable (single call reference or prologue match, body validated)
    Probable,
    /// Unknown / low confidence (weak single evidence)
    Unknown,
    /// Rejected: failed validation (invalid body, no RET, overlaps, etc.)
    Rejected,
}

impl FunctionConfidence {
    pub fn from_confidence(c: Confidence) -> Self {
        if c.0 >= 0.85 {
            FunctionConfidence::Confirmed
        } else if c.0 >= 0.65 {
            FunctionConfidence::High
        } else if c.0 >= 0.4 {
            FunctionConfidence::Probable
        } else if c.0 >= 0.15 {
            FunctionConfidence::Unknown
        } else {
            FunctionConfidence::Rejected
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            FunctionConfidence::Confirmed => "Confirmed",
            FunctionConfidence::High => "High",
            FunctionConfidence::Probable => "Probable",
            FunctionConfidence::Unknown => "Unknown",
            FunctionConfidence::Rejected => "Rejected",
        }
    }
}

impl std::fmt::Display for FunctionConfidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Function body validation result (P0-3.1).
///
/// Validates that a candidate function address actually contains a valid
/// function body: valid instructions, terminates with RET/tail-call,
/// doesn't overlap other functions, etc.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FunctionValidation {
    /// Whether validation was attempted
    pub validated: bool,
    /// First instruction decoded successfully
    pub valid_entry: bool,
    /// Function body contains at least one RET instruction
    pub has_return: bool,
    /// Function body contains a tail-call JMP to another function
    pub has_tail_call: bool,
    /// Number of instructions in the function body (linear sweep estimate)
    pub instruction_count: usize,
    /// Estimated end address (last instruction end)
    pub estimated_end: Option<u64>,
    /// Validation failure reason (if any)
    pub failure_reason: Option<String>,
    /// How the function body terminates
    pub termination_kind: TerminationKind,
}

/// How a function body terminates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TerminationKind {
    /// Function ends with RET
    Return,
    /// Function ends with direct JMP to another function
    TailCallDirect,
    /// Function ends with indirect JMP (IAT, register, memory)
    TailCallIndirect,
    /// Linear sweep stopped at next function boundary before finding terminator
    #[default]
    BoundaryStop,
    /// No valid terminator found (potential false positive)
    NoTerminator,
    /// Empty function body
    Empty,
}

/// A discovered function with full evidence chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Function {
    pub name: String,
    pub address: Address,
    pub end_address: Option<Address>,
    pub size: Option<usize>,
    pub basic_blocks: Vec<basic_block::BasicBlock>,
    pub calls: Vec<u64>,
    pub called_by: Vec<u64>,
    pub confidence_tier: FunctionConfidence,
    /// P0-3.1: Function body validation result
    pub validation: FunctionValidation,
    /// P0-5.6B: Multi-dimensional function reality (optional, non-breaking).
    /// When None, consumers should fall back to confidence_tier.
    #[serde(default)]
    pub reality: Option<FunctionReality>,
}

impl Function {
    pub fn new(name: String, address: Address) -> Self {
        Function {
            name,
            address,
            end_address: None,
            size: None,
            basic_blocks: Vec::new(),
            calls: Vec::new(),
            called_by: Vec::new(),
            confidence_tier: FunctionConfidence::Unknown,
            validation: FunctionValidation::default(),
            reality: None,
        }
    }
}

impl std::fmt::Display for Function {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Function: {} @ {} [{}]",
            self.name, self.address, self.confidence_tier
        )?;
        if let Some(end) = self.end_address {
            write!(f, " - {}", end)?;
        }
        if let Some(size) = self.size {
            write!(f, " ({} bytes)", size)?;
        }
        if !self.calls.is_empty() {
            write!(f, " [{} calls]", self.calls.len())?;
        }
        Ok(())
    }
}

/// Function discovery engine with recursive descent and negative evidence.
pub struct FunctionDiscovery;

impl FunctionDiscovery {
    /// Discover functions in a binary.
    ///
    /// Strategy (P0-1 refined):
    /// 1. Seed functions: entry point + exports
    /// 2. Recursive descent from seeds: disassemble, follow CALL targets
    /// 3. Prologue pattern matching (as supplementary, lower weight)
    /// 4. Apply Negative Evidence to reduce false positives
    /// 5. Assign confidence tiers
    ///
    /// Every discovered function carries evidence.
    pub fn discover(binary: &Binary) -> Vec<WithEvidence<Function>> {
        let disasm = match create_disassembler(binary.architecture) {
            Ok(d) => d,
            Err(_) => return Vec::new(),
        };

        let mut functions: BTreeMap<u64, WithEvidence<Function>> = BTreeMap::new();
        let mut call_target_counts: BTreeMap<u64, usize> = BTreeMap::new();

        // Phase 1: Seed from entry point and exports (high confidence)
        Self::seed_functions(binary, &mut functions);

        // Phase 1.5: .pdata exception metadata (x64 authoritative function boundaries)
        // This is the highest-confidence source for x64: every function has a
        // RUNTIME_FUNCTION entry used by Windows exception handling.
        Self::discover_from_pdata(binary, &mut functions);

        // Phase 2: Scan all executable sections for CALL targets
        Self::scan_call_targets(binary, disasm.as_ref(), &mut call_target_counts);

        // Phase 3: Add call targets as functions
        for (target, count) in &call_target_counts {
            if !functions.contains_key(target) {
                // Validate: target must be in an executable section
                if Self::is_in_executable_section(binary, *target) {
                    let func = Function::new(format!("sub_{:016X}", target), Address(*target));
                    functions.insert(
                        *target,
                        WithEvidence::new(func).with_evidence(
                            Evidence::new(EvidenceKind::CallReference { count: *count })
                                .with_address(*target)
                                .with_weight(if *count >= 3 { 0.7 } else { 0.5 }),
                        ),
                    );
                }
            } else if let Some(entry) = functions.get_mut(target) {
                entry.evidence.push(
                    Evidence::new(EvidenceKind::CallReference { count: *count }).with_weight(0.3),
                );
                entry.confidence = entry.evidence.confidence();
            }
        }

        // Phase 3.5: Address-Taken Function Discovery
        // Scan for LEA reg, [rip+disp] where effective address is executable.
        // These are function pointer candidates (e.g., function pointer tables).
        Self::discover_address_taken_functions(binary, disasm.as_ref(), &mut functions);

        // Phase 4: Prologue pattern matching (supplementary, lower weight)
        Self::scan_prologues(binary, &mut functions);

        // Phase 4.2: Orphan leaf function detection (int3 padding + RET)
        // Catches tiny leaf functions that have no pdata and no CALL references.
        Self::discover_orphan_leaf_functions(binary, disasm.as_ref(), &mut functions);

        // Phase 4.3: Thunk following (MSVC O2 jump islands)
        // If a discovered function is just an unconditional JMP, follow it
        // to find the real function body.
        Self::follow_thunks(binary, disasm.as_ref(), &mut functions);

        // Phase 4.5: Validate function bodies (P0-3.1)
        Self::validate_function_bodies(binary, disasm.as_ref(), &mut functions);

        // Phase 5: Apply Negative Evidence
        Self::apply_negative_evidence(binary, disasm.as_ref(), &mut functions);

        // Phase 6: Assign confidence tiers and sort
        let mut result: Vec<WithEvidence<Function>> = functions.into_values().collect();
        for entry in &mut result {
            entry.value.confidence_tier = FunctionConfidence::from_confidence(entry.confidence);
        }

        // Phase 7: Build Function Reality (P0-5.6B)
        // Multi-dimensional reality: Start / Body / End / Identity.
        // Does NOT modify confidence_tier or discovery algorithm.
        for entry in &mut result {
            entry.value.reality = Some(Self::build_function_reality(entry));
        }

        result.sort_by(|a, b| {
            b.confidence
                .0
                .partial_cmp(&a.confidence.0)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        result
    }

    /// P0-5.6B: Build multi-dimensional Function Reality from existing Evidence + Claims.
    ///
    /// This does NOT modify discovery, confidence, or weights.
    /// It only constructs a Reality view from the evidence already collected.
    ///
    /// Flow: Evidence → Claims → Aggregation → Adjudication → RealityStatus
    fn build_function_reality(entry: &WithEvidence<Function>) -> FunctionReality {
        let claims = entry.evidence.claims();
        let addr = entry.value.address.0;

        // --- Start Reality ---
        let start_positive: Vec<EvidenceClaim> = claims
            .iter()
            .filter(|c| {
                c.claim_type == ClaimType::FunctionStart && c.strength != ClaimStrength::Negative
            })
            .cloned()
            .collect();
        let start_negative: Vec<EvidenceClaim> = claims
            .iter()
            .filter(|c| {
                c.claim_type == ClaimType::FunctionStart && c.strength == ClaimStrength::Negative
            })
            .cloned()
            .collect();
        let (start_status, start_contradictions) =
            adjudicate_reality(&start_positive, &start_negative);
        let start = BoundaryReality {
            address: Some(addr),
            status: start_status,
            confidence: entry.confidence,
            positive_claims: start_positive,
            negative_claims: start_negative,
            contradictions: start_contradictions,
        };

        // --- Body Reality ---
        let body_positive: Vec<EvidenceClaim> = claims
            .iter()
            .filter(|c| {
                c.claim_type == ClaimType::FunctionBody && c.strength != ClaimStrength::Negative
            })
            .cloned()
            .collect();
        let body_negative: Vec<EvidenceClaim> = claims
            .iter()
            .filter(|c| {
                c.claim_type == ClaimType::FunctionBody && c.strength == ClaimStrength::Negative
            })
            .cloned()
            .collect();
        let (body_status, body_contradictions) = adjudicate_reality(&body_positive, &body_negative);
        let body = BodyReality {
            instruction_count: entry.value.validation.instruction_count,
            basic_block_count: entry.value.basic_blocks.len(),
            termination_kind: format!("{:?}", entry.value.validation.termination_kind),
            status: body_status,
            confidence: entry.confidence,
            positive_claims: body_positive,
            negative_claims: body_negative,
            contradictions: body_contradictions,
        };

        // --- End Reality ---
        let end_positive: Vec<EvidenceClaim> = claims
            .iter()
            .filter(|c| {
                c.claim_type == ClaimType::FunctionEnd && c.strength != ClaimStrength::Negative
            })
            .cloned()
            .collect();
        let end_negative: Vec<EvidenceClaim> = claims
            .iter()
            .filter(|c| {
                c.claim_type == ClaimType::FunctionEnd && c.strength == ClaimStrength::Negative
            })
            .cloned()
            .collect();
        let (end_status, end_contradictions) = adjudicate_reality(&end_positive, &end_negative);

        // End address: prefer precise claim subject, then validation.estimated_end,
        // then fall back to end_address (from .pdata).
        // Observed End ≠ Estimated End ≠ Confirmed End — estimated_end is marked
        // as Contextual/Probable, not Confirmed.
        let end_addr = end_positive
            .iter()
            .find_map(|c| match c.subject {
                fox_core::ClaimSubject::Address(a) => Some(a),
                _ => None,
            })
            .or_else(|| entry.value.validation.estimated_end)
            .or_else(|| entry.value.end_address.map(|a| a.0));

        let end = BoundaryReality {
            address: end_addr,
            status: end_status,
            confidence: entry.confidence,
            positive_claims: end_positive,
            negative_claims: end_negative,
            contradictions: end_contradictions,
        };

        // --- Identity Reality (from existing identity info) ---
        // Identity is read from FunctionIdentityTable by the caller; here we
        // set a placeholder that will be enriched after identity table build.
        let identity = IdentityReality {
            kind: "Unknown".to_string(),
            confidence: Confidence::ZERO,
            claims: claims
                .iter()
                .filter(|c| {
                    c.claim_type == ClaimType::FunctionIdentity
                        || c.claim_type == ClaimType::ExternalIdentity
                })
                .cloned()
                .collect(),
        };

        // --- Range: only when both Start and End have acceptable reality ---
        // Freeze 5: NEVER fabricate range when End is Unknown.
        let range = if start_status != RealityStatus::Rejected
            && start_status != RealityStatus::Unknown
            && end_status != RealityStatus::Rejected
            && end_status != RealityStatus::Unknown
        {
            end_addr.map(|ea| FunctionRange {
                start: addr,
                end_exclusive: ea,
            })
        } else {
            None
        };

        FunctionReality {
            start,
            body,
            end,
            identity,
            range,
        }
    }

    /// Seed functions from entry point and exports.
    fn seed_functions(binary: &Binary, functions: &mut BTreeMap<u64, WithEvidence<Function>>) {
        // Entry point
        functions.insert(
            binary.entry_point,
            WithEvidence::new(Function::new(
                format!("entry_{:016X}", binary.entry_point),
                Address(binary.entry_point),
            ))
            .with_evidence(
                Evidence::new(EvidenceKind::EntryPoint)
                    .with_address(binary.entry_point)
                    .with_weight(0.95),
            ),
        );

        // Exports
        for export in &binary.exports {
            let addr = binary.image_base + export.address;
            if !Self::is_in_executable_section(binary, addr) {
                continue; // skip forwarded exports pointing outside .text
            }
            let name = export
                .name
                .clone()
                .unwrap_or_else(|| format!("export_{}", export.ordinal));
            let func = Function::new(name, Address(addr));
            let entry = functions
                .entry(addr)
                .or_insert_with(|| WithEvidence::new(func));
            entry.evidence.push(
                Evidence::new(EvidenceKind::ExportEntry)
                    .with_address(addr)
                    .with_weight(0.9),
            );
            entry.confidence = entry.evidence.confidence();
        }
    }

    /// Discover functions from .pdata exception metadata (x64 only).
    ///
    /// .pdata contains RUNTIME_FUNCTION entries for EVERY function in the binary,
    /// including leaf functions and optimized functions. This is authoritative
    /// metadata used by Windows exception handling, not a heuristic.
    ///
    /// Evidence weight: 0.85 (high 鈥?authoritative metadata, but pdata can include
    /// data labels in rare cases, so not 1.0).
    fn discover_from_pdata(binary: &Binary, functions: &mut BTreeMap<u64, WithEvidence<Function>>) {
        if binary.architecture != fox_arch::Architecture::X64 {
            return; // .pdata is x64-specific
        }

        for rf in binary.exception_functions() {
            if !Self::is_in_executable_section(binary, rf.begin_va) {
                continue;
            }

            if let Some(entry) = functions.get_mut(&rf.begin_va) {
                // Already discovered — add pdata as corroborating evidence
                entry.evidence.push(
                    Evidence::new(EvidenceKind::PdataEntry)
                        .with_address(rf.begin_va)
                        .with_end_address(rf.end_va)
                        .with_detail(format!(".pdata: [0x{:X}, 0x{:X})", rf.begin_va, rf.end_va))
                        .with_weight(0.4),
                );
                entry.confidence = entry.evidence.confidence();
                // Update end_address from authoritative pdata
                if entry.value.end_address.is_none() {
                    entry.value.end_address = Some(Address(rf.end_va));
                }
            } else {
                let mut func =
                    Function::new(format!("sub_{:016X}", rf.begin_va), Address(rf.begin_va));
                func.end_address = Some(Address(rf.end_va));
                functions.insert(
                    rf.begin_va,
                    WithEvidence::new(func).with_evidence(
                        Evidence::new(EvidenceKind::PdataEntry)
                            .with_address(rf.begin_va)
                            .with_end_address(rf.end_va)
                            .with_detail(format!(
                                ".pdata: [0x{:X}, 0x{:X})",
                                rf.begin_va, rf.end_va
                            ))
                            .with_weight(0.85),
                    ),
                );
            }
        }
    }

    /// Scan executable sections for CALL targets.
    fn scan_call_targets(
        binary: &Binary,
        disasm: &dyn fox_disasm::Disassembler,
        call_target_counts: &mut BTreeMap<u64, usize>,
    ) {
        for section in binary.executable_sections() {
            let data = &binary.raw_data[section.raw_offset..section.raw_offset + section.raw_size];
            let base_addr = binary.image_base + section.virtual_address;

            if let Ok(instructions) = disasm.disassemble(data, base_addr) {
                for inst in &instructions {
                    if inst.is_call {
                        if let Some(target) = inst.call_target {
                            *call_target_counts.entry(target).or_insert(0) += 1;
                        }
                    }
                }
            }
        }
    }

    /// Scan for function prologue patterns (supplementary).
    fn scan_prologues(binary: &Binary, functions: &mut BTreeMap<u64, WithEvidence<Function>>) {
        let prologues = match binary.architecture {
            fox_arch::Architecture::X64 => fox_arch::x64::FUNCTION_PROLOGUES,
            fox_arch::Architecture::X86 => fox_arch::x86::FUNCTION_PROLOGUES,
            _ => &[],
        };

        for section in binary.executable_sections() {
            let data = &binary.raw_data[section.raw_offset..section.raw_offset + section.raw_size];
            let base_addr = binary.image_base + section.virtual_address;

            for (i, _byte) in data.iter().enumerate() {
                let mut found = false;
                // MSVC aligns functions with int3 (0xCC) or nop (0x90) padding
                let preceded_by_padding = i == 0 || data[i - 1] == 0xCC || data[i - 1] == 0x90;

                // Exact byte-pattern prologues
                for pattern in prologues {
                    if i + pattern.len() <= data.len() && &data[i..i + pattern.len()] == *pattern {
                        let addr = base_addr + i as u64;
                        functions.entry(addr).or_insert_with(|| {
                            let func = Function::new(format!("sub_{:016X}", addr), Address(addr));
                            WithEvidence::new(func).with_evidence(
                                Evidence::new(EvidenceKind::FunctionPrologue)
                                    .with_address(addr)
                                    .with_weight(0.4),
                            )
                        });
                        found = true;
                        break;
                    }
                }

                if found {
                    continue;
                }

                // MSVC x64: sub rsp, imm8 (48 83 EC NN) 鈥?common function entry
                // Require preceding padding to avoid matching in-function stack adjustments.
                if binary.architecture == fox_arch::Architecture::X64
                    && preceded_by_padding
                    && i + 4 <= data.len()
                    && data[i] == 0x48
                    && data[i + 1] == 0x83
                    && data[i + 2] == 0xEC
                {
                    let addr = base_addr + i as u64;
                    functions.entry(addr).or_insert_with(|| {
                        let func = Function::new(format!("sub_{:016X}", addr), Address(addr));
                        WithEvidence::new(func).with_evidence(
                            Evidence::new(EvidenceKind::FunctionPrologue)
                                .with_address(addr)
                                .with_detail("sub rsp, imm8 (MSVC x64 entry)")
                                .with_weight(0.35),
                        )
                    });
                    continue;
                }

                // MSVC x64: sub rsp, imm32 (48 81 EC NN NN NN NN)
                if binary.architecture == fox_arch::Architecture::X64
                    && i + 7 <= data.len()
                    && data[i] == 0x48
                    && data[i + 1] == 0x81
                    && data[i + 2] == 0xEC
                {
                    let addr = base_addr + i as u64;
                    functions.entry(addr).or_insert_with(|| {
                        let func = Function::new(format!("sub_{:016X}", addr), Address(addr));
                        WithEvidence::new(func).with_evidence(
                            Evidence::new(EvidenceKind::FunctionPrologue)
                                .with_address(addr)
                                .with_detail("sub rsp, imm32 (MSVC x64 entry)")
                                .with_weight(0.35),
                        )
                    });
                }

                // MSVC x64: mov [rsp+disp8], r32 (89 [40-7F] 24 NN)
                // Parameter home space store 鈥?common leaf function entry.
                // Require preceding int3 (0xCC) padding or section start to avoid body matches.
                if binary.architecture == fox_arch::Architecture::X64
                    && preceded_by_padding
                    && i + 4 <= data.len()
                    && data[i] == 0x89
                    && data[i + 1] >= 0x40
                    && data[i + 1] <= 0x7F
                    && data[i + 2] == 0x24
                {
                    let addr = base_addr + i as u64;
                    functions.entry(addr).or_insert_with(|| {
                        let func = Function::new(format!("sub_{:016X}", addr), Address(addr));
                        WithEvidence::new(func).with_evidence(
                            Evidence::new(EvidenceKind::FunctionPrologue)
                                .with_address(addr)
                                .with_detail("mov [rsp+disp], r32 (MSVC x64 param home)")
                                .with_weight(0.3),
                        )
                    });
                }

                // MSVC x64: mov [rsp+disp8], r64 (48/4C 89 [40-7F] 24 NN)
                if binary.architecture == fox_arch::Architecture::X64
                    && preceded_by_padding
                    && i + 5 <= data.len()
                    && (data[i] == 0x48 || data[i] == 0x4C)
                    && data[i + 1] == 0x89
                    && data[i + 2] >= 0x40
                    && data[i + 2] <= 0x7F
                    && data[i + 3] == 0x24
                {
                    let addr = base_addr + i as u64;
                    functions.entry(addr).or_insert_with(|| {
                        let func = Function::new(format!("sub_{:016X}", addr), Address(addr));
                        WithEvidence::new(func).with_evidence(
                            Evidence::new(EvidenceKind::FunctionPrologue)
                                .with_address(addr)
                                .with_detail("mov [rsp+disp], r64 (MSVC x64 param home)")
                                .with_weight(0.3),
                        )
                    });
                }
            }
        }
    }

    /// Discover orphan leaf functions: addresses preceded by int3 padding that
    /// contain a RET within the first few instructions. These are tiny leaf
    /// functions that have no .pdata entry and no CALL references.
    ///
    /// Evidence weight: 0.25 (weak 鈥?padding+RET can match data, validation filters FPs)
    fn discover_orphan_leaf_functions(
        binary: &Binary,
        disasm: &dyn fox_disasm::Disassembler,
        functions: &mut BTreeMap<u64, WithEvidence<Function>>,
    ) {
        for section in binary.executable_sections() {
            let data = &binary.raw_data[section.raw_offset..section.raw_offset + section.raw_size];
            let base_addr = binary.image_base + section.virtual_address;

            // Scan for int3 (0xCC) followed by a non-int3 byte that starts a valid function
            for i in 1..data.len() {
                if data[i - 1] != 0xCC {
                    continue;
                }
                if data[i] == 0xCC || data[i] == 0x00 {
                    continue; // still padding or data
                }
                let addr = base_addr + i as u64;
                if functions.contains_key(&addr) {
                    continue; // already discovered
                }

                // Try to disassemble up to 16 bytes and look for RET
                let end = (i + 16).min(data.len());
                if let Ok(insts) = disasm.disassemble(&data[i..end], addr) {
                    let has_ret = insts
                        .iter()
                        .any(|inst| inst.mnemonic.eq_ignore_ascii_case("ret"));
                    let has_call = insts
                        .iter()
                        .any(|inst| inst.mnemonic.eq_ignore_ascii_case("call"));
                    // Must have RET and must NOT have CALL (leaf function heuristic)
                    if has_ret && !has_call && !insts.is_empty() {
                        functions.insert(
                            addr,
                            WithEvidence::new(Function::new(
                                format!("sub_{:016X}", addr),
                                Address(addr),
                            ))
                            .with_evidence(
                                Evidence::new(EvidenceKind::FunctionPrologue)
                                    .with_address(addr)
                                    .with_detail("Orphan leaf: int3 padding + RET, no CALL")
                                    .with_weight(0.25),
                            ),
                        );
                    }
                }
            }
        }
    }

    /// Follow thunk chains: if a discovered function starts with an
    /// unconditional JMP, resolve the target and add it as a function candidate.
    ///
    /// MSVC O2 generates "jump islands" (thunks) where CALL targets are
    /// JMP instructions to the real function body. Without thunk following,
    /// the real functions are never discovered.
    ///
    /// Evidence weight: 0.6 (medium 鈥?derived from CALL target + JMP resolution)
    fn follow_thunks(
        binary: &Binary,
        disasm: &dyn fox_disasm::Disassembler,
        functions: &mut BTreeMap<u64, WithEvidence<Function>>,
    ) {
        let mut to_follow: Vec<u64> = functions.keys().copied().collect();
        let mut visited = std::collections::HashSet::new();

        // Also collect JMP targets from within function bodies (tail calls)
        for func in functions.values() {
            let addr = func.value.address.0;
            let section = match binary
                .sections
                .iter()
                .find(|s| s.contains_address(addr - binary.image_base))
            {
                Some(s) => s,
                None => continue,
            };
            let off =
                (addr - binary.image_base - section.virtual_address) as usize + section.raw_offset;
            let end = (off + 512).min(binary.raw_data.len());
            if off >= end {
                continue;
            }
            let data = &binary.raw_data[off..end];
            if let Ok(insts) = disasm.disassemble(data, addr) {
                for inst in &insts {
                    if inst.is_jump && !inst.is_conditional_jump {
                        if let Some(target) = inst.jump_target {
                            if Self::is_in_executable_section(binary, target) && target != addr {
                                to_follow.push(target);
                            }
                        }
                    }
                }
            }
        }

        while let Some(addr) = to_follow.pop() {
            if !visited.insert(addr) {
                continue;
            }

            // Disassemble first instruction at this address
            let section = match binary
                .sections
                .iter()
                .find(|s| s.contains_address(addr - binary.image_base))
            {
                Some(s) => s,
                None => continue,
            };
            let off =
                (addr - binary.image_base - section.virtual_address) as usize + section.raw_offset;
            if off + 16 > binary.raw_data.len() {
                continue;
            }
            let data = &binary.raw_data[off..off + 16.min(binary.raw_data.len() - off)];

            let insts = match disasm.disassemble(data, addr) {
                Ok(i) => i,
                Err(_) => continue,
            };

            if let Some(first) = insts.first() {
                // Check if this is an unconditional JMP (thunk)
                if first.is_jump && !first.is_conditional_jump {
                    if let Some(target) = first.jump_target {
                        if Self::is_in_executable_section(binary, target)
                            && !functions.contains_key(&target)
                        {
                            // Add the real function as a candidate
                            functions.insert(
                                target,
                                WithEvidence::new(Function::new(
                                    format!("sub_{:016X}", target),
                                    Address(target),
                                ))
                                .with_evidence(
                                    Evidence::new(EvidenceKind::ThunkTarget)
                                        .with_address(target)
                                        .with_detail(format!(
                                            "Reached via thunk JMP @ 0x{:X}",
                                            addr
                                        ))
                                        .with_weight(0.6),
                                ),
                            );
                            to_follow.push(target);
                        } else if let Some(entry) = functions.get_mut(&target) {
                            // Already discovered 鈥?add thunk evidence
                            entry.evidence.push(
                                Evidence::new(EvidenceKind::ThunkTarget)
                                    .with_address(target)
                                    .with_detail(format!("Reached via thunk JMP @ 0x{:X}", addr))
                                    .with_weight(0.3),
                            );
                            entry.confidence = entry.evidence.confidence();
                        }
                    }
                }
            }
        }
    }

    /// P0-5.2: Identify import thunks among discovered functions.
    ///
    /// An import thunk is a single indirect JMP through an IAT entry:
    ///   x86:  jmp dword ptr [IAT_entry_VA]
    ///   x64:  jmp [rip+disp]  (IAT entry)
    ///
    /// Only recognized when the JMP target address can be proven to belong
    /// to the PE Import Address Table. Pattern-only matching is explicitly
    /// rejected (Fail-Closed).
    ///
    /// Returns: HashMap<thunk_address, (dll_name, func_name)>
    pub fn identify_import_thunks(
        binary: &Binary,
        disasm: &dyn fox_disasm::Disassembler,
        functions: &[WithEvidence<Function>],
    ) -> std::collections::HashMap<u64, (String, String)> {
        let mut thunks = std::collections::HashMap::new();

        // Build IAT VA -> (dll, func) map
        let mut iat_map = std::collections::HashMap::new();
        for import in &binary.imports {
            for func in &import.functions {
                let iat_va = func.iat_address + binary.image_base;
                let name = func
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("ordinal_{}", func.ordinal.unwrap_or(0)));
                iat_map.insert(iat_va, (import.dll_name.clone(), name));
            }
        }

        if iat_map.is_empty() {
            return thunks;
        }

        for func in functions {
            let addr = func.value.address.0;

            // Disassemble first instruction at this address
            let section = match binary
                .sections
                .iter()
                .find(|s| s.contains_address(addr - binary.image_base))
            {
                Some(s) => s,
                None => continue,
            };
            let off =
                (addr - binary.image_base - section.virtual_address) as usize + section.raw_offset;
            if off + 16 > binary.raw_data.len() {
                continue;
            }
            let data = &binary.raw_data[off..off + 16.min(binary.raw_data.len() - off)];

            let insts = match disasm.disassemble(data, addr) {
                Ok(i) => i,
                Err(_) => continue,
            };

            if let Some(first) = insts.first() {
                // Must be an unconditional (non-conditional) JMP
                if !first.is_jump || first.is_conditional_jump {
                    continue;
                }

                // Must be INDIRECT jump (memory operand), not direct JMP
                // Direct JMP thunks are handled by follow_thunks (MSVC O2 jump islands)
                let mut iat_target_va: Option<u64> = None;

                for op in &first.operands_structured {
                    if let Some(ref mem) = op.memory {
                        // x64: RIP-relative → effective_address is the IAT entry VA
                        if mem.is_rip_relative {
                            if let Some(ea) = mem.effective_address {
                                iat_target_va = Some(ea);
                            }
                        }
                        // x86: absolute address [disp32] → base=None, index=None, displacement=IAT VA
                        else if mem.base.is_none() && mem.index.is_none() && mem.displacement != 0
                        {
                            iat_target_va = Some(mem.displacement as u64);
                        }
                    }
                }

                // Must resolve to an IAT entry (Fail-Closed: no IAT membership → not ImportThunk)
                if let Some(iat_va) = iat_target_va {
                    if let Some((dll, func_name)) = iat_map.get(&iat_va) {
                        thunks.insert(addr, (dll.clone(), func_name.clone()));
                    }
                }
            }
        }

        thunks
    }

    /// Discover address-taken functions: scan for LEA reg, [rip+disp] where
    /// the effective address points into an executable section.
    ///
    /// This catches functions referenced via function pointers, vtables,
    /// and other indirect call mechanisms that are not direct CALL targets.
    ///
    /// Evidence weight: 0.55 (medium — address reference is strong but
    /// could be a data pointer or code label)
    fn discover_address_taken_functions(
        binary: &Binary,
        disasm: &dyn fox_disasm::Disassembler,
        functions: &mut BTreeMap<u64, WithEvidence<Function>>,
    ) {
        let mut taken_counts: BTreeMap<u64, usize> = BTreeMap::new();

        for section in binary.executable_sections() {
            let data = &binary.raw_data[section.raw_offset..section.raw_offset + section.raw_size];
            let base_addr = binary.image_base + section.virtual_address;

            if let Ok(instructions) = disasm.disassemble(data, base_addr) {
                for inst in &instructions {
                    if !inst.mnemonic.eq_ignore_ascii_case("lea") {
                        continue;
                    }
                    // Check second operand (source) for RIP-relative memory
                    if let Some(src) = inst.operands_structured.get(1) {
                        if let Some(mem) = &src.memory {
                            if mem.is_rip_relative {
                                if let Some(ea) = mem.effective_address {
                                    if Self::is_in_executable_section(binary, ea) {
                                        *taken_counts.entry(ea).or_insert(0) += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Also scan read-only data sections for function pointers
        for section in &binary.sections {
            if section.is_writable() || section.is_executable() {
                continue; // skip writable and executable (already scanned)
            }
            if section.raw_size == 0 {
                continue;
            }
            let data = &binary.raw_data[section.raw_offset..section.raw_offset + section.raw_size];
            // Scan for 8-byte pointers that point into executable sections
            let mut i = 0;
            while i + 8 <= data.len() {
                let ptr = u64::from_le_bytes([
                    data[i],
                    data[i + 1],
                    data[i + 2],
                    data[i + 3],
                    data[i + 4],
                    data[i + 5],
                    data[i + 6],
                    data[i + 7],
                ]);
                if ptr >= binary.image_base && Self::is_in_executable_section(binary, ptr) {
                    *taken_counts.entry(ptr).or_insert(0) += 1;
                }
                i += 8;
            }
        }

        // Add candidates
        for (addr, count) in &taken_counts {
            let detail = format!("Address referenced {} time(s) via LEA/data", count);
            if functions.contains_key(addr) {
                if let Some(entry) = functions.get_mut(addr) {
                    entry.evidence.push(
                        Evidence::new(EvidenceKind::AddressTaken)
                            .with_address(*addr)
                            .with_detail(&detail)
                            .with_weight(if *count >= 2 { 0.4 } else { 0.25 }),
                    );
                    entry.confidence = entry.evidence.confidence();
                }
            } else {
                functions.insert(
                    *addr,
                    WithEvidence::new(Function::new(format!("sub_{:016X}", addr), Address(*addr)))
                        .with_evidence(
                            Evidence::new(EvidenceKind::AddressTaken)
                                .with_address(*addr)
                                .with_detail(&detail)
                                .with_weight(if *count >= 2 { 0.55 } else { 0.4 }),
                        ),
                );
            }
        }
    }

    /// Validate function bodies (P0-3.1).
    ///
    /// For each candidate function:
    /// 1. Linear sweep from entry until RET / tail-call JMP / next function boundary
    /// 2. Check first instruction decodes
    /// 3. Check body contains RET or tail-call
    /// 4. Record instruction count and estimated end
    /// 5. Add Positive or Negative evidence
    fn validate_function_bodies(
        binary: &Binary,
        disasm: &dyn fox_disasm::Disassembler,
        functions: &mut BTreeMap<u64, WithEvidence<Function>>,
    ) {
        // Collect all function entry addresses for boundary detection
        let entry_addrs: Vec<u64> = functions.keys().cloned().collect();

        let mut updates: Vec<(u64, FunctionValidation, Option<Evidence>, Option<Evidence>)> =
            Vec::new();

        for &addr in functions.keys() {
            let mut validation = FunctionValidation {
                validated: true,
                ..Default::default()
            };

            // Find section data for this address
            let section_data = Self::get_section_data_at(binary, addr);
            let (data, base_addr) = match section_data {
                Some(d) => d,
                None => {
                    validation.failure_reason = Some("Address not in any section".to_string());
                    updates.push((
                        addr,
                        validation,
                        None,
                        Some(
                            Evidence::new(EvidenceKind::InvalidFunctionBody {
                                reason: "not in any section".to_string(),
                            })
                            .with_address(addr)
                            .with_weight(-0.5),
                        ),
                    ));
                    continue;
                }
            };

            let offset = (addr - base_addr) as usize;
            if offset >= data.len() {
                validation.failure_reason = Some("Address past section end".to_string());
                updates.push((
                    addr,
                    validation,
                    None,
                    Some(
                        Evidence::new(EvidenceKind::InvalidFunctionBody {
                            reason: "past section end".to_string(),
                        })
                        .with_address(addr)
                        .with_weight(-0.5),
                    ),
                ));
                continue;
            }

            // Linear sweep from entry
            let mut cur_offset = offset;
            let mut cur_addr = addr;
            let mut inst_count = 0usize;
            let mut has_ret = false;
            let mut has_tail_call = false;
            let mut tail_call_is_indirect = false;
            let mut last_end = addr;
            let max_instructions = 5000; // safety limit

            while cur_offset < data.len() && inst_count < max_instructions {
                // Stop if we hit another function entry
                if cur_addr != addr && entry_addrs.contains(&cur_addr) {
                    break;
                }

                match disasm.disassemble_one(&data[cur_offset..], cur_addr) {
                    Ok(Some(inst)) => {
                        if inst_count == 0 {
                            validation.valid_entry = true;
                        }
                        inst_count += 1;
                        last_end = cur_addr + inst.length as u64;

                        if inst.is_ret {
                            has_ret = true;
                            break;
                        }
                        // Tail call: unconditional JMP (direct to function entry OR indirect)
                        if inst.is_jump && !inst.is_conditional_jump {
                            if let Some(target) = inst.jump_target {
                                // Direct JMP: tail call if target is another function entry
                                if entry_addrs.contains(&target) && target != addr {
                                    has_tail_call = true;
                                    tail_call_is_indirect = false;
                                    break;
                                }
                            } else {
                                // Indirect JMP (jmp [rip+disp], jmp rax, etc.) = potential tail call
                                has_tail_call = true;
                                tail_call_is_indirect = true;
                                break;
                            }
                        }

                        cur_offset += inst.length;
                        cur_addr += inst.length as u64;
                    }
                    Ok(None) => {
                        // Invalid instruction boundary
                        break;
                    }
                    Err(_) => break,
                }
            }

            validation.has_return = has_ret;
            validation.has_tail_call = has_tail_call;
            validation.instruction_count = inst_count;
            validation.estimated_end = Some(last_end);

            // Classify termination kind
            validation.termination_kind = if has_ret {
                TerminationKind::Return
            } else if has_tail_call && tail_call_is_indirect {
                TerminationKind::TailCallIndirect
            } else if has_tail_call {
                TerminationKind::TailCallDirect
            } else if inst_count == 0 {
                TerminationKind::Empty
            } else if cur_offset >= data.len() || entry_addrs.contains(&cur_addr) {
                TerminationKind::BoundaryStop
            } else {
                TerminationKind::NoTerminator
            };

            // Determine validation outcome
            if validation.valid_entry && (has_ret || has_tail_call) && inst_count > 0 {
                // Valid function body
                let pos_evidence = Evidence::new(EvidenceKind::ValidFunctionBody)
                    .with_address(addr)
                    .with_weight(0.6);
                if has_tail_call {
                    updates.push((
                        addr,
                        validation,
                        Some(pos_evidence),
                        Some(
                            Evidence::new(EvidenceKind::TailCall)
                                .with_address(addr)
                                .with_weight(0.3),
                        ),
                    ));
                } else {
                    updates.push((addr, validation, Some(pos_evidence), None));
                }
            } else {
                let reason = if !validation.valid_entry {
                    "invalid entry instruction"
                } else if !has_ret && !has_tail_call && inst_count <= 2 {
                    "suspicious: <=2 instructions with no terminator (likely false positive)"
                } else if !has_ret && !has_tail_call {
                    "no RET or tail-call"
                } else if inst_count == 0 {
                    "empty body"
                } else {
                    "unknown validation failure"
                };
                validation.failure_reason = Some(reason.to_string());
                // Stronger negative evidence for suspiciously short functions
                let neg_weight = if inst_count <= 2 { -0.55 } else { -0.4 };
                updates.push((
                    addr,
                    validation,
                    None,
                    Some(
                        Evidence::new(EvidenceKind::InvalidFunctionBody {
                            reason: reason.to_string(),
                        })
                        .with_address(addr)
                        .with_weight(neg_weight),
                    ),
                ));
            }
        }

        // Apply updates
        for (addr, validation, pos_ev, neg_ev) in updates {
            if let Some(entry) = functions.get_mut(&addr) {
                entry.value.validation = validation;
                if let Some(ev) = pos_ev {
                    entry.evidence.push(ev);
                }
                if let Some(ev) = neg_ev {
                    entry.evidence.push(ev);
                }
                entry.confidence = Self::recalculate_confidence(&entry.evidence);
            }
        }
    }

    /// Get section data slice and base address for a given VA.
    fn get_section_data_at(binary: &Binary, addr: u64) -> Option<(&[u8], u64)> {
        for section in &binary.sections {
            let section_start = binary.image_base + section.virtual_address;
            let section_end = section_start + section.virtual_size as u64;
            if addr >= section_start && addr < section_end {
                let end = (section.raw_offset + section.raw_size).min(binary.raw_data.len());
                if section.raw_offset < end {
                    return Some((&binary.raw_data[section.raw_offset..end], section_start));
                }
            }
        }
        None
    }

    /// Apply negative evidence to reduce false positives.
    fn apply_negative_evidence(
        binary: &Binary,
        disasm: &dyn fox_disasm::Disassembler,
        functions: &mut BTreeMap<u64, WithEvidence<Function>>,
    ) {
        let executable_ranges: Vec<(u64, u64)> = binary
            .executable_sections()
            .iter()
            .map(|s| {
                (
                    binary.image_base + s.virtual_address,
                    binary.image_base + s.virtual_address + s.virtual_size as u64,
                )
            })
            .collect();

        // First pass: collect negative evidence and addresses to modify
        let mut updates: Vec<(u64, f64)> = Vec::new();
        let mut to_remove: Vec<u64> = Vec::new();

        for (addr, entry) in functions.iter() {
            let mut negative_weight = 0.0f64;

            // Negative: address not in executable section
            if !executable_ranges
                .iter()
                .any(|(start, end)| *addr >= *start && *addr < *end)
            {
                negative_weight += 0.8;
            }

            // Negative: first byte doesn't decode as valid instruction
            if let Some(section) = binary
                .sections
                .iter()
                .find(|s| s.contains_address(addr - binary.image_base))
            {
                let rva = addr - binary.image_base;
                if let Some(off) = section.rva_to_offset(rva) {
                    if off < binary.raw_data.len() {
                        let slice = &binary.raw_data[off..];
                        if let Ok(None) = disasm.disassemble_one(slice, *addr) {
                            negative_weight += 0.6;
                        }
                    }
                }
            }

            if negative_weight > 0.0 {
                updates.push((*addr, negative_weight));
            }

            if entry.confidence.0 <= 0.05 {
                to_remove.push(*addr);
            }
        }

        // Second pass: apply updates
        for (addr, neg_weight) in updates {
            if let Some(e) = functions.get_mut(&addr) {
                e.evidence.push(
                    Evidence::new(EvidenceKind::NegativeNonExecutableSection)
                        .with_address(addr)
                        .with_weight(-neg_weight),
                );
                e.confidence = Self::recalculate_confidence(&e.evidence);
                if e.confidence.0 <= 0.05 {
                    to_remove.push(addr);
                }
            }
        }

        for addr in to_remove {
            functions.remove(&addr);
        }
    }

    /// Recalculate confidence considering negative evidence (negative weights).
    fn recalculate_confidence(evidence: &fox_core::EvidenceList) -> Confidence {
        let positive: Vec<f64> = evidence
            .items
            .iter()
            .filter(|e| e.weight > 0.0)
            .map(|e| e.weight)
            .collect();
        let negative: f64 = evidence
            .items
            .iter()
            .filter(|e| e.weight < 0.0)
            .map(|e| e.weight.abs())
            .sum();

        if positive.is_empty() {
            return Confidence::ZERO;
        }

        let max_positive = positive.iter().cloned().fold(0.0f64, f64::max);
        let extra = (positive.len() - 1) as f64;
        let bonus = 0.1 * extra * (1.0 - max_positive);
        let raw = max_positive + bonus - negative;
        Confidence::new(raw.max(0.0))
    }

    /// Check if an address is within an executable section.
    fn is_in_executable_section(binary: &Binary, addr: u64) -> bool {
        let rva = addr.checked_sub(binary.image_base).unwrap_or(addr);
        binary
            .sections
            .iter()
            .any(|s| s.is_executable() && s.contains_address(rva))
    }
}

/// Full analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub functions: Vec<WithEvidence<Function>>,
    pub cfg: cfg::ControlFlowGraph,
    pub call_graph: callgraph::CallGraph,
    pub identity_table: fox_core::identity::FunctionIdentityTable,
    /// P0-4.1: Unified per-function analysis pipeline results.
    /// Contains IR/SSA/DataFlow/Memory/Evidence for each function.
    #[serde(default)]
    pub pipeline: pipeline::PipelineResult,
}

/// Run full analysis pipeline on a binary.
/// P0-4.5: Safe Dispatch — analyze binary only if execution model is Native.
///
/// Returns `FoxError::UnsupportedExecutionModel` for ManagedCLR / MixedMode / Unknown,
/// preventing the Native Pipeline from scanning non-native code (e.g. .NET IL).
pub fn analyze_binary(binary: &Binary) -> FoxResult<AnalysisResult> {
    if !binary.execution_model.native_pipeline_applicable() {
        return Err(FoxError::UnsupportedExecutionModel(format!(
            "Container: {:?}, Architecture: {}, Execution Model: {}, CLR: {}, Native Pipeline: NOT DISPATCHED",
            binary.format,
            binary.architecture,
            binary.execution_model.display_name(),
            binary.clr_present,
        )));
    }

    Ok(analyze_binary_native(binary))
}

/// Native analysis pipeline (P0-4.1 unified pipeline).
///
/// Only callable after Safe Dispatch confirms ExecutionModel::Native.
fn analyze_binary_native(binary: &Binary) -> AnalysisResult {
    let functions = FunctionDiscovery::discover(binary);

    let disasm = create_disassembler(binary.architecture).ok();

    // P0-5.2: Identify import thunks (jmp [IAT]) before CFG/CallGraph/Identity
    let import_thunks = if let Some(d) = disasm.as_ref() {
        FunctionDiscovery::identify_import_thunks(binary, d.as_ref(), &functions)
    } else {
        std::collections::HashMap::new()
    };

    let cfg = if let Some(d) = disasm.as_ref() {
        cfg::ControlFlowGraph::build(binary, &functions, d.as_ref())
    } else {
        cfg::ControlFlowGraph::new()
    };

    let call_graph =
        callgraph::CallGraph::build(binary, &functions, &cfg.function_cfgs, &import_thunks);
    let identity_table = build_identity_table(binary, &functions, &call_graph, &import_thunks);

    // P0-4.1: Unified per-function analysis pipeline
    // IR → SSA → DataFlow → Memory → Evidence, all sharing the same CFG and IR
    let pipeline = pipeline::AnalysisPipeline::run(binary, &functions, &cfg);

    AnalysisResult {
        functions,
        cfg,
        call_graph,
        identity_table,
        pipeline,
    }
}

/// Build FunctionIdentityTable from discovered functions and call graph.
///
/// P0-3.4: Classifies each function address as Canonical/Thunk/Folded/Alias,
/// records thunk relationships, and tracks address-taken functions.
fn build_identity_table(
    binary: &Binary,
    functions: &[WithEvidence<Function>],
    call_graph: &callgraph::CallGraph,
    import_thunks: &std::collections::HashMap<u64, (String, String)>,
) -> fox_core::identity::FunctionIdentityTable {
    use fox_core::identity::{FunctionIdentityTable, IdentityKind};
    let mut table = FunctionIdentityTable::new();

    // First pass: classify each function
    for func in functions {
        let addr = func.value.address.0;

        // P0-5.2: Check if this is an import thunk (jmp [IAT])
        if let Some((dll, func_name)) = import_thunks.get(&addr) {
            let ident = table.get_or_create(addr);
            ident.kind = IdentityKind::ImportThunk;
            ident.source_symbols.push(format!("{}!{}", dll, func_name));
            // Count call references
            ident.call_reference_count = call_graph
                .nodes
                .iter()
                .flat_map(|n| n.incoming_calls.iter())
                .filter(|&&caller| caller == addr)
                .count();
            continue;
        }

        // Check evidence for address-taken
        let has_address_taken = func
            .evidence
            .items
            .iter()
            .any(|e| matches!(e.kind, fox_core::EvidenceKind::AddressTaken));

        // Check if first instruction is JMP (thunk)
        let mut is_thunk = false;
        let mut thunk_target: Option<u64> = None;
        if let Some(section) = binary
            .sections
            .iter()
            .find(|s| s.contains_address(addr - binary.image_base))
        {
            let off =
                (addr - binary.image_base - section.virtual_address) as usize + section.raw_offset;
            if off + 16 <= binary.raw_data.len() {
                let data = &binary.raw_data[off..off + 16];
                if let Ok(disasm) = crate::create_disassembler(binary.architecture) {
                    if let Ok(insts) = disasm.disassemble(data, addr) {
                        if let Some(first) = insts.first() {
                            if first.is_jump && !first.is_conditional_jump {
                                if let Some(target) = first.jump_target {
                                    is_thunk = true;
                                    thunk_target = Some(target);
                                }
                            }
                        }
                    }
                }
            }
        }

        if is_thunk {
            if let Some(target) = thunk_target {
                table.record_thunk(addr, target);
                // Set address_taken on thunk identity
                if let Some(t) = table.binary_identities.get_mut(&addr) {
                    t.address_taken = has_address_taken;
                }
                continue;
            }
        }

        let ident = table.get_or_create(addr);
        ident.address_taken = has_address_taken;
        ident.kind = IdentityKind::Canonical;

        // Count call references
        ident.call_reference_count = call_graph
            .nodes
            .iter()
            .flat_map(|n| n.incoming_calls.iter())
            .filter(|&&caller| caller == addr)
            .count();
    }

    // Record source symbol mappings from named functions
    let named_funcs: Vec<(String, u64)> = functions
        .iter()
        .filter(|f| !f.value.name.starts_with("sub_"))
        .map(|f| (f.value.name.clone(), f.value.address.0))
        .collect();
    for (name, addr) in &named_funcs {
        if let Some(ident) = table.binary_identities.get(addr) {
            if ident.is_canonical() {
                table.record_source_mapping(name, *addr);
            }
        }
    }

    // P0-5.2: Record source mappings for import thunks (DLL!FunctionName)
    for (addr, (dll, func_name)) in import_thunks {
        let sym = format!("{}!{}", dll, func_name);
        table.record_source_mapping(&sym, *addr);
    }

    table
}
