//! FOX Memory Semantics (P0-3.4 / P0-4.2)
//!
//! Memory Location abstraction:
//! - Stack slot (based on RSP/RBP offset)
//! - Global (RIP-relative or absolute address)
//! - Heap / unknown pointer
//! - Alias candidates
//!
//! P0-4.2: MemoryOperation upgraded from boolean flags to semantic enum
//! (Load/Store/ReadWrite/Unknown). destination_register and source_register
//! are derived from structured IR operand access modes, not heuristics.
//!
//! This prepares for Memory SSA (P0-4.3) and Alias Analysis.

use crate::{IRFunction, IROperand, OperandAccess};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A memory location classification.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemoryLocation {
    /// Stack slot: base register (RSP/RBP) + displacement
    Stack {
        base_register: String,
        displacement: i64,
        size: u32,
    },
    /// Global variable: RIP-relative or absolute address
    Global {
        address: u64,
        size: u32,
        rip_relative: bool,
    },
    /// Heap or unknown pointer-based access
    Heap {
        base_register: String,
        index_register: Option<String>,
        scale: u32,
        displacement: i64,
        size: u32,
    },
    /// Unknown memory location (cannot classify)
    Unknown { description: String, size: u32 },
}

impl MemoryLocation {
    pub fn size(&self) -> u32 {
        match self {
            MemoryLocation::Stack { size, .. } => *size,
            MemoryLocation::Global { size, .. } => *size,
            MemoryLocation::Heap { size, .. } => *size,
            MemoryLocation::Unknown { size, .. } => *size,
        }
    }

    pub fn is_stack(&self) -> bool {
        matches!(self, MemoryLocation::Stack { .. })
    }

    pub fn is_global(&self) -> bool {
        matches!(self, MemoryLocation::Global { .. })
    }

    /// Conservative alias check: returns true if two locations MAY alias.
    ///
    /// - Same exact location: definitely alias
    /// - Stack vs Global: never alias
    /// - Stack vs Stack with different offsets: may alias if overlapping
    /// - Heap: always may alias (conservative)
    /// - Unknown: always may alias
    pub fn may_alias(&self, other: &MemoryLocation) -> bool {
        match (self, other) {
            (
                MemoryLocation::Stack {
                    base_register: b1,
                    displacement: d1,
                    size: s1,
                },
                MemoryLocation::Stack {
                    base_register: b2,
                    displacement: d2,
                    size: s2,
                },
            ) => {
                if b1 != b2 {
                    return true; // different base registers -> conservative
                }
                // Same base: check overlap
                let start1 = *d1;
                let end1 = d1 + *s1 as i64;
                let start2 = *d2;
                let end2 = d2 + *s2 as i64;
                start1 < end2 && start2 < end1
            }
            (
                MemoryLocation::Global { address: a1, .. },
                MemoryLocation::Global { address: a2, .. },
            ) => {
                a1 == a2 // exact match for globals
            }
            (MemoryLocation::Stack { .. }, MemoryLocation::Global { .. }) => false,
            (MemoryLocation::Global { .. }, MemoryLocation::Stack { .. }) => false,
            (MemoryLocation::Heap { .. }, _) => true,
            (_, MemoryLocation::Heap { .. }) => true,
            (MemoryLocation::Unknown { .. }, _) => true,
            (_, MemoryLocation::Unknown { .. }) => true,
        }
    }
}

/// The kind of memory operation — a reliable semantic object, not boolean flags.
///
/// P0-4.2: Derived from structured IR OperandAccess, never from string parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemoryOperationKind {
    /// Read from memory (e.g. mov rcx, [rsp+8])
    Load,
    /// Write to memory (e.g. mov [rsp+8], rax)
    Store,
    /// Both read and write (e.g. xchg [mem], reg, lock add [mem], imm)
    ReadWrite,
    /// Cannot determine access mode from structured IR
    Unknown,
}

impl MemoryOperationKind {
    pub fn is_load(&self) -> bool {
        matches!(
            self,
            MemoryOperationKind::Load | MemoryOperationKind::ReadWrite
        )
    }

    pub fn is_store(&self) -> bool {
        matches!(
            self,
            MemoryOperationKind::Store | MemoryOperationKind::ReadWrite
        )
    }

    pub fn from_access(access: OperandAccess) -> Self {
        match access {
            OperandAccess::Read => MemoryOperationKind::Load,
            OperandAccess::Write => MemoryOperationKind::Store,
            OperandAccess::ReadWrite => MemoryOperationKind::ReadWrite,
        }
    }
}

/// A memory operation with full semantic information.
///
/// P0-4.2: Replaces boolean is_load/is_store with kind: MemoryOperationKind.
/// destination_register / source_register are derived from structured IR
/// operand access modes, not "first register operand" heuristics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryOperation {
    /// Address of the machine instruction producing this operation
    pub instruction_address: u64,
    /// Semantic operation kind
    pub kind: MemoryOperationKind,
    /// Classified memory location
    pub location: MemoryLocation,
    /// For Load: the register receiving the value (operand with access=Write)
    /// For Store: None (the value comes from source_register)
    pub destination_register: Option<String>,
    /// For Store: the register providing the value (operand with access=Read)
    /// For Load: None (the value goes to destination_register)
    pub source_register: Option<String>,
    /// Human-readable evidence detail linking to the original instruction
    pub evidence_detail: String,
}

/// Memory analysis result for a function.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MemoryAnalysis {
    pub operations: Vec<MemoryOperation>,
    pub stack_slots: HashSet<(String, i64)>,
    pub globals: HashSet<u64>,
    pub heap_accesses: usize,
    pub unknown_accesses: usize,
}

impl MemoryAnalysis {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_operation(&mut self, op: MemoryOperation) {
        match &op.location {
            MemoryLocation::Stack {
                base_register,
                displacement,
                ..
            } => {
                self.stack_slots
                    .insert((base_register.clone(), *displacement));
            }
            MemoryLocation::Global { address, .. } => {
                self.globals.insert(*address);
            }
            MemoryLocation::Heap { .. } => {
                self.heap_accesses += 1;
            }
            MemoryLocation::Unknown { .. } => {
                self.unknown_accesses += 1;
            }
        }
        self.operations.push(op);
    }

    pub fn load_count(&self) -> usize {
        self.operations.iter().filter(|o| o.kind.is_load()).count()
    }

    pub fn store_count(&self) -> usize {
        self.operations.iter().filter(|o| o.kind.is_store()).count()
    }

    /// Count operations by kind.
    pub fn count_by_kind(&self, kind: MemoryOperationKind) -> usize {
        self.operations.iter().filter(|o| o.kind == kind).count()
    }
}

/// Classify a memory operand from structured IR.
pub fn classify_memory(
    base: Option<&str>,
    index: Option<&str>,
    scale: u32,
    displacement: i64,
    size: u32,
    rip_relative: bool,
    effective_address: Option<u64>,
) -> MemoryLocation {
    // RIP-relative -> global
    if rip_relative {
        if let Some(addr) = effective_address {
            return MemoryLocation::Global {
                address: addr,
                size,
                rip_relative: true,
            };
        }
        return MemoryLocation::Global {
            address: displacement as u64,
            size,
            rip_relative: true,
        };
    }

    let base_str = base.unwrap_or("").to_string();

    // Stack access: RSP or RBP based
    if (base_str == "RSP"
        || base_str == "RBP"
        || base_str == "ESP"
        || base_str == "EBP"
        || base_str == "SP"
        || base_str == "BP")
        && index.is_none()
    {
        return MemoryLocation::Stack {
            base_register: base_str,
            displacement,
            size,
        };
    }

    // Absolute address (no base, no index) -> global
    if base.is_none() && index.is_none() {
        return MemoryLocation::Global {
            address: displacement as u64,
            size,
            rip_relative: false,
        };
    }

    // Everything else -> heap/pointer
    MemoryLocation::Heap {
        base_register: base_str,
        index_register: index.map(|s| s.to_string()),
        scale,
        displacement,
        size,
    }
}

/// Analyze memory operations in an IR function.
///
/// P0-4.2 / P0-4.2R: Canonical entry point for memory semantic analysis.
///
/// For each memory operand in each instruction:
/// - Classify the MemoryLocation (Stack/Global/Heap/Unknown)
/// - Determine MemoryOperationKind from structured OperandAccess (not string parsing)
/// - Determine destination/source registers based on OPCODE SEMANTICS +
///   structured operand access modes (not "first register" heuristic)
/// - Attach evidence linking to the original instruction
///
/// P0-4.2R fix: destination_register is only set when the opcode genuinely
/// moves data from memory to a register (Mov/Pop/Load/Lea). For CMP/TEST,
/// memory is read but the result goes to FLAGS — destination_register = None.
pub fn analyze_function_memory(ir: &IRFunction) -> MemoryAnalysis {
    let mut analysis = MemoryAnalysis::new();

    for block in &ir.basic_blocks {
        for inst in &block.instructions {
            for (op_idx, op) in inst.operands.iter().enumerate() {
                if let IROperand::Memory {
                    base,
                    index,
                    scale,
                    displacement,
                    size,
                    access,
                    is_rip_relative,
                    effective_address,
                } = op
                {
                    let location = classify_memory(
                        base.as_deref(),
                        index.as_deref(),
                        *scale as u32,
                        *displacement,
                        *size as u32,
                        *is_rip_relative,
                        *effective_address,
                    );

                    let kind = MemoryOperationKind::from_access(*access);

                    // P0-4.2R: Determine data register roles based on OPCODE SEMANTICS,
                    // not just "first register with matching access".
                    //
                    // source_register: explicit Register operand with access=Read
                    //   (the register providing data to the operation)
                    // destination_register: explicit Register operand with access=Write,
                    //   BUT only if the opcode genuinely moves memory data TO a register.
                    //   CMP/TEST read memory but result → FLAGS, so destination = None.
                    //   ReadWrite (RMW) writes result to memory, so destination = None.
                    let source_register = find_register_with_access(
                        &inst.operands,
                        OperandAccess::Read,
                        true, // include ReadWrite
                    );

                    let destination_register = match kind {
                        MemoryOperationKind::Load => {
                            if produces_register_destination(&inst.op) {
                                find_register_with_access(
                                    &inst.operands,
                                    OperandAccess::Write,
                                    true, // include ReadWrite
                                )
                            } else {
                                // CMP/TEST/etc.: memory read but no register destination
                                None
                            }
                        }
                        MemoryOperationKind::Store => None,
                        MemoryOperationKind::ReadWrite => None, // result → memory
                        MemoryOperationKind::Unknown => None,
                    };

                    let evidence_detail = format!(
                        "instr=0x{:x} op={:?} operand_idx={} access={:?} kind={:?} location={:?}",
                        inst.address.0, inst.op, op_idx, access, kind, location
                    );

                    analysis.add_operation(MemoryOperation {
                        instruction_address: inst.address.0,
                        kind,
                        location,
                        destination_register,
                        source_register,
                        evidence_detail,
                    });
                }
            }
        }
    }

    analysis
}

/// Returns true if this opcode, when reading from memory, produces a register
/// data destination (i.e., memory value is loaded INTO a register).
///
/// CMP/TEST read memory but the result goes to FLAGS, not a register.
/// RMW instructions (ADD/SUB/AND/...) with memory operands are ReadWrite,
/// not Load, so they are not relevant here.
fn produces_register_destination(op: &crate::IROp) -> bool {
    use crate::IROp;
    match op {
        // Genuine memory-to-register data movement
        IROp::Mov | IROp::Load | IROp::Pop | IROp::Lea => true,
        // Everything else: no register data destination from a memory Load
        // (Cmp/Test → FLAGS; Push/Call/Jump → memory is source but not to a register)
        _ => false,
    }
}

/// Find the first explicit Register operand with the given access mode.
///
/// `include_read_write` controls whether ReadWrite registers match.
/// Only matches `IROperand::Register` — NOT `IROperand::Flags` (FLAGS is never
/// a memory data destination/source).
fn find_register_with_access(
    operands: &[IROperand],
    target: OperandAccess,
    include_read_write: bool,
) -> Option<String> {
    operands.iter().find_map(|o| {
        if let IROperand::Register { name, access, .. } = o {
            let matches =
                *access == target || (include_read_write && *access == OperandAccess::ReadWrite);
            if matches {
                Some(name.clone())
            } else {
                None
            }
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_classification() {
        let loc = classify_memory(Some("RSP"), None, 1, -0x20, 8, false, None);
        assert!(loc.is_stack());
        if let MemoryLocation::Stack {
            base_register,
            displacement,
            ..
        } = loc
        {
            assert_eq!(base_register, "RSP");
            assert_eq!(displacement, -0x20);
        }
    }

    #[test]
    fn test_rip_relative_global() {
        let loc = classify_memory(Some("RIP"), None, 1, 0x1234, 4, true, Some(0x140005000));
        assert!(loc.is_global());
        if let MemoryLocation::Global {
            address,
            rip_relative,
            ..
        } = loc
        {
            assert_eq!(address, 0x140005000);
            assert!(rip_relative);
        }
    }

    #[test]
    fn test_heap_classification() {
        let loc = classify_memory(Some("RBX"), Some("RCX"), 4, 0x10, 4, false, None);
        assert!(matches!(loc, MemoryLocation::Heap { .. }));
    }

    #[test]
    fn test_stack_no_alias_different_offsets() {
        let s1 = MemoryLocation::Stack {
            base_register: "RSP".into(),
            displacement: -0x20,
            size: 8,
        };
        let s2 = MemoryLocation::Stack {
            base_register: "RSP".into(),
            displacement: -0x10,
            size: 8,
        };
        assert!(!s1.may_alias(&s2));
    }

    #[test]
    fn test_stack_alias_overlapping() {
        let s1 = MemoryLocation::Stack {
            base_register: "RSP".into(),
            displacement: -0x20,
            size: 16,
        };
        let s2 = MemoryLocation::Stack {
            base_register: "RSP".into(),
            displacement: -0x18,
            size: 8,
        };
        assert!(s1.may_alias(&s2));
    }

    #[test]
    fn test_stack_global_no_alias() {
        let s = MemoryLocation::Stack {
            base_register: "RSP".into(),
            displacement: -8,
            size: 8,
        };
        let g = MemoryLocation::Global {
            address: 0x140005000,
            size: 8,
            rip_relative: false,
        };
        assert!(!s.may_alias(&g));
    }

    #[test]
    fn test_heap_aliases_everything() {
        let h = MemoryLocation::Heap {
            base_register: "RAX".into(),
            index_register: None,
            scale: 1,
            displacement: 0,
            size: 8,
        };
        let s = MemoryLocation::Stack {
            base_register: "RSP".into(),
            displacement: -8,
            size: 8,
        };
        assert!(h.may_alias(&s));
    }

    // ============================================================
    // P0-4.2: Memory Semantic Normalization Tests
    // ============================================================

    use crate::{Address, IRBasicBlock, IRFunction, IRInstruction, IROp, IROperand};

    /// Helper: build a simple IR function with one block containing given instructions.
    fn make_function(instructions: Vec<IRInstruction>) -> IRFunction {
        IRFunction {
            name: "test_fn".into(),
            address: Address(0x140001000),
            basic_blocks: vec![IRBasicBlock {
                id: 0,
                start_address: Address(0x140001000),
                end_address: Address(0x140001100),
                instructions,
                successors: vec![],
                predecessors: vec![],
            }],
            entry_block: 0,
        }
    }

    /// Helper: build a register operand.
    fn reg(name: &str, access: OperandAccess) -> IROperand {
        IROperand::Register {
            name: name.into(),
            width: 64,
            access,
        }
    }

    /// Helper: build a memory operand.
    #[allow(clippy::too_many_arguments)]
    fn mem(
        base: Option<&str>,
        index: Option<&str>,
        scale: u8,
        disp: i64,
        size: u8,
        access: OperandAccess,
        rip: bool,
        eff: Option<u64>,
    ) -> IROperand {
        IROperand::Memory {
            base: base.map(|s| s.into()),
            index: index.map(|s| s.into()),
            scale,
            displacement: disp,
            size,
            access,
            is_rip_relative: rip,
            effective_address: eff,
        }
    }

    /// Helper: build an IR instruction.
    fn inst(addr: u64, op: IROp, operands: Vec<IROperand>, mnemonic: &str) -> IRInstruction {
        IRInstruction {
            address: Address(addr),
            op,
            operands,
            original_mnemonic: Some(mnemonic.into()),
            original_operands: None,
            size: 5,
            reads_registers: vec![],
            writes_registers: vec![],
            implicit_reads: vec![],
            implicit_writes: vec![],
            reads_flags: false,
            writes_flags: false,
        }
    }

    /// Test 1: Load from stack — mov rcx, [rsp+8]
    /// Memory operand has access=Read → kind=Load
    /// Destination register = RCX (access=Write)
    #[test]
    fn test_load_from_stack() {
        let ir = make_function(vec![inst(
            0x140001000,
            IROp::Mov,
            vec![
                reg("RCX", OperandAccess::Write),
                mem(Some("RSP"), None, 1, 8, 8, OperandAccess::Read, false, None),
            ],
            "mov",
        )]);

        let analysis = analyze_function_memory(&ir);
        assert_eq!(analysis.operations.len(), 1);

        let op = &analysis.operations[0];
        assert_eq!(op.kind, MemoryOperationKind::Load);
        assert!(op.kind.is_load());
        assert!(!op.kind.is_store());
        assert_eq!(op.destination_register, Some("RCX".into()));
        assert_eq!(op.source_register, None);
        assert!(matches!(op.location, MemoryLocation::Stack { .. }));
        assert_eq!(op.instruction_address, 0x140001000);
        assert!(!op.evidence_detail.is_empty());
    }

    /// Test 2: Store to stack — mov [rsp+8], rax
    /// Memory operand has access=Write → kind=Store
    /// Source register = RAX (access=Read)
    #[test]
    fn test_store_to_stack() {
        let ir = make_function(vec![inst(
            0x140001005,
            IROp::Mov,
            vec![
                mem(
                    Some("RSP"),
                    None,
                    1,
                    8,
                    8,
                    OperandAccess::Write,
                    false,
                    None,
                ),
                reg("RAX", OperandAccess::Read),
            ],
            "mov",
        )]);

        let analysis = analyze_function_memory(&ir);
        assert_eq!(analysis.operations.len(), 1);

        let op = &analysis.operations[0];
        assert_eq!(op.kind, MemoryOperationKind::Store);
        assert!(!op.kind.is_load());
        assert!(op.kind.is_store());
        assert_eq!(op.destination_register, None);
        assert_eq!(op.source_register, Some("RAX".into()));
        assert!(matches!(op.location, MemoryLocation::Stack { .. }));
    }

    /// Test 3: RIP-relative load — mov eax, [rip+0x1234]
    /// Should classify as Global, kind=Load
    #[test]
    fn test_rip_relative_load() {
        let ir = make_function(vec![inst(
            0x14000100a,
            IROp::Mov,
            vec![
                reg("EAX", OperandAccess::Write),
                mem(
                    Some("RIP"),
                    None,
                    1,
                    0x1234,
                    4,
                    OperandAccess::Read,
                    true,
                    Some(0x140005000),
                ),
            ],
            "mov",
        )]);

        let analysis = analyze_function_memory(&ir);
        assert_eq!(analysis.operations.len(), 1);

        let op = &analysis.operations[0];
        assert_eq!(op.kind, MemoryOperationKind::Load);
        assert_eq!(op.destination_register, Some("EAX".into()));
        assert!(matches!(
            op.location,
            MemoryLocation::Global {
                address: 0x140005000,
                ..
            }
        ));
    }

    /// Test 4: Heap access — mov eax, [rbx+rcx*4+0x10]
    /// Should classify as Heap (conservative), kind=Load
    #[test]
    fn test_heap_access_load() {
        let ir = make_function(vec![inst(
            0x140001010,
            IROp::Mov,
            vec![
                reg("EAX", OperandAccess::Write),
                mem(
                    Some("RBX"),
                    Some("RCX"),
                    4,
                    0x10,
                    4,
                    OperandAccess::Read,
                    false,
                    None,
                ),
            ],
            "mov",
        )]);

        let analysis = analyze_function_memory(&ir);
        let op = &analysis.operations[0];
        assert_eq!(op.kind, MemoryOperationKind::Load);
        assert!(matches!(op.location, MemoryLocation::Heap { .. }));
    }

    /// Test 5: ReadWrite memory — lock add [rsp], 1 (memory is both read and written)
    /// Memory operand has access=ReadWrite → kind=ReadWrite
    #[test]
    fn test_readwrite_memory() {
        let ir = make_function(vec![inst(
            0x140001015,
            IROp::Add,
            vec![
                mem(
                    Some("RSP"),
                    None,
                    1,
                    0,
                    8,
                    OperandAccess::ReadWrite,
                    false,
                    None,
                ),
                IROperand::Immediate {
                    value: 1,
                    width: 8,
                    is_signed: false,
                },
            ],
            "add",
        )]);

        let analysis = analyze_function_memory(&ir);
        let op = &analysis.operations[0];
        assert_eq!(op.kind, MemoryOperationKind::ReadWrite);
        assert!(op.kind.is_load());
        assert!(op.kind.is_store());
        // ReadWrite with immediate operand: no register data source/dest
        assert_eq!(op.destination_register, None);
        assert_eq!(op.source_register, None);
    }

    /// Test 6: destination_register must NOT use "first register" heuristic.
    /// For a Store, the first register operand might be the memory base (RSP),
    /// but RSP is inside the Memory operand, not a separate Register operand.
    /// The source register should be the register with access=Read.
    #[test]
    fn test_destination_source_not_first_register_heuristic() {
        // mov [rsp+0x20], rcx  —  RCX is source (Read), not destination
        let ir = make_function(vec![inst(
            0x140001020,
            IROp::Mov,
            vec![
                mem(
                    Some("RSP"),
                    None,
                    1,
                    0x20,
                    8,
                    OperandAccess::Write,
                    false,
                    None,
                ),
                reg("RCX", OperandAccess::Read),
            ],
            "mov",
        )]);

        let analysis = analyze_function_memory(&ir);
        let op = &analysis.operations[0];
        assert_eq!(op.kind, MemoryOperationKind::Store);
        // source_register must be RCX, not "first register" which would be wrong
        assert_eq!(op.source_register, Some("RCX".into()));
        assert_eq!(op.destination_register, None);
    }

    /// Test 7: Conservative classification — unknown base register → Heap
    /// Must NOT guess Stack or Global.
    #[test]
    fn test_conservative_unknown_base() {
        let ir = make_function(vec![inst(
            0x140001025,
            IROp::Mov,
            vec![
                reg("RAX", OperandAccess::Write),
                mem(Some("R12"), None, 1, 0, 8, OperandAccess::Read, false, None),
            ],
            "mov",
        )]);

        let analysis = analyze_function_memory(&ir);
        let op = &analysis.operations[0];
        // R12 is not RSP/RBP → must be Heap (conservative), not Stack
        assert!(matches!(op.location, MemoryLocation::Heap { .. }));
    }

    /// Test 8: Evidence chain — every operation has instruction_address and detail
    #[test]
    fn test_evidence_chain() {
        let ir = make_function(vec![
            inst(
                0x140001000,
                IROp::Mov,
                vec![
                    reg("RCX", OperandAccess::Write),
                    mem(Some("RSP"), None, 1, 8, 8, OperandAccess::Read, false, None),
                ],
                "mov",
            ),
            inst(
                0x140001005,
                IROp::Mov,
                vec![
                    mem(
                        Some("RSP"),
                        None,
                        1,
                        16,
                        8,
                        OperandAccess::Write,
                        false,
                        None,
                    ),
                    reg("RDX", OperandAccess::Read),
                ],
                "mov",
            ),
        ]);

        let analysis = analyze_function_memory(&ir);
        assert_eq!(analysis.operations.len(), 2);

        for op in &analysis.operations {
            assert!(
                op.instruction_address != 0,
                "instruction_address must be set"
            );
            assert!(
                !op.evidence_detail.is_empty(),
                "evidence_detail must not be empty"
            );
            // evidence_detail should contain the instruction address
            assert!(
                op.evidence_detail
                    .contains(&format!("0x{:x}", op.instruction_address)),
                "evidence_detail should contain instruction address"
            );
        }

        // First op is Load at 0x140001000
        assert_eq!(analysis.operations[0].instruction_address, 0x140001000);
        assert_eq!(analysis.operations[0].kind, MemoryOperationKind::Load);
        // Second op is Store at 0x140001005
        assert_eq!(analysis.operations[1].instruction_address, 0x140001005);
        assert_eq!(analysis.operations[1].kind, MemoryOperationKind::Store);
    }

    /// Test 9: MemoryOperationKind::from_access maps correctly
    #[test]
    fn test_kind_from_access() {
        assert_eq!(
            MemoryOperationKind::from_access(OperandAccess::Read),
            MemoryOperationKind::Load
        );
        assert_eq!(
            MemoryOperationKind::from_access(OperandAccess::Write),
            MemoryOperationKind::Store
        );
        assert_eq!(
            MemoryOperationKind::from_access(OperandAccess::ReadWrite),
            MemoryOperationKind::ReadWrite
        );
    }

    /// Test 10: Multiple memory operations in one function — loads and stores counted separately
    #[test]
    fn test_load_store_counts() {
        let ir = make_function(vec![
            inst(
                0x1000,
                IROp::Mov,
                vec![
                    reg("RAX", OperandAccess::Write),
                    mem(Some("RSP"), None, 1, 8, 8, OperandAccess::Read, false, None),
                ],
                "mov",
            ),
            inst(
                0x1005,
                IROp::Mov,
                vec![
                    mem(
                        Some("RSP"),
                        None,
                        1,
                        16,
                        8,
                        OperandAccess::Write,
                        false,
                        None,
                    ),
                    reg("RBX", OperandAccess::Read),
                ],
                "mov",
            ),
            inst(
                0x100a,
                IROp::Mov,
                vec![
                    reg("RCX", OperandAccess::Write),
                    mem(
                        Some("RBP"),
                        None,
                        1,
                        -8,
                        8,
                        OperandAccess::Read,
                        false,
                        None,
                    ),
                ],
                "mov",
            ),
        ]);

        let analysis = analyze_function_memory(&ir);
        assert_eq!(analysis.load_count(), 2);
        assert_eq!(analysis.store_count(), 1);
        assert_eq!(analysis.count_by_kind(MemoryOperationKind::Load), 2);
        assert_eq!(analysis.count_by_kind(MemoryOperationKind::Store), 1);
        assert_eq!(analysis.operations.len(), 3);
    }

    /// Test 11: Stack slot tracking — RSP and RBP both count as stack
    #[test]
    fn test_stack_slot_tracking() {
        let ir = make_function(vec![
            inst(
                0x1000,
                IROp::Mov,
                vec![
                    reg("RAX", OperandAccess::Write),
                    mem(
                        Some("RSP"),
                        None,
                        1,
                        -0x20,
                        8,
                        OperandAccess::Read,
                        false,
                        None,
                    ),
                ],
                "mov",
            ),
            inst(
                0x1005,
                IROp::Mov,
                vec![
                    reg("RBX", OperandAccess::Write),
                    mem(
                        Some("RBP"),
                        None,
                        1,
                        -0x18,
                        8,
                        OperandAccess::Read,
                        false,
                        None,
                    ),
                ],
                "mov",
            ),
        ]);

        let analysis = analyze_function_memory(&ir);
        assert_eq!(analysis.stack_slots.len(), 2);
        assert!(analysis.stack_slots.contains(&("RSP".to_string(), -0x20)));
        assert!(analysis.stack_slots.contains(&("RBP".to_string(), -0x18)));
    }

    // ============================================================
    // P0-4.2R: Memory Data-Register Role Correctness Tests
    // ============================================================

    /// R1: cmp [rsp+8], rax — memory is Read (Load kind) but result goes to FLAGS.
    /// destination_register MUST be None. source_register = RAX (comparison operand).
    #[test]
    fn test_cmp_memory_register_does_not_create_destination() {
        let ir = make_function(vec![inst(
            0x140002000,
            IROp::Cmp,
            vec![
                mem(Some("RSP"), None, 1, 8, 8, OperandAccess::Read, false, None),
                reg("RAX", OperandAccess::Read),
                IROperand::Flags {
                    access: OperandAccess::Write,
                },
            ],
            "cmp",
        )]);

        let analysis = analyze_function_memory(&ir);
        assert_eq!(analysis.operations.len(), 1);

        let op = &analysis.operations[0];
        assert_eq!(op.kind, MemoryOperationKind::Load);
        // CRITICAL: CMP does not produce a register destination
        assert_eq!(
            op.destination_register, None,
            "CMP must not create a memory data destination register"
        );
        // RAX is the comparison source
        assert_eq!(op.source_register, Some("RAX".into()));
    }

    /// R2: test [rsp+8], rax — same as CMP, result goes to FLAGS.
    #[test]
    fn test_test_memory_register_does_not_create_destination() {
        let ir = make_function(vec![inst(
            0x140002005,
            IROp::Test,
            vec![
                mem(Some("RSP"), None, 1, 8, 8, OperandAccess::Read, false, None),
                reg("RCX", OperandAccess::Read),
                IROperand::Flags {
                    access: OperandAccess::Write,
                },
            ],
            "test",
        )]);

        let analysis = analyze_function_memory(&ir);
        let op = &analysis.operations[0];
        assert_eq!(op.kind, MemoryOperationKind::Load);
        assert_eq!(
            op.destination_register, None,
            "TEST must not create a memory data destination register"
        );
        assert_eq!(op.source_register, Some("RCX".into()));
    }

    /// R3: mov rcx, [rsp+8] — genuine Load, destination = RCX.
    #[test]
    fn test_mov_memory_load_destination() {
        let ir = make_function(vec![inst(
            0x140002010,
            IROp::Mov,
            vec![
                reg("RCX", OperandAccess::Write),
                mem(Some("RSP"), None, 1, 8, 8, OperandAccess::Read, false, None),
            ],
            "mov",
        )]);

        let analysis = analyze_function_memory(&ir);
        let op = &analysis.operations[0];
        assert_eq!(op.kind, MemoryOperationKind::Load);
        assert_eq!(op.destination_register, Some("RCX".into()));
        assert_eq!(op.source_register, None); // no register is read
    }

    /// R4: mov [rsp+8], rax — genuine Store, source = RAX.
    #[test]
    fn test_mov_memory_store_source() {
        let ir = make_function(vec![inst(
            0x140002015,
            IROp::Mov,
            vec![
                mem(
                    Some("RSP"),
                    None,
                    1,
                    8,
                    8,
                    OperandAccess::Write,
                    false,
                    None,
                ),
                reg("RAX", OperandAccess::Read),
            ],
            "mov",
        )]);

        let analysis = analyze_function_memory(&ir);
        let op = &analysis.operations[0];
        assert_eq!(op.kind, MemoryOperationKind::Store);
        assert_eq!(op.destination_register, None);
        assert_eq!(op.source_register, Some("RAX".into()));
    }

    /// R5: add [rsp+8], rax — ReadWrite (RMW). Result goes to memory, not register.
    /// destination = None, source = RAX.
    #[test]
    fn test_readwrite_register_roles() {
        let ir = make_function(vec![inst(
            0x140002020,
            IROp::Add,
            vec![
                mem(
                    Some("RSP"),
                    None,
                    1,
                    8,
                    8,
                    OperandAccess::ReadWrite,
                    false,
                    None,
                ),
                reg("RAX", OperandAccess::Read),
                IROperand::Flags {
                    access: OperandAccess::Write,
                },
            ],
            "add",
        )]);

        let analysis = analyze_function_memory(&ir);
        let op = &analysis.operations[0];
        assert_eq!(op.kind, MemoryOperationKind::ReadWrite);
        // RMW: result goes to memory, NOT a register
        assert_eq!(
            op.destination_register, None,
            "RMW instruction must not create a register destination"
        );
        assert_eq!(op.source_register, Some("RAX".into()));
    }

    /// R6: FLAGS is never matched as destination/source (it's IROperand::Flags,
    /// not IROperand::Register). This test verifies the variant distinction holds.
    #[test]
    fn test_flags_never_matched_as_data_register() {
        // cmp [mem], rax — FLAGS is Write but must not appear as destination
        let ir = make_function(vec![inst(
            0x140002025,
            IROp::Cmp,
            vec![
                mem(Some("RSP"), None, 1, 8, 8, OperandAccess::Read, false, None),
                reg("RDX", OperandAccess::Read),
                IROperand::Flags {
                    access: OperandAccess::Write,
                },
            ],
            "cmp",
        )]);

        let analysis = analyze_function_memory(&ir);
        let op = &analysis.operations[0];
        assert_ne!(op.destination_register, Some("FLAGS".into()));
        assert_ne!(op.source_register, Some("FLAGS".into()));
        assert_eq!(op.destination_register, None);
        assert_eq!(op.source_register, Some("RDX".into()));
    }

    /// R7: pop rax — Load from stack, Pop opcode produces register destination.
    #[test]
    fn test_pop_produces_destination() {
        let ir = make_function(vec![inst(
            0x140002030,
            IROp::Pop,
            vec![
                reg("RAX", OperandAccess::Write),
                mem(Some("RSP"), None, 1, 0, 8, OperandAccess::Read, false, None),
            ],
            "pop",
        )]);

        let analysis = analyze_function_memory(&ir);
        let op = &analysis.operations[0];
        assert_eq!(op.kind, MemoryOperationKind::Load);
        assert_eq!(op.destination_register, Some("RAX".into()));
    }

    /// R8: Comprehensive instruction matrix — verify all roles at once.
    #[test]
    fn test_instruction_role_matrix() {
        let ir = make_function(vec![
            // mov rcx, [rsp+8] → Load, dest=RCX, src=None
            inst(
                0x3000,
                IROp::Mov,
                vec![
                    reg("RCX", OperandAccess::Write),
                    mem(Some("RSP"), None, 1, 8, 8, OperandAccess::Read, false, None),
                ],
                "mov",
            ),
            // mov [rsp+16], rdx → Store, dest=None, src=RDX
            inst(
                0x3005,
                IROp::Mov,
                vec![
                    mem(
                        Some("RSP"),
                        None,
                        1,
                        16,
                        8,
                        OperandAccess::Write,
                        false,
                        None,
                    ),
                    reg("RDX", OperandAccess::Read),
                ],
                "mov",
            ),
            // cmp [rsp+24], r8 → Load, dest=None, src=R8
            inst(
                0x300a,
                IROp::Cmp,
                vec![
                    mem(
                        Some("RSP"),
                        None,
                        1,
                        24,
                        8,
                        OperandAccess::Read,
                        false,
                        None,
                    ),
                    reg("R8", OperandAccess::Read),
                    IROperand::Flags {
                        access: OperandAccess::Write,
                    },
                ],
                "cmp",
            ),
            // test [rsp+32], r9 → Load, dest=None, src=R9
            inst(
                0x300f,
                IROp::Test,
                vec![
                    mem(
                        Some("RSP"),
                        None,
                        1,
                        32,
                        8,
                        OperandAccess::Read,
                        false,
                        None,
                    ),
                    reg("R9", OperandAccess::Read),
                    IROperand::Flags {
                        access: OperandAccess::Write,
                    },
                ],
                "test",
            ),
            // add [rsp+40], r10 → ReadWrite, dest=None, src=R10
            inst(
                0x3014,
                IROp::Add,
                vec![
                    mem(
                        Some("RSP"),
                        None,
                        1,
                        40,
                        8,
                        OperandAccess::ReadWrite,
                        false,
                        None,
                    ),
                    reg("R10", OperandAccess::Read),
                    IROperand::Flags {
                        access: OperandAccess::Write,
                    },
                ],
                "add",
            ),
        ]);

        let analysis = analyze_function_memory(&ir);
        assert_eq!(analysis.operations.len(), 5);

        // mov rcx, [rsp+8]
        assert_eq!(analysis.operations[0].kind, MemoryOperationKind::Load);
        assert_eq!(
            analysis.operations[0].destination_register,
            Some("RCX".into())
        );
        assert_eq!(analysis.operations[0].source_register, None);

        // mov [rsp+16], rdx
        assert_eq!(analysis.operations[1].kind, MemoryOperationKind::Store);
        assert_eq!(analysis.operations[1].destination_register, None);
        assert_eq!(analysis.operations[1].source_register, Some("RDX".into()));

        // cmp [rsp+24], r8
        assert_eq!(analysis.operations[2].kind, MemoryOperationKind::Load);
        assert_eq!(analysis.operations[2].destination_register, None);
        assert_eq!(analysis.operations[2].source_register, Some("R8".into()));

        // test [rsp+32], r9
        assert_eq!(analysis.operations[3].kind, MemoryOperationKind::Load);
        assert_eq!(analysis.operations[3].destination_register, None);
        assert_eq!(analysis.operations[3].source_register, Some("R9".into()));

        // add [rsp+40], r10
        assert_eq!(analysis.operations[4].kind, MemoryOperationKind::ReadWrite);
        assert_eq!(analysis.operations[4].destination_register, None);
        assert_eq!(analysis.operations[4].source_register, Some("R10".into()));
    }
}
