//! FOX Robustness / Fuzz Tests
//!
//! P0-1 requirement: Malformed PE must not panic/crash/out-of-bounds.
//! Must return structured errors.

use fox_binary::Binary;

/// Helper: create a minimal valid PE32+ header template
fn minimal_pe_template() -> Vec<u8> {
    // DOS header + PE signature + COFF header + Optional header
    let mut data = vec![0u8; 0x200];

    // DOS header
    data[0] = 0x4D; // 'M'
    data[1] = 0x5A; // 'Z'
                    // e_lfanew at 0x3C
    data[0x3C] = 0x80;
    data[0x3D] = 0x00;
    data[0x3E] = 0x00;
    data[0x3F] = 0x00;

    // PE signature at 0x80
    data[0x80] = 0x50; // 'P'
    data[0x81] = 0x45; // 'E'
    data[0x82] = 0x00;
    data[0x83] = 0x00;

    // COFF header at 0x84
    data[0x84] = 0x64; // Machine = x86-64 (0x8664)
    data[0x85] = 0x86;
    data[0x86] = 0x01; // NumberOfSections = 1
    data[0x87] = 0x00;
    // TimeDateStamp at 0x88
    // PointerToSymbolTable at 0x8C
    // NumberOfSymbols at 0x90
    data[0x94] = 0xF0; // SizeOfOptionalHeader = 0xF0 (240)
    data[0x95] = 0x00;
    data[0x96] = 0x22; // Characteristics = EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    data[0x97] = 0x00;

    // Optional header at 0x98
    data[0x98] = 0x0B; // Magic = PE32+ (0x20B)
    data[0x99] = 0x02;
    // ... rest zeroed is acceptable for minimal parse

    data
}

#[test]
fn test_truncated_pe() {
    // Truncated at various points must not panic
    for len in [
        0, 1, 2, 4, 0x3C, 0x40, 0x7F, 0x80, 0x83, 0x84, 0x97, 0x98, 0x100,
    ] {
        let data = &minimal_pe_template()[..len];
        let result = Binary::load(data.to_vec());
        // Should return Err, not panic
        assert!(
            result.is_err(),
            "Expected error for truncated PE of length {}",
            len
        );
    }
}

#[test]
fn test_invalid_dos_signature() {
    let mut data = minimal_pe_template();
    data[0] = 0x00;
    data[1] = 0x00;
    let result = Binary::load(data);
    assert!(result.is_err());
}

#[test]
fn test_invalid_pe_signature() {
    let mut data = minimal_pe_template();
    data[0x80] = 0x00;
    data[0x81] = 0x00;
    let result = Binary::load(data);
    assert!(result.is_err());
}

#[test]
fn test_invalid_machine_type() {
    let mut data = minimal_pe_template();
    data[0x84] = 0xFF;
    data[0x85] = 0xFF;
    let result = Binary::load(data);
    // Should either error or parse as unknown architecture, not panic
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_section_count_overflow() {
    let mut data = minimal_pe_template();
    data[0x86] = 0xFF; // NumberOfSections = 255
    data[0x87] = 0xFF; // = 65535
    let result = Binary::load(data);
    // Should not panic, may error due to missing section headers
    let _ = result;
}

#[test]
fn test_invalid_section_rva() {
    let mut data = minimal_pe_template();
    // Add a section header with invalid RVA
    let section_off = 0x98 + 0xF0; // after optional header
    if section_off + 40 <= data.len() {
        data[section_off..section_off + 8].copy_from_slice(b".text\0\0\0");
        data[section_off + 12] = 0xFF; // VirtualSize huge
        data[section_off + 13] = 0xFF;
        data[section_off + 14] = 0xFF;
        data[section_off + 15] = 0xFF;
    }
    let result = Binary::load(data);
    let _ = result;
}

#[test]
fn test_zero_length_data() {
    let result = Binary::load(vec![]);
    assert!(result.is_err());
}

#[test]
fn test_random_bytes() {
    // Completely random bytes should not panic
    let data: Vec<u8> = (0..256).map(|i| (i * 7 + 13) as u8).collect();
    let result = Binary::load(data);
    let _ = result;
}

#[test]
fn test_all_zeros() {
    let data = vec![0u8; 1024];
    let result = Binary::load(data);
    assert!(result.is_err());
}

#[test]
fn test_all_ff() {
    let data = vec![0xFFu8; 1024];
    let result = Binary::load(data);
    let _ = result;
}

#[test]
fn test_invalid_import_rva() {
    // PE with import directory pointing to invalid RVA
    let mut data = minimal_pe_template();
    // Set import directory RVA in optional header data directories
    // For PE32+, import directory is at offset 0x98 + 112 = 0x108
    let import_dir_off = 0x98 + 112;
    if import_dir_off + 8 <= data.len() {
        data[import_dir_off] = 0xFF; // Invalid RVA
        data[import_dir_off + 1] = 0xFF;
        data[import_dir_off + 2] = 0xFF;
        data[import_dir_off + 3] = 0xFF;
    }
    let result = Binary::load(data);
    let _ = result;
}

#[test]
fn test_analysis_on_malformed_binary() {
    // Even if binary parses, analysis should not panic
    let data = minimal_pe_template();
    if let Ok(binary) = Binary::load(data) {
        let result = fox_analysis::analyze_binary(&binary);
        // Should produce some result, not panic
        let _ = result;
    }
}

#[test]
fn test_disasm_on_invalid_bytes() {
    // Disassembler should handle invalid instruction streams gracefully
    use fox_arch::Architecture;
    use fox_disasm::create_disassembler;

    let disasm = create_disassembler(Architecture::X64).unwrap();
    let invalid_data = [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00];
    let result = disasm.disassemble(&invalid_data, 0x1000);
    // Should return Ok with some instructions or empty, not Err/panic
    assert!(result.is_ok());
}

// === P0-2 Analysis Robustness Tests ===

use fox_analysis::dataflow::DataFlowResult;
use fox_analysis::dominators::DominatorTree;
use fox_analysis::ssa::SSAConstructor;
use fox_analysis::type_recovery::TypeRecovery;
use fox_core::Address;
use fox_ir::{IRBasicBlock, IRFunction, IRInstruction, IROp, IROperand, OperandAccess};
use std::collections::{HashMap, HashSet};
fn make_empty_ir_func() -> IRFunction {
    IRFunction {
        name: "empty".into(),
        address: Address(0x1000),
        basic_blocks: vec![IRBasicBlock {
            id: 0,
            start_address: Address(0x1000),
            end_address: Address(0x1000),
            instructions: vec![],
            successors: vec![],
            predecessors: vec![],
        }],
        entry_block: 0,
    }
}

fn make_self_loop_cfg() -> (HashMap<usize, Vec<usize>>, HashMap<usize, Vec<usize>>) {
    let mut succ = HashMap::new();
    succ.insert(0, vec![0]); // self-loop
    let mut pred = HashMap::new();
    pred.insert(0, vec![0]);
    (succ, pred)
}

fn make_unreachable_block_cfg() -> (HashMap<usize, Vec<usize>>, HashMap<usize, Vec<usize>>) {
    let mut succ = HashMap::new();
    succ.insert(0, vec![1]);
    succ.insert(1, vec![]);
    succ.insert(2, vec![]); // unreachable
    let mut pred = HashMap::new();
    pred.insert(0, vec![]);
    pred.insert(1, vec![0]);
    pred.insert(2, vec![]); // no predecessors
    (succ, pred)
}

#[test]
fn test_dataflow_empty_instructions() {
    // Data flow on empty instruction list must not panic
    let df = DataFlowResult::analyze(0x1000, &[]);
    assert!(df.reaching_definitions.definitions.is_empty());
    assert_eq!(df.constant_propagation.propagated_count, 0);
}

#[test]
fn test_dominators_self_loop() {
    // Dominator analysis on self-loop CFG must not infinite-loop or panic
    let (succ, pred) = make_self_loop_cfg();
    let dt = DominatorTree::compute(&succ, &pred, 0, 1);
    assert!(dt.dominates(0, 0));
}

#[test]
fn test_dominators_unreachable_block() {
    // Dominator analysis with unreachable block must not panic
    let (succ, pred) = make_unreachable_block_cfg();
    let dt = DominatorTree::compute(&succ, &pred, 0, 3);
    assert_eq!(dt.block_count, 3);
}

#[test]
fn test_ssa_empty_function() {
    // SSA construction on empty function must not panic
    let func = make_empty_ir_func();
    let ssa = SSAConstructor::construct(&func);
    assert!(ssa.phi_nodes.is_empty());
}

#[test]
fn test_type_recovery_empty_instructions() {
    // Type recovery on empty instruction list must not panic
    let result = TypeRecovery::analyze(0x1000, &[]);
    assert!(result.inferences.is_empty());
}

#[test]
fn test_dataflow_recursive_function_pattern() {
    // Simulate a recursive call pattern: function calls itself
    let insts = vec![
        IRInstruction {
            address: Address(0x1000),
            op: IROp::Call,
            operands: vec![IROperand::Label("self".into())],
            original_mnemonic: Some("call".into()),
            original_operands: None,
            size: 5,
            reads_registers: vec![],
            writes_registers: vec![],
            implicit_reads: vec!["rsp".into()],
            implicit_writes: vec!["rsp".into()],
            reads_flags: false,
            writes_flags: false,
        },
        IRInstruction {
            address: Address(0x1005),
            op: IROp::Return,
            operands: vec![],
            original_mnemonic: Some("ret".into()),
            original_operands: None,
            size: 1,
            reads_registers: vec![],
            writes_registers: vec![],
            implicit_reads: vec!["rsp".into()],
            implicit_writes: vec!["rsp".into()],
            reads_flags: false,
            writes_flags: false,
        },
    ];
    let df = DataFlowResult::analyze(0x1000, &insts);
    // Should not panic, should produce some analysis
    assert!(df.reaching_definitions.reaching.len() <= 2);
}

#[test]
fn test_ssa_indirect_jump_block() {
    // SSA on CFG with indirect jump (unknown successor) must not panic
    let func = IRFunction {
        name: "indirect".into(),
        address: Address(0x1000),
        basic_blocks: vec![IRBasicBlock {
            id: 0,
            start_address: Address(0x1000),
            end_address: Address(0x1003),
            instructions: vec![IRInstruction {
                address: Address(0x1000),
                op: IROp::Jump,
                operands: vec![IROperand::Register {
                    name: "rax".into(),
                    width: 64,
                    access: OperandAccess::Read,
                }],
                original_mnemonic: Some("jmp".into()),
                original_operands: None,
                size: 2,
                reads_registers: vec!["rax".into()],
                writes_registers: vec![],
                implicit_reads: vec![],
                implicit_writes: vec![],
                reads_flags: false,
                writes_flags: false,
            }],
            successors: vec![], // unknown target
            predecessors: vec![],
        }],
        entry_block: 0,
    };
    let ssa = SSAConstructor::construct(&func);
    // Should not panic
    assert_eq!(ssa.basic_blocks.len(), 1);
}
