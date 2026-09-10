//! P0-6.6A Dogfood: Structured IR on real NtcMach functions.
//! Tests: 0x41C9A8 (linear), 0x41F000 (control flow), 0x401390 (scale).

use fox_analysis::analyze_binary;
use fox_binary::Binary;
use fox_decompiler::{recover_control_structures, DecompilerFunction, StructuredIRBuilder};
use std::path::PathBuf;

fn ntcmach_path() -> PathBuf {
    PathBuf::from(r"C:\Users\Administrator\Desktop\制版软件\NtcMach.exe")
}

fn build_for_function(addr: u64) -> Option<DecompilerFunction> {
    let path = ntcmach_path();
    let data = std::fs::read(&path).ok()?;
    let binary = Binary::load(data).ok()?;
    let result = analyze_binary(&binary).ok()?;

    let func_cfg = result
        .cfg
        .function_cfgs
        .iter()
        .find(|f| f.function_address.0 == addr)?;
    let ctx = result.pipeline.function_analysis.get(&addr)?;
    let ssa = ctx.ssa.as_ref()?;

    let control_structures = recover_control_structures(func_cfg, ssa);
    let mut builder = StructuredIRBuilder::new();
    Some(builder.build(func_cfg, ssa, control_structures))
}

#[test]
fn gate_b_0x41c9a8_linear() {
    let func = build_for_function(0x41C9A8).expect("build 0x41C9A8");
    println!("=== Gate B: 0x41C9A8 (linear smoke test) ===");
    println!("{}", func);
    println!();

    // Assertions
    assert_eq!(func.address, 0x41C9A8);
    assert!(!func.statements.is_empty(), "should have statements");
    assert!(
        func.statements
            .iter()
            .any(|s| matches!(s, fox_decompiler::Statement::Return { .. })),
        "should have a Return statement"
    );
    assert!(
        func.statements
            .iter()
            .any(|s| matches!(s, fox_decompiler::Statement::Assign { .. })),
        "should have Assign statements"
    );
    assert!(
        !func.evidence.budget_exhausted,
        "budget should not be exhausted"
    );
    println!(
        "Gate B PASS: {} statements, {} unknown",
        func.statements.len(),
        func.evidence.unknown_statements
    );
}

#[test]
fn gate_c_0x41f000_control_flow() {
    let func = build_for_function(0x41F000).expect("build 0x41F000");
    println!("=== Gate C: 0x41F000 (control flow) ===");
    println!("{}", func);
    println!();

    // Assertions
    assert_eq!(func.address, 0x41F000);
    assert!(!func.statements.is_empty());

    // Should have GuardClause (jz @ 0x41F010)
    let has_guard = func
        .statements
        .iter()
        .any(|s| matches!(s, fox_decompiler::Statement::GuardClause { .. }));
    assert!(has_guard, "should have GuardClause (jz @ 0x41F010)");

    // Should have Unknown (jz @ 0x41F020, double return)
    let has_unknown = func
        .statements
        .iter()
        .any(|s| matches!(s, fox_decompiler::Statement::Unknown { .. }));
    assert!(
        has_unknown,
        "should have Unknown (jz @ 0x41F020 double return)"
    );

    // Should have Return
    let has_return = func
        .statements
        .iter()
        .any(|s| matches!(s, fox_decompiler::Statement::Return { .. }));
    assert!(has_return, "should have Return");

    // Unknown is first-class: check it has a reason
    for s in &func.statements {
        if let fox_decompiler::Statement::Unknown { reason, .. } = s {
            assert!(!reason.is_empty(), "Unknown should have a reason");
            println!("  Unknown reason: {}", reason);
        }
    }

    println!(
        "Gate C PASS: {} statements, {} guard, {} unknown",
        func.statements.len(),
        func.statements
            .iter()
            .filter(|s| matches!(s, fox_decompiler::Statement::GuardClause { .. }))
            .count(),
        func.evidence.unknown_statements
    );
}

#[test]
fn gate_e_0x401390_scale() {
    let func = build_for_function(0x401390).expect("build 0x401390");
    println!("=== Gate E: 0x401390 (scale / resource budget) ===");
    println!("Address: 0x{:X}", func.address);
    println!("Statements: {}", func.statements.len());
    println!("SSA instrs: {}", func.evidence.ssa_instructions);
    println!("CFG blocks: {}", func.evidence.cfg_blocks);
    println!("Control structures: {}", func.evidence.control_structures);
    println!("Unknown statements: {}", func.evidence.unknown_statements);
    println!("Budget exhausted: {}", func.evidence.budget_exhausted);
    println!();

    // Print first 30 statements
    println!("--- First 30 statements ---");
    for (i, s) in func.statements.iter().take(30).enumerate() {
        let kind = match s {
            fox_decompiler::Statement::Assign { .. } => "Assign",
            fox_decompiler::Statement::If { .. } => "If",
            fox_decompiler::Statement::GuardClause { .. } => "GuardClause",
            fox_decompiler::Statement::Return { .. } => "Return",
            fox_decompiler::Statement::CallStmt { .. } => "CallStmt",
            fox_decompiler::Statement::Unknown { .. } => "Unknown",
            fox_decompiler::Statement::PhiAssign { .. } => "PhiAssign",
        };
        println!("  {:3}: {}", i, kind);
    }

    // Assertions: must not crash/OOM, must produce statements
    assert_eq!(func.address, 0x401390);
    assert!(!func.statements.is_empty(), "should produce statements");

    // Should have If and GuardClause (large function with many branches)
    let if_count = func
        .statements
        .iter()
        .filter(|s| matches!(s, fox_decompiler::Statement::If { .. }))
        .count();
    let guard_count = func
        .statements
        .iter()
        .filter(|s| matches!(s, fox_decompiler::Statement::GuardClause { .. }))
        .count();
    println!();
    println!("If: {}, GuardClause: {}", if_count, guard_count);
    assert!(if_count > 0, "should have If statements");
    assert!(guard_count > 0, "should have GuardClause statements");

    // Budget: either not exhausted, or if exhausted, it should be graceful
    // (no panic/OOM is the key requirement)
    println!("Gate E PASS: completed without crash/OOM");
}

#[test]
fn gate_d_evidence_traceability() {
    // Verify every statement has evidence with instruction addresses
    let func = build_for_function(0x41F000).expect("build 0x41F000");

    for (i, stmt) in func.statements.iter().enumerate() {
        let evidence = match stmt {
            fox_decompiler::Statement::Assign { evidence, .. } => evidence,
            fox_decompiler::Statement::If { evidence, .. } => evidence,
            fox_decompiler::Statement::GuardClause { evidence, .. } => evidence,
            fox_decompiler::Statement::Return { evidence, .. } => evidence,
            fox_decompiler::Statement::CallStmt { evidence, .. } => evidence,
            fox_decompiler::Statement::Unknown { evidence, .. } => evidence,
            fox_decompiler::Statement::PhiAssign { evidence, .. } => evidence,
        };
        assert!(
            !evidence.instruction_addresses.is_empty(),
            "statement {} should have at least one instruction address",
            i
        );
        assert!(
            !evidence.reason.is_empty(),
            "statement {} should have a reason",
            i
        );
    }
    println!(
        "Gate D PASS: all {} statements have evidence",
        func.statements.len()
    );
}
