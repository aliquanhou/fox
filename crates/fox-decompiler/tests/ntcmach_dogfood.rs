//! P0-6.1 / P0-6.3A NtcMach.exe real-world dogfood.
//!
//! P0-6.1: Expression Recovery (SSA → Expression Tree).
//! P0-6.3A: Condition Recovery (CMP/TEST + Jcc → structured condition).
//!
//! Loads the real commercial binary, runs the analysis pipeline,
//! and validates on a SMALL SAMPLE of actual SSA data.
//! NOT full-binary recovery (that would be too heavy for a test).

use fox_analysis::analyze_binary;
use fox_binary::Binary;
use fox_decompiler::{recover_all_conditions, ConditionRecovery, Expression, ExpressionRecovery};
use std::path::PathBuf;

fn ntcmach_path() -> PathBuf {
    let candidates = vec![
        r"C:\Users\Administrator\Desktop\制版软件\NtcMach.exe",
        r"..\..\..\..\..\Desktop\制版软件\NtcMach.exe",
    ];
    for c in candidates {
        let p = PathBuf::from(c);
        if p.exists() {
            return p;
        }
    }
    panic!("NtcMach.exe not found");
}

#[test]
fn ntcmach_expression_recovery_dogfood() {
    let path = ntcmach_path();
    let data = std::fs::read(&path).expect("read NtcMach.exe");
    let binary = Binary::load(data).expect("parse NtcMach.exe");
    let result = analyze_binary(&binary).expect("analyze NtcMach.exe");

    // Conservative settings for real binary
    let recovery = ExpressionRecovery {
        max_depth: 32,
        max_nodes: 500,
        function_total_budget: 5000,
    };

    let mut sampled = 0;
    let mut total_definitions = 0;
    let mut total_binary_ops = 0;
    let mut total_loads = 0;
    let mut total_unknown = 0;
    let mut sample_outputs: Vec<String> = Vec::new();

    // Only sample the first 3 functions that have SSA
    for (addr, ctx) in &result.pipeline.function_analysis {
        if sampled >= 3 {
            break;
        }
        let ssa = match &ctx.ssa {
            Some(s) => s,
            None => continue,
        };

        // Skip thunk/tiny functions (≤2 instructions skip SSA in pipeline)
        if ssa.basic_blocks.is_empty() || ssa.basic_blocks[0].instructions.is_empty() {
            continue;
        }

        sampled += 1;

        // Only recover first 5 definitions per function to keep it light
        let defs = recovery.recover_all_definitions(ssa);
        let defs: Vec<_> = defs.into_iter().take(5).collect();

        for (_block, _inst, name, version, expr) in &defs {
            total_definitions += 1;
            match expr {
                Expression::Binary { .. } => total_binary_ops += 1,
                Expression::Load { .. } => total_loads += 1,
                Expression::Unknown { .. } => total_unknown += 1,
                _ => {}
            }
            if sample_outputs.len() < 10 {
                sample_outputs.push(format!(
                    "  func@0x{:x} {}.{} = {}",
                    addr, name, version, expr
                ));
            }
        }
    }

    println!("=== P0-6.1 NtcMach Expression Recovery Dogfood (sampled) ===");
    println!("Functions sampled: {}", sampled);
    println!("Definitions recovered: {}", total_definitions);
    println!("  Binary ops: {}", total_binary_ops);
    println!("  Loads: {}", total_loads);
    println!("  Unknown: {}", total_unknown);
    println!();
    println!("Sample expressions:");
    for s in &sample_outputs {
        println!("{}", s);
    }

    assert!(sampled > 0, "no functions with SSA found");
    assert!(total_definitions > 0, "no definitions recovered");
}

/// P0-6.3A: Condition Recovery dogfood on NtcMach 0x401390.
///
/// This function has two early-return patterns:
///   test ecx, ecx  @ 0x4013B3  →  jnz @ 0x4013B5
///   test eax, eax  @ 0x4013F2  →  jnz @ 0x4013F4
///
/// Validates the full chain: TEST → FLAGS version → JNZ condition → C-like condition.
#[test]
fn ntcmach_condition_recovery_dogfood_0x401390() {
    let path = ntcmach_path();
    let data = std::fs::read(&path).expect("read NtcMach.exe");
    let binary = Binary::load(data).expect("parse NtcMach.exe");
    let result = analyze_binary(&binary).expect("analyze NtcMach.exe");

    let target_addr = 0x401390u64;
    let ctx = result
        .pipeline
        .function_analysis
        .get(&target_addr)
        .expect("function 0x401390 not found");
    let ssa = ctx.ssa.as_ref().expect("SSA not built for 0x401390");

    println!("=== P0-6.3A NtcMach Condition Recovery Dogfood: 0x401390 ===");
    println!("SSA proper_renaming: {}", ssa.proper_renaming);
    println!(
        "FLAGS max version: {:?}",
        ssa.variable_versions.get("FLAGS")
    );
    assert!(
        ssa.variable_versions.get("FLAGS").is_some_and(|v| *v > 0),
        "FLAGS must be versioned (was all v0 before P0-6.3A)"
    );
    assert!(
        !ssa.variable_versions.contains_key("eflags"),
        "eflags dual-model must be eliminated"
    );

    let conditions = recover_all_conditions(ssa);
    println!("Total CondJump instructions: {}", conditions.len());

    let mut resolved = 0;
    let mut producer_not_cmp = 0;
    let mut not_found = 0;

    for c in &conditions {
        match c {
            ConditionRecovery::Resolved(cond) => {
                resolved += 1;
                println!(
                    "  RESOLVED @ 0x{:X}: {}  (producer @ 0x{:X}, {})",
                    cond.branch_address,
                    cond,
                    cond.flags_producer_address,
                    if cond.is_test { "TEST" } else { "CMP" }
                );
            }
            ConditionRecovery::ProducerNotCmpTest {
                producer_address,
                producer_op,
                branch_address,
                ..
            } => {
                producer_not_cmp += 1;
                println!(
                    "  PRODUCER_NOT_CMP/TEST @ 0x{:X}: producer=0x{:X} op={}",
                    branch_address, producer_address, producer_op
                );
            }
            ConditionRecovery::ProducerNotFound { branch_address, .. } => {
                not_found += 1;
                println!("  PRODUCER_NOT_FOUND @ 0x{:X}", branch_address);
            }
            ConditionRecovery::NotConditionalJump => {}
        }
    }

    println!();
    println!("Resolved: {}", resolved);
    println!("Producer not CMP/TEST: {}", producer_not_cmp);
    println!("Producer not found: {}", not_found);

    // 0x401390 must have at least the two test+jnz early-return conditions resolved
    assert!(
        resolved >= 2,
        "expected at least 2 resolved conditions (test ecx + test eax), got {}",
        resolved
    );

    // Verify the two specific early-return conditions
    let early_returns: Vec<_> = conditions
        .iter()
        .filter_map(|c| match c {
            ConditionRecovery::Resolved(cond) => Some(cond),
            _ => None,
        })
        .filter(|c| c.branch_address == 0x4013B5 || c.branch_address == 0x4013F4)
        .collect();

    assert_eq!(
        early_returns.len(),
        2,
        "expected both early-return JNZ conditions resolved"
    );

    for cond in &early_returns {
        assert!(cond.is_test, "early-return producer should be TEST");
        assert_eq!(
            cond.operator,
            fox_ir::JumpCondition::NotEqual,
            "early-return branch should be JNZ (NotEqual)"
        );
        // test reg, reg → both operands are the same register
        match (&cond.left, &cond.right) {
            (
                fox_decompiler::ConditionOperand::Register { name: ln, .. },
                fox_decompiler::ConditionOperand::Register { name: rn, .. },
            ) => {
                assert_eq!(ln, rn, "test reg,reg should have same register operands");
            }
            _ => panic!("test reg,reg should have register operands"),
        }
    }

    println!();
    println!("P0-6.3A Condition Recovery dogfood PASSED");
}
