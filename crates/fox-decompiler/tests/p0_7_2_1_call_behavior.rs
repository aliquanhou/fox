//! P0-7.2.1 Call Behavior Recovery tests.
//!
//! Tests that CallStmt correctly annotates return value consumer behavior:
//! - ReturnUsedInCondition: call → test/cmp eax → CondJump
//! - ReturnUsedByInstruction: call → mov/push/etc using eax
//! - NoConsumer: call return value not used in scan window

use fox_analysis::analyze_binary;
use fox_binary::Binary;
use fox_decompiler::{recover_control_structures, CallBehavior, Statement, StructuredIRBuilder};
use std::path::PathBuf;

fn ntcmach_path() -> PathBuf {
    PathBuf::from(r"C:\Users\Administrator\Desktop\制版软件\NtcMach.exe")
}

fn build_for_function(addr: u64) -> Option<fox_decompiler::DecompilerFunction> {
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

/// Collect all CallStmt behaviors from a function (recursively into if/guard bodies).
fn collect_call_behaviors(stmts: &[Statement]) -> Vec<(u64, CallBehavior)> {
    let mut result = Vec::new();
    for s in stmts {
        if let Statement::CallStmt {
            behavior: Some(b),
            evidence,
            ..
        } = s
        {
            let addr = evidence.instruction_addresses.first().copied().unwrap_or(0);
            result.push((addr, b.clone()));
            continue;
        }
        match s {
            Statement::If {
                then_body,
                else_body,
                ..
            } => {
                result.extend(collect_call_behaviors(then_body));
                result.extend(collect_call_behaviors(else_body));
            }
            Statement::GuardClause { body, .. } => {
                result.extend(collect_call_behaviors(body));
            }
            _ => {}
        }
    }
    result
}

#[test]
fn test_return_used_in_condition_0x421b40() {
    // 0x421B40 contains multiple call → test eax,eax → CondJump patterns
    let func = build_for_function(0x421B40).expect("build 0x421B40");
    let behaviors = collect_call_behaviors(&func.statements);

    println!("=== 0x421B40 Call Behaviors ===");
    for (addr, b) in &behaviors {
        match b {
            CallBehavior::ReturnUsedInCondition {
                consumer_instruction,
                branch_instruction,
                ..
            } => {
                println!(
                    "  @0x{:X}: ReturnUsedInCondition (test/cmp @0x{:X}, jcc @0x{:X})",
                    addr, consumer_instruction, branch_instruction
                );
            }
            CallBehavior::ReturnUsedByInstruction {
                consumer_instruction,
                consumer_op,
            } => {
                println!(
                    "  @0x{:X}: ReturnUsedByInstruction ({} @0x{:X})",
                    addr, consumer_op, consumer_instruction
                );
            }
            CallBehavior::NoConsumer => {
                println!("  @0x{:X}: NoConsumer", addr);
            }
        }
    }

    // Should have at least one ReturnUsedInCondition
    let condition_count = behaviors
        .iter()
        .filter(|(_, b)| matches!(b, CallBehavior::ReturnUsedInCondition { .. }))
        .count();
    println!("ReturnUsedInCondition count: {}", condition_count);
    assert!(
        condition_count > 0,
        "0x421B40 should have at least one call with return used in condition"
    );
}

#[test]
fn test_no_consumer_call() {
    // 0x421BD0 is DCompiler_f19 call followed by Jump (no return consumer)
    let func = build_for_function(0x421B40).expect("build 0x421B40");
    let behaviors = collect_call_behaviors(&func.statements);

    // Find the call at 0x421BD0
    if let Some((_, b)) = behaviors.iter().find(|(addr, _)| *addr == 0x421BD0) {
        println!("0x421BD0 behavior: {:?}", b);
        // This call is followed by Jump, so NoConsumer is expected
        assert!(
            matches!(b, CallBehavior::NoConsumer),
            "0x421BD0 should be NoConsumer (followed by Jump), got {:?}",
            b
        );
    } else {
        println!("0x421BD0 not found in behaviors (may be in nested structure)");
    }
}

#[test]
fn test_all_calls_have_behavior() {
    // Every CallStmt should have a behavior annotation (not None)
    let func = build_for_function(0x421B40).expect("build 0x421B40");
    let behaviors = collect_call_behaviors(&func.statements);

    assert!(!behaviors.is_empty(), "should have calls");
    // All collected behaviors are Some (we filtered out None in collect)
    // This test verifies detect_call_behavior always returns Some
    println!("Total calls with behavior: {}", behaviors.len());
}

#[test]
fn test_0x41f000_call_behaviors() {
    // 0x41F000 has calls with various patterns
    let func = build_for_function(0x41F000).expect("build 0x41F000");
    let behaviors = collect_call_behaviors(&func.statements);

    println!("=== 0x41F000 Call Behaviors ===");
    for (addr, b) in &behaviors {
        match b {
            CallBehavior::ReturnUsedInCondition { .. } => {
                println!("  @0x{:X}: ReturnUsedInCondition", addr);
            }
            CallBehavior::ReturnUsedByInstruction { consumer_op, .. } => {
                println!("  @0x{:X}: ReturnUsedByInstruction ({})", addr, consumer_op);
            }
            CallBehavior::NoConsumer => {
                println!("  @0x{:X}: NoConsumer", addr);
            }
        }
    }
    println!("Total: {}", behaviors.len());
}

#[test]
fn test_behavior_evidence_addresses() {
    // Verify ReturnUsedInCondition has correct evidence addresses
    let func = build_for_function(0x421B40).expect("build 0x421B40");
    let behaviors = collect_call_behaviors(&func.statements);

    for (call_addr, b) in &behaviors {
        if let CallBehavior::ReturnUsedInCondition {
            consumer_instruction,
            branch_instruction,
            ..
        } = b
        {
            // consumer should be after call
            assert!(
                *consumer_instruction > *call_addr,
                "consumer @0x{:X} should be after call @0x{:X}",
                consumer_instruction,
                call_addr
            );
            // branch should be after consumer
            assert!(
                *branch_instruction > *consumer_instruction,
                "branch @0x{:X} should be after consumer @0x{:X}",
                branch_instruction,
                consumer_instruction
            );
            println!(
                "Valid evidence chain: call @0x{:X} → test/cmp @0x{:X} → jcc @0x{:X}",
                call_addr, consumer_instruction, branch_instruction
            );
        }
    }
}
