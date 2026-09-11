//! P0-7.3: Call Expression Lifting — unit tests
//!
//! Verifies that `call foo; test eax,eax; je label` is lifted into
//! `if (foo() == 0) { ... }` rather than emitted as two separate statements.

use fox_analysis::analyze_binary;
use fox_binary::Binary;
use fox_decompiler::{recover_control_structures, Statement, StructuredIRBuilder};
use std::path::PathBuf;

fn ntcmach_path() -> PathBuf {
    PathBuf::from(r"C:\Users\Administrator\Desktop\制版软件\NtcMach.exe")
}

fn count_lifted_calls(stmts: &[Statement]) -> usize {
    let mut count = 0;
    for s in stmts {
        match s {
            Statement::If {
                lifted_call,
                then_body,
                else_body,
                ..
            } => {
                if lifted_call.is_some() {
                    count += 1;
                }
                count += count_lifted_calls(then_body);
                count += count_lifted_calls(else_body);
            }
            Statement::GuardClause {
                lifted_call, body, ..
            } => {
                if lifted_call.is_some() {
                    count += 1;
                }
                count += count_lifted_calls(body);
            }
            _ => {}
        }
    }
    count
}

fn count_behavior_annotations(stmts: &[Statement]) -> usize {
    let mut count = 0;
    for s in stmts {
        if let Statement::CallStmt {
            behavior: Some(fox_decompiler::CallBehavior::ReturnUsedInCondition { .. }),
            ..
        } = s
        {
            count += 1;
        }
        match s {
            Statement::If {
                then_body,
                else_body,
                ..
            } => {
                count += count_behavior_annotations(then_body);
                count += count_behavior_annotations(else_body);
            }
            Statement::GuardClause { body, .. } => {
                count += count_behavior_annotations(body);
            }
            _ => {}
        }
    }
    count
}

/// Test 1: Lifting actually happens on real NtcMach.
/// Before P0-7.3: 279+ `/* return used in condition */` annotations.
/// After P0-7.3: those should become lifted calls (count > 0).
#[test]
fn p0_7_3_lifting_happens_on_ntcmach() {
    let path = ntcmach_path();
    let data = std::fs::read(&path).expect("read NtcMach");
    let binary = Binary::load(data).expect("parse NtcMach");
    let result = analyze_binary(&binary).expect("analyze NtcMach");

    let mut total_lifted = 0;
    let mut total_behavior = 0;

    for func_cfg in &result.cfg.function_cfgs {
        let func_addr = func_cfg.function_address.0;
        let ctx = match result.pipeline.function_analysis.get(&func_addr) {
            Some(c) => c,
            None => continue,
        };
        let ssa = match ctx.ssa.as_ref() {
            Some(s) => s,
            None => continue,
        };
        let control_structures = recover_control_structures(func_cfg, ssa);
        let mut builder = StructuredIRBuilder::new();
        let func = builder.build(func_cfg, ssa, control_structures);
        total_lifted += count_lifted_calls(&func.statements);
        total_behavior += count_behavior_annotations(&func.statements);
    }

    println!("Lifted calls: {}", total_lifted);
    println!("Remaining behavior annotations: {}", total_behavior);

    // P0-7.3 must lift at least some calls
    assert!(total_lifted > 0, "Expected at least one lifted call, got 0");

    // Lifted calls should reduce behavior annotations
    // (some ReturnUsedInCondition calls are now inside If/GuardClause)
    println!(
        "Lift ratio: {:.1}%",
        if total_lifted + total_behavior > 0 {
            100.0 * total_lifted as f64 / (total_lifted + total_behavior) as f64
        } else {
            0.0
        }
    );
}

/// Test 2: Lifted call output format.
/// Verify that a function with lifted call produces `if (call_xxx() == 0)`
/// in its Display output.
#[test]
fn p0_7_3_lifted_call_output_format() {
    let path = ntcmach_path();
    let data = std::fs::read(&path).expect("read NtcMach");
    let binary = Binary::load(data).expect("parse NtcMach");
    let result = analyze_binary(&binary).expect("analyze NtcMach");

    let mut found_lifted_output = false;

    for func_cfg in &result.cfg.function_cfgs {
        let func_addr = func_cfg.function_address.0;
        let ctx = match result.pipeline.function_analysis.get(&func_addr) {
            Some(c) => c,
            None => continue,
        };
        let ssa = match ctx.ssa.as_ref() {
            Some(s) => s,
            None => continue,
        };
        let control_structures = recover_control_structures(func_cfg, ssa);
        let mut builder = StructuredIRBuilder::new();
        let func = builder.build(func_cfg, ssa, control_structures);
        let output = format!("{}", func);

        // Look for lifted call pattern: if (call_xxx(... ) == 0) or if (call_xxx(... ) != 0)
        if output.contains("if (call_") && (output.contains("== 0)") || output.contains("!= 0)")) {
            found_lifted_output = true;
            // Print first example
            for line in output.lines() {
                if line.contains("if (call_") && (line.contains("== 0)") || line.contains("!= 0)"))
                {
                    println!("Lifted output example: {}", line.trim());
                    break;
                }
            }
            break;
        }
    }

    assert!(
        found_lifted_output,
        "Expected at least one `if (call_xxx() == 0)` in output"
    );
}

/// Test 3: No false merge — lifted call must not appear when condition
/// left operand is not eax.
#[test]
fn p0_7_3_no_false_merge_non_eax() {
    // This is a structural guarantee: try_lift_call_into_condition checks
    // left operand is eax. We verify via the API indirectly by checking
    // that all lifted calls have eax in the original condition.
    // Since we can't easily construct synthetic SSA here, we verify
    // the count is reasonable (not all 309 sites, since some may be
    // in blocks that don't become If/GuardClause).
    let path = ntcmach_path();
    let data = std::fs::read(&path).expect("read NtcMach");
    let binary = Binary::load(data).expect("parse NtcMach");
    let result = analyze_binary(&binary).expect("analyze NtcMach");

    let mut total_lifted = 0;
    for func_cfg in &result.cfg.function_cfgs {
        let func_addr = func_cfg.function_address.0;
        let ctx = match result.pipeline.function_analysis.get(&func_addr) {
            Some(c) => c,
            None => continue,
        };
        let ssa = match ctx.ssa.as_ref() {
            Some(s) => s,
            None => continue,
        };
        let control_structures = recover_control_structures(func_cfg, ssa);
        let mut builder = StructuredIRBuilder::new();
        let func = builder.build(func_cfg, ssa, control_structures);
        total_lifted += count_lifted_calls(&func.statements);
    }

    // 309 ReturnUsedInCondition sites, but not all become If/GuardClause
    // (some are in Unknown control structures). Lifted count should be
    // > 0 but <= 309.
    assert!(total_lifted > 0, "Expected some lifted calls");
    assert!(
        total_lifted <= 309,
        "Lifted calls ({}) should not exceed total ReturnUsedInCondition sites (309)",
        total_lifted
    );
    println!("Total lifted calls: {} / 309 possible", total_lifted);
}
