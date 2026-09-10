//! P0-6.1 NtcMach.exe real-world dogfood for Expression Recovery.
//!
//! Loads the real commercial binary, runs the analysis pipeline,
//! and recovers expressions from a SMALL SAMPLE of actual SSA data.
//! NOT full-binary recovery (that would be too heavy for a test).

use fox_analysis::analyze_binary;
use fox_binary::Binary;
use fox_decompiler::{Expression, ExpressionRecovery};
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
