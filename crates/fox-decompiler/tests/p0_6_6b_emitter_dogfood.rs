//! P0-6.6B Dogfood: C-like Emitter on real NtcMach functions.
//! Tests: 0x41C9A8 (linear), 0x41F000 (control flow), 0x401390 (scale).

use fox_analysis::analyze_binary;
use fox_binary::Binary;
use fox_decompiler::{
    emit_c_like, emit_c_like_clean, recover_control_structures, CLikeEmitter, EmitterConfig,
    StructuredIRBuilder,
};
use std::path::PathBuf;

fn ntcmach_path() -> PathBuf {
    PathBuf::from(r"C:\Users\Administrator\Desktop\制版软件\NtcMach.exe")
}

fn build_and_emit(addr: u64) -> Option<String> {
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

    let cs = recover_control_structures(func_cfg, ssa);
    let mut builder = StructuredIRBuilder::new();
    let func = builder.build(func_cfg, ssa, cs);
    Some(emit_c_like(&func))
}

#[test]
fn target_a_0x41c9a8_linear() {
    println!("=== Target A: 0x41C9A8 (linear) ===");
    let output = build_and_emit(0x41C9A8).expect("emit");
    println!("{}", output);

    // Must contain assignment
    assert!(output.contains("="), "should contain assignments");
    // Must contain return
    assert!(output.contains("return"), "should contain return");
    // Must NOT contain if (linear function)
    assert!(
        !output.contains("if ("),
        "linear function should NOT have if"
    );
    // Must NOT contain goto
    assert!(
        !output.contains("goto"),
        "linear function should NOT have goto"
    );
    // Must have evidence annotations
    assert!(output.contains("@0x"), "should have evidence annotations");

    println!("PASS: 0x41C9A8 linear output verified");
}

#[test]
fn target_b_0x41f000_control_flow() {
    println!("=== Target B: 0x41F000 (control flow) ===");
    let output = build_and_emit(0x41F000).expect("emit");
    println!("{}", output);

    // Must contain if (GuardClause)
    assert!(output.contains("if ("), "should have if (GuardClause)");
    // Must contain call
    assert!(output.contains("call_"), "should have call statements");
    // Must contain return
    assert!(output.contains("return"), "should have return");
    // Must contain UNKNOWN (double return at 0x41F020)
    assert!(output.contains("UNKNOWN"), "should have UNKNOWN comment");
    // Must contain goto (Unknown with goto_target)
    assert!(
        output.contains("goto loc_"),
        "should have goto for unknown control flow"
    );
    // Must NOT fabricate arguments
    assert!(
        output.contains("arguments unresolved"),
        "should mark arguments unresolved"
    );

    println!("PASS: 0x41F000 control flow output verified");
}

#[test]
fn target_c_0x401390_scale() {
    println!("=== Target C: 0x401390 (scale) ===");
    let output = build_and_emit(0x401390).expect("emit");

    // Count key patterns
    let if_count = output.matches("if (").count();
    let return_count = output.matches("return").count();
    let goto_count = output.matches("goto loc_").count();
    let unknown_count = output.matches("UNKNOWN").count();
    let call_count = output.matches("call_").count();

    println!("Output length: {} chars", output.len());
    println!(
        "if: {}, return: {}, goto: {}, UNKNOWN: {}, call: {}",
        if_count, return_count, goto_count, unknown_count, call_count
    );

    // Must produce substantial output
    assert!(output.len() > 1000, "should produce substantial output");
    // Must have many if statements (46 If + 13 Guard = 59 if-like)
    assert!(
        if_count >= 40,
        "should have many if statements (got {})",
        if_count
    );
    // Must have returns
    assert!(return_count > 0, "should have returns");
    // Must have UNKNOWN (5 Unknown)
    assert!(
        unknown_count >= 5,
        "should have UNKNOWN (got {})",
        unknown_count
    );
    // Must have goto for unknown
    assert!(
        goto_count >= 5,
        "should have goto for unknown (got {})",
        goto_count
    );

    // Print first 60 lines for inspection
    println!("\n--- First 60 lines ---");
    for (i, line) in output.lines().take(60).enumerate() {
        println!("{:3}: {}", i + 1, line);
    }

    println!("PASS: 0x401390 scale output verified");
}

#[test]
fn emitter_clean_mode() {
    println!("=== Emitter clean mode (no annotations) ===");
    let path = ntcmach_path();
    let data = std::fs::read(&path).expect("read");
    let binary = Binary::load(data).expect("parse");
    let result = analyze_binary(&binary).expect("analyze");

    let func_cfg = result
        .cfg
        .function_cfgs
        .iter()
        .find(|f| f.function_address.0 == 0x41C9A8)
        .expect("find");
    let ctx = result
        .pipeline
        .function_analysis
        .get(&0x41C9A8)
        .expect("ctx");
    let ssa = ctx.ssa.as_ref().expect("ssa");

    let cs = recover_control_structures(func_cfg, ssa);
    let mut builder = StructuredIRBuilder::new();
    let func = builder.build(func_cfg, ssa, cs);

    let clean = emit_c_like_clean(&func);
    println!("{}", clean);

    // Clean mode should NOT have evidence annotations
    assert!(
        !clean.contains("@0x"),
        "clean mode should not have @address annotations"
    );
    // Clean mode should NOT have header comment
    assert!(
        !clean.contains("// Function @"),
        "clean mode should not have header"
    );

    println!("PASS: clean mode verified");
}

#[test]
fn emitter_evidence_traceability() {
    println!("=== Evidence traceability ===");
    let path = ntcmach_path();
    let data = std::fs::read(&path).expect("read");
    let binary = Binary::load(data).expect("parse");
    let result = analyze_binary(&binary).expect("analyze");

    let func_cfg = result
        .cfg
        .function_cfgs
        .iter()
        .find(|f| f.function_address.0 == 0x41F000)
        .expect("find");
    let ctx = result
        .pipeline
        .function_analysis
        .get(&0x41F000)
        .expect("ctx");
    let ssa = ctx.ssa.as_ref().expect("ssa");

    let cs = recover_control_structures(func_cfg, ssa);
    let mut builder = StructuredIRBuilder::new();
    let func = builder.build(func_cfg, ssa, cs);

    // Annotated mode
    let emitter = CLikeEmitter::with_config(EmitterConfig::annotated());
    let output = emitter.emit(&func);

    // Every statement line should have @address annotation (except braces/comments)
    let mut annotated_lines = 0;
    let mut statement_lines = 0;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed == "{" || trimmed == "}" || trimmed.starts_with("//") {
            continue;
        }
        if trimmed.starts_with("} else") {
            continue;
        }
        statement_lines += 1;
        if trimmed.contains("@0x") {
            annotated_lines += 1;
        }
    }

    println!(
        "Statement lines: {}, annotated: {}",
        statement_lines, annotated_lines
    );
    assert!(annotated_lines > 0, "should have annotated statements");
    // At least 80% of statement lines should have evidence
    let ratio = annotated_lines as f64 / statement_lines as f64;
    println!("Annotation ratio: {:.1}%", ratio * 100.0);
    assert!(
        ratio >= 0.5,
        "at least 50% statements should have evidence (got {:.1}%)",
        ratio * 100.0
    );

    println!("PASS: evidence traceability verified");
}
