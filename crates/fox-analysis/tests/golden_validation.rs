//! FOX Golden Validation Integration Tests (P0-3.C2/C3)
//!
//! Automated Differential Validation:
//! Known Binary -> FOX Analysis -> Actual Fixture -> Compare with Expected -> PASS/FAIL
//!
//! Expected fixtures live in golden/expected/<sample>.json.
//! If an expected fixture is missing, the test is skipped (not failed).

use fox_analysis::golden::{ActualFixture, ExpectedFixture, GoldenComparator};
use fox_binary::Binary;
use std::path::PathBuf;

fn samples_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // fox-analysis/
    p.pop(); // crates/
    p.push("samples");
    p.push("target");
    p.push("release");
    p
}

fn expected_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("golden");
    p.push("expected");
    p
}

fn load_binary(name: &str) -> Option<Binary> {
    let path = samples_dir().join(format!("{}.exe", name));
    if !path.exists() {
        return None;
    }
    let data = std::fs::read(&path).ok()?;
    Binary::load(data).ok()
}

fn load_expected(name: &str) -> Option<ExpectedFixture> {
    let path = expected_dir().join(format!("{}.json", name));
    if !path.exists() {
        return None;
    }
    let json = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&json).ok()
}

fn analyze_to_actual(name: &str, binary: &Binary) -> ActualFixture {
    let result = fox_analysis::analyze_binary(binary).unwrap();
    let function_count = result.functions.len();
    let function_names: Vec<String> = result
        .functions
        .iter()
        .map(|f| f.value.name.clone())
        .collect();

    let mut basic_block_count = 0;
    let mut cfg_edge_count = 0;
    let mut ir_operation_count = 0;
    for fcfg in &result.cfg.function_cfgs {
        basic_block_count += fcfg.blocks.len();
        for bb in &fcfg.blocks {
            cfg_edge_count += bb.successors.len();
            ir_operation_count += bb.instructions.len();
        }
    }

    let mut call_edge_count = 0;
    let mut external_calls: Vec<String> = Vec::new();
    for node in &result.call_graph.nodes {
        for edge in &node.outgoing_calls {
            call_edge_count += 1;
            if let Some(sym) = &edge.resolved_symbol {
                external_calls.push(sym.clone());
            }
        }
    }
    external_calls.sort();
    external_calls.dedup();

    ActualFixture {
        sample_name: name.to_string(),
        function_count,
        function_names,
        basic_block_count,
        cfg_edge_count,
        call_edge_count,
        external_calls,
        ir_operation_count,
    }
}

fn run_golden_test(name: &str) {
    let binary = match load_binary(name) {
        Some(b) => b,
        None => {
            eprintln!("[SKIP] {}: binary not found (build samples first)", name);
            return;
        }
    };

    let expected = match load_expected(name) {
        Some(e) => e,
        None => {
            eprintln!(
                "[SKIP] {}: expected fixture not found in golden/expected/",
                name
            );
            // Print actual fixture for bootstrap
            let actual = analyze_to_actual(name, &binary);
            eprintln!(
                "[BOOTSTRAP] {} actual: functions={}, blocks={}, edges={}, calls={}, ir={}",
                name,
                actual.function_count,
                actual.basic_block_count,
                actual.cfg_edge_count,
                actual.call_edge_count,
                actual.ir_operation_count
            );
            return;
        }
    };

    let actual = analyze_to_actual(name, &binary);

    // Auto-update mode: write actual fixture as expected
    if std::env::var("FOX_UPDATE_GOLDEN").is_ok() {
        let expected_path = expected_dir().join(format!("{}.json", name));
        // Merge actual data into expected fixture (preserve metadata)
        let mut updated = expected.clone();
        updated.function_count = actual.function_count;
        updated.function_names = actual.function_names.clone();
        updated.basic_block_count = actual.basic_block_count;
        updated.cfg_edge_count = actual.cfg_edge_count;
        updated.call_edge_count = actual.call_edge_count;
        updated.external_calls = actual.external_calls.clone();
        updated.ir_operation_count = actual.ir_operation_count;
        let json = serde_json::to_string_pretty(&updated).unwrap();
        std::fs::write(&expected_path, json).unwrap();
        eprintln!(
            "[UPDATED] {}: functions={}, blocks={}, edges={}",
            name, actual.function_count, actual.basic_block_count, actual.cfg_edge_count
        );
        return;
    }

    let result = GoldenComparator::compare(&expected, &actual);

    if !result.passed {
        eprintln!(
            "[FAIL] {}: {} failures, {} warnings",
            name,
            result.failures.len(),
            result.warnings.len()
        );
        for f in &result.failures {
            eprintln!(
                "  ERROR [{}]: expected={}, actual={}",
                f.field, f.expected, f.actual
            );
        }
        for w in &result.warnings {
            eprintln!(
                "  WARN  [{}]: expected={}, actual={}",
                w.field, w.expected, w.actual
            );
        }
        panic!("Golden validation failed for {}", name);
    } else {
        eprintln!(
            "[PASS] {}: {} fields checked, {} passed",
            name,
            result.checked_fields.len(),
            result.passed_fields.len()
        );
    }
}

#[test]
fn golden_01_linear() {
    run_golden_test("01_linear");
}

#[test]
fn golden_02_branch() {
    run_golden_test("02_branch");
}

#[test]
fn golden_03_loop() {
    run_golden_test("03_loop");
}

#[test]
fn golden_04_nested_branch() {
    run_golden_test("04_nested_branch");
}

#[test]
fn golden_05_call() {
    run_golden_test("05_call");
}

#[test]
fn golden_06_recursive() {
    run_golden_test("06_recursive");
}

#[test]
fn golden_07_switch() {
    run_golden_test("07_switch");
}

#[test]
fn golden_08_pointer() {
    run_golden_test("08_pointer");
}

#[test]
fn golden_09_function_pointer() {
    run_golden_test("09_function_pointer");
}

#[test]
fn golden_10_optimized() {
    run_golden_test("10_optimized");
}

#[test]
fn golden_11_external_api() {
    run_golden_test("11_external_api");
}

#[test]
fn golden_12_indirect_call() {
    run_golden_test("12_indirect_call");
}

#[test]
fn golden_13_switch() {
    run_golden_test("13_switch");
}

#[test]
fn golden_14_pointer_arithmetic() {
    run_golden_test("14_pointer_arithmetic");
}

#[test]
fn golden_15_global_variable() {
    run_golden_test("15_global_variable");
}

#[test]
fn golden_16_struct_access() {
    run_golden_test("16_struct_access");
}

#[test]
fn golden_17_loop_phi() {
    run_golden_test("17_loop_phi");
}

#[test]
fn golden_18_nested_loop() {
    run_golden_test("18_nested_loop");
}

#[test]
fn golden_19_constant_propagation() {
    run_golden_test("19_constant_propagation");
}

#[test]
fn golden_20_dataflow() {
    run_golden_test("20_dataflow");
}

#[test]
fn comparator_exact_match() {
    let expected = ExpectedFixture {
        sample_name: "test".into(),
        source_file: "test.c".into(),
        compiler: "rustc".into(),
        compiler_version: "1.75".into(),
        optimization: "release".into(),
        architecture: "x64".into(),
        function_count: 1,
        function_names: vec!["main".into()],
        basic_block_count: 3,
        cfg_edge_count: 2,
        call_edge_count: 0,
        external_calls: vec![],
        ir_operation_count: 10,
        functions: vec![],
        match_modes: Default::default(),
    };
    let actual = ActualFixture {
        sample_name: "test".into(),
        function_count: 1,
        function_names: vec!["main".into()],
        basic_block_count: 3,
        cfg_edge_count: 2,
        call_edge_count: 0,
        external_calls: vec![],
        ir_operation_count: 10,
    };
    let result = GoldenComparator::compare(&expected, &actual);
    assert!(result.passed, "Should pass: {:?}", result.failures);
}

#[test]
fn comparator_function_count_mismatch() {
    let expected = ExpectedFixture {
        sample_name: "test".into(),
        source_file: "test.c".into(),
        compiler: "rustc".into(),
        compiler_version: "1.75".into(),
        optimization: "release".into(),
        architecture: "x64".into(),
        function_count: 1,
        function_names: vec![],
        basic_block_count: 1,
        cfg_edge_count: 0,
        call_edge_count: 0,
        external_calls: vec![],
        ir_operation_count: 5,
        functions: vec![],
        match_modes: Default::default(),
    };
    let actual = ActualFixture {
        sample_name: "test".into(),
        function_count: 2,
        function_names: vec![],
        basic_block_count: 1,
        cfg_edge_count: 0,
        call_edge_count: 0,
        external_calls: vec![],
        ir_operation_count: 5,
    };
    let result = GoldenComparator::compare(&expected, &actual);
    assert!(!result.passed);
    assert!(result.failures.iter().any(|f| f.field == "function_count"));
}
