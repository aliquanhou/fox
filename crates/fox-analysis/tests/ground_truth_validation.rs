//! FOX Ground Truth Differential Validation (P0-3.1)
//!
//! Independent Ground Truth from MSVC linker .map files.
//! Compares FOX Function Discovery against known function boundaries.
//!
//! Metrics: TP / FP / FN / Boundary Start Error / Boundary End Error
//!
//! P0-3.4R: Metrics are clearly labeled:
//! - GT-region Precision: TP / (TP + FP) where FP only counts addresses
//!   within the GT function address range (excludes CRT/runtime outside GT)
//! - Binary-wide Precision: N/A (requires complete binary-wide Ground Truth)
//! - Outputs machine-readable JSON to tests/ground_truth/results/

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GroundTruthFunction {
    name: String,
    start_va: String, // hex
    end_va: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GroundTruthFixture {
    sample_name: String,
    expected_function_count: usize,
    expected_functions: Vec<GroundTruthFunction>,
}

fn parse_hex(s: &str) -> u64 {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16).unwrap_or_else(|_| panic!("invalid hex: {}", s))
}

fn ground_truth_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // fox-analysis/
    p.pop(); // crates/
    p.push("tests");
    p.push("ground_truth");
    p
}

fn list_ground_truth_samples() -> Vec<String> {
    let expected_dir = ground_truth_dir().join("expected");
    let mut samples = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&expected_dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.ends_with(".json") {
                    samples.push(name.trim_end_matches(".json").to_string());
                }
            }
        }
    }
    samples.sort();
    samples
}

struct BoundaryResult {
    tp: usize,
    fp: usize,
    fn_: usize,
    boundary_start_errors: usize,
    boundary_end_errors: usize,
    total_expected: usize,
    total_actual: usize,
    gt_min: u64,
    gt_max: u64,
}

/// Machine-readable per-sample metrics (P0-3.4R)
#[derive(Debug, Serialize)]
struct SampleMetrics {
    sample: String,
    tp: usize,
    fp: usize,
    fn_: usize,
    tn: usize,
    boundary_start_errors: usize,
    boundary_end_errors: usize,
    identity_errors: usize,
    expected_functions: usize,
    actual_functions_total: usize,
    gt_region_start: String,
    gt_region_end: String,
    gt_region_precision: f64,
    gt_region_recall: f64,
    gt_region_f1: f64,
    binary_wide_precision: String, // "N/A" without complete binary GT
    binary_wide_recall: String,    // "N/A"
}

/// Machine-readable aggregate metrics (P0-3.4R)
#[derive(Debug, Serialize)]
struct AggregateMetrics {
    total_samples: usize,
    total_tp: usize,
    total_fp: usize,
    total_fn: usize,
    total_expected: usize,
    gt_region_precision: f64,
    gt_region_recall: f64,
    gt_region_f1: f64,
    binary_wide_precision: String,
    binary_wide_recall: String,
    metric_definitions: MetricDefinitions,
    samples: Vec<SampleMetrics>,
}

#[derive(Debug, Serialize)]
struct MetricDefinitions {
    gt_region_precision: String,
    gt_region_recall: String,
    binary_wide_precision: String,
    fp_definition: String,
    tn_definition: String,
}

fn compute_metrics(sample: &str, r: &BoundaryResult) -> SampleMetrics {
    let precision = if r.tp + r.fp > 0 {
        r.tp as f64 / (r.tp + r.fp) as f64
    } else {
        0.0
    };
    let recall = if r.tp + r.fn_ > 0 {
        r.tp as f64 / (r.tp + r.fn_) as f64
    } else {
        0.0
    };
    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };
    // TN: addresses in GT region that are correctly NOT identified as functions.
    // Approximated as (GT region size in bytes / typical function size) - (TP + FP).
    // This is a rough estimate; exact TN requires instruction-level analysis.
    let region_bytes = r.gt_max.saturating_sub(r.gt_min) as usize;
    let estimated_slots = region_bytes / 32; // assume avg 32 bytes per function slot
    let tn = estimated_slots.saturating_sub(r.tp + r.fp);

    SampleMetrics {
        sample: sample.to_string(),
        tp: r.tp,
        fp: r.fp,
        fn_: r.fn_,
        tn,
        boundary_start_errors: r.boundary_start_errors,
        boundary_end_errors: r.boundary_end_errors,
        identity_errors: 0, // tracked separately in identity tests
        expected_functions: r.total_expected,
        actual_functions_total: r.total_actual,
        gt_region_start: format!("0x{:X}", r.gt_min),
        gt_region_end: format!("0x{:X}", r.gt_max),
        gt_region_precision: precision,
        gt_region_recall: recall,
        gt_region_f1: f1,
        binary_wide_precision: "N/A".to_string(),
        binary_wide_recall: "N/A".to_string(),
    }
}

fn compare_boundaries(sample: &str) -> BoundaryResult {
    let gt_dir = ground_truth_dir();
    let expected_path = gt_dir.join("expected").join(format!("{}.json", sample));
    let binary_path = gt_dir.join("binaries").join(format!("{}.exe", sample));

    let fixture: GroundTruthFixture =
        serde_json::from_str(&std::fs::read_to_string(&expected_path).expect("expected fixture"))
            .expect("parse fixture");

    let binary_data = std::fs::read(&binary_path).expect("binary");
    let binary = fox_binary::Binary::load(binary_data).expect("parse binary");
    let result = fox_analysis::analyze_binary(&binary);

    // Build ground truth map: start_va -> function
    let mut gt_map: BTreeMap<u64, &GroundTruthFunction> = BTreeMap::new();
    for f in &fixture.expected_functions {
        let va = parse_hex(&f.start_va);
        gt_map.insert(va, f);
    }

    // Build FOX discovered set: function address -> end address
    let mut fox_addrs: BTreeMap<u64, Option<u64>> = BTreeMap::new();
    for func in &result.functions {
        let addr = func.value.address.0;
        let end = func
            .value
            .end_address
            .map(|a| a.0)
            .or(func.value.validation.estimated_end);
        fox_addrs.insert(addr, end);
    }

    let mut tp = 0;
    let mut fp = 0;
    let mut fn_ = 0;
    let mut boundary_start_errors = 0;
    let mut boundary_end_errors = 0;

    // Check each ground truth function
    for (gt_addr, gt_func) in &gt_map {
        if fox_addrs.contains_key(gt_addr) {
            tp += 1;
            // Check boundary end if both have it
            if let (Some(gt_end_str), Some(fox_end)) =
                (&gt_func.end_va, fox_addrs.get(gt_addr).unwrap())
            {
                let gt_end = parse_hex(gt_end_str);
                if gt_end != *fox_end {
                    boundary_end_errors += 1;
                }
            }
        } else {
            // Check if FOX found it at a nearby address (boundary start error)
            let tolerance = 16u64; // within 16 bytes
            let nearby = fox_addrs.keys().any(|&fa| {
                fa > gt_addr.saturating_sub(tolerance) && fa < gt_addr + tolerance && fa != *gt_addr
            });
            if nearby {
                boundary_start_errors += 1;
                tp += 1; // count as found but with start error
            } else {
                fn_ += 1;
            }
        }
    }

    // FP: FOX functions not in ground truth (excluding CRT/runtime functions)
    // We only count FP for addresses in the gt_* function region
    let gt_min = *gt_map.keys().next().unwrap_or(&0);
    let gt_max = gt_map
        .keys()
        .last()
        .map(|k| {
            // extend to include the last function's end
            let last = gt_map[k];
            last.end_va
                .as_ref()
                .map(|e| parse_hex(e))
                .unwrap_or(*k + 0x100)
        })
        .unwrap_or(0);

    for fox_addr in fox_addrs.keys() {
        if *fox_addr >= gt_min && *fox_addr <= gt_max && !gt_map.contains_key(fox_addr) {
            fp += 1;
        }
    }

    BoundaryResult {
        tp,
        fp,
        fn_,
        boundary_start_errors,
        boundary_end_errors,
        total_expected: fixture.expected_function_count,
        total_actual: fox_addrs.len(),
        gt_min,
        gt_max,
    }
}

fn run_sample(sample: &str) {
    let r = compare_boundaries(sample);
    let m = compute_metrics(sample, &r);

    eprintln!(
        "[GT] {}: TP={} FP={} FN={} StartErr={} EndErr={} | expected={} actual={} | GT-region precision={:.2} recall={:.2}",
        sample, r.tp, r.fp, r.fn_, r.boundary_start_errors, r.boundary_end_errors,
        r.total_expected, r.total_actual, m.gt_region_precision, m.gt_region_recall
    );

    // P0-3.1: Report metrics, do not assert. Ground Truth measures real accuracy.
}

#[test]
fn ground_truth_all_samples() {
    let samples = list_ground_truth_samples();
    assert!(!samples.is_empty(), "No ground truth samples found");
    eprintln!(
        "Running Ground Truth Differential on {} samples...",
        samples.len()
    );

    let mut total_tp = 0;
    let mut total_fp = 0;
    let mut total_fn = 0;
    let mut total_expected = 0;
    let mut sample_metrics = Vec::new();

    for sample in &samples {
        let r = compare_boundaries(sample);
        total_tp += r.tp;
        total_fp += r.fp;
        total_fn += r.fn_;
        total_expected += r.total_expected;
        let m = compute_metrics(sample, &r);
        eprintln!(
            "  {}: TP={} FP={} FN={} StartErr={} EndErr={} (expected={})",
            sample,
            r.tp,
            r.fp,
            r.fn_,
            r.boundary_start_errors,
            r.boundary_end_errors,
            r.total_expected
        );
        sample_metrics.push(m);
    }

    let precision = if total_tp + total_fp > 0 {
        total_tp as f64 / (total_tp + total_fp) as f64
    } else {
        0.0
    };
    let recall = if total_tp + total_fn > 0 {
        total_tp as f64 / (total_tp + total_fn) as f64
    } else {
        0.0
    };
    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };

    eprintln!("\n=== Ground Truth Summary (P0-3.4R Metrics) ===");
    eprintln!(
        "Samples: {} | Expected functions: {} | TP: {} | FP: {} | FN: {}",
        samples.len(),
        total_expected,
        total_tp,
        total_fp,
        total_fn
    );
    eprintln!(
        "GT-region Precision: {:.4} | GT-region Recall: {:.4} | GT-region F1: {:.4}",
        precision, recall, f1
    );
    eprintln!("Binary-wide Precision: N/A (requires complete binary-wide Ground Truth)");
    eprintln!("Binary-wide Recall: N/A");
    eprintln!(
        "NOTE: FP only counts addresses within GT function region [gt_min, gt_max]. \
         CRT/runtime functions outside GT region are excluded from FP."
    );

    // Write machine-readable JSON
    let aggregate = AggregateMetrics {
        total_samples: samples.len(),
        total_tp,
        total_fp,
        total_fn,
        total_expected,
        gt_region_precision: precision,
        gt_region_recall: recall,
        gt_region_f1: f1,
        binary_wide_precision: "N/A".to_string(),
        binary_wide_recall: "N/A".to_string(),
        metric_definitions: MetricDefinitions {
            gt_region_precision: "TP / (TP + FP), where FP only counts FOX-discovered \
                addresses within the GT function region [gt_min, gt_max] that are not \
                in Ground Truth. Excludes CRT/runtime outside GT region."
                .to_string(),
            gt_region_recall: "TP / (TP + FN), where FN = GT functions not found by FOX."
                .to_string(),
            binary_wide_precision: "N/A without complete binary-wide Ground Truth covering \
                all functions (application + CRT + runtime + compiler-generated)."
                .to_string(),
            fp_definition: "FOX-discovered function address within GT region that is not \
                in Ground Truth."
                .to_string(),
            tn_definition: "Estimated: (GT region bytes / 32) - (TP + FP). Approximate \
                count of non-function addresses correctly not identified as functions."
                .to_string(),
        },
        samples: sample_metrics,
    };

    let results_dir = ground_truth_dir().join("results");
    std::fs::create_dir_all(&results_dir).ok();
    let json_path = results_dir.join("ground_truth_metrics.json");
    if let Ok(json) = serde_json::to_string_pretty(&aggregate) {
        std::fs::write(&json_path, &json).ok();
        eprintln!("Machine-readable metrics written to: {:?}", json_path);
    }

    // P0-3.1: Report real metrics, do not assert 100%.
    // Ground Truth exists to measure FOX accurately, not to force a pass.
    eprintln!(
        "NOTE: This is a measurement test. FN={} indicates real discovery gaps.",
        total_fn
    );
}

#[test]
fn ground_truth_01_linear() {
    run_sample("01_linear_O0");
    run_sample("01_linear_O2");
}

#[test]
fn ground_truth_02_if_else() {
    run_sample("02_if_else_O0");
    run_sample("02_if_else_O2");
}

#[test]
fn ground_truth_03_nested_branch() {
    run_sample("03_nested_branch_O0");
    run_sample("03_nested_branch_O2");
}

#[test]
fn ground_truth_04_loop() {
    run_sample("04_loop_O0");
    run_sample("04_loop_O2");
}

#[test]
fn ground_truth_05_nested_loop() {
    run_sample("05_nested_loop_O0");
    run_sample("05_nested_loop_O2");
}

#[test]
fn ground_truth_06_direct_call() {
    run_sample("06_direct_call_O0");
    run_sample("06_direct_call_O2");
}

#[test]
fn ground_truth_07_recursion() {
    run_sample("07_recursion_O0");
    run_sample("07_recursion_O2");
}

#[test]
fn ground_truth_08_switch() {
    run_sample("08_switch_O0");
    run_sample("08_switch_O2");
}

#[test]
fn ground_truth_09_function_pointer() {
    run_sample("09_function_pointer_O0");
    run_sample("09_function_pointer_O2");
}

#[test]
fn ground_truth_10_optimized() {
    run_sample("10_optimized_O0");
    run_sample("10_optimized_O2");
}
