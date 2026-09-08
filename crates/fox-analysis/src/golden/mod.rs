//! FOX Ground Truth Validator (P0-3.5)
//!
//! Automated Differential Validation:
//! Known Source -> Compiler -> Binary -> Expected Fixture -> FOX -> Actual Fixture -> Comparator -> PASS/FAIL
//!
//! This is the FOX Truth Layer: analysis results must be automatically
//! compared against Ground Truth, and failures must propagate to CI.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Comparison mode for a field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MatchMode {
    /// Exact match required
    Exact,
    /// Semantic equivalence (e.g., CFG isomorphism)
    SemanticEquivalent,
    /// Expected difference (compiler-specific variation)
    ExpectedDifference,
    /// Unknown / not checked
    Unknown,
}

/// Expected fixture for a golden sample.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedFixture {
    pub sample_name: String,
    pub source_file: String,
    pub compiler: String,
    pub compiler_version: String,
    pub optimization: String,
    pub architecture: String,
    /// Expected function count
    pub function_count: usize,
    /// Expected function names (if known)
    pub function_names: Vec<String>,
    /// Expected basic block count (total across all functions)
    pub basic_block_count: usize,
    /// Expected CFG edge count (total)
    pub cfg_edge_count: usize,
    /// Expected call edges (total)
    pub call_edge_count: usize,
    /// Expected external calls (DLL!symbol pairs)
    pub external_calls: Vec<String>,
    /// Expected IR operation count (total)
    pub ir_operation_count: usize,
    /// Per-function expected data
    pub functions: Vec<ExpectedFunction>,
    /// Match mode for each field
    #[serde(default)]
    pub match_modes: std::collections::HashMap<String, MatchMode>,
}

/// Expected data for a single function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedFunction {
    pub name: String,
    pub expected_blocks: usize,
    pub expected_edges: usize,
    pub expected_calls: usize,
    pub expected_ir_ops: usize,
}

/// Actual fixture produced by FOX analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActualFixture {
    pub sample_name: String,
    pub function_count: usize,
    pub function_names: Vec<String>,
    pub basic_block_count: usize,
    pub cfg_edge_count: usize,
    pub call_edge_count: usize,
    pub external_calls: Vec<String>,
    pub ir_operation_count: usize,
}

/// A single validation failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationFailure {
    pub field: String,
    pub expected: String,
    pub actual: String,
    pub mode: MatchMode,
    pub severity: Severity,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Error,
    Warning,
    Info,
}

/// Overall validation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub sample_name: String,
    pub passed: bool,
    pub failures: Vec<ValidationFailure>,
    pub warnings: Vec<ValidationFailure>,
    pub checked_fields: Vec<String>,
    pub passed_fields: Vec<String>,
}

impl ValidationResult {
    pub fn new(sample_name: &str) -> Self {
        Self {
            sample_name: sample_name.to_string(),
            passed: true,
            failures: Vec::new(),
            warnings: Vec::new(),
            checked_fields: Vec::new(),
            passed_fields: Vec::new(),
        }
    }

    pub fn fail(&mut self, field: &str, expected: impl ToString, actual: impl ToString) {
        self.passed = false;
        self.failures.push(ValidationFailure {
            field: field.to_string(),
            expected: expected.to_string(),
            actual: actual.to_string(),
            mode: MatchMode::Exact,
            severity: Severity::Error,
        });
        self.checked_fields.push(field.to_string());
    }

    pub fn pass_field(&mut self, field: &str) {
        self.checked_fields.push(field.to_string());
        self.passed_fields.push(field.to_string());
    }

    pub fn warn(&mut self, field: &str, expected: impl ToString, actual: impl ToString) {
        self.warnings.push(ValidationFailure {
            field: field.to_string(),
            expected: expected.to_string(),
            actual: actual.to_string(),
            mode: MatchMode::ExpectedDifference,
            severity: Severity::Warning,
        });
    }
}

/// The Ground Truth Comparator.
pub struct GoldenComparator;

impl GoldenComparator {
    /// Compare expected fixture against actual fixture.
    pub fn compare(expected: &ExpectedFixture, actual: &ActualFixture) -> ValidationResult {
        let mut result = ValidationResult::new(&expected.sample_name);

        // Function count
        Self::compare_usize(
            &mut result,
            "function_count",
            expected.function_count,
            actual.function_count,
        );

        // Basic block count
        Self::compare_usize(
            &mut result,
            "basic_block_count",
            expected.basic_block_count,
            actual.basic_block_count,
        );

        // CFG edge count
        Self::compare_usize(
            &mut result,
            "cfg_edge_count",
            expected.cfg_edge_count,
            actual.cfg_edge_count,
        );

        // Call edge count
        Self::compare_usize(
            &mut result,
            "call_edge_count",
            expected.call_edge_count,
            actual.call_edge_count,
        );

        // IR operation count (with tolerance)
        let ir_tolerance = (expected.ir_operation_count as f64 * 0.1) as usize;
        if actual
            .ir_operation_count
            .abs_diff(expected.ir_operation_count)
            <= ir_tolerance
        {
            result.pass_field("ir_operation_count");
        } else {
            result.fail(
                "ir_operation_count",
                expected.ir_operation_count,
                actual.ir_operation_count,
            );
        }

        // External calls: check that all expected externals are present
        let actual_external_set: HashSet<&str> =
            actual.external_calls.iter().map(|s| s.as_str()).collect();
        let mut missing_externals = Vec::new();
        for ext in &expected.external_calls {
            if !actual_external_set.contains(ext.as_str()) {
                missing_externals.push(ext.clone());
            }
        }
        if missing_externals.is_empty() {
            result.pass_field("external_calls");
        } else {
            result.fail(
                "external_calls",
                format!("all of {:?}", expected.external_calls),
                format!("missing: {:?}", missing_externals),
            );
        }

        // Function names: check expected names are subset
        let actual_names: HashSet<&str> =
            actual.function_names.iter().map(|s| s.as_str()).collect();
        let mut missing_names = Vec::new();
        for name in &expected.function_names {
            if !actual_names.contains(name.as_str()) {
                missing_names.push(name.clone());
            }
        }
        if missing_names.is_empty() {
            result.pass_field("function_names");
        } else {
            result.warn(
                "function_names",
                format!("all of {:?}", expected.function_names),
                format!("missing: {:?}", missing_names),
            );
        }

        result
    }

    fn compare_usize(result: &mut ValidationResult, field: &str, expected: usize, actual: usize) {
        if expected == actual {
            result.pass_field(field);
        } else {
            result.fail(field, expected, actual);
        }
    }
}

/// Load expected fixture from JSON string.
pub fn load_expected_fixture(json: &str) -> Result<ExpectedFixture, serde_json::Error> {
    serde_json::from_str(json)
}

/// Serialize actual fixture to JSON.
pub fn serialize_actual_fixture(actual: &ActualFixture) -> String {
    serde_json::to_string_pretty(actual).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_expected() -> ExpectedFixture {
        ExpectedFixture {
            sample_name: "01_linear".into(),
            source_file: "01_linear.c".into(),
            compiler: "rustc".into(),
            compiler_version: "1.75".into(),
            optimization: "release".into(),
            architecture: "x64".into(),
            function_count: 1,
            function_names: vec!["main".into()],
            basic_block_count: 1,
            cfg_edge_count: 0,
            call_edge_count: 0,
            external_calls: vec![],
            ir_operation_count: 5,
            functions: vec![],
            match_modes: Default::default(),
        }
    }

    #[test]
    fn test_exact_match_pass() {
        let expected = make_expected();
        let actual = ActualFixture {
            sample_name: "01_linear".into(),
            function_count: 1,
            function_names: vec!["main".into()],
            basic_block_count: 1,
            cfg_edge_count: 0,
            call_edge_count: 0,
            external_calls: vec![],
            ir_operation_count: 5,
        };
        let result = GoldenComparator::compare(&expected, &actual);
        assert!(result.passed, "Should pass: {:?}", result.failures);
    }

    #[test]
    fn test_function_count_mismatch() {
        let expected = make_expected();
        let actual = ActualFixture {
            sample_name: "01_linear".into(),
            function_count: 2, // wrong
            function_names: vec!["main".into(), "sub_123".into()],
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

    #[test]
    fn test_ir_tolerance() {
        let expected = make_expected();
        let actual = ActualFixture {
            sample_name: "01_linear".into(),
            function_count: 1,
            function_names: vec!["main".into()],
            basic_block_count: 1,
            cfg_edge_count: 0,
            call_edge_count: 0,
            external_calls: vec![],
            ir_operation_count: 5, // within 10% tolerance of 5
        };
        let result = GoldenComparator::compare(&expected, &actual);
        assert!(result.passed);
    }

    #[test]
    fn test_missing_external_call() {
        let mut expected = make_expected();
        expected.external_calls = vec!["kernel32.dll!Sleep".into()];
        let actual = ActualFixture {
            sample_name: "01_linear".into(),
            function_count: 1,
            function_names: vec!["main".into()],
            basic_block_count: 1,
            cfg_edge_count: 0,
            call_edge_count: 1,
            external_calls: vec![], // missing
            ir_operation_count: 5,
        };
        let result = GoldenComparator::compare(&expected, &actual);
        assert!(!result.passed);
        assert!(result.failures.iter().any(|f| f.field == "external_calls"));
    }

    #[test]
    fn test_fixture_serialization_roundtrip() {
        let expected = make_expected();
        let json = serde_json::to_string(&expected).unwrap();
        let parsed: ExpectedFixture = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.sample_name, expected.sample_name);
        assert_eq!(parsed.function_count, expected.function_count);
    }
}
