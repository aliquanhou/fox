//! P0-4.5 Reality Gate tests
//!
//! Verifies Binary Format Reality & Safe Dispatch:
//! - CLR detection
//! - ExecutionModel classification
//! - Safe Dispatch (ManagedCLR → error, Native → pipeline)
//! - Native binaries not regressed

use fox_analysis::analyze_binary;
use fox_binary::{Binary, ExecutionModel};

/// Build a minimal PE32 binary with optional CLR header (see pe/mod.rs tests).
fn make_pe32(clr_rva: u32, clr_size: u32) -> Vec<u8> {
    let mut data = vec![0u8; 0x200];
    data[0..2].copy_from_slice(b"MZ");
    data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    data[0x80..0x84].copy_from_slice(b"PE\0\0");
    data[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes());
    data[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    data[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes());
    data[0x98..0x9A].copy_from_slice(&0x10Bu16.to_le_bytes());
    data[0xA8..0xAC].copy_from_slice(&0x1000u32.to_le_bytes());
    data[0xB4..0xB8].copy_from_slice(&0x10000000u32.to_le_bytes());
    data[0x168..0x16C].copy_from_slice(&clr_rva.to_le_bytes());
    data[0x16C..0x170].copy_from_slice(&clr_size.to_le_bytes());
    data[0x178..0x180].copy_from_slice(b".text\0\0\0");
    data[0x180..0x184].copy_from_slice(&0x100u32.to_le_bytes());
    data[0x184..0x188].copy_from_slice(&0x1000u32.to_le_bytes());
    data[0x188..0x18C].copy_from_slice(&0x100u32.to_le_bytes());
    data[0x18C..0x190].copy_from_slice(&0x100u32.to_le_bytes());
    data[0x19C..0x1A0].copy_from_slice(&0x60000020u32.to_le_bytes());
    data
}

#[test]
fn test_managed_clr_safe_dispatch() {
    let data = make_pe32(0x2008, 72);
    let binary = Binary::load(data).unwrap();
    assert_eq!(binary.execution_model, ExecutionModel::ManagedCLR);
    // analyze_binary must return Err, not hang or produce fake results
    let result = analyze_binary(&binary);
    assert!(result.is_err(), "ManagedCLR must not enter Native Pipeline");
    let err = result.unwrap_err();
    let msg = format!("{}", err);
    assert!(
        msg.contains("Unsupported execution model"),
        "error should mention unsupported execution model, got: {}",
        msg
    );
}

#[test]
fn test_native_binary_enters_pipeline() {
    let data = make_pe32(0, 0);
    let binary = Binary::load(data).unwrap();
    assert_eq!(binary.execution_model, ExecutionModel::Native);
    // Native binary should enter pipeline (may produce empty result for minimal binary)
    let result = analyze_binary(&binary);
    assert!(result.is_ok(), "Native binary must enter Native Pipeline");
}

#[test]
fn test_clr_present_field() {
    let managed = Binary::load(make_pe32(0x2008, 72)).unwrap();
    assert!(managed.clr_present);

    let native = Binary::load(make_pe32(0, 0)).unwrap();
    assert!(!native.clr_present);
}

#[test]
fn test_architecture_independent_of_execution_model() {
    // PE32 + x86 + CLR must be classified as x86 ManagedCLR, NOT Native x86
    let managed = Binary::load(make_pe32(0x2008, 72)).unwrap();
    assert_eq!(managed.architecture, fox_arch::Architecture::X86);
    assert_eq!(managed.execution_model, ExecutionModel::ManagedCLR);
    assert!(!managed.execution_model.native_pipeline_applicable());
}
