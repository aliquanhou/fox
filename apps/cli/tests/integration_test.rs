//! FOX Integration Tests
//!
//! Tests the full pipeline: Binary load -> Parse -> Analyze -> Evidence

use fox_analysis::FunctionDiscovery;
use fox_arch::Architecture;
use fox_binary::{Binary, BinaryFormat};
use fox_core::EvidenceKind;

/// Test that we can detect PE format from minimal header bytes.
#[test]
fn test_pe_format_detection() {
    let mut data = vec![0u8; 0x200];
    data[0..2].copy_from_slice(b"MZ");
    data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    data[0x80..0x84].copy_from_slice(b"PE\0\0");
    // Machine = x64 (0x8664) at offset 0x84
    data[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    // Optional header magic = PE32+ (0x20B) at offset 0x98
    data[0x98..0x9A].copy_from_slice(&0x20Bu16.to_le_bytes());

    assert_eq!(Binary::detect_format(&data), BinaryFormat::PE32Plus);
}

#[test]
fn test_unknown_format() {
    let data = vec![0x00, 0x01, 0x02, 0x03];
    assert_eq!(Binary::detect_format(&data), BinaryFormat::Unknown);
}

#[test]
fn test_elf_format_detection() {
    let mut data = vec![0u8; 64];
    data[0..4].copy_from_slice(b"\x7FELF");
    data[4] = 2; // 64-bit
    assert_eq!(Binary::detect_format(&data), BinaryFormat::ELF64);

    data[4] = 1; // 32-bit
    assert_eq!(Binary::detect_format(&data), BinaryFormat::ELF32);
}

/// Test evidence system with function discovery.
#[test]
fn test_function_discovery_evidence() {
    // Create a minimal PE with a function prologue in .text section
    let mut data = vec![0u8; 0x400];

    // DOS header
    data[0..2].copy_from_slice(b"MZ");
    data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

    // PE signature
    data[0x80..0x84].copy_from_slice(b"PE\0\0");

    // COFF header at 0x84
    data[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // x64
    data[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    data[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes()); // size of optional header (240 for PE32+)
    data[0x96..0x98].copy_from_slice(&0x0002u16.to_le_bytes()); // characteristics: EXECUTABLE_IMAGE

    // Optional header at 0x98
    data[0x98..0x9A].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+ magic
                                                               // Entry point RVA at 0xA8 (offset 16 from optional header start)
    data[0xA8..0xAC].copy_from_slice(&0x1000u32.to_le_bytes());
    // Image base at 0xB0 (offset 24 for PE32+)
    data[0xB0..0xB8].copy_from_slice(&0x140000000u64.to_le_bytes());

    // Section table at 0x188 (0x98 + 0xF0)
    let sec_off = 0x188;
    // Name: .text
    data[sec_off..sec_off + 5].copy_from_slice(b".text");
    // Virtual size
    data[sec_off + 8..sec_off + 12].copy_from_slice(&0x100u32.to_le_bytes());
    // Virtual address
    data[sec_off + 12..sec_off + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    // Raw size
    data[sec_off + 16..sec_off + 20].copy_from_slice(&0x200u32.to_le_bytes());
    // Raw offset - point to 0x200 where we put code
    data[sec_off + 20..sec_off + 24].copy_from_slice(&0x200u32.to_le_bytes());
    // Characteristics: 0x60000020 (code, execute, read)
    data[sec_off + 36..sec_off + 40].copy_from_slice(&0x60000020u32.to_le_bytes());

    // Put a function prologue at raw offset 0x200 (RVA 0x1000)
    // push rbp; mov rbp, rsp; ret
    data[0x200] = 0x55;
    data[0x201] = 0x48;
    data[0x202] = 0x89;
    data[0x203] = 0xE5;
    data[0x204] = 0xC3;

    let binary = Binary::load(data).expect("Failed to load PE");
    assert_eq!(binary.format, BinaryFormat::PE32Plus);
    assert_eq!(binary.architecture, Architecture::X64);
    assert_eq!(binary.sections.len(), 1);
    assert_eq!(binary.sections[0].name, ".text");
    assert!(binary.sections[0].is_executable());

    let functions = FunctionDiscovery::discover(&binary);
    // Should find at least entry point function
    assert!(!functions.is_empty());

    // Entry point function should have EntryPoint evidence
    let entry_func = functions.iter().find(|f| f.value.address.0 == 0x140001000);
    assert!(entry_func.is_some(), "Entry point function not found");
    let entry_func = entry_func.unwrap();
    let has_entry_evidence = entry_func
        .evidence
        .items
        .iter()
        .any(|e| matches!(e.kind, EvidenceKind::EntryPoint));
    assert!(
        has_entry_evidence,
        "Entry point function missing EntryPoint evidence"
    );
}

/// Test that evidence confidence increases with more evidence.
#[test]
fn test_evidence_confidence_accumulation() {
    use fox_core::{Confidence, EvidenceKind, WithEvidence};

    let mut result = WithEvidence::new("test_function");
    assert_eq!(result.confidence, Confidence::ZERO);

    result = result.with_evidence_kind(EvidenceKind::FunctionPrologue);
    assert!(result.confidence.0 > 0.0);

    let before = result.confidence.0;
    result = result.with_evidence_kind(EvidenceKind::ValidReturn);
    result = result.with_evidence_kind(EvidenceKind::CallReference { count: 3 });
    assert!(result.confidence.0 > before);
    assert!(result.evidence.len() == 3);
}
