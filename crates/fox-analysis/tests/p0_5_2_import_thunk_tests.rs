//! P0-5.2 Import Thunk & External Call Identity tests
//!
//! Verifies:
//! - Import thunk recognition (jmp [IAT] → ImportThunk identity)
//! - Non-IAT indirect JMP is NOT classified as ImportThunk (Fail-Closed)
//! - CALL to import thunk → DirectExternal with resolved symbol
//! - DirectInternal no longer includes import thunk calls
//! - ImportThunk evidence chain is complete
//! - Identity table correctly classifies import thunks

use fox_analysis::analyze_binary;
use fox_binary::{Binary, ExecutionModel};
use fox_core::identity::IdentityKind;

/// Build a minimal PE32 binary with a single import and an import thunk.
/// Layout:
///   .text: RVA 0x1000, raw 0x200
///     0x1000: import thunk (jmp [IAT])
///     0x1100: entry function (call thunk, ret)
///   .data: RVA 0x2000, raw 0x400, size 0x2000
///     0x2000: import directory
///     0x2020: ILT
///     0x2040: DLL name
///     0x2060: hint/name
///     0x2800: IAT entry
fn make_pe32_with_import_thunk() -> Vec<u8> {
    let mut data = vec![0u8; 0x6000];
    // DOS header
    data[0..2].copy_from_slice(b"MZ");
    data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    // PE signature
    data[0x80..0x84].copy_from_slice(b"PE\0\0");
    // COFF header
    data[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes()); // x86
    data[0x86..0x88].copy_from_slice(&2u16.to_le_bytes()); // 2 sections
    data[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes()); // optional header size
                                                              // Optional header (PE32)
    data[0x98..0x9A].copy_from_slice(&0x10Bu16.to_le_bytes()); // PE32 magic
    data[0xA8..0xAC].copy_from_slice(&0x1100u32.to_le_bytes()); // entry point RVA (entry func)
    data[0xB4..0xB8].copy_from_slice(&0x10000000u32.to_le_bytes()); // image base
    data[0xB8..0xBC].copy_from_slice(&0x1000u32.to_le_bytes()); // section alignment
    data[0xBC..0xC0].copy_from_slice(&0x200u32.to_le_bytes()); // file alignment
    data[0xD0..0xD4].copy_from_slice(&0x6000u32.to_le_bytes()); // SizeOfImage
    data[0xD4..0xD8].copy_from_slice(&0x400u32.to_le_bytes()); // SizeOfHeaders
    data[0xDC..0xDE].copy_from_slice(&3u16.to_le_bytes()); // Subsystem: Windows CUI
                                                           // NumberOfRvaAndSizes at optional header offset 0x5C = file offset 0xF4
    data[0xF4..0xF8].copy_from_slice(&2u32.to_le_bytes()); // 2 data directories (export+import)
                                                           // Data directories: Import (index 1) at file offset 0x100
    data[0x100..0x104].copy_from_slice(&0x2000u32.to_le_bytes()); // import RVA
    data[0x104..0x108].copy_from_slice(&0x28u32.to_le_bytes()); // import size
                                                                // Section 1: .text at RVA 0x1000
    data[0x178..0x180].copy_from_slice(b".text\0\0\0");
    data[0x180..0x184].copy_from_slice(&0x200u32.to_le_bytes()); // virtual size
    data[0x184..0x188].copy_from_slice(&0x1000u32.to_le_bytes()); // RVA
    data[0x188..0x18C].copy_from_slice(&0x200u32.to_le_bytes()); // raw size
    data[0x18C..0x190].copy_from_slice(&0x200u32.to_le_bytes()); // raw offset
    data[0x19C..0x1A0].copy_from_slice(&0x60000020u32.to_le_bytes()); // RX
                                                                      // Section 2: .data at RVA 0x2000 (section header at 0x178 + 40 = 0x1A0)
    data[0x1A0..0x1A8].copy_from_slice(b".data\0\0\0");
    data[0x1A8..0x1AC].copy_from_slice(&0x2000u32.to_le_bytes()); // virtual size
    data[0x1AC..0x1B0].copy_from_slice(&0x2000u32.to_le_bytes()); // RVA
    data[0x1B0..0x1B4].copy_from_slice(&0x2000u32.to_le_bytes()); // raw size
    data[0x1B4..0x1B8].copy_from_slice(&0x400u32.to_le_bytes()); // raw offset
    data[0x1C4..0x1C8].copy_from_slice(&0xC0000040u32.to_le_bytes()); // RW

    // Helper: RVA -> raw offset (section-based)
    // .text: RVA 0x1000-0x11FF -> raw 0x200-0x3FF
    // .data: RVA 0x2000-0x3FFF -> raw 0x400-0x23FF
    let rva_to_raw = |rva: u32| -> usize {
        if (0x1000..0x1200).contains(&rva) {
            0x200 + (rva - 0x1000) as usize
        } else if (0x2000..0x4000).contains(&rva) {
            0x400 + (rva - 0x2000) as usize
        } else {
            0
        }
    };

    // Import thunk at RVA 0x1000: jmp dword ptr [IAT_VA]
    // IAT RVA = 0x2800, IAT VA = 0x10002800
    let thunk_off = rva_to_raw(0x1000);
    data[thunk_off] = 0xFF;
    data[thunk_off + 1] = 0x25;
    data[thunk_off + 2..thunk_off + 6].copy_from_slice(&0x10002800u32.to_le_bytes());

    // Entry function at RVA 0x1100: call thunk, ret
    let entry_off = rva_to_raw(0x1100);
    data[entry_off] = 0xE8; // call rel32
                            // call target VA = 0x10001000, next_ip VA = 0x10001105, rel = 0x10001000 - 0x10001105 = -0x105
    data[entry_off + 1..entry_off + 5].copy_from_slice(&0xFFFFFEFBu32.to_le_bytes());
    data[entry_off + 5] = 0xC3; // ret

    // Import directory at RVA 0x2000
    let import_off = rva_to_raw(0x2000);
    data[import_off..import_off + 4].copy_from_slice(&0x2020u32.to_le_bytes()); // ILT RVA
    data[import_off + 12..import_off + 16].copy_from_slice(&0x2040u32.to_le_bytes()); // name RVA
    data[import_off + 16..import_off + 20].copy_from_slice(&0x2800u32.to_le_bytes()); // IAT RVA (FirstThunk)
                                                                                      // Null descriptor at import_off+20 (already zero)

    // DLL name at RVA 0x2040
    let name_off = rva_to_raw(0x2040);
    let name = b"KERNEL32.dll\0";
    data[name_off..name_off + name.len()].copy_from_slice(name);

    // ILT entry at RVA 0x2020: points to hint/name
    let ilt_off = rva_to_raw(0x2020);
    data[ilt_off..ilt_off + 4].copy_from_slice(&0x2060u32.to_le_bytes()); // hint/name RVA
                                                                          // Null ILT entry at ilt_off+4 (already zero)

    // Hint/Name at RVA 0x2060
    let hn_off = rva_to_raw(0x2060);
    data[hn_off..hn_off + 2].copy_from_slice(&0u16.to_le_bytes()); // hint
    let func_name = b"TestFunc\0";
    data[hn_off + 2..hn_off + 2 + func_name.len()].copy_from_slice(func_name);

    // IAT entry at RVA 0x2800: points to hint/name (bound import)
    let iat_off = rva_to_raw(0x2800);
    data[iat_off..iat_off + 4].copy_from_slice(&0x2060u32.to_le_bytes());

    data
}

#[test]
fn test_import_thunk_identified() {
    let data = make_pe32_with_import_thunk();
    let binary = Binary::load(data).unwrap();
    assert_eq!(binary.execution_model, ExecutionModel::Native);

    let result = analyze_binary(&binary).unwrap();
    eprintln!(
        "[DEBUG] identity table size: {}",
        result.identity_table.binary_identities.len()
    );
    for (addr, id) in &result.identity_table.binary_identities {
        eprintln!(
            "[DEBUG]   identity @ 0x{:X}: kind={:?}, symbols={:?}",
            addr, id.kind, id.source_symbols
        );
    }

    // The thunk at 0x10001000 should be in the identity table as ImportThunk
    let thunk_addr = 0x10001000u64;
    let thunk_id = result
        .identity_table
        .binary_identities
        .get(&thunk_addr)
        .expect("Import thunk not found in identity table");
    assert_eq!(
        thunk_id.kind,
        IdentityKind::ImportThunk,
        "Thunk identity kind should be ImportThunk, got {:?}",
        thunk_id.kind
    );
    assert!(
        thunk_id
            .source_symbols
            .iter()
            .any(|s| s.contains("KERNEL32.dll")),
        "Import thunk should have KERNEL32.dll source symbol"
    );
}

#[test]
fn test_call_to_import_thunk_is_direct_external() {
    let data = make_pe32_with_import_thunk();
    let binary = Binary::load(data).unwrap();
    let result = analyze_binary(&binary).unwrap();

    // The entry function at 0x10001100 calls the thunk
    // This call should be classified as DirectExternal, not DirectInternal
    assert!(
        result.call_graph.direct_external >= 1,
        "Expected at least 1 DirectExternal call, got {}",
        result.call_graph.direct_external
    );

    // Find the call edge and verify it has a resolved symbol
    let entry_node = result
        .call_graph
        .nodes
        .iter()
        .find(|n| n.address.0 == 0x10001100)
        .expect("Entry function not found in call graph");

    let external_calls: Vec<_> = entry_node
        .outgoing_calls
        .iter()
        .filter(|e| e.resolved_symbol.is_some())
        .collect();
    assert!(
        !external_calls.is_empty(),
        "Entry function should have at least one resolved external call"
    );
    assert!(
        external_calls[0]
            .resolved_symbol
            .as_ref()
            .unwrap()
            .contains("TestFunc"),
        "Resolved symbol should contain TestFunc, got {:?}",
        external_calls[0].resolved_symbol
    );
}

#[test]
fn test_non_iat_jump_not_import_thunk() {
    // Build a binary where a function starts with jmp [global_var] (not IAT)
    // This should NOT be classified as ImportThunk (Fail-Closed)
    let mut data = make_pe32_with_import_thunk();
    // Overwrite the thunk at RVA 0x1000 to jump to a non-IAT address (0x10002500, in .data but not IAT)
    let thunk_off = 0x200; // raw offset for RVA 0x1000
    data[thunk_off] = 0xFF;
    data[thunk_off + 1] = 0x25;
    data[thunk_off + 2..thunk_off + 6].copy_from_slice(&0x10002500u32.to_le_bytes()); // non-IAT address

    let binary = Binary::load(data).unwrap();
    let result = analyze_binary(&binary).unwrap();

    let thunk_addr = 0x10001000u64;
    if let Some(id) = result.identity_table.binary_identities.get(&thunk_addr) {
        assert_ne!(
            id.kind,
            IdentityKind::ImportThunk,
            "Non-IAT jump should NOT be classified as ImportThunk"
        );
    }
}

#[test]
fn test_import_thunk_evidence_chain() {
    let data = make_pe32_with_import_thunk();
    let binary = Binary::load(data).unwrap();
    let result = analyze_binary(&binary).unwrap();

    // Verify the call graph external edge has evidence
    let entry_node = result
        .call_graph
        .nodes
        .iter()
        .find(|n| n.address.0 == 0x10001100)
        .expect("Entry function not found");

    let external_edge = entry_node
        .outgoing_calls
        .iter()
        .find(|e| e.resolved_symbol.is_some())
        .expect("No external call edge found");

    assert!(
        !external_edge.evidence.items.is_empty(),
        "External call edge should have evidence"
    );
}
