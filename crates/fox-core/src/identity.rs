//! FOX Function Identity Model
//!
//! P0-3.4: Distinguishes Binary Function Identity from Source Function Identity.
//!
//! In real-world binaries, the relationship between source-level functions
//! and binary-level functions is not 1:1:
//!
//! - ICF (Identical COMDAT Folding): multiple source functions with identical
//!   compiled bodies are folded into a single binary function by the linker.
//! - Thunks/Jump Islands: CALL targets are JMP instructions that redirect to
//!   the real function body.
//! - Function Pointers: a function's address is taken and stored, making it
//!   reachable via indirect calls.
//! - Inlining: a source function may have no independent binary identity.
//!
//! This module models these relationships so that FOX does not incorrectly
//! treat a thunk as a real function, or an ICF-folded function as two
//! separate functions.

use serde::{Deserialize, Serialize};

/// The kind of binary identity a function address represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityKind {
    /// Canonical function: real code body, entry point of a function.
    Canonical,
    /// Thunk: single JMP instruction redirecting to a canonical function.
    Thunk,
    /// ImportThunk: single indirect JMP through IAT to an external function.
    /// e.g., `jmp dword ptr [IAT_entry]` on x86, `jmp [rip+disp]` on x64.
    ImportThunk,
    /// Folded: this binary function is the result of ICF folding multiple
    /// source functions into one body.
    Folded,
    /// Alias: this address is an alternative name for another function
    /// (e.g., export forwarding, weak alias).
    Alias,
    /// Unknown: identity not yet determined.
    Unknown,
}

impl IdentityKind {
    pub fn display_name(&self) -> &'static str {
        match self {
            IdentityKind::Canonical => "Canonical",
            IdentityKind::Thunk => "Thunk",
            IdentityKind::ImportThunk => "ImportThunk",
            IdentityKind::Folded => "Folded (ICF)",
            IdentityKind::Alias => "Alias",
            IdentityKind::Unknown => "Unknown",
        }
    }
}

/// Binary function identity: the actual code at a specific address.
///
/// This is the "machine-level" identity. Multiple source functions may
/// map to the same binary identity (via ICF), and a binary identity may
/// be reachable through multiple thunks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryFunctionIdentity {
    /// Address of the actual code body.
    pub address: u64,
    /// Kind of identity.
    pub kind: IdentityKind,
    /// If this is a Thunk, the canonical function it redirects to.
    pub thunk_target: Option<u64>,
    /// Source-level function names that map to this binary identity.
    /// For ICF-folded functions, this will have multiple entries.
    pub source_symbols: Vec<String>,
    /// Thunk addresses that redirect to this canonical function.
    pub thunk_addresses: Vec<u64>,
    /// Whether this function's address is taken (stored in data or
    /// loaded via LEA), making it reachable via function pointers.
    pub address_taken: bool,
    /// Number of direct CALL references to this function (or its thunks).
    pub call_reference_count: usize,
}

impl BinaryFunctionIdentity {
    pub fn new(address: u64) -> Self {
        BinaryFunctionIdentity {
            address,
            kind: IdentityKind::Unknown,
            thunk_target: None,
            source_symbols: Vec::new(),
            thunk_addresses: Vec::new(),
            address_taken: false,
            call_reference_count: 0,
        }
    }

    /// Returns true if this is a real function body (not a thunk).
    pub fn is_canonical(&self) -> bool {
        matches!(self.kind, IdentityKind::Canonical | IdentityKind::Folded)
    }

    /// Returns true if multiple source functions fold to this binary identity.
    pub fn is_icf_folded(&self) -> bool {
        self.source_symbols.len() > 1
    }
}

/// Source function identity: a function as defined in source code.
///
/// This is the "language-level" identity. A source function may:
/// - Map to exactly one binary function (normal case)
/// - Be inlined (no binary identity)
/// - Be ICF-folded with other source functions (shared binary identity)
/// - Be unreferenced (dead code, no binary identity)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFunctionIdentity {
    /// Source-level function name (from symbols/map/PDB).
    pub name: String,
    /// The binary identity this source function maps to, if any.
    /// None means inlined or removed.
    pub binary_address: Option<u64>,
    /// Whether this source function was inlined (no independent body).
    pub inlined: bool,
    /// Whether this source function was removed by the linker
    /// (unreferenced COMDAT).
    pub removed: bool,
    /// Other source functions that share the same binary identity (ICF).
    pub folded_with: Vec<String>,
}

/// A relationship between two function identities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IdentityRelation {
    /// `from` is a thunk that redirects to `to`.
    ThunkRedirect { from: u64, to: u64 },
    /// `from` and `to` are source functions folded into the same binary body.
    IcfFold {
        from: String,
        to: String,
        binary_address: u64,
    },
    /// `from` is an alias for `to` (export forwarding, etc.).
    Alias { from: u64, to: u64 },
}

/// The complete function identity table for a binary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionIdentityTable {
    /// Binary identities keyed by address.
    pub binary_identities: std::collections::BTreeMap<u64, BinaryFunctionIdentity>,
    /// Source identities keyed by name.
    pub source_identities: std::collections::BTreeMap<String, SourceFunctionIdentity>,
    /// Identity relationships.
    pub relations: Vec<IdentityRelation>,
}

impl FunctionIdentityTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create a binary identity.
    pub fn get_or_create(&mut self, address: u64) -> &mut BinaryFunctionIdentity {
        self.binary_identities
            .entry(address)
            .or_insert_with(|| BinaryFunctionIdentity::new(address))
    }

    /// Record a thunk relationship.
    pub fn record_thunk(&mut self, thunk_addr: u64, target_addr: u64) {
        // Mark thunk
        {
            let thunk = self.get_or_create(thunk_addr);
            thunk.kind = IdentityKind::Thunk;
            thunk.thunk_target = Some(target_addr);
        }
        // Mark target as canonical and record thunk pointer
        {
            let target = self.get_or_create(target_addr);
            if target.kind == IdentityKind::Unknown {
                target.kind = IdentityKind::Canonical;
            }
            if !target.thunk_addresses.contains(&thunk_addr) {
                target.thunk_addresses.push(thunk_addr);
            }
        }
        self.relations.push(IdentityRelation::ThunkRedirect {
            from: thunk_addr,
            to: target_addr,
        });
    }

    /// Record that a source function maps to a binary address.
    pub fn record_source_mapping(&mut self, name: &str, binary_address: u64) {
        // Update binary identity
        {
            let bin = self.get_or_create(binary_address);
            if !bin.source_symbols.iter().any(|s| s == name) {
                bin.source_symbols.push(name.to_string());
            }
            if bin.source_symbols.len() > 1 {
                bin.kind = IdentityKind::Folded;
            } else if bin.kind == IdentityKind::Unknown {
                bin.kind = IdentityKind::Canonical;
            }
        }

        // Update source identity
        let folded_with = self
            .binary_identities
            .get(&binary_address)
            .map(|b| {
                b.source_symbols
                    .iter()
                    .filter(|s| *s != name)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();

        let src = self
            .source_identities
            .entry(name.to_string())
            .or_insert_with(|| SourceFunctionIdentity {
                name: name.to_string(),
                binary_address: None,
                inlined: false,
                removed: false,
                folded_with: Vec::new(),
            });
        src.binary_address = Some(binary_address);
        src.folded_with = folded_with;

        // Record ICF relation if folded
        if let Some(bin) = self.binary_identities.get(&binary_address) {
            if bin.source_symbols.len() > 1 {
                for other in &bin.source_symbols {
                    if other != name {
                        self.relations.push(IdentityRelation::IcfFold {
                            from: name.to_string(),
                            to: other.clone(),
                            binary_address,
                        });
                    }
                }
            }
        }
    }

    /// Count canonical (real) functions.
    pub fn canonical_count(&self) -> usize {
        self.binary_identities
            .values()
            .filter(|b| b.is_canonical())
            .count()
    }

    /// Count thunks.
    pub fn thunk_count(&self) -> usize {
        self.binary_identities
            .values()
            .filter(|b| matches!(b.kind, IdentityKind::Thunk))
            .count()
    }

    /// Count ICF-folded binary identities.
    pub fn folded_count(&self) -> usize {
        self.binary_identities
            .values()
            .filter(|b| b.is_icf_folded())
            .count()
    }
}
