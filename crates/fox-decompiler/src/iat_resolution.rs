//! GAP-RM-4: IAT / Import symbol resolution.
//!
//! Upper callgraph only resolved 1 external symbol on NTCDLLV.DLL
//! (direct_external=1, indirect_unknown=168) because `call [iat_entry]`
//! was never matched against the PE import table. This module builds an
//! IAT-address -> symbol map from `Binary.imports` so `call [0x416000]`
//! can be attributed to e.g. `CreateFileW` instead of Unknown.

use std::collections::HashMap;

/// Maps an IAT entry address (the `call [mem]` target) to an import symbol name.
#[derive(Debug, Clone, Default)]
pub struct IatMap {
    entries: HashMap<u64, String>,
}

impl IatMap {
    /// Build from the parsed binary import table.
    pub fn from_binary(bin: &fox_binary::Binary) -> Self {
        let mut entries = HashMap::new();
        for imp in &bin.imports {
            for f in &imp.functions {
                if let Some(name) = &f.name {
                    // iat_address is an RVA; call [mem] gives a VA = image_base + RVA.
                    entries.insert(bin.image_base + f.iat_address, name.clone());
                }
            }
        }
        Self { entries }
    }

    #[allow(dead_code)]
    pub fn debug_dump(&self) {
        for (k, v) in self.entries.iter().take(5) {
            eprintln!("RM4DBG iat_key={:X} name={}", k, v);
        }
    }

    /// Look up a symbol name by IAT entry address.
    pub fn lookup(&self, iat_addr: u64) -> Option<&str> {
        self.entries.get(&iat_addr).map(|s| s.as_str())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_hit() {
        let mut m = IatMap::default();
        m.entries.insert(0x416000, "CreateFileW".to_string());
        assert_eq!(m.lookup(0x416000), Some("CreateFileW"));
        assert_eq!(m.lookup(0x416004), None);
    }
}
