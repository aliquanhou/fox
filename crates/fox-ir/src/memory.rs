//! FOX Memory Semantics (P0-3.4)
//!
//! Memory Location abstraction:
//! - Stack slot (based on RSP/RBP offset)
//! - Global (RIP-relative or absolute address)
//! - Heap / unknown pointer
//! - Alias candidates
//!
//! This prepares for Memory SSA (P0-3.7) and Alias Analysis.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A memory location classification.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemoryLocation {
    /// Stack slot: base register (RSP/RBP) + displacement
    Stack {
        base_register: String,
        displacement: i64,
        size: u32,
    },
    /// Global variable: RIP-relative or absolute address
    Global {
        address: u64,
        size: u32,
        rip_relative: bool,
    },
    /// Heap or unknown pointer-based access
    Heap {
        base_register: String,
        index_register: Option<String>,
        scale: u32,
        displacement: i64,
        size: u32,
    },
    /// Unknown memory location (cannot classify)
    Unknown { description: String, size: u32 },
}

impl MemoryLocation {
    pub fn size(&self) -> u32 {
        match self {
            MemoryLocation::Stack { size, .. } => *size,
            MemoryLocation::Global { size, .. } => *size,
            MemoryLocation::Heap { size, .. } => *size,
            MemoryLocation::Unknown { size, .. } => *size,
        }
    }

    pub fn is_stack(&self) -> bool {
        matches!(self, MemoryLocation::Stack { .. })
    }

    pub fn is_global(&self) -> bool {
        matches!(self, MemoryLocation::Global { .. })
    }

    /// Conservative alias check: returns true if two locations MAY alias.
    ///
    /// - Same exact location: definitely alias
    /// - Stack vs Global: never alias
    /// - Stack vs Stack with different offsets: may alias if overlapping
    /// - Heap: always may alias (conservative)
    /// - Unknown: always may alias
    pub fn may_alias(&self, other: &MemoryLocation) -> bool {
        match (self, other) {
            (
                MemoryLocation::Stack {
                    base_register: b1,
                    displacement: d1,
                    size: s1,
                },
                MemoryLocation::Stack {
                    base_register: b2,
                    displacement: d2,
                    size: s2,
                },
            ) => {
                if b1 != b2 {
                    return true; // different base registers -> conservative
                }
                // Same base: check overlap
                let start1 = *d1;
                let end1 = d1 + *s1 as i64;
                let start2 = *d2;
                let end2 = d2 + *s2 as i64;
                start1 < end2 && start2 < end1
            }
            (
                MemoryLocation::Global { address: a1, .. },
                MemoryLocation::Global { address: a2, .. },
            ) => {
                a1 == a2 // exact match for globals
            }
            (MemoryLocation::Stack { .. }, MemoryLocation::Global { .. }) => false,
            (MemoryLocation::Global { .. }, MemoryLocation::Stack { .. }) => false,
            (MemoryLocation::Heap { .. }, _) => true,
            (_, MemoryLocation::Heap { .. }) => true,
            (MemoryLocation::Unknown { .. }, _) => true,
            (_, MemoryLocation::Unknown { .. }) => true,
        }
    }
}

/// A memory operation (load or store).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryOperation {
    pub address: u64,
    pub is_load: bool,
    pub is_store: bool,
    pub location: MemoryLocation,
    pub data_register: Option<String>,
}

/// Memory analysis result for a function.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MemoryAnalysis {
    pub operations: Vec<MemoryOperation>,
    pub stack_slots: HashSet<(String, i64)>,
    pub globals: HashSet<u64>,
    pub heap_accesses: usize,
    pub unknown_accesses: usize,
}

impl MemoryAnalysis {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_operation(&mut self, op: MemoryOperation) {
        match &op.location {
            MemoryLocation::Stack {
                base_register,
                displacement,
                ..
            } => {
                self.stack_slots
                    .insert((base_register.clone(), *displacement));
            }
            MemoryLocation::Global { address, .. } => {
                self.globals.insert(*address);
            }
            MemoryLocation::Heap { .. } => {
                self.heap_accesses += 1;
            }
            MemoryLocation::Unknown { .. } => {
                self.unknown_accesses += 1;
            }
        }
        self.operations.push(op);
    }

    pub fn load_count(&self) -> usize {
        self.operations.iter().filter(|o| o.is_load).count()
    }

    pub fn store_count(&self) -> usize {
        self.operations.iter().filter(|o| o.is_store).count()
    }
}

/// Classify a memory operand from structured IR.
pub fn classify_memory(
    base: Option<&str>,
    index: Option<&str>,
    scale: u32,
    displacement: i64,
    size: u32,
    rip_relative: bool,
    effective_address: Option<u64>,
) -> MemoryLocation {
    // RIP-relative -> global
    if rip_relative {
        if let Some(addr) = effective_address {
            return MemoryLocation::Global {
                address: addr,
                size,
                rip_relative: true,
            };
        }
        return MemoryLocation::Global {
            address: displacement as u64,
            size,
            rip_relative: true,
        };
    }

    let base_str = base.unwrap_or("").to_string();

    // Stack access: RSP or RBP based
    if (base_str == "RSP"
        || base_str == "RBP"
        || base_str == "ESP"
        || base_str == "EBP"
        || base_str == "SP"
        || base_str == "BP")
        && index.is_none()
    {
        return MemoryLocation::Stack {
            base_register: base_str,
            displacement,
            size,
        };
    }

    // Absolute address (no base, no index) -> global
    if base.is_none() && index.is_none() {
        return MemoryLocation::Global {
            address: displacement as u64,
            size,
            rip_relative: false,
        };
    }

    // Everything else -> heap/pointer
    MemoryLocation::Heap {
        base_register: base_str,
        index_register: index.map(|s| s.to_string()),
        scale,
        displacement,
        size,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_classification() {
        let loc = classify_memory(Some("RSP"), None, 1, -0x20, 8, false, None);
        assert!(loc.is_stack());
        if let MemoryLocation::Stack {
            base_register,
            displacement,
            ..
        } = loc
        {
            assert_eq!(base_register, "RSP");
            assert_eq!(displacement, -0x20);
        }
    }

    #[test]
    fn test_rip_relative_global() {
        let loc = classify_memory(Some("RIP"), None, 1, 0x1234, 4, true, Some(0x140005000));
        assert!(loc.is_global());
        if let MemoryLocation::Global {
            address,
            rip_relative,
            ..
        } = loc
        {
            assert_eq!(address, 0x140005000);
            assert!(rip_relative);
        }
    }

    #[test]
    fn test_heap_classification() {
        let loc = classify_memory(Some("RBX"), Some("RCX"), 4, 0x10, 4, false, None);
        assert!(matches!(loc, MemoryLocation::Heap { .. }));
    }

    #[test]
    fn test_stack_no_alias_different_offsets() {
        let s1 = MemoryLocation::Stack {
            base_register: "RSP".into(),
            displacement: -0x20,
            size: 8,
        };
        let s2 = MemoryLocation::Stack {
            base_register: "RSP".into(),
            displacement: -0x10,
            size: 8,
        };
        assert!(!s1.may_alias(&s2));
    }

    #[test]
    fn test_stack_alias_overlapping() {
        let s1 = MemoryLocation::Stack {
            base_register: "RSP".into(),
            displacement: -0x20,
            size: 16,
        };
        let s2 = MemoryLocation::Stack {
            base_register: "RSP".into(),
            displacement: -0x18,
            size: 8,
        };
        assert!(s1.may_alias(&s2));
    }

    #[test]
    fn test_stack_global_no_alias() {
        let s = MemoryLocation::Stack {
            base_register: "RSP".into(),
            displacement: -8,
            size: 8,
        };
        let g = MemoryLocation::Global {
            address: 0x140005000,
            size: 8,
            rip_relative: false,
        };
        assert!(!s.may_alias(&g));
    }

    #[test]
    fn test_heap_aliases_everything() {
        let h = MemoryLocation::Heap {
            base_register: "RAX".into(),
            index_register: None,
            scale: 1,
            displacement: 0,
            size: 8,
        };
        let s = MemoryLocation::Stack {
            base_register: "RSP".into(),
            displacement: -8,
            size: 8,
        };
        assert!(h.may_alias(&s));
    }
}
