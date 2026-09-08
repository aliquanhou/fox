//! FOX Address abstraction
//!
//! Addresses in FOX are always 64-bit internally, with metadata about
//! the address space they belong to.

use serde::{Deserialize, Serialize};

/// A 64-bit address with optional section/segment context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct Address(pub u64);

impl Address {
    pub const ZERO: Address = Address(0);

    pub fn new(value: u64) -> Self {
        Address(value)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn offset(&self, delta: i64) -> Option<Address> {
        if delta >= 0 {
            self.0.checked_add(delta as u64).map(Address)
        } else {
            self.0.checked_sub(delta.unsigned_abs()).map(Address)
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:016X}", self.0)
    }
}

impl From<u64> for Address {
    fn from(v: u64) -> Self {
        Address(v)
    }
}

impl From<u32> for Address {
    fn from(v: u32) -> Self {
        Address(v as u64)
    }
}
