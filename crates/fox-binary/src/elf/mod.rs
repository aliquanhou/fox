//! ELF Parser - P0 placeholder
//!
//! Full implementation scheduled for P0-2.

use crate::Binary;
use fox_core::FoxResult;

pub struct ELF;

impl ELF {
    pub fn parse(_data: &[u8]) -> FoxResult<Binary> {
        Err(fox_core::FoxError::NotImplemented(
            "ELF parser (P0-2)".into(),
        ))
    }
}
