//! FOX Error Types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum FoxError {
    #[error("Invalid binary format: {0}")]
    InvalidFormat(String),

    #[error("Unsupported architecture: {0}")]
    UnsupportedArchitecture(String),

    #[error("Unsupported binary format: {0}")]
    UnsupportedBinaryFormat(String),

    #[error("Unsupported execution model: {0}")]
    UnsupportedExecutionModel(String),

    #[error("Parse error at offset 0x{offset:X}: {message}")]
    ParseError { offset: usize, message: String },

    #[error("Disassembly error: {0}")]
    DisassemblyError(String),

    #[error("Analysis error: {0}")]
    AnalysisError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Address out of range: 0x{0:X}")]
    AddressOutOfRange(u64),

    #[error("Invalid evidence: {0}")]
    InvalidEvidence(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("{0}")]
    Other(String),
}

impl From<anyhow::Error> for FoxError {
    fn from(e: anyhow::Error) -> Self {
        FoxError::Other(e.to_string())
    }
}
