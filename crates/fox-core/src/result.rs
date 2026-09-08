//! FOX Result type alias

pub type FoxResult<T> = std::result::Result<T, crate::error::FoxError>;
