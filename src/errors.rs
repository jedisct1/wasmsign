pub use anyhow::{anyhow, bail, ensure, Error};
use parity_wasm::elements;
use std::io;

#[derive(Debug, thiserror::Error)]
pub enum WError {
    #[error("Internal error: {0}")]
    InternalError(&'static str),
    #[error("Incorrect usage: {0}")]
    UsageError(&'static str),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    WAsmError(#[from] elements::Error),
    #[error("{0}")]
    SignatureError(&'static str),
    #[error("{0}")]
    EdDSASignatureError(#[from] ed25519_compact::Error),
    #[error("Unsupported")]
    Unsupported,
}
