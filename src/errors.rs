use parity_wasm::elements;
use std::io;

#[allow(dead_code)]
#[derive(Debug, Fail)]
pub enum WError {
    #[fail(display = "Internal error: {}", _0)]
    InternalError(&'static str),
    #[fail(display = "Incorrect usage: {}", _0)]
    UsageError(&'static str),
    #[fail(display = "Parse error: {}", _0)]
    ParseError(String),
    #[fail(display = "{}", _0)]
    Io(#[cause] io::Error),
    #[fail(display = "{}", _0)]
    WAsmError(#[cause] elements::Error),
    #[fail(display = "{}", _0)]
    SignatureError(&'static str),
    #[fail(display = "{}", _0)]
    EdDSASignatureError(#[cause] ed25519_compact::Error),
    #[fail(display = "Unsupported")]
    Unsupported,
}

impl From<io::Error> for WError {
    fn from(e: io::Error) -> WError {
        WError::Io(e)
    }
}

impl From<elements::Error> for WError {
    fn from(e: elements::Error) -> WError {
        WError::WAsmError(e)
    }
}

impl From<ed25519_compact::Error> for WError {
    fn from(e: ed25519_compact::Error) -> WError {
        WError::EdDSASignatureError(e)
    }
}
