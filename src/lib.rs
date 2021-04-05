pub mod errors;
pub mod signature;
mod wasm_signature;

pub use self::errors::*;
pub use self::signature::*;

pub const DEFAULT_SYMBOL_NAME: &str = "___SIGNATURE";
pub const DEFAULT_CUSTOM_SECTION_NAME: &str = "signature_wasmsign";

pub fn keygen(signature_alg: &dyn SignatureAlg) -> KeyPair {
    signature_alg.keygen()
}

pub fn sign(
    module_bytes: &[u8],
    key_pair: &KeyPair,
    ad: Option<&[u8]>,
    symbol_name: &str,
) -> Result<Vec<u8>, WError> {
    let signature_alg = key_pair.sk.to_alg()?;
    wasm_signature::attach_signature(&module_bytes, &signature_alg, ad, &key_pair, symbol_name)
}

pub fn sign_custom_section(
    module_bytes: &[u8],
    key_pair: &KeyPair,
    ad: Option<&[u8]>,
    custom_section_name: &str,
) -> Result<Vec<u8>, WError> {
    let signature_alg = key_pair.sk.to_alg()?;
    wasm_signature::attach_signature_in_custom_section(
        &module_bytes,
        &signature_alg,
        ad,
        &key_pair,
        custom_section_name,
    )
}

pub fn verify(
    module_bytes: &[u8],
    pk: &PublicKey,
    ad: Option<&[u8]>,
    symbol_name: &str,
) -> Result<(), WError> {
    pk.to_alg()?;
    wasm_signature::verify_signature(&module_bytes, ad, pk, symbol_name)
}

pub fn verify_custom_section(
    module_bytes: &[u8],
    pk: &PublicKey,
    ad: Option<&[u8]>,
    custom_section_name: &str,
) -> Result<(), WError> {
    pk.to_alg()?;
    wasm_signature::verify_signature_in_custom_section(&module_bytes, ad, pk, custom_section_name)
}
