

pub mod errors;
pub mod signature;
mod wasm_signature;

pub use self::errors::*;
pub use self::signature::*;
use parity_wasm::elements::*;

pub const DEFAULT_SYMBOL_NAME: &str = "___SIGNATURE";

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
    let module: Module = parity_wasm::deserialize_buffer(module_bytes)?;
    let module =
        wasm_signature::attach_signature(module, &signature_alg, ad, &key_pair, symbol_name)?;
    let signed_module_bytes = parity_wasm::serialize(module)?;
    Ok(signed_module_bytes)
}

pub fn verify(
    module_bytes: &[u8],
    pk: &PublicKey,
    ad: Option<&[u8]>,
    symbol_name: &str,
) -> Result<(), WError> {
    pk.to_alg()?;
    let module: Module = parity_wasm::deserialize_buffer(module_bytes)?;
    wasm_signature::verify_signature(&module, ad, pk, symbol_name)
}
