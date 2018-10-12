extern crate byteorder;
#[macro_use]
extern crate failure;
extern crate parity_wasm;

mod errors;
mod signature;
mod wasm_signature;

use self::errors::*;
use self::signature::*;

fn main() -> Result<(), WError> {
    let module_path = "module.wasm";
    let mut module = parity_wasm::deserialize_file(module_path)?;
    let signature_type = 0x12345678;
    let signature_raw = vec![1, 2, 3, 4, 5];
    let signature = Signature::new(signature_type, signature_raw);
    module = wasm_signature::attach_signature(module, &signature, "__SIGNATURE")?;

    println!("{:#?}", module);

    let signature = wasm_signature::get_signature(&module, "__SIGNATURE")?;
    println!("signature: {:#?}", signature);

    Ok(())
}
