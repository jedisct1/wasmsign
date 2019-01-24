use super::*;
use std::fs::File;
use std::io::prelude::*;
use wasmsign;
use wasmsign::signature::eddsa::*;

pub fn keygen(config: &Config) -> Result<(), WError> {
    let default_signature_alg = EdDSA;
    let (pk_path, sk_path) = match (&config.pk_path, &config.sk_path) {
        (Some(pk_path), Some(sk_path)) => (pk_path, sk_path),
        _ => Err(WError::UsageError(
            "Please mention the file paths to store the public and secret keys",
        ))?,
    };
    let key_pair = wasmsign::keygen(&default_signature_alg);
    File::create(pk_path)?.write_all(&key_pair.pk.to_bytes())?;
    File::create(sk_path)?.write_all(&key_pair.sk.to_bytes())?;
    println!("Public key stored to [{}]", pk_path.to_str().unwrap());
    println!("Secret key stored to [{}]", sk_path.to_str().unwrap());
    Ok(())
}

pub fn sign(config: &Config) -> Result<(), WError> {
    let (pk_path, sk_path) = match (&config.pk_path, &config.sk_path) {
        (Some(pk_path), Some(sk_path)) => (pk_path, sk_path),
        _ => Err(WError::UsageError(
            "Please mention the file paths to store the public and secret keys",
        ))?,
    };
    let mut pk_bytes = vec![];
    let mut sk_bytes = vec![];
    File::open(pk_path)?.read_to_end(&mut pk_bytes)?;
    File::open(sk_path)?.read_to_end(&mut sk_bytes)?;
    let pk = PublicKey::from_bytes(&pk_bytes)?;
    let sk = SecretKey::from_bytes(&sk_bytes)?;
    let alg_id = pk.alg_id();
    if alg_id != sk.alg_id() {
        Err(WError::UsageError(
            "Public and secret keys are not of the same type",
        ))?
    }
    let key_pair = KeyPair::new(alg_id, pk, sk);
    let input_path = match &config.input_path {
        Some(input_path) => input_path,
        _ => Err(WError::UsageError("Input file path required"))?,
    };
    let output_path = match &config.output_path {
        Some(output_path) => output_path,
        _ => Err(WError::UsageError("Output file path required"))?,
    };
    let ad: Option<&[u8]> = config.ad.as_ref().map(|s| s.as_slice());
    let mut module_bytes = vec![];
    File::open(input_path)?.read_to_end(&mut module_bytes)?;
    let signed_module_bytes = wasmsign::sign(&module_bytes, &key_pair, ad, &config.symbol_name)?;
    File::create(output_path)?.write_all(&signed_module_bytes)?;
    Ok(())
}

pub fn verify(config: &Config) -> Result<(), WError> {
    let pk_path = match &config.pk_path {
        Some(pk_path) => pk_path,
        _ => Err(WError::UsageError(
            "Please mention the file paths containing the public key",
        ))?,
    };
    let mut pk_bytes = vec![];
    File::open(pk_path)?.read_to_end(&mut pk_bytes)?;
    let pk = PublicKey::from_bytes(&pk_bytes)?;
    let input_path = match &config.input_path {
        Some(input_path) => input_path,
        _ => Err(WError::UsageError("Input file path required"))?,
    };
    let ad: Option<&[u8]> = config.ad.as_ref().map(|s| s.as_slice());
    let mut module_bytes = vec![];
    File::open(input_path)?.read_to_end(&mut module_bytes)?;
    wasmsign::verify(&module_bytes, &pk, ad, &config.symbol_name)
}
