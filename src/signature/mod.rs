use super::errors::*;
use byteorder::{ByteOrder, LittleEndian, WriteBytesExt};

pub mod eddsa;

use self::eddsa::*;

#[derive(Debug)]
pub struct Signature {
    alg_id: u32,
    raw: Vec<u8>,
}

impl Signature {
    pub fn new(alg_id: u32, raw: Vec<u8>) -> Self {
        Signature { alg_id, raw }
    }

    pub fn length(signature_alg: &Box<dyn SignatureAlg>) -> usize {
        4 + signature_alg.raw_signature_length()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        bytes
            .write_u32::<LittleEndian>(self.alg_id)
            .expect("Unable to serialize");
        bytes.extend_from_slice(&self.raw);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WError> {
        let bytes_len = bytes.len();
        if bytes_len <= 4 {
            return Err(WError::ParseError("Short encoded signature".to_string()));
        }
        let alg_id = LittleEndian::read_u32(&bytes[..4]);
        let raw = bytes[4..].to_vec();
        Ok(Signature { alg_id, raw })
    }

    pub fn to_alg(&self) -> Result<Box<dyn SignatureAlg>, WError> {
        match self.alg_id {
            eddsa::ALG_ID => Ok(Box::new(EdDSA)),
            _ => Err(WError::SignatureError("Unsupported signature scheme")),
        }
    }
}

pub struct AnyKey {
    alg_id: u32,
    raw: Vec<u8>,
}

impl AnyKey {
    fn new(alg_id: u32, raw: Vec<u8>) -> Self {
        AnyKey { alg_id, raw }
    }
}

pub trait Key {
    fn alg_id(&self) -> u32;
    fn raw(&self) -> &[u8];

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes
            .write_u32::<LittleEndian>(self.alg_id())
            .expect("Unable to serialize");
        bytes.extend_from_slice(self.raw());
        bytes
    }

    fn anykey_from_bytes(bytes: &[u8]) -> Result<AnyKey, WError> {
        let bytes_len = bytes.len();
        if bytes_len <= 4 {
            return Err(WError::ParseError("Short encoded signature".to_string()));
        }
        let alg_id = LittleEndian::read_u32(&bytes[..4]);
        let raw = bytes[4..].to_vec();
        Ok(AnyKey::new(alg_id, raw))
    }

    fn to_alg(&self) -> Result<Box<dyn SignatureAlg>, WError> {
        match self.alg_id() {
            eddsa::ALG_ID => Ok(Box::new(EdDSA)),
            _ => Err(WError::SignatureError("Unsupported signature scheme")),
        }
    }
}

#[derive(Debug)]
pub struct PublicKey {
    alg_id: u32,
    raw: Vec<u8>,
}

#[derive(Debug)]
pub struct SecretKey {
    alg_id: u32,
    raw: Vec<u8>,
}

impl Key for PublicKey {
    fn alg_id(&self) -> u32 {
        self.alg_id
    }

    fn raw(&self) -> &[u8] {
        &self.raw
    }
}

impl PublicKey {
    pub fn new(alg_id: u32, raw: Vec<u8>) -> Self {
        PublicKey { alg_id, raw }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WError> {
        let key = Self::anykey_from_bytes(bytes)?;
        Ok(PublicKey {
            alg_id: key.alg_id,
            raw: key.raw,
        })
    }
}

impl Key for SecretKey {
    fn alg_id(&self) -> u32 {
        self.alg_id
    }

    fn raw(&self) -> &[u8] {
        &self.raw
    }
}

impl SecretKey {
    pub fn new(alg_id: u32, raw: Vec<u8>) -> Self {
        SecretKey { alg_id, raw }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WError> {
        let key = Self::anykey_from_bytes(bytes)?;
        Ok(SecretKey {
            alg_id: key.alg_id,
            raw: key.raw,
        })
    }
}

#[derive(Debug)]
pub struct KeyPair {
    alg_id: u32,
    pub pk: PublicKey,
    pub sk: SecretKey,
}

impl KeyPair {
    pub fn new(alg_id: u32, pk: PublicKey, sk: SecretKey) -> Self {
        assert!(pk.alg_id() == sk.alg_id());
        KeyPair { alg_id, pk, sk }
    }
}

pub trait SignatureAlg {
    fn alg_id(&self) -> u32;
    fn raw_signature_length(&self) -> usize;
    fn keygen(&self) -> KeyPair;
    fn sign(&self, data: &[u8], ad: Option<&[u8]>, key_pair: &KeyPair)
        -> Result<Signature, WError>;
    fn verify(
        &self,
        data: &[u8],
        ad: Option<&[u8]>,
        pk: &[u8],
        signature: &Signature,
    ) -> Result<(), WError>;
}
