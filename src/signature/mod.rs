use super::errors::*;
use byteorder::{ByteOrder, LittleEndian, WriteBytesExt};

#[derive(Debug)]
pub struct Signature {
    id: u32,
    raw: Vec<u8>,
}

impl Signature {
    pub fn new(id: u32, raw: Vec<u8>) -> Self {
        Signature { id, raw }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        bytes.write_u32::<LittleEndian>(self.id).unwrap();
        bytes.extend_from_slice(&self.raw);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WError> {
        let bytes_len = bytes.len();
        if bytes_len <= 4 {
            Err(WError::ParseError("Short encoded signature".to_string()))?;
        }
        let id = LittleEndian::read_u32(&bytes[..4]);
        let raw = bytes[4..].to_vec();
        Ok(Signature { id, raw })
    }
}

