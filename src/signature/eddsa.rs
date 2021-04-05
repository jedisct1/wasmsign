use super::*;
use byteorder::{LittleEndian, WriteBytesExt};
use hmac_sha512::Hash;
use std::u32;

const CONTEXT: &[u8] = b"WasmSignature";
pub const ALG_ID: u32 = 0x0000_0002;

pub struct EdDSA;

impl SignatureAlg for EdDSA {
    fn alg_id(&self) -> u32 {
        ALG_ID
    }

    fn raw_signature_length(&self) -> usize {
        ed25519_compact::Signature::BYTES
    }

    fn keygen(&self) -> KeyPair {
        let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::default());
        KeyPair {
            alg_id: ALG_ID,
            pk: PublicKey::new(ALG_ID, kp.pk.to_vec()),
            sk: SecretKey::new(ALG_ID, kp.sk.to_vec()),
        }
    }

    fn sign(
        &self,
        data: &[u8],
        ad: Option<&[u8]>,
        key_pair: &KeyPair,
    ) -> Result<Signature, WError> {
        let prehashed = Self::prehash(data, ad)?;
        let xsk = ed25519_compact::SecretKey::from_slice(key_pair.sk.raw())?;
        let raw = xsk
            .sign(prehashed, Some(ed25519_compact::Noise::default()))
            .to_vec();
        Ok(Signature::new(ALG_ID, raw))
    }

    fn verify(
        &self,
        data: &[u8],
        ad: Option<&[u8]>,
        pk: &[u8],
        signature: &Signature,
    ) -> Result<(), WError> {
        assert_eq!(signature.alg_id, ALG_ID);
        let prehashed = Self::prehash(data, ad)?;
        let xpk = ed25519_compact::PublicKey::from_slice(pk)?;
        let xsignature = ed25519_compact::Signature::from_slice(&signature.raw)?;
        xpk.verify(prehashed, &xsignature).map_err(|e| e.into())
    }
}

impl EdDSA {
    fn prehash(data: &[u8], ad: Option<&[u8]>) -> Result<[u8; 64], WError> {
        let mut ad_len = vec![];
        let ad = ad.unwrap_or_default();
        if ad.len() > u32::MAX as usize {
            return Err(WError::UsageError("Additional data too long"))
        }
        ad_len.write_u32::<LittleEndian>(ad.len() as u32)?;

        let mut prehashed = Hash::default();
        prehashed.update(CONTEXT);
        prehashed.update(&ad_len);
        prehashed.update(ad);
        prehashed.update(data);
        Ok(prehashed.finalize())
    }
}
