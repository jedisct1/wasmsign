use super::*;
use byteorder::{LittleEndian, WriteBytesExt};
use ed25519_dalek::SIGNATURE_LENGTH;
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};
use std::u32;

const CONTEXT: &[u8] = b"WasmSignature";
pub const ALG_ID: u32 = 0x0000_0001;

pub struct EdDSA;

impl SignatureAlg for EdDSA {
    fn alg_id(&self) -> u32 {
        ALG_ID
    }

    fn raw_signature_length(&self) -> usize {
        SIGNATURE_LENGTH
    }

    fn keygen(&self) -> KeyPair {
        let mut csprng = OsRng::new().expect("CSPRNG not available");
        let keypair = ed25519_dalek::Keypair::generate::<Sha512, _>(&mut csprng);
        KeyPair {
            alg_id: ALG_ID,
            pk: PublicKey::new(ALG_ID, keypair.public.to_bytes().to_vec()),
            sk: SecretKey::new(ALG_ID, keypair.secret.to_bytes().to_vec()),
        }
    }

    fn sign(
        &self,
        data: &[u8],
        ad: Option<&[u8]>,
        key_pair: &KeyPair,
    ) -> Result<Signature, WError> {
        let prehashed = Self::prehash(data, ad)?;
        let xpk = ed25519_dalek::PublicKey::from_bytes(key_pair.pk.raw())?;
        let xsk = ed25519_dalek::SecretKey::from_bytes(key_pair.sk.raw())?;
        let xkey_pair = ed25519_dalek::Keypair {
            public: xpk,
            secret: xsk,
        };
        let raw = xkey_pair
            .sign_prehashed(prehashed, Some(CONTEXT))
            .to_bytes()
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
        let xpk = ed25519_dalek::PublicKey::from_bytes(pk)?;
        let xsignature = ed25519_dalek::Signature::from_bytes(&signature.raw)?;
        xpk.verify_prehashed(prehashed, Some(CONTEXT), &xsignature)
            .map_err(|e| e.into())
    }
}

impl EdDSA {
    fn prehash(data: &[u8], ad: Option<&[u8]>) -> Result<Sha512, WError> {
        let mut ad_len = vec![];
        let ad = ad.unwrap_or_default();
        if ad.len() > u32::MAX as usize {
            Err(WError::UsageError("Additional data too long"))?
        }
        ad_len.write_u32::<LittleEndian>(ad.len() as u32)?;

        let mut prehashed = Sha512::default();
        prehashed.input(&ad_len);
        prehashed.input(ad);
        prehashed.input(data);

        Ok(prehashed)
    }
}
