use std::fs::File;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, anyhow, ensure};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf::{HKDF_SHA256, Salt};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::frames::Sha;
use crate::io::{Hash, atomic, atomic_files, hash, hex, read_up_to};

pub(crate) const TAG_BYTES: usize = 16;
const DIGEST_NONCE: u64 = u64::MAX;
const KEY_INFO: &[u8] = b"GRFP ChaCha20-Poly1305 key v1\0";
const SIGNATURE_PREFIX: &[u8] = b"GRFP Ed25519 catalog v1\0";

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Seal {
    pub salt: Sha,
    pub original_digest: Vec<u8>,
}

pub(crate) struct Cipher {
    key: LessSafeKey,
    aad: [u8; 13],
}

impl Cipher {
    pub(crate) fn new(
        path: &Path,
        salt: &Hash,
        bytes: u64,
        block_size: usize,
        bundle: bool,
    ) -> Result<Self> {
        let master = Zeroizing::new(key_bytes(path, 32)?);
        ensure!(master.len() == 32, "Expected a 32-byte GRFP encryption key");
        let prk = Salt::new(HKDF_SHA256, salt).extract(&master);
        let info = [KEY_INFO];
        let mut key = Zeroizing::new([0; 32]);
        prk.expand(&info, &CHACHA20_POLY1305)
            .and_then(|okm| okm.fill(&mut *key))
            .map_err(|_| anyhow!("Could not derive the archive encryption key"))?;
        let key = UnboundKey::new(&CHACHA20_POLY1305, key.as_ref())
            .map_err(|_| anyhow!("Invalid archive encryption key"))?;
        let mut aad = [0; 13];
        aad[..8].copy_from_slice(&bytes.to_le_bytes());
        aad[8..12].copy_from_slice(&(block_size as u32).to_le_bytes());
        aad[12] = u8::from(bundle);
        Ok(Self {
            key: LessSafeKey::new(key),
            aad,
        })
    }

    pub(crate) fn encrypt(&self, i: u64, message: &mut Vec<u8>) -> Result<()> {
        self.key
            .seal_in_place_append_tag(nonce(i), Aad::from(self.aad), message)
            .map_err(|_| anyhow!("Could not encrypt archive block"))
    }

    pub(crate) fn decrypt<'a>(&self, i: u64, message: &'a mut [u8]) -> Result<&'a [u8]> {
        let plain = self
            .key
            .open_in_place(nonce(i), Aad::from(self.aad), message)
            .map_err(|_| {
                anyhow!("Archive authentication failed. Check the encryption key and data.")
            })?;
        Ok(plain)
    }

    pub(crate) fn seal_digest(&self, salt: Hash, digest: Hash) -> Result<Seal> {
        let mut original_digest = digest.to_vec();
        self.encrypt(DIGEST_NONCE, &mut original_digest)?;
        Ok(Seal {
            salt: Sha(salt),
            original_digest,
        })
    }

    pub(crate) fn open_digest(&self, seal: &Seal) -> Result<Hash> {
        self.decrypt(DIGEST_NONCE, &mut seal.original_digest.clone())?
            .try_into()
            .map_err(|_| anyhow!("Invalid encrypted original checksum"))
    }
}

fn nonce(i: u64) -> Nonce {
    let mut bytes = [0; 12];
    bytes[4..].copy_from_slice(&i.to_le_bytes());
    Nonce::assume_unique_for_key(bytes)
}

pub(crate) fn random_bytes() -> Result<Hash> {
    let mut bytes = [0; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow!("Operating system randomness unavailable"))?;
    Ok(bytes)
}

fn key_bytes(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("Open key {}", path.display()))?;
    ensure!(file.metadata()?.is_file(), "Expected a regular key file");
    let bytes = read_up_to(file, limit + 1)?;
    ensure!(bytes.len() <= limit, "Key file is too large");
    Ok(bytes)
}

pub fn generate_encryption_key(path: &Path) -> Result<()> {
    let key = Zeroizing::new(random_bytes()?);
    atomic(path, |file| Ok(file.write_all(key.as_ref())?))
}

pub fn generate_signing_key(private: &Path, public: &Path) -> Result<()> {
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| anyhow!("Could not generate the Ed25519 key"))?;
    let pair = read_signer(document.as_ref())?;
    atomic_files(&[private.to_path_buf(), public.to_path_buf()], |files| {
        files[0].write_all(document.as_ref())?;
        files[1].write_all(pair.public_key().as_ref())?;
        Ok(())
    })
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Signature {
    pub public_key: Sha,
    pub signature: Vec<u8>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureStatus {
    pub public_key_sha256: String,
    pub trusted: bool,
}

fn read_signer(bytes: &[u8]) -> Result<Ed25519KeyPair> {
    Ed25519KeyPair::from_pkcs8(bytes).map_err(|_| anyhow!("Invalid PKCS#8 Ed25519 private key"))
}

fn signature_message(catalog: &[u8]) -> Vec<u8> {
    [SIGNATURE_PREFIX, &hash(catalog)].concat()
}

pub(crate) fn sign(catalog: &[u8], private: &Path) -> Result<Signature> {
    let bytes = Zeroizing::new(key_bytes(private, 512)?);
    let pair = read_signer(&bytes)?;
    Ok(Signature {
        public_key: Sha(pair.public_key().as_ref().try_into()?),
        signature: pair.sign(&signature_message(catalog)).as_ref().to_vec(),
    })
}

impl Signature {
    pub(crate) fn verify(&self, catalog: &[u8], trusted: Option<&Path>) -> Result<SignatureStatus> {
        if let Some(path) = trusted {
            let key = key_bytes(path, 32)?;
            ensure!(
                key.as_slice() == self.public_key.0,
                "Archive signer does not match the trusted public key"
            );
        }
        UnparsedPublicKey::new(&ED25519, self.public_key.0)
            .verify(&signature_message(catalog), &self.signature)
            .map_err(|_| anyhow!("Invalid archive signature"))?;
        Ok(SignatureStatus {
            public_key_sha256: hex(&hash(&self.public_key.0)),
            trusted: trusted.is_some(),
        })
    }
}
