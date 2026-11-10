//! # Encrypted keystore
//!
//! Seed-at-rest protection: the 64-byte BIP39 seed (or mnemonic phrase)
//! is encrypted with XChaCha20-Poly1305 — wait, we use ChaCha20-Poly1305
//! (12-byte nonce, random per encryption) — keyed by
//! PBKDF2-HMAC-SHA256(passphrase, salt, 600 000 iterations).
//!
//! File format (all little-endian where applicable):
//! ```text
//! [8B magic "MBTCKS01"][4B kdf_iters u32][32B salt][12B nonce][ciphertext…]
//! ```
//! The ciphertext is `seed(64B) || tag(16B)`.
//!
//! Rules:
//! - Wrong passphrase → `Decrypt` error, never partial plaintext.
//! - Secrets are zeroized on drop; `Debug` never prints key material.
//! - No secret bytes ever appear in errors or logs.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha256;
use std::path::Path;
use thiserror::Error;
use zeroize::Zeroize;

/// File magic — also the format version.
const MAGIC: &[u8; 8] = b"MBTCKS01";
/// PBKDF2 iterations (OWASP-aligned for interactive unlock).
pub const KDF_ITERS: u32 = 600_000;
/// Salt length.
const SALT_LEN: usize = 32;
/// Nonce length (ChaCha20-Poly1305 IETF).
const NONCE_LEN: usize = 12;
/// Encrypted payload: 64-byte seed.
const SEED_LEN: usize = 64;
/// Poly1305 tag length.
const TAG_LEN: usize = 16;

/// Keystore errors — deliberately vague; never leak which check failed.
#[derive(Debug, Error)]
pub enum KeystoreError {
    /// Decryption failed (wrong passphrase or corrupt file).
    #[error("keystore unlock failed")]
    Unlock,
    /// File malformed.
    #[error("keystore file malformed")]
    Malformed,
    /// IO failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// RNG failure while encrypting.
    #[error("rng failed")]
    Rng,
}

/// The decrypted secret material — a 64-byte seed. `Debug` redacts.
pub struct SecretSeed {
    inner: SecretBox<[u8; SEED_LEN]>,
}

impl SecretSeed {
    /// Access the seed bytes (callers must not log/persist them raw).
    pub fn expose(&self) -> &[u8; SEED_LEN] {
        self.inner.expose_secret()
    }
}

impl fmt::Debug for SecretSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretSeed").finish_non_exhaustive()
    }
}

use std::fmt;

/// A loaded keystore file (encrypted blob + metadata).
#[derive(Clone, Debug)]
pub struct Keystore {
    /// kdf_iters, salt, nonce, ciphertext.
    pub kdf_iters: u32,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl Keystore {
    /// Serialize to the on-disk byte format.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 4 + SALT_LEN + NONCE_LEN + self.ciphertext.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.kdf_iters.to_le_bytes());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parse from disk bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, KeystoreError> {
        if bytes.len() < 8 + 4 + SALT_LEN + NONCE_LEN + TAG_LEN {
            return Err(KeystoreError::Malformed);
        }
        if &bytes[..8] != MAGIC {
            return Err(KeystoreError::Malformed);
        }
        let kdf_iters = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[12..12 + SALT_LEN]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[12 + SALT_LEN..12 + SALT_LEN + NONCE_LEN]);
        let ciphertext = bytes[12 + SALT_LEN + NONCE_LEN..].to_vec();
        if ciphertext.len() != SEED_LEN + TAG_LEN {
            return Err(KeystoreError::Malformed);
        }
        Ok(Self {
            kdf_iters,
            salt,
            nonce,
            ciphertext,
        })
    }

    /// Save to a file (atomic-ish: write tmp + rename).
    pub fn save(&self, path: &Path) -> Result<(), KeystoreError> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, self.encode())?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Load from a file.
    pub fn load(path: &Path) -> Result<Self, KeystoreError> {
        let bytes = std::fs::read(path)?;
        Self::decode(&bytes)
    }

    /// Encrypt a seed under `passphrase` → a ready-to-save keystore.
    /// Uses fresh OS-random salt + nonce.
    pub fn encrypt(seed: &[u8; SEED_LEN], passphrase: &str) -> Result<Self, KeystoreError> {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut salt).map_err(|_| KeystoreError::Rng)?;
        getrandom::fill(&mut nonce_bytes).map_err(|_| KeystoreError::Rng)?;

        let key = derive_key(passphrase, &salt, KDF_ITERS);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, Payload::from(seed.as_slice()))
            .map_err(|_| KeystoreError::Rng)?;

        let mut key_zero = key;
        key_zero.zeroize();
        Ok(Self {
            kdf_iters: KDF_ITERS,
            salt,
            nonce: nonce_bytes,
            ciphertext: ct,
        })
    }

    /// Decrypt with `passphrase` → the seed. Wrong passphrase → `Unlock`.
    pub fn decrypt(&self, passphrase: &str) -> Result<SecretSeed, KeystoreError> {
        let key = derive_key(passphrase, &self.salt, self.kdf_iters);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = Nonce::from_slice(&self.nonce);
        let pt = cipher
            .decrypt(nonce, self.ciphertext.as_slice())
            .map_err(|_| KeystoreError::Unlock)?;
        if pt.len() != SEED_LEN {
            return Err(KeystoreError::Malformed);
        }
        let mut seed = [0u8; SEED_LEN];
        seed.copy_from_slice(&pt);
        // Zero the Vec plaintext copy.
        let mut pt_vec = pt;
        pt_vec.zeroize();
        Ok(SecretSeed {
            inner: SecretBox::new(Box::new(seed)),
        })
    }
}

/// PBKDF2-HMAC-SHA256 → 32-byte key.
fn derive_key(passphrase: &str, salt: &[u8; SALT_LEN], iters: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, iters, &mut out);
    out
}

/// Convenience: encrypt + save in one call.
pub fn encrypt_keystore(
    seed: &[u8; SEED_LEN],
    passphrase: &str,
    path: &Path,
) -> Result<(), KeystoreError> {
    Keystore::encrypt(seed, passphrase)?.save(path)
}

/// Convenience: load + decrypt in one call.
pub fn decrypt_keystore(path: &Path, passphrase: &str) -> Result<SecretSeed, KeystoreError> {
    Keystore::load(path)?.decrypt(passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let seed = [42u8; SEED_LEN];
        let ks = Keystore::encrypt(&seed, "correct horse").unwrap();
        let back = ks.decrypt("correct horse").unwrap();
        assert_eq!(back.expose(), &seed);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let seed = [1u8; SEED_LEN];
        let ks = Keystore::encrypt(&seed, "right").unwrap();
        assert!(matches!(ks.decrypt("wrong"), Err(KeystoreError::Unlock)));
    }

    #[test]
    fn file_roundtrip_and_malformed() {
        let seed = [9u8; SEED_LEN];
        let ks = Keystore::encrypt(&seed, "pw").unwrap();
        let bytes = ks.encode();
        let parsed = Keystore::decode(&bytes).unwrap();
        assert_eq!(parsed.ciphertext, ks.ciphertext);
        assert!(Keystore::decode(&bytes[..20]).is_err());
        let mut bad = bytes.clone();
        bad[0] ^= 0xff;
        assert!(Keystore::decode(&bad).is_err());
    }

    #[test]
    fn save_load_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.ks");
        let seed = [3u8; SEED_LEN];
        encrypt_keystore(&seed, "pw", &path).unwrap();
        let back = decrypt_keystore(&path, "pw").unwrap();
        assert_eq!(back.expose(), &seed);
        assert!(decrypt_keystore(&path, "bad").is_err());
    }

    #[test]
    fn debug_redacts() {
        let ks = Keystore::encrypt(&[7u8; SEED_LEN], "pw").unwrap();
        let dbg = format!("{:?}", ks);
        // ciphertext bytes shouldn't trivially appear — Debug prints
        // struct fields but ciphertext is Vec<u8> which WILL print.
        // That's acceptable (it's encrypted), but seed must not appear.
        let seed_hex = [7u8; SEED_LEN]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert!(!dbg.contains(&seed_hex));
    }

    #[test]
    fn different_nonce_each_encrypt() {
        let seed = [5u8; SEED_LEN];
        let a = Keystore::encrypt(&seed, "pw").unwrap();
        let b = Keystore::encrypt(&seed, "pw").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
        // Both decrypt to same seed.
        assert_eq!(
            a.decrypt("pw").unwrap().expose(),
            b.decrypt("pw").unwrap().expose()
        );
    }
}
