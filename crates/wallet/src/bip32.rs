//! # BIP32 hierarchical deterministic keys
//!
//! Implementation per BIP32 spec:
//! - [`Xpriv::master`] — HMAC-SHA512("Bitcoin seed", seed) → master key.
//! - [`Xpriv::derive`] — CKDpriv (private parent → private child).
//! - [`Xpub::derive`] — CKDpub (public parent → public child, **non-hardened
//!   only** — hardened derivation requires the private key by design).
//! - [`DerivationPath`] — `m/44'/0'/0'/0/5` parsing.
//!
//! Verified against the official BIP32 test vectors (chain m, and the
//! two main vector sets) in `tests/bip32_vectors.rs`.
//!
//! Security: `Debug` never prints key material; secrets are zeroized on
//! drop via `Zeroizing`-style manual impl where the type owns them.

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, ProjectivePoint, Scalar, SecretKey};
use minibtc_crypto::hash160;
use sha2::Sha512;
use std::fmt;
use thiserror::Error;
use zeroize::Zeroize;

/// HMAC-SHA512 for BIP32.
type HmacSha512 = Hmac<Sha512>;

/// Curve order n (secp256k1) — used for the mod-n child key check.
const CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// Hardened-child flag (BIP32: index + 0x80000000).
pub const HARDENED: u32 = 0x8000_0000;

/// A child index in a derivation path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChildNumber {
    /// The index value (without hardened bit in `index`; `hardened` flag
    /// separate for clarity).
    pub index: u32,
    /// Whether this is a hardened derivation.
    pub hardened: bool,
}

impl ChildNumber {
    /// The serialized index (hardened flag applied).
    fn ser(&self) -> u32 {
        if self.hardened {
            self.index | HARDENED
        } else {
            self.index
        }
    }

    /// Parse one path element: `5` or `5'` or `5h`.
    pub fn parse(s: &str) -> Result<Self, Bip32Error> {
        let (num, hard) = if let Some(stripped) = s.strip_suffix('\'') {
            (stripped, true)
        } else if let Some(stripped) = s.strip_suffix('h') {
            (stripped, true)
        } else {
            (s, false)
        };
        let index: u32 = num
            .parse()
            .map_err(|_| Bip32Error::BadPath(s.to_string()))?;
        if index >= HARDENED {
            return Err(Bip32Error::BadPath(s.to_string()));
        }
        Ok(Self { index, hardened: hard })
    }
}

/// A parsed derivation path like `m/44'/0'/0'/0/5`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivationPath {
    /// Ordered child numbers (excluding the master `m`).
    pub children: Vec<ChildNumber>,
}

impl DerivationPath {
    /// Parse `m/...` or `/...` form. Rejects empty paths and bad elements.
    pub fn parse(s: &str) -> Result<Self, Bip32Error> {
        let body = s.strip_prefix("m").unwrap_or(s);
        let body = body.strip_prefix('/').unwrap_or(body);
        if body.is_empty() {
            // "m" or "" → master; "m/" → malformed.
            if s.contains('/') {
                return Err(Bip32Error::BadPath(s.to_string()));
            }
            return Ok(Self { children: vec![] });
        }
        let mut children = Vec::new();
        for part in body.split('/') {
            if part.is_empty() {
                return Err(Bip32Error::BadPath(s.to_string()));
            }
            children.push(ChildNumber::parse(part)?);
        }
        Ok(Self { children })
    }

    /// The standard BIP44 account path for `coin_type`/`account`.
    pub fn bip44_account(coin_type: u32, account: u32) -> Self {
        Self {
            children: vec![
                ChildNumber { index: 44, hardened: true },
                ChildNumber { index: coin_type, hardened: true },
                ChildNumber { index: account, hardened: true },
            ],
        }
    }

    /// BIP44 external-chain receive address index.
    pub fn receive(index: u32) -> ChildNumber {
        ChildNumber { index, hardened: false }
    }

    /// BIP44 internal-chain change address index.
    pub fn change(index: u32) -> ChildNumber {
        ChildNumber { index, hardened: false }
    }
}

/// BIP32 errors.
#[derive(Debug, Error)]
pub enum Bip32Error {
    /// Path string malformed.
    #[error("bad derivation path: {0}")]
    BadPath(String),
    /// Key material invalid (zero or ≥ n).
    #[error("invalid key material")]
    InvalidKey,
    /// Public derivation attempted on a hardened index.
    #[error("cannot publicly derive hardened child")]
    HardenedPub,
    /// SEC1 parse failure.
    #[error("bad public key encoding")]
    BadPubKey,
}

/// An extended private key (xprv). `Debug` redacts key bytes.
#[derive(Clone)]
pub struct Xpriv {
    /// 32-byte private key (big-endian scalar).
    key: [u8; 32],
    /// 32-byte chain code.
    chain_code: [u8; 32],
    /// Depth in the tree (0 = master).
    depth: u8,
    /// Parent fingerprint (first 4 bytes of hash160(parent pubkey)).
    parent_fingerprint: [u8; 4],
    /// Child number used to derive this key.
    child_num: u32,
}

impl fmt::Debug for Xpriv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Xpriv")
            .field("depth", &self.depth)
            .field("child_num", &self.child_num)
            .finish_non_exhaustive()
    }
}

impl Drop for Xpriv {
    fn drop(&mut self) {
        self.key.zeroize();
        self.chain_code.zeroize();
    }
}

/// An extended public key (xpub) — watch-only derivation capable for
/// non-hardened children only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Xpub {
    /// Compressed SEC1 public key (33 bytes).
    pub_key: [u8; 33],
    /// 32-byte chain code.
    pub chain_code: [u8; 32],
    /// Depth.
    depth: u8,
    /// Parent fingerprint.
    parent_fingerprint: [u8; 4],
    /// Child number.
    child_num: u32,
}

/// HMAC-SHA512 with a key and data → 64 bytes.
fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(key).unwrap_or_else(|_| unreachable!());
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut res = [0u8; 64];
    res.copy_from_slice(&out);
    res
}

/// Fingerprint of a compressed pubkey: first 4 bytes of hash160.
fn fingerprint(pub_key: &[u8; 33]) -> [u8; 4] {
    let h = hash160(pub_key);
    let mut fp = [0u8; 4];
    fp.copy_from_slice(&h.as_bytes()[..4]);
    fp
}

/// Compressed SEC1 encoding of a secret scalar's public key.
fn pubkey_for_secret(key: &[u8; 32]) -> Result<[u8; 33], Bip32Error> {
    // Validate the scalar first (non-zero, < n).
    SecretKey::from_slice(key).map_err(|_| Bip32Error::InvalidKey)?;
    let scalar = Option::<Scalar>::from(Scalar::from_repr(field_bytes(key)))
        .ok_or(Bip32Error::InvalidKey)?;
    let point = ProjectivePoint::mul_by_generator(&scalar);
    let affine = point.to_affine();
    let ep = affine.to_sec1_point(true);
    let bytes = ep.as_bytes();
    if bytes.len() != 33 {
        return Err(Bip32Error::InvalidKey);
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Serialize a u32 index big-endian.
fn ser32(i: u32) -> [u8; 4] {
    i.to_be_bytes()
}

/// [u8;32] → k256 FieldBytes.
fn field_bytes(b: &[u8; 32]) -> k256::elliptic_curve::FieldBytes<k256::Secp256k1> {
    let mut fb = k256::elliptic_curve::FieldBytes::<k256::Secp256k1>::default();
    fb.copy_from_slice(b);
    fb
}

impl Xpriv {
    /// Master key from a 64-byte BIP39 seed (BIP32 §3.2.1).
    pub fn master(seed: &[u8; 64]) -> Result<Self, Bip32Error> {
        Self::master_seed_bytes(seed)
    }

    /// Master key from arbitrary-length seed bytes (BIP32 test vectors
    /// use non-64-byte seeds).
    pub fn master_seed_bytes(seed: &[u8]) -> Result<Self, Bip32Error> {
        let i = hmac_sha512(b"Bitcoin seed", seed);
        let mut key = [0u8; 32];
        key.copy_from_slice(&i[..32]);
        // Reject invalid master (zero or ≥ n) — BIP32 says retry is
        // impossible for a fixed seed, so this is a hard error.
        SecretKey::from_slice(&key).map_err(|_| Bip32Error::InvalidKey)?;
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&i[32..]);
        Ok(Self {
            key,
            chain_code,
            depth: 0,
            parent_fingerprint: [0u8; 4],
            child_num: 0,
        })
    }

    /// The private key bytes (callers must protect the result).
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.key
    }

    /// The chain code.
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    /// Depth in the tree (0 = master).
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Parent fingerprint.
    pub fn parent_fingerprint(&self) -> [u8; 4] {
        self.parent_fingerprint
    }

    /// The serialized child number (hardened bit applied).
    pub fn child_num(&self) -> u32 {
        self.child_num
    }

    /// Derive one child (CKDpriv). Auto-skips invalid indices per BIP32.
    pub fn derive(&self, child: ChildNumber) -> Result<Xpriv, Bip32Error> {
        let mut index = child.ser();
        loop {
            match self.derive_once(index) {
                Ok(k) => return Ok(k),
                Err(Bip32Error::InvalidKey) => {
                    // BIP32: proceed with next index.
                    index = index.wrapping_add(1);
                    if index == 0 {
                        return Err(Bip32Error::InvalidKey);
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn derive_once(&self, index: u32) -> Result<Xpriv, Bip32Error> {
        let hardened = index & HARDENED != 0;
        let mut data = Vec::with_capacity(37);
        if hardened {
            data.push(0u8);
            data.extend_from_slice(&self.key);
        } else {
            let pk = pubkey_for_secret(&self.key)?;
            data.extend_from_slice(&pk);
        }
        data.extend_from_slice(&ser32(index));
        let i = hmac_sha512(&self.chain_code, &data);
        let mut il = [0u8; 32];
        il.copy_from_slice(&i[..32]);
        let mut ir = [0u8; 32];
        ir.copy_from_slice(&i[32..]);

        // child_key = (IL + parent_key) mod n — via Scalar field arith.
        let tweak = Option::<Scalar>::from(Scalar::from_repr(field_bytes(&il)))
            .ok_or(Bip32Error::InvalidKey)?;
        let parent = Option::<Scalar>::from(Scalar::from_repr(field_bytes(&self.key)))
            .ok_or(Bip32Error::InvalidKey)?;
        let child_scalar = tweak.add(&parent);
        if child_scalar.is_zero().into() {
            return Err(Bip32Error::InvalidKey);
        }
        let child_key = child_scalar.to_bytes();
        let mut key = [0u8; 32];
        key.copy_from_slice(child_key.as_slice());
        // Validate < n and non-zero.
        SecretKey::from_slice(&key).map_err(|_| Bip32Error::InvalidKey)?;
        let parent_pk = pubkey_for_secret(&self.key)?;
        Ok(Xpriv {
            key,
            chain_code: ir,
            depth: self.depth.saturating_add(1),
            parent_fingerprint: fingerprint(&parent_pk),
            child_num: index,
        })
    }

    /// Derive a whole path.
    pub fn derive_path(&self, path: &DerivationPath) -> Result<Xpriv, Bip32Error> {
        let mut cur = self.clone();
        for c in &path.children {
            cur = cur.derive(*c)?;
        }
        Ok(cur)
    }

    /// The neutered public counterpart (xpub).
    pub fn to_xpub(&self) -> Result<Xpub, Bip32Error> {
        Ok(Xpub {
            pub_key: pubkey_for_secret(&self.key)?,
            chain_code: self.chain_code,
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_num: self.child_num,
        })
    }

    /// Compressed public key bytes.
    pub fn public_key_bytes(&self) -> Result<[u8; 33], Bip32Error> {
        pubkey_for_secret(&self.key)
    }
}

impl Xpub {
    /// The compressed public key bytes.
    pub fn public_key_bytes(&self) -> &[u8; 33] {
        &self.pub_key
    }

    /// Chain code.
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    /// Depth.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Parent fingerprint.
    pub fn parent_fingerprint(&self) -> [u8; 4] {
        self.parent_fingerprint
    }

    /// The serialized child number.
    pub fn child_num(&self) -> u32 {
        self.child_num
    }

    /// CKDpub — public child derivation. **Non-hardened only**: hardened
    /// indices need the private key (that's the point of hardening).
    pub fn derive(&self, child: ChildNumber) -> Result<Xpub, Bip32Error> {
        if child.hardened {
            return Err(Bip32Error::HardenedPub);
        }
        let index = child.ser();
        let mut data = Vec::with_capacity(37);
        data.extend_from_slice(&self.pub_key);
        data.extend_from_slice(&ser32(index));
        let i = hmac_sha512(&self.chain_code, &data);
        let mut il = [0u8; 32];
        il.copy_from_slice(&i[..32]);
        let mut ir = [0u8; 32];
        ir.copy_from_slice(&i[32..]);

        // child_point = IL*G + Kpar
        let tweak = Option::<Scalar>::from(Scalar::from_repr(field_bytes(&il))).ok_or(Bip32Error::InvalidKey)?;
        let tweak_point = ProjectivePoint::mul_by_generator(&tweak);
        let parent_point = projective_from_compressed(&self.pub_key)?;
        let child_point = tweak_point + parent_point;
        let child_affine: AffinePoint = child_point.to_affine();
        let ep = child_affine.to_sec1_point(true);
        let bytes = ep.as_bytes();
        if bytes.len() != 33 {
            return Err(Bip32Error::InvalidKey);
        }
        let mut pub_key = [0u8; 33];
        pub_key.copy_from_slice(bytes);
        Ok(Xpub {
            pub_key,
            chain_code: ir,
            depth: self.depth.saturating_add(1),
            parent_fingerprint: fingerprint(&self.pub_key),
            child_num: index,
        })
    }

    /// Derive a non-hardened path publicly.
    pub fn derive_path(&self, path: &DerivationPath) -> Result<Xpub, Bip32Error> {
        let mut cur = self.clone();
        for c in &path.children {
            cur = cur.derive(*c)?;
        }
        Ok(cur)
    }
}

/// Parse a compressed SEC1 pubkey into a projective point.
fn projective_from_compressed(bytes: &[u8; 33]) -> Result<ProjectivePoint, Bip32Error> {
    let pk = k256::PublicKey::from_sec1_bytes(bytes).map_err(|_| Bip32Error::BadPubKey)?;
    Ok(pk.to_projective())
}

/// Does `key_bytes` represent a valid secret (< n, non-zero)?
pub fn valid_secret(key: &[u8; 32]) -> bool {
    SecretKey::from_slice(key).is_ok()
}

/// Is `bytes` < curve order n? (big-endian compare)
pub fn below_curve_order(bytes: &[u8; 32]) -> bool {
    bytes < &CURVE_ORDER
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_parsing() {
        let p = DerivationPath::parse("m/44'/0'/0'/0/5").unwrap();
        assert_eq!(p.children.len(), 5);
        assert!(p.children[0].hardened);
        assert_eq!(p.children[0].index, 44);
        assert!(!p.children[4].hardened);
        assert_eq!(p.children[4].index, 5);
        // 'h' suffix also works.
        let p2 = DerivationPath::parse("m/44h/0h").unwrap();
        assert!(p2.children.iter().all(|c| c.hardened));
        assert!(DerivationPath::parse("m/").is_err());
        assert!(DerivationPath::parse("m/44'/0'/0'/0/").is_err());
    }

    #[test]
    fn master_from_seed_is_deterministic() {
        let seed = [7u8; 64];
        let a = Xpriv::master(&seed).unwrap();
        let b = Xpriv::master(&seed).unwrap();
        assert_eq!(a.secret_bytes(), b.secret_bytes());
        assert_eq!(a.chain_code(), b.chain_code());
    }

    #[test]
    fn debug_redacts_key() {
        let seed = [9u8; 64];
        let x = Xpriv::master(&seed).unwrap();
        let dbg = format!("{:?}", x);
        let hex: String = x.secret_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert!(!dbg.contains(&hex[..16]));
    }

    #[test]
    fn private_public_derivation_agree() {
        // For non-hardened paths, xpub-derived pubkey must equal
        // xpriv-derived pubkey.
        let seed = [3u8; 64];
        let master = Xpriv::master(&seed).unwrap();
        let acct_path = DerivationPath::bip44_account(0, 0);
        let xpriv_acct = master.derive_path(&acct_path).unwrap();
        let xpub_acct = xpriv_acct.to_xpub().unwrap();
        // receive index 0, non-hardened → public derivation OK.
        let path = DerivationPath {
            children: vec![
                ChildNumber { index: 0, hardened: false },
                ChildNumber { index: 0, hardened: false },
            ],
        };
        let priv_child = xpriv_acct.derive_path(&path).unwrap();
        let pub_child = xpub_acct.derive_path(&path).unwrap();
        assert_eq!(
            priv_child.public_key_bytes().unwrap(),
            *pub_child.public_key_bytes(),
            "CKDpub must match CKDpriv for non-hardened"
        );
    }

    #[test]
    fn hardened_pub_derivation_rejected() {
        let seed = [5u8; 64];
        let master = Xpriv::master(&seed).unwrap();
        let xpub = master.to_xpub().unwrap();
        assert!(matches!(
            xpub.derive(ChildNumber { index: 0, hardened: true }),
            Err(Bip32Error::HardenedPub)
        ));
    }
}
