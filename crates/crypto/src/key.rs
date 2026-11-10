//! secp256k1 keys, ECDSA signatures and the rules Bitcoin places on them.
//!
//! - [`Keypair`] — a private signing key + its public key, generated only from
//!   the OS CSPRNG (`getrandom::SysRng`).
//! - [`PublicKey`] — SEC1 compressed bytes; its [`hash160`](crate::hash160)
//!   is what an address commits to.
//! - [`Signature`] — a strict-DER, low-S ECDSA signature over a 32-byte
//!   sighash. Signing uses RFC 6979 deterministic nonces (`sign_prehash`),
//!   which is exactly what Bitcoin's `secp256k1_ecdsa_sign` does with the
//!   32-byte sighash as the message digest — no extra hashing layer.
//!
//! Consensus rules enforced here (blueprint Tier 1): signatures must parse as
//! strict DER and must have a low-S value; anything else is rejected, not
//! normalized — that is what kills signature malleability.

use getrandom::SysRng;
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature as EcdsaSignature, SigningKey, VerifyingKey};
use k256::elliptic_curve::scalar::IsHigh;
use k256::elliptic_curve::Generate;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

use crate::hash::{hex_decode, hex_encode, Hash256};

/// Errors from key/signature operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    /// The bytes were not a valid SEC1 public key.
    #[error("invalid public key: {0}")]
    BadPublicKey(String),
    /// The bytes were not a valid 32-byte secret scalar.
    #[error("invalid secret key")]
    BadSecretKey,
    /// The bytes were not strict DER, or had trailing data.
    #[error("invalid DER signature: {0}")]
    BadDer(String),
    /// The signature's `s` value is in the upper half of the group order.
    /// Bitcoin consensus rejects high-S signatures outright (low-S rule).
    #[error("signature is not low-S")]
    HighS,
    /// The compact (r‖s) encoding had the wrong length.
    #[error("compact signature must be 64 bytes")]
    BadCompactLen,
    /// Signing failed internally (should be unreachable for a 32-byte digest,
    /// but the API stays honest rather than panicking).
    #[error("signing failed")]
    SignFailed,
    /// The OS entropy source failed while generating a key.
    #[error("OS entropy source failed")]
    RngFailed,
}

/// A secp256k1 keypair: the secret signing key from which the public key is
/// always derivable.
///
/// `Debug` is redacted on purpose — a keypair must never print its secret.
#[derive(Clone)]
pub struct Keypair {
    signing: SigningKey,
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Keypair(<redacted>)")
    }
}

impl Keypair {
    /// Fresh random keypair from the OS entropy source. Fails honestly if
    /// the entropy source does — a wallet create must not proceed on a
    /// silently weak key.
    pub fn generate() -> Result<Self, KeyError> {
        SigningKey::try_generate_from_rng(&mut SysRng)
            .map(|signing| Keypair { signing })
            .map_err(|_| KeyError::RngFailed)
    }

    /// Rebuild a keypair from its 32-byte secret scalar.
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Result<Self, KeyError> {
        let field = k256::FieldBytes::from(*bytes);
        SigningKey::from_bytes(&field)
            .map(|signing| Keypair { signing })
            .map_err(|_| KeyError::BadSecretKey)
    }

    /// The 32-byte secret scalar. Callers (the keystore) must wrap the result
    /// in `Zeroizing`/`SecretVec` immediately — it is key material.
    pub fn secret_bytes(&self) -> [u8; 32] {
        let bytes = self.signing.to_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes.as_slice());
        out
    }

    /// The matching public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            verifying: *self.signing.verifying_key(),
        }
    }

    /// Sign a 32-byte sighash digest. RFC 6979 deterministic nonce; the
    /// returned signature is normalized to low-S before storage.
    pub fn sign_digest(&self, digest: &Hash256) -> Result<Signature, KeyError> {
        let sig: EcdsaSignature = PrehashSigner::<EcdsaSignature>::sign_prehash(
            &self.signing,
            digest.as_bytes(),
        )
        .map_err(|_| KeyError::SignFailed)?;
        Signature::from_ecdsa(sig.normalize_s())
    }
}

/// A secp256k1 public key (SEC1 encoding).
#[derive(Clone, Copy)]
pub struct PublicKey {
    verifying: VerifyingKey,
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.to_sec1_bytes();
        write!(f, "PublicKey({}…)", hex_encode(&bytes[..4.min(bytes.len())]))
    }
}

impl PublicKey {
    /// Parse SEC1 bytes — compressed (33B) or uncompressed (65B), as Bitcoin
    /// accepts on the wire.
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        VerifyingKey::from_sec1_bytes(bytes)
            .map(|verifying| PublicKey { verifying })
            .map_err(|e| KeyError::BadPublicKey(e.to_string()))
    }

    /// 33-byte compressed SEC1 encoding — the canonical form we hash.
    pub fn to_sec1_bytes(&self) -> Vec<u8> {
        self.verifying.to_sec1_point(true).as_bytes().to_vec()
    }

    /// The 20-byte hash committed to by P2PKH outputs: `hash160` of the
    /// *compressed* SEC1 encoding (Bitcoin standardness).
    pub fn key_hash(&self) -> crate::Hash160 {
        crate::hash160(&self.to_sec1_bytes())
    }

    /// Verify `sig` over `digest`. The signature must already be strict-DER
    /// and low-S ([`Signature::from_der`] enforces both).
    pub fn verify_digest(&self, digest: &Hash256, sig: &Signature) -> bool {
        PrehashVerifier::<EcdsaSignature>::verify_prehash(
            &self.verifying,
            digest.as_bytes(),
            &sig.inner,
        )
        .is_ok()
    }
}

/// An ECDSA signature over a 32-byte digest: strict DER on the wire,
/// low-S by consensus, RFC 6979 when produced by [`Keypair`].
#[derive(Clone)]
pub struct Signature {
    inner: EcdsaSignature,
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let der = self.to_der();
        write!(f, "Signature({}…)", &hex_encode(&der)[..16.min(der.len() * 2)])
    }
}

impl Signature {
    fn from_ecdsa(sig: EcdsaSignature) -> Result<Self, KeyError> {
        if sig.s().is_high().unwrap_u8() != 0 {
            return Err(KeyError::HighS);
        }
        Ok(Self { inner: sig })
    }

    /// Parse a strict-DER signature and enforce the low-S rule. Trailing
    /// bytes, non-minimal INTEGERs, and high-S values are all rejected —
    /// the malleability surface stays closed.
    pub fn from_der(bytes: &[u8]) -> Result<Self, KeyError> {
        let sig =
            EcdsaSignature::from_der(bytes).map_err(|e| KeyError::BadDer(e.to_string()))?;
        Self::from_ecdsa(sig)
    }

    /// DER encoding — what travels inside a scriptSig push.
    pub fn to_der(&self) -> Vec<u8> {
        // `inner` is always low-S (enforced at construction), so DER is stable.
        let der = self.inner.to_der();
        der.as_bytes().to_vec()
    }

    /// Compact 64-byte `r ‖ s` form, big-endian scalars — for indexes/tests.
    pub fn to_compact(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out.copy_from_slice(self.inner.to_bytes().as_slice());
        out
    }

    /// Parse compact form (used by tests and non-script paths). Low-S is
    /// enforced here too — there is no non-consensus signature type.
    pub fn from_compact(bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() != 64 {
            return Err(KeyError::BadCompactLen);
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(bytes);
        let sig = EcdsaSignature::from_slice(&arr)
            .map_err(|e| KeyError::BadDer(e.to_string()))?;
        Self::from_ecdsa(sig)
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex_encode(&self.to_sec1_bytes()))
    }
}
impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = PublicKey;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("hex-encoded SEC1 public key")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<PublicKey, E> {
                let bytes = hex_decode(v).map_err(E::custom)?;
                PublicKey::from_sec1_bytes(&bytes).map_err(E::custom)
            }
        }
        d.deserialize_str(V)
    }
}

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex_encode(&self.to_der()))
    }
}
impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = Signature;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("hex-encoded DER signature")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Signature, E> {
                let bytes = hex_decode(v).map_err(E::custom)?;
                Signature::from_der(&bytes).map_err(E::custom)
            }
        }
        d.deserialize_str(V)
    }
}

impl Serialize for Keypair {
    fn serialize<S: Serializer>(&self, _s: S) -> Result<S::Ok, S::Error> {
        // Keypairs never serialize — the keystore owns secret persistence.
        Err(serde::ser::Error::custom("Keypair is not serializable"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_of(data: &[u8]) -> Hash256 {
        crate::double_sha256(data)
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = Keypair::generate().unwrap();
        let digest = digest_of(b"sighash");
        let sig = kp.sign_digest(&digest).unwrap();
        assert!(kp.public_key().verify_digest(&digest, &sig));
    }

    #[test]
    fn wrong_key_and_tampered_digest_fail() {
        let alice = Keypair::generate().unwrap();
        let mallory = Keypair::generate().unwrap();
        let digest = digest_of(b"pay alice");
        let sig = alice.sign_digest(&digest).unwrap();
        assert!(!mallory.public_key().verify_digest(&digest, &sig));
        let other = digest_of(b"pay mallory");
        assert!(!alice.public_key().verify_digest(&other, &sig));
    }

    #[test]
    fn produced_signatures_are_low_s_strict_der_and_deterministic() {
        for i in 0..16u8 {
            let kp = Keypair::generate().unwrap();
            let digest = digest_of(&[i]);
            let sig = kp.sign_digest(&digest).unwrap();
            // RFC 6979: same key + same digest → identical signature.
            let sig2 = kp.sign_digest(&digest).unwrap();
            assert_eq!(sig.to_der(), sig2.to_der());
            // Strict-DER round-trip.
            let reparsed = Signature::from_der(&sig.to_der()).unwrap();
            assert_eq!(reparsed.to_der(), sig.to_der());
        }
    }

    /// secp256k1 group order n, as 32 big-endian bytes.
    const CURVE_ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
        0xd0, 0x36, 0x41, 0x41,
    ];

    /// `a - b` on 32-byte big-endian integers (a ≥ b). Test-only helper.
    fn sub_be(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = i16::from(a[i]) - i16::from(b[i]) - borrow;
            if d < 0 {
                out[i] = (d + 256) as u8;
                borrow = 1;
            } else {
                out[i] = d as u8;
                borrow = 0;
            }
        }
        out
    }

    /// Minimal DER encoder for `SEQUENCE { INTEGER r, INTEGER s }` —
    /// test-only, used to forge a high-S signature the parser must reject.
    fn der_encode_sig(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
        fn integer(x: &[u8; 32]) -> Vec<u8> {
            // strip leading zeros, keep at least one byte
            let start = x.iter().position(|&b| b != 0).unwrap_or(31);
            let mut body = x[start..].to_vec();
            if body.is_empty() {
                body.push(0);
            }
            // INTEGER is signed: prepend 0x00 when the high bit is set
            if body[0] & 0x80 != 0 {
                let mut v = vec![0x00];
                v.extend_from_slice(&body);
                body = v;
            }
            let mut v = vec![0x02, body.len() as u8];
            v.extend_from_slice(&body);
            v
        }
        let mut body = integer(r);
        body.extend(integer(s));
        let mut out = vec![0x30, body.len() as u8];
        out.extend(body);
        out
    }

    #[test]
    fn high_s_signature_is_rejected_by_from_der() {
        let kp = Keypair::generate().unwrap();
        let digest = digest_of(b"malleability");
        let sig = kp.sign_digest(&digest).unwrap();
        let compact = sig.to_compact();
        let mut r = [0u8; 32];
        let mut s_low = [0u8; 32];
        r.copy_from_slice(&compact[..32]);
        s_low.copy_from_slice(&compact[32..]);
        // The malleated twin: s' = n - s_low is always > n/2 → must be rejected.
        let s_high = sub_be(&CURVE_ORDER, &s_low);
        let forged = der_encode_sig(&r, &s_high);
        assert!(matches!(
            Signature::from_der(&forged),
            Err(KeyError::HighS)
        ));
        // Sanity: the low-S original parses and verifies.
        assert!(kp.public_key().verify_digest(&digest, &sig));
    }

    #[test]
    fn non_der_truncated_and_trailing_inputs_rejected() {
        let kp = Keypair::generate().unwrap();
        let sig = kp.sign_digest(&digest_of(b"x")).unwrap();
        let der = sig.to_der();
        assert!(Signature::from_der(&der[..der.len() - 1]).is_err());
        let mut padded = der.clone();
        padded.push(0x00);
        assert!(Signature::from_der(&padded).is_err(), "trailing bytes must fail");
        // Non-minimal INTEGER encoding (unnecessary leading zero) — strict
        // DER must reject it even though the scalars are in range.
        let non_minimal = [
            0x30, 0x08, 0x02, 0x02, 0x00, 0x01, 0x02, 0x02, 0x00, 0x01,
        ];
        assert!(Signature::from_der(&non_minimal).is_err());
        assert!(Signature::from_der(b"").is_err());
    }

    #[test]
    fn compact_form_roundtrips() {
        let kp = Keypair::generate().unwrap();
        let sig = kp.sign_digest(&digest_of(b"compact")).unwrap();
        let compact = sig.to_compact();
        let sig2 = Signature::from_compact(&compact).unwrap();
        assert_eq!(sig2.to_der(), sig.to_der());
        assert!(Signature::from_compact(&compact[..63]).is_err());
    }

    #[test]
    fn pubkey_roundtrip_and_hash() {
        let kp = Keypair::generate().unwrap();
        let pk = kp.public_key();
        let bytes = pk.to_sec1_bytes();
        assert_eq!(bytes.len(), 33);
        assert_eq!(bytes[0], 0x02 | (bytes[0] & 1)); // compressed prefix sanity
        let pk2 = PublicKey::from_sec1_bytes(&bytes).unwrap();
        assert_eq!(pk2.to_sec1_bytes(), bytes);
        assert_eq!(pk.key_hash(), crate::hash160(&bytes));
        assert!(PublicKey::from_sec1_bytes(&[0x02]).is_err());
        assert!(PublicKey::from_sec1_bytes(&[0x04; 65]).is_err());
    }

    #[test]
    fn keypair_secret_roundtrip_and_rejects_zero() {
        let kp = Keypair::generate().unwrap();
        let secret = kp.secret_bytes();
        let kp2 = Keypair::from_secret_bytes(&secret).unwrap();
        assert_eq!(
            kp2.public_key().to_sec1_bytes(),
            kp.public_key().to_sec1_bytes()
        );
        assert!(Keypair::from_secret_bytes(&[0u8; 32]).is_err());
        assert!(Keypair::from_secret_bytes(&[0xff; 32]).is_err()); // >= n
    }
}
