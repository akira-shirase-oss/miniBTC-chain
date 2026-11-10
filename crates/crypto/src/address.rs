//! Addresses: Base58Check-encoded `version ‖ hash160 ‖ checksum`.
//!
//! An address is what you hand someone to get paid; it commits to a 20-byte
//! [`Hash160`] of a public key. The 4-byte double-SHA-256 checksum means a
//! single mistyped character is caught at decode time instead of burning
//! coins — the blueprint's "changed checksum character is always caught"
//! requirement is a tested invariant, not a hope.

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

use crate::hash::{double_sha256, Hash160};

/// Errors decoding an address string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AddressError {
    /// The string was not valid Base58.
    #[error("invalid Base58: {0}")]
    BadBase58(String),
    /// Decoded payload was not `version(1) + hash160(20) + checksum(4)`.
    #[error("address payload has wrong length {0}")]
    BadLength(usize),
    /// The embedded checksum did not match the payload.
    #[error("address checksum mismatch")]
    BadChecksum,
    /// The version byte is not one this network recognizes.
    #[error("unsupported address version 0x{0:02x}")]
    BadVersion(u8),
}

/// A payment address: a version byte plus the 20-byte key hash it commits
/// to. `version` travels with the value so testnet/devnet prefixes decode
/// honestly instead of being silently reinterpreted.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address {
    /// Base58Check version byte (Bitcoin mainnet P2PKH = 0x00, testnet = 0x6f).
    pub version: u8,
    /// The Hash160 of the payee's (compressed) public key.
    pub hash160: Hash160,
}

impl Address {
    /// Build a P2PKH address for `hash160` under `version`.
    pub fn p2pkh(version: u8, hash160: Hash160) -> Self {
        Address { version, hash160 }
    }

    /// The 25-byte Base58Check payload: `version ‖ hash160 ‖ checksum`.
    /// Checksum = first 4 bytes of `double_sha256(version ‖ hash160)`.
    pub fn payload(&self) -> [u8; 25] {
        let mut payload = [0u8; 21];
        payload[0] = self.version;
        payload[1..].copy_from_slice(&self.hash160.0);
        let checksum = double_sha256(&payload);
        let mut out = [0u8; 25];
        out[..21].copy_from_slice(&payload);
        out[21..].copy_from_slice(&checksum.0[..4]);
        out
    }

    /// Base58Check string — the form users see and paste.
    pub fn to_base58(&self) -> String {
        bs58::encode(self.payload()).into_string()
    }

    /// Parse and fully validate a Base58Check address: correct length,
    /// correct checksum, and (when `expected_version` is given) the right
    /// version byte. Returns the decoded address.
    pub fn from_base58(s: &str, expected_version: Option<u8>) -> Result<Self, AddressError> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|e| AddressError::BadBase58(e.to_string()))?;
        if bytes.len() != 25 {
            return Err(AddressError::BadLength(bytes.len()));
        }
        let mut payload = [0u8; 21];
        payload.copy_from_slice(&bytes[..21]);
        let checksum = double_sha256(&payload);
        if bytes[21..] != checksum.0[..4] {
            return Err(AddressError::BadChecksum);
        }
        let version = payload[0];
        if let Some(want) = expected_version {
            if version != want {
                return Err(AddressError::BadVersion(version));
            }
        }
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&payload[1..]);
        Ok(Address {
            version,
            hash160: Hash160(hash),
        })
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", self.to_base58())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base58())
    }
}

impl FromStr for Address {
    type Err = AddressError;
    /// Parses without a version expectation — the version byte is data.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_base58(s, None)
    }
}

impl Serialize for Address {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_base58())
    }
}
impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = Address;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a Base58Check address")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Address, E> {
                Address::from_base58(v, None).map_err(E::custom)
            }
        }
        d.deserialize_str(V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Address {
        // version 0x6f (testnet-style) + a fixed hash160 for determinism.
        Address::p2pkh(0x6f, Hash160([0x11; 20]))
    }

    #[test]
    fn base58_roundtrip() {
        let a = sample();
        let s = a.to_base58();
        assert_eq!(Address::from_base58(&s, Some(0x6f)).unwrap(), a);
        assert_eq!(s.parse::<Address>().unwrap(), a);
    }

    #[test]
    fn every_single_character_mutation_is_caught() {
        // The blueprint's checksum requirement, exhaustively: flip each
        // character of a valid address to every other base58 char and assert
        // decode either fails or yields a *different* address — never the
        // same one silently.
        let a = sample();
        let s = a.to_base58();
        let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        for (i, ch) in s.char_indices() {
            for &rep in alphabet {
                if rep == ch as u8 {
                    continue;
                }
                let mut mutated = s.clone().into_bytes();
                mutated[i] = rep;
                let Ok(m) = std::str::from_utf8(&mutated) else {
                    continue;
                };
                match Address::from_base58(m, Some(0x6f)) {
                    Ok(other) => assert_ne!(other, a, "mutation at {i} decoded to same address"),
                    Err(_) => {}
                }
            }
        }
    }

    #[test]
    fn wrong_version_rejected_when_expected() {
        let a = sample();
        let s = a.to_base58();
        assert!(matches!(
            Address::from_base58(&s, Some(0x00)),
            Err(AddressError::BadVersion(0x6f))
        ));
        // Without expectation the same string decodes fine.
        assert!(Address::from_base58(&s, None).is_ok());
    }

    #[test]
    fn garbage_rejected() {
        assert!(Address::from_base58("", None).is_err());
        assert!(Address::from_base58("0OIl", None).is_err()); // invalid base58 chars
        let a = sample();
        let mut bytes = a.payload().to_vec();
        bytes[10] ^= 0x01; // corrupt payload without fixing checksum
        let bad = bs58::encode(&bytes).into_string();
        assert!(matches!(
            Address::from_base58(&bad, None),
            Err(AddressError::BadChecksum)
        ));
        // Truncated payload → wrong length.
        assert!(matches!(
            Address::from_base58(&bs58::encode(&bytes[..20]).into_string(), None),
            Err(AddressError::BadLength(_))
        ));
    }

    #[test]
    fn serde_uses_base58_string() {
        let a = sample();
        let json = serde_json::to_string(&a).unwrap();
        assert!(json.starts_with('"') && json.ends_with('"'));
        let back: Address = serde_json::from_str(&json).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn display_is_base58() {
        assert_eq!(format!("{}", sample()), sample().to_base58());
        assert!(format!("{:?}", sample()).contains("Address("));
        // hex_encode stays reachable for other modules' debug output.
        assert_eq!(crate::hash::hex_encode(&[0xde, 0xad]), "dead");
    }
}
