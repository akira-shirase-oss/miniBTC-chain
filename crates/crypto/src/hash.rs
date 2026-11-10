//! Hash primitives: [`Hash256`] (double-SHA-256) and [`Hash160`]
//! (SHA-256 then RIPEMD-160), plus strict hex codecs.
//!
//! Every transaction id, block hash, merkle node and address payload in
//! MiniBTC routes through these two functions. They are newtypes over fixed
//! byte arrays so the type system keeps a txid distinct from a block hash —
//! same length, different meaning.

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;

/// Errors produced by hex decoding.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HexError {
    /// The string had an odd number of characters.
    #[error("odd-length hex string")]
    OddLength,
    /// A character outside `[0-9a-fA-F]` appeared.
    #[error("non-hex character at byte {0}")]
    InvalidChar(usize),
    /// The decoded length did not match the expected fixed size.
    #[error("wrong length: expected {expected} bytes, got {got}")]
    WrongLength {
        /// Bytes expected.
        expected: usize,
        /// Bytes decoded.
        got: usize,
    },
}

/// Strict lowercase/uppercase hex decode. Rejects odd lengths and any
/// non-hex byte — callers get a typed error, never a panic or a silent
/// truncation.
pub fn hex_decode(s: &str) -> Result<Vec<u8>, HexError> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(HexError::OddLength);
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        let hi = hex_val(pair[0]).ok_or(HexError::InvalidChar(i * 2))?;
        let lo = hex_val(pair[1]).ok_or(HexError::InvalidChar(i * 2 + 1))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Lowercase hex encode — the canonical display form for hashes.
pub fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(char::from(DIGITS[(b >> 4) as usize]));
        s.push(char::from(DIGITS[(b & 0x0f) as usize]));
    }
    s
}

macro_rules! hash_newtype {
    ($name:ident, $len:literal, $doc:literal) => {
        #[doc = $doc]
        ///
        /// `Copy`, `Eq`, `Hash` — cheap to key maps. Serializes as lowercase
        /// hex for readable JSON on the wire.
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub [u8; $len]);

        impl $name {
            /// The all-zero value (genesis `prev_hash`, null references).
            pub const ZERO: Self = Self([0u8; $len]);

            /// Raw bytes.
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            /// Lowercase hex.
            pub fn to_hex(&self) -> String {
                hex_encode(&self.0)
            }

            /// Parse exactly `$len * 2` hex chars; anything else is an error.
            pub fn from_hex(s: &str) -> Result<Self, HexError> {
                let bytes = hex_decode(s)?;
                if bytes.len() != $len {
                    return Err(HexError::WrongLength {
                        expected: $len,
                        got: bytes.len(),
                    });
                }
                let mut out = [0u8; $len];
                out.copy_from_slice(&bytes);
                Ok(Self(out))
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::ZERO
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    f,
                    concat!(stringify!($name), "({}…)"),
                    &self.to_hex()[..16.min($len * 2)]
                )
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.to_hex())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct V;
                impl Visitor<'_> for V {
                    type Value = $name;
                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        write!(f, "a {}-char hex string", $len * 2)
                    }
                    fn visit_str<E: de::Error>(self, v: &str) -> Result<$name, E> {
                        $name::from_hex(v).map_err(|_| {
                            E::custom(format!("expected a {}-char hex string", $len * 2))
                        })
                    }
                }
                d.deserialize_str(V)
            }
        }
    };
}

hash_newtype!(
    Hash256,
    32,
    "A 256-bit hash: the output of double-SHA-256 — txids, block hashes, merkle nodes."
);
hash_newtype!(
    Hash160,
    20,
    "A 160-bit hash: SHA-256 then RIPEMD-160 — the payload inside addresses."
);

/// Single SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let out = Sha256::digest(data);
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

/// **Double-SHA-256**: `SHA256(SHA256(data))` — Bitcoin's id function for
/// transaction ids, block hashes and merkle nodes.
pub fn double_sha256(data: &[u8]) -> Hash256 {
    let once = Sha256::digest(data);
    let twice = Sha256::digest(once);
    let mut out = [0u8; 32];
    out.copy_from_slice(&twice);
    Hash256(out)
}

/// **Hash160**: `RIPEMD160(SHA256(data))` — Bitcoin's address compression:
/// 20 bytes instead of 32, still collision-resistant for our purposes.
pub fn hash160(data: &[u8]) -> Hash160 {
    use ripemd::Ripemd160;
    let sha = Sha256::digest(data);
    let ripe = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripe);
    Hash160(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn double_sha256_known_answer() {
        // SHA256("") = e3b0c4…, double of it is a fixed value — pin it so a
        // dependency change that altered hashing is caught immediately.
        let h = double_sha256(b"");
        assert_eq!(
            h.to_hex(),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );
    }

    #[test]
    fn hash160_of_empty_is_fixed() {
        // ripemd160(sha256("")) — pinned known answer.
        assert_eq!(
            hash160(b"").to_hex(),
            "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"
        );
    }

    #[test]
    fn hex_roundtrip_and_strictness() {
        let h = double_sha256(b"minibtc");
        assert_eq!(Hash256::from_hex(&h.to_hex()).unwrap(), h);
        assert!(Hash256::from_hex(&h.to_hex()[..62]).is_err()); // too short
        assert!(Hash256::from_hex("zz").is_err()); // non-hex
        assert!(hex_decode("abc").is_err()); // odd length
        assert_eq!(hex_decode("AB").unwrap(), vec![0xab]);
    }

    #[test]
    fn hash_ordering_is_numeric_big_endian() {
        // [u8;32] Ord is byte-wise = numeric for big-endian display order.
        let mut a = Hash256::ZERO;
        let mut b = Hash256::ZERO;
        a.0[31] = 1;
        b.0[0] = 1;
        assert!(
            b > a,
            "a hash with a high first byte must exceed one with only the last set"
        );
    }
}
