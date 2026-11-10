//! # minibtc-crypto
//!
//! The cryptographic core of MiniBTC: hashes, secp256k1 keys, ECDSA
//! signatures, and Base58Check address encoding. Everything here is a thin,
//! careful wrapper over audited crates — **we never hand-roll cryptography**
//! (blueprint §4 engineering rules). This crate has no I/O and no clocks.

pub mod address;
pub mod hash;
pub mod key;

pub use address::{Address, AddressError};
pub use hash::{double_sha256, hash160, sha256, Hash160, Hash256, HexError};
pub use key::{KeyError, Keypair, PublicKey, Signature};
