//! # minibtc-crypto
//!
//! The cryptographic core of MiniBTC: hashes, secp256k1 keys, ECDSA
//! signatures, and Base58Check address encoding. Everything here is a thin,
//! careful wrapper over audited crates — **we never hand-roll cryptography**
//! (blueprint §4 engineering rules). This crate has no I/O and no clocks.

// Phase scaffold: modules land with their build phase (see docs/ROADMAP.md).
