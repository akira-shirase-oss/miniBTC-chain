//! # minibtc-wallet
//!
//! Keys, addresses and the spending wallet:
//!
//! - [`bip39`] — mnemonic generation/validation + PBKDF2 seed.
//! - [`bip32`] — HD derivation (CKDpriv/CKDpub) with official vectors.
//! - [`keystore`] — passphrase-encrypted seed file; secrets zeroized.
//! - [`Wallet`] — BIP44 accounts, UTXO tracking, coin selection,
//!   change, fee policy, build+sign+broadcast.
//!
//! Hard rules: private key material never appears in `Debug`, logs,
//! errors, RPC or MCP output.

pub mod bip32;
pub mod bip39;
pub mod keystore;
pub mod wallet;

pub use bip32::{ChildNumber, DerivationPath, Xpriv};
pub use bip39::{Mnemonic, generate_mnemonic, mnemonic_from_phrase, seed_from_mnemonic};
pub use keystore::{Keystore, decrypt_keystore, encrypt_keystore};
pub use wallet::{CoinSelection, Wallet, WalletError};
