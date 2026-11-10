//! # minibtc-wallet
//!
//! The user's side of the network: seeds (BIP39), deterministic keys
//! (BIP32/BIP44), address bookkeeping, UTXO tracking, coin selection and
//! transaction building/signing. The wallet never talks to the network
//! directly — it hands signed transactions to the node's RPC.

// Phase scaffold: modules land with their build phase (see docs/ROADMAP.md).
