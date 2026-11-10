//! # minibtc-chainstate
//!
//! The node's view of the chain: the UTXO set, the block index, the active
//! tip, and the connect/disconnect machinery that makes reorgs exact. State
//! changes go through the storage crate so a crash never leaves a half-applied
//! block.

// Phase scaffold: modules land with their build phase (see docs/ROADMAP.md).
