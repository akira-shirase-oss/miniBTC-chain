//! # minibtc-storage
//!
//! Durable state: blocks, the UTXO set, and lookup indexes in a single redb
//! database per node datadir. Writes are transactional (a block and its index
//! updates commit atomically); recovery replays committed state only.

// Phase scaffold: modules land with their build phase (see docs/ROADMAP.md).
