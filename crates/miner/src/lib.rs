//! # minibtc-miner
//!
//! Block production: assemble a candidate block from the mempool (coinbase +
//! fee-paying transactions), then grind nonces until the header hash meets the
//! target. Pure template logic here; the async search loop lives in the node.

// Phase scaffold: modules land with their build phase (see docs/ROADMAP.md).
