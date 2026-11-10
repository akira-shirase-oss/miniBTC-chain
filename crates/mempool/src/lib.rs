//! # minibtc-mempool
//!
//! The node's pool of valid, unconfirmed transactions. Mempool contents are
//! **policy, not consensus**: nodes may legitimately differ. Every bound here
//! exists to keep memory and CPU finite under adversarial load.

// Phase scaffold: modules land with their build phase (see docs/ROADMAP.md).
