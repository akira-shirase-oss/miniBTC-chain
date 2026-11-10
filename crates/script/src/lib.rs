//! # minibtc-script
//!
//! The locking/unlocking language: a deliberately small, bounded stack machine
//! that decides whether an input may spend an output. P2PKH first; execution is
//! always finite (no loops) and every resource is capped.

// Phase scaffold: modules land with their build phase (see docs/ROADMAP.md).
