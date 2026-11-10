//! # minibtc-p2p
//!
//! The wire protocol between nodes: a length-prefixed, checksummed message
//! envelope over TCP, a version handshake, inventory-based gossip, and
//! headers-first initial sync. Every peer is untrusted; every byte is bounded.

// Phase scaffold: modules land with their build phase (see docs/ROADMAP.md).
