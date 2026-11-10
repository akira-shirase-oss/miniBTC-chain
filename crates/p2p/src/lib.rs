//! # minibtc-p2p
//!
//! The wire protocol between nodes: a length-prefixed, checksummed message
//! envelope over TCP, a version handshake, inventory-based gossip, and
//! headers-first initial sync. Every peer is untrusted; every byte is bounded.
//!
//! - [`codec`] — framing + the full message set (version/verack/inv/
//!   getdata/tx/block/headers/ping/pong/addr/reject).
//! - [`peer`] — peer manager: handshake, limits, scoring, banning,
//!   timeouts, eclipse resistance.
//! - [`sync`] — relay + headers-first sync state machine.

pub mod codec;
pub mod peer;
pub mod sync;
