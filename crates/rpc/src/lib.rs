//! # minibtc-rpc
//!
//! The single control surface: a JSON-RPC 2.0 API over HTTP that the CLI,
//! the explorer and the MCP server all share. Auth is a per-datadir cookie
//! token; the server binds localhost by default. Every method validates its
//! inputs as untrusted.

// Phase scaffold: modules land with their build phase (see docs/ROADMAP.md).
