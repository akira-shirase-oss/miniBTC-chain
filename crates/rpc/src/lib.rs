//! # minibtc-rpc
//!
//! The single control surface: a JSON-RPC 2.0 API over HTTP that the CLI,
//! the explorer and the MCP server all share. Auth is a per-datadir cookie
//! token; the server binds localhost by default. Every method validates its
//! inputs as untrusted.
//!
//! - [`types`] — JSON-RPC 2.0 envelope + error codes.
//! - [`backend`] — the `RpcBackend` trait the node implements.
//! - [`render`] — chain objects → JSON payloads.
//! - [`server`] — axum HTTP server + cookie auth.
//! - [`client`] — typed async client used by CLI / MCP / tests.

pub mod backend;
pub mod client;
pub mod render;
pub mod server;
pub mod types;

pub use backend::{RpcBackend, SharedBackend, NODE_METHODS};
pub use client::RpcClient;
pub use server::{serve, CookieAuth};
pub use types::{JsonRpcRequest, JsonRpcResponse, RpcError};
