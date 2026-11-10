//! The backend contract: whatever serves JSON-RPC methods. The node
//! implements this over its live chain/mempool/peer state; tests implement
//! it over fixtures. One method per RPC call, params already validated
//! as untrusted JSON.

use crate::types::RpcError;
use serde_json::Value;
use std::sync::Arc;

/// A JSON-RPC backend. Implementations must treat `params` as untrusted
/// and bound every allocation/loop.
pub trait RpcBackend: Send + Sync {
    /// Dispatch one method call. `method` is the JSON-RPC method name;
    /// `params` is the positional params array (possibly empty).
    fn call(&self, method: &str, params: &[Value]) -> Result<Value, RpcError>;

    /// Method names this backend serves (for `rpc.discover` / docs).
    fn methods(&self) -> &'static [&'static str] {
        &[]
    }
}

/// Shared backend handle.
pub type SharedBackend = Arc<dyn RpcBackend>;

/// All method names the MiniBTC node serves — kept here so the server,
/// CLI help and MCP tool list share one source of truth.
pub const NODE_METHODS: &[&str] = &[
    "getblockchaininfo",
    "getblockcount",
    "getblockhash",
    "getblock",
    "getbestblockhash",
    "getrawtransaction",
    "gettxout",
    "getaddressutxos",
    "scantxoutset",
    "getaddressinfo",
    "validateaddress",
    "getmempoolinfo",
    "getrawmempool",
    "getpeerinfo",
    "banpeer",
    "getnetworkinfo",
    "sendrawtransaction",
    "generatetoaddress",
];
