//! Typed JSON-RPC client — the single control surface shared by the CLI,
//! the explorer backend and the MCP server. HTTP Basic auth with the
//! datadir cookie; every call bounded by an HTTP timeout.

use crate::server::CookieAuth;
use crate::types::{JsonRpcRequest, JsonRpcResponse, RpcError};
use serde_json::{Value, json};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Default per-call timeout.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Mining can legitimately take longer on harder params.
const MINE_TIMEOUT: Duration = Duration::from_secs(300);

/// A connected RPC client.
#[derive(Clone)]
pub struct RpcClient {
    http: reqwest::Client,
    url: String,
    user: String,
    pass: String,
    next_id: std::sync::Arc<AtomicU64>,
}

impl std::fmt::Debug for RpcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcClient")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

impl RpcClient {
    /// Connect to `http://host:port` with explicit credentials.
    pub fn new(host: &str, port: u16, auth: CookieAuth) -> Result<Self, RpcError> {
        let http = reqwest::Client::builder()
            .timeout(CALL_TIMEOUT)
            .build()
            .map_err(|e| RpcError::Internal(format!("http client: {e}")))?;
        Ok(Self {
            http,
            url: format!("http://{host}:{port}/"),
            user: auth.user,
            pass: auth.pass,
            next_id: std::sync::Arc::new(AtomicU64::new(1)),
        })
    }

    /// Connect using the node's `.cookie` file inside `datadir`.
    pub fn from_datadir(datadir: &Path, port: u16) -> Result<Self, RpcError> {
        let cookie_path = datadir.join(".cookie");
        let contents = std::fs::read_to_string(&cookie_path)
            .map_err(|e| RpcError::App(format!("cannot read {}: {e}", cookie_path.display())))?;
        let auth = CookieAuth::from_cookie_file(&contents)?;
        Self::new("127.0.0.1", port, auth)
    }

    /// Raw call: method + positional params → result Value.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: json!(id),
            method: method.to_string(),
            params,
        };
        let resp = self
            .http
            .post(&self.url)
            .basic_auth(&self.user, Some(&self.pass))
            .json(&req)
            .send()
            .await
            .map_err(|e| RpcError::Internal(format!("rpc transport: {e}")))?;
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(RpcError::App(
                "RPC auth failed — wrong cookie or node not running".into(),
            ));
        }
        let body: JsonRpcResponse = resp
            .json()
            .await
            .map_err(|e| RpcError::Internal(format!("rpc decode: {e}")))?;
        if let Some(err) = body.error {
            return Err(match err.code {
                -32601 => RpcError::MethodNotFound(err.message),
                -32602 => RpcError::InvalidParams(err.message),
                -32600 => RpcError::InvalidRequest(err.message),
                -32700 => RpcError::Parse(err.message),
                _ => RpcError::App(err.message),
            });
        }
        body.result
            .ok_or_else(|| RpcError::Internal("empty rpc result".into()))
    }

    /// Call with a custom timeout (mining).
    pub async fn call_timeout(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, RpcError> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| RpcError::Internal(format!("http client: {e}")))?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: json!(id),
            method: method.to_string(),
            params,
        };
        let resp = http
            .post(&self.url)
            .basic_auth(&self.user, Some(&self.pass))
            .json(&req)
            .send()
            .await
            .map_err(|e| RpcError::Internal(format!("rpc transport: {e}")))?;
        let body: JsonRpcResponse = resp
            .json()
            .await
            .map_err(|e| RpcError::Internal(format!("rpc decode: {e}")))?;
        if let Some(err) = body.error {
            return Err(RpcError::App(err.message));
        }
        body.result
            .ok_or_else(|| RpcError::Internal("empty rpc result".into()))
    }

    // ---- Typed conveniences ----

    /// `getblockchaininfo`.
    pub async fn getblockchaininfo(&self) -> Result<Value, RpcError> {
        self.call("getblockchaininfo", json!([])).await
    }

    /// `getblockcount`.
    pub async fn getblockcount(&self) -> Result<u64, RpcError> {
        let v = self.call("getblockcount", json!([])).await?;
        v.as_u64()
            .ok_or_else(|| RpcError::Internal("bad getblockcount".into()))
    }

    /// `getblockhash height`.
    pub async fn getblockhash(&self, height: u64) -> Result<String, RpcError> {
        let v = self.call("getblockhash", json!([height])).await?;
        v.as_str()
            .map(str::to_string)
            .ok_or_else(|| RpcError::Internal("bad getblockhash".into()))
    }

    /// `getbestblockhash`.
    pub async fn getbestblockhash(&self) -> Result<String, RpcError> {
        let v = self.call("getbestblockhash", json!([])).await?;
        v.as_str()
            .map(str::to_string)
            .ok_or_else(|| RpcError::Internal("bad getbestblockhash".into()))
    }

    /// `getblock` by hash or height.
    pub async fn getblock(&self, ref_or_height: &str, verbosity: u8) -> Result<Value, RpcError> {
        self.call("getblock", json!([ref_or_height, verbosity]))
            .await
    }

    /// `getrawtransaction txid [verbose]`.
    pub async fn getrawtransaction(&self, txid: &str, verbose: bool) -> Result<Value, RpcError> {
        self.call("getrawtransaction", json!([txid, verbose])).await
    }

    /// `gettxout txid vout`.
    pub async fn gettxout(&self, txid: &str, vout: u32) -> Result<Value, RpcError> {
        self.call("gettxout", json!([txid, vout])).await
    }

    /// `getaddressinfo address`.
    pub async fn getaddressinfo(&self, address: &str) -> Result<Value, RpcError> {
        self.call("getaddressinfo", json!([address])).await
    }

    /// `validateaddress address`.
    pub async fn validateaddress(&self, address: &str) -> Result<Value, RpcError> {
        self.call("validateaddress", json!([address])).await
    }

    /// `getmempoolinfo`.
    pub async fn getmempoolinfo(&self) -> Result<Value, RpcError> {
        self.call("getmempoolinfo", json!([])).await
    }

    /// `getrawmempool [verbose]`.
    pub async fn getrawmempool(&self, verbose: bool) -> Result<Value, RpcError> {
        self.call("getrawmempool", json!([verbose])).await
    }

    /// `getpeerinfo`.
    pub async fn getpeerinfo(&self) -> Result<Value, RpcError> {
        self.call("getpeerinfo", json!([])).await
    }

    /// `getnetworkinfo`.
    pub async fn getnetworkinfo(&self) -> Result<Value, RpcError> {
        self.call("getnetworkinfo", json!([])).await
    }

    /// `sendrawtransaction hex`.
    pub async fn sendrawtransaction(&self, hex_tx: &str) -> Result<String, RpcError> {
        let v = self.call("sendrawtransaction", json!([hex_tx])).await?;
        v.as_str()
            .map(str::to_string)
            .ok_or_else(|| RpcError::Internal("bad sendrawtransaction result".into()))
    }

    /// `generatetoaddress nblocks address` (devnet only) — long timeout.
    pub async fn generatetoaddress(&self, nblocks: u64, address: &str) -> Result<Value, RpcError> {
        self.call_timeout("generatetoaddress", json!([nblocks, address]), MINE_TIMEOUT)
            .await
    }
}
