//! JSON-RPC 2.0 wire types and standard error codes.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A JSON-RPC 2.0 request object.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// Must be `"2.0"`.
    pub jsonrpc: String,
    /// Request id (number, string, or null). Echoed in the response.
    /// Missing → Null → treated as a notification (no response body).
    #[serde(default)]
    pub id: Value,
    /// Method name.
    pub method: String,
    /// Params — array (positional) or object (named). Optional.
    #[serde(default)]
    pub params: Value,
}

/// A JSON-RPC 2.0 error object.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RpcErrorObj {
    /// Error code.
    pub code: i64,
    /// Human-readable message.
    pub message: String,
    /// Optional structured data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// A JSON-RPC 2.0 response object.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// Echoed request id.
    pub id: Value,
    /// Result on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcErrorObj>,
}

impl JsonRpcResponse {
    /// Success response.
    pub fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Error response.
    pub fn err(id: Value, err: RpcError) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(err.to_obj()),
        }
    }
}

/// Domain + protocol error for the RPC layer.
#[derive(Clone, Debug, thiserror::Error)]
pub enum RpcError {
    /// -32700 parse error.
    #[error("parse error: {0}")]
    Parse(String),
    /// -32600 invalid request.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// -32601 method not found.
    #[error("method not found: {0}")]
    MethodNotFound(String),
    /// -32602 invalid params.
    #[error("invalid params: {0}")]
    InvalidParams(String),
    /// -32603 internal error.
    #[error("internal error: {0}")]
    Internal(String),
    /// -32000 generic application error (validation, not found, policy).
    #[error("{0}")]
    App(String),
}

impl RpcError {
    /// Standard JSON-RPC error object.
    pub fn to_obj(&self) -> RpcErrorObj {
        let (code, msg) = match self {
            Self::Parse(m) => (-32700, format!("Parse error: {m}")),
            Self::InvalidRequest(m) => (-32600, format!("Invalid Request: {m}")),
            Self::MethodNotFound(m) => (-32601, format!("Method not found: {m}")),
            Self::InvalidParams(m) => (-32602, format!("Invalid params: {m}")),
            Self::Internal(m) => (-32603, format!("Internal error: {m}")),
            Self::App(m) => (-32000, m.clone()),
        };
        RpcErrorObj {
            code,
            message: msg,
            data: None,
        }
    }
}

/// Extract positional params as a slice, or reject non-array params.
pub fn params_array<'a>(params: &'a Value) -> Result<&'a [Value], RpcError> {
    match params {
        Value::Array(a) => Ok(a.as_slice()),
        Value::Null => Ok(&[]),
        _ => Err(RpcError::InvalidParams(
            "expected positional params array".into(),
        )),
    }
}

/// Get param `i` or a typed error.
pub fn param_at<'a>(params: &'a [Value], i: usize, name: &str) -> Result<&'a Value, RpcError> {
    params
        .get(i)
        .ok_or_else(|| RpcError::InvalidParams(format!("missing param {name}")))
}

/// Parse a string param.
pub fn param_str<'a>(params: &'a [Value], i: usize, name: &str) -> Result<&'a str, RpcError> {
    param_at(params, i, name)?
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams(format!("param {name} must be a string")))
}

/// Parse a u64-ish integer param (accepts JSON number or decimal string).
pub fn param_u64(params: &[Value], i: usize, name: &str) -> Result<u64, RpcError> {
    let v = param_at(params, i, name)?;
    if let Some(n) = v.as_u64() {
        return Ok(n);
    }
    if let Some(s) = v.as_str() {
        return s
            .parse::<u64>()
            .map_err(|_| RpcError::InvalidParams(format!("param {name} not a number")));
    }
    Err(RpcError::InvalidParams(format!(
        "param {name} must be a number"
    )))
}

/// Parse an optional integer param with default.
pub fn param_u64_opt(params: &[Value], i: usize, default: u64) -> Result<u64, RpcError> {
    match params.get(i) {
        None | Some(Value::Null) => Ok(default),
        Some(v) => {
            if let Some(n) = v.as_u64() {
                Ok(n)
            } else if let Some(b) = v.as_bool() {
                Ok(u64::from(b))
            } else if let Some(s) = v.as_str() {
                s.parse::<u64>()
                    .map_err(|_| RpcError::InvalidParams("bad integer param".into()))
            } else {
                Err(RpcError::InvalidParams("bad integer param".into()))
            }
        }
    }
}
