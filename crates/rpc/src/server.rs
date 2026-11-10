//! JSON-RPC 2.0 HTTP server: POST / with cookie auth, bounded body,
//! spawn_blocking dispatch so slow methods never stall the executor.

use crate::backend::SharedBackend;
use crate::types::{JsonRpcRequest, JsonRpcResponse, RpcError, params_array};
use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine;
use serde_json::Value;
use std::sync::Arc;
use tower_http::limit::RequestBodyLimitLayer;

/// Max JSON-RPC request body — a full block hex fits comfortably.
const MAX_BODY: usize = 8 * 1024 * 1024;

/// Cookie-file credentials (Bitcoin-style `user:password` in `.cookie`).
#[derive(Clone, Debug)]
pub struct CookieAuth {
    /// Basic-auth username (usually `__cookie__`-style token user).
    pub user: String,
    /// Basic-auth password — the secret half.
    pub pass: String,
}

impl CookieAuth {
    /// Generate fresh random credentials.
    pub fn generate() -> Self {
        use rand::Rng;
        let mut u = [0u8; 16];
        let mut p = [0u8; 32];
        rand::rng().fill_bytes(&mut u);
        rand::rng().fill_bytes(&mut p);
        Self {
            user: hex::encode(u),
            pass: hex::encode(p),
        }
    }

    /// Serialize as the `.cookie` file contents (`user:pass\n`).
    pub fn to_cookie_file(&self) -> String {
        format!("{}:{}\n", self.user, self.pass)
    }

    /// Parse `.cookie` file contents.
    pub fn from_cookie_file(contents: &str) -> Result<Self, RpcError> {
        let line = contents.lines().next().unwrap_or("");
        let (u, p) = line
            .split_once(':')
            .ok_or_else(|| RpcError::InvalidRequest("malformed cookie file".into()))?;
        if u.is_empty() || p.is_empty() {
            return Err(RpcError::InvalidRequest("empty cookie credentials".into()));
        }
        Ok(Self {
            user: u.to_string(),
            pass: p.to_string(),
        })
    }

    /// Constant-time-ish credential check.
    fn check(&self, user: &str, pass: &str) -> bool {
        // Length check first (cheap), then byte compare — devnet-grade;
        // the cookie is a local-devnet secret, not a password store.
        user.len() == self.user.len()
            && pass.len() == self.pass.len()
            && user.as_bytes().ct_eq(self.user.as_bytes())
            && pass.as_bytes().ct_eq(self.pass.as_bytes())
    }
}

/// Extract + verify HTTP Basic credentials from headers.
fn authorized(headers: &HeaderMap, auth: &CookieAuth) -> bool {
    let Some(v) = headers.get(header::AUTHORIZATION) else {
        return false;
    };
    let Ok(s) = v.to_str() else {
        return false;
    };
    let Some(b64) = s.strip_prefix("Basic ") else {
        return false;
    };
    let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) else {
        return false;
    };
    let Ok(creds) = String::from_utf8(raw) else {
        return false;
    };
    let Some((u, p)) = creds.split_once(':') else {
        return false;
    };
    auth.check(u, p)
}

/// Shared server state.
#[derive(Clone)]
struct ServerState {
    backend: SharedBackend,
    auth: Arc<CookieAuth>,
}

/// Build the axum router. Binds are the caller's choice — always
/// localhost in practice (`serve` binds 127.0.0.1).
pub fn router(backend: SharedBackend, auth: CookieAuth) -> Router {
    let state = ServerState {
        backend,
        auth: Arc::new(auth),
    };
    Router::new()
        .route("/", post(rpc_handler).get(info_handler))
        .route("/healthz", get(healthz))
        .layer(RequestBodyLimitLayer::new(MAX_BODY))
        .with_state(state)
}

/// Serve on `addr` (expected `127.0.0.1:port`) until shutdown.
pub async fn serve(
    backend: SharedBackend,
    auth: CookieAuth,
    addr: std::net::SocketAddr,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "rpc server listening");
    axum::serve(listener, router(backend, auth)).await
}

async fn healthz() -> &'static str {
    "ok"
}

async fn info_handler(State(st): State<ServerState>, headers: HeaderMap) -> Response {
    if !authorized(&headers, &st.auth) {
        return unauthorized();
    }
    Json(serde_json::json!({
        "service": "minibtc-rpc",
        "version": env!("CARGO_PKG_VERSION"),
        "methods": st.backend.methods(),
    }))
    .into_response()
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic realm=\"minibtc\"")],
        "unauthorized",
    )
        .into_response()
}

async fn rpc_handler(State(st): State<ServerState>, headers: HeaderMap, body: Bytes) -> Response {
    if !authorized(&headers, &st.auth) {
        return unauthorized();
    }
    // Parse envelope.
    let req: JsonRpcRequest = match serde_json::from_slice::<JsonRpcRequest>(&body) {
        Ok(r) if r.jsonrpc == "2.0" => r,
        Ok(_) => {
            return Json(JsonRpcResponse::err(
                Value::Null,
                RpcError::InvalidRequest("jsonrpc must be \"2.0\"".into()),
            ))
            .into_response();
        }
        Err(e) => {
            return Json(JsonRpcResponse::err(
                Value::Null,
                RpcError::Parse(e.to_string()),
            ))
            .into_response();
        }
    };
    // Notifications (no id) get no response per spec — but our clients
    // always send ids; treat id-less as notification → 204.
    if req.id.is_null() {
        return StatusCode::NO_CONTENT.into_response();
    }
    let id = req.id.clone();
    let method = req.method.clone();
    let params = match params_array(&req.params) {
        Ok(p) => p.to_vec(),
        Err(e) => {
            return Json(JsonRpcResponse::err(id, e)).into_response();
        }
    };
    let backend = st.backend.clone();
    let result = tokio::task::spawn_blocking(move || backend.call(&method, &params))
        .await
        .unwrap_or_else(|e| Err(RpcError::Internal(format!("backend panic: {e}"))));
    match result {
        Ok(v) => Json(JsonRpcResponse::ok(id, v)).into_response(),
        Err(e) => Json(JsonRpcResponse::err(id, e)).into_response(),
    }
}

/// Constant-time byte compare helper (slice ct_eq via subtle-free impl).
trait CtEq {
    fn ct_eq(&self, other: &[u8]) -> bool;
}
impl CtEq for [u8] {
    fn ct_eq(&self, other: &[u8]) -> bool {
        if self.len() != other.len() {
            return false;
        }
        let mut diff = 0u8;
        for (a, b) in self.iter().zip(other.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}
