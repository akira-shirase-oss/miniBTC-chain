//! RPC server integration: auth, dispatch, error mapping, bounds.

use minibtc_rpc::server::CookieAuth;
use minibtc_rpc::{serve, JsonRpcResponse, RpcBackend, RpcError, NODE_METHODS};
use serde_json::{json, Value};
use std::sync::Arc;

/// Fixture backend: echoes method+params, errors on "fail".
struct Fixture;

impl RpcBackend for Fixture {
    fn call(&self, method: &str, params: &[Value]) -> Result<Value, RpcError> {
        match method {
            "echo" => Ok(json!({ "method": method, "params": params })),
            "fail" => Err(RpcError::App("boom".into())),
            "notfound_probe" => Err(RpcError::MethodNotFound(method.into())),
            _ => Err(RpcError::MethodNotFound(method.into())),
        }
    }
    fn methods(&self) -> &'static [&'static str] {
        NODE_METHODS
    }
}

async fn spawn() -> (String, CookieAuth, tokio::task::JoinHandle<()>) {
    let auth = CookieAuth {
        user: "testuser".into(),
        pass: "testpass".into(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let backend: Arc<dyn RpcBackend> = Arc::new(Fixture);
    // serve() binds its own listener — instead build router directly.
    let app = minibtc_rpc::server::router(backend, auth.clone());
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://127.0.0.1:{port}/"), auth, handle)
}

fn basic(user: &str, pass: &str) -> String {
    use base64::Engine;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
    )
}

#[tokio::test]
async fn unauthorized_without_cookie() {
    let (url, _auth, _h) = spawn().await;
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"echo","params":[]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn authorized_call_roundtrip() {
    let (url, auth, _h) = spawn().await;
    let resp = reqwest::Client::new()
        .post(&url)
        .header("authorization", basic(&auth.user, &auth.pass))
        .json(&json!({"jsonrpc":"2.0","id":7,"method":"echo","params":[1,"x"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: JsonRpcResponse = resp.json().await.unwrap();
    assert!(body.error.is_none());
    let result = body.result.unwrap();
    assert_eq!(result["method"], "echo");
    assert_eq!(result["params"], json!([1, "x"]));
}

#[tokio::test]
async fn method_error_maps_to_rpc_error() {
    let (url, auth, _h) = spawn().await;
    let resp = reqwest::Client::new()
        .post(&url)
        .header("authorization", basic(&auth.user, &auth.pass))
        .json(&json!({"jsonrpc":"2.0","id":3,"method":"nope","params":[]}))
        .send()
        .await
        .unwrap();
    let body: JsonRpcResponse = resp.json().await.unwrap();
    let err = body.error.unwrap();
    assert_eq!(err.code, -32601);
}

#[tokio::test]
async fn malformed_json_is_parse_error() {
    let (url, auth, _h) = spawn().await;
    let resp = reqwest::Client::new()
        .post(&url)
        .header("authorization", basic(&auth.user, &auth.pass))
        .header("content-type", "application/json")
        .body("{not json")
        .send()
        .await
        .unwrap();
    let body: JsonRpcResponse = resp.json().await.unwrap();
    assert_eq!(body.error.unwrap().code, -32700);
}

#[tokio::test]
async fn notification_gets_204() {
    let (url, auth, _h) = spawn().await;
    let resp = reqwest::Client::new()
        .post(&url)
        .header("authorization", basic(&auth.user, &auth.pass))
        .json(&json!({"jsonrpc":"2.0","method":"echo","params":[]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
}

#[tokio::test]
async fn wrong_password_rejected() {
    let (url, auth, _h) = spawn().await;
    let resp = reqwest::Client::new()
        .post(&url)
        .header("authorization", basic(&auth.user, "wrong"))
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"echo","params":[]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn healthz_is_public() {
    let (url, _auth, _h) = spawn().await;
    let resp = reqwest::Client::new()
        .get(format!("{url}healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");
}
