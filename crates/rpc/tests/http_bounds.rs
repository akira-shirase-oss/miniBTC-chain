//! HTTP bounds on a real loopback socket: credentials before the body,
//! the body cap and deadline, the header deadline (idle sockets close) and
//! the connection cap. Raw TCP so a test can stop mid-request.

use minibtc_rpc::http::{Limits, serve_bounded};
use minibtc_rpc::server::CookieAuth;
use minibtc_rpc::{RpcBackend, RpcError};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct Echo;

impl RpcBackend for Echo {
    fn call(&self, method: &str, _params: &[Value]) -> Result<Value, RpcError> {
        Ok(json!(method))
    }
}

const HEADER_DEADLINE: Duration = Duration::from_millis(500);
const BODY_DEADLINE: Duration = Duration::from_millis(500);

async fn spawn(max_connections: usize) -> SocketAddr {
    let auth = CookieAuth {
        user: "u".into(),
        pass: "p".into(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    let router = minibtc_rpc::server::router_with(Arc::new(Echo), auth, BODY_DEADLINE);
    let limits = Limits {
        max_connections,
        header_read_timeout: HEADER_DEADLINE,
    };
    tokio::spawn(serve_bounded(listener, router, limits));
    addr
}

fn basic() -> String {
    use base64::Engine;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("u:p")
    )
}

/// Send `head` (and nothing else); return the status line the server
/// answers with, or `None` if it answers nothing within `within`.
async fn status_after(addr: SocketAddr, head: &str, within: Duration) -> Option<String> {
    let mut s = TcpStream::connect(addr)
        .await
        .unwrap_or_else(|e| panic!("connect: {e}"));
    s.write_all(head.as_bytes())
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    let mut buf = vec![0u8; 512];
    let n = tokio::time::timeout(within, s.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    let text = String::from_utf8_lossy(&buf[..n]).into_owned();
    text.lines().next().map(str::to_string)
}

/// Whether the server closes `s` within `within` (EOF or reset).
async fn closed_within(s: &mut TcpStream, within: Duration) -> bool {
    let mut buf = [0u8; 512];
    tokio::time::timeout(within, async {
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    })
    .await
    .is_ok()
}

#[tokio::test]
async fn an_unauthenticated_request_is_refused_before_its_body_is_read() {
    let addr = spawn(8).await;
    // Declares 8 MiB (exactly the cap) and sends none of it: the server
    // must answer from the headers, not wait for or buffer the body.
    let head = "POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\
                Content-Length: 8388608\r\n\r\n";
    let status = status_after(addr, head, Duration::from_secs(3)).await;
    assert_eq!(
        status.as_deref(),
        Some("HTTP/1.1 401 Unauthorized"),
        "refused from the headers alone"
    );
    // Over the cap without credentials: refused without reading either.
    let head = "POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\
                Content-Length: 8388609\r\n\r\n";
    let status = status_after(addr, head, Duration::from_secs(3))
        .await
        .unwrap_or_default();
    assert!(
        status.contains(" 401 ") || status.contains(" 413 "),
        "refused: {status}"
    );
}

#[tokio::test]
async fn an_authenticated_body_over_the_cap_gets_413() {
    let addr = spawn(8).await;
    let head = format!(
        "POST / HTTP/1.1\r\nHost: x\r\nAuthorization: {}\r\n\
         Content-Type: application/json\r\nContent-Length: 8388609\r\n\r\n",
        basic()
    );
    let status = status_after(addr, &head, Duration::from_secs(3)).await;
    assert_eq!(status.as_deref(), Some("HTTP/1.1 413 Payload Too Large"));
}

#[tokio::test]
async fn a_body_that_never_arrives_times_out() {
    let addr = spawn(8).await;
    let head = format!(
        "POST / HTTP/1.1\r\nHost: x\r\nAuthorization: {}\r\n\
         Content-Type: application/json\r\nContent-Length: 100\r\n\r\n{{\"jsonrpc\"",
        basic()
    );
    let started = Instant::now();
    let status = status_after(addr, &head, Duration::from_secs(5)).await;
    assert_eq!(status.as_deref(), Some("HTTP/1.1 408 Request Timeout"));
    assert!(started.elapsed() >= BODY_DEADLINE);
}

#[tokio::test]
async fn idle_and_half_sent_connections_are_closed_after_the_header_deadline() {
    let addr = spawn(8).await;
    // Connected, nothing sent.
    let mut idle = TcpStream::connect(addr)
        .await
        .unwrap_or_else(|e| panic!("connect: {e}"));
    // Half a request line, then silence.
    let mut half = TcpStream::connect(addr)
        .await
        .unwrap_or_else(|e| panic!("connect: {e}"));
    half.write_all(b"POST / HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    let within = HEADER_DEADLINE + Duration::from_secs(3);
    assert!(
        closed_within(&mut idle, within).await,
        "an idle socket must be closed"
    );
    assert!(
        closed_within(&mut half, within).await,
        "a half-sent request must be closed"
    );
}

#[tokio::test]
async fn connections_past_the_cap_are_closed_at_once() {
    let addr = spawn(2).await;
    let mut held = Vec::new();
    for _ in 0..2 {
        held.push(
            TcpStream::connect(addr)
                .await
                .unwrap_or_else(|e| panic!("connect: {e}")),
        );
    }
    // Let the server accept both before the third arrives.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut third = TcpStream::connect(addr)
        .await
        .unwrap_or_else(|e| panic!("connect: {e}"));
    assert!(
        closed_within(&mut third, HEADER_DEADLINE / 2).await,
        "the connection over the cap is closed before any deadline"
    );
    // Once the held ones close, the server accepts again.
    drop(held);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"x","params":[]}"#;
    let head = format!(
        "POST / HTTP/1.1\r\nHost: x\r\nAuthorization: {}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        basic(),
        body.len()
    );
    let status = status_after(addr, &head, Duration::from_secs(3)).await;
    assert_eq!(status.as_deref(), Some("HTTP/1.1 200 OK"));
}
