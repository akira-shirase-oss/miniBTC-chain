//! Listener rules and bounded serving for every MiniBTC web surface: the
//! node RPC, the explorer and the wallet UI.
//!
//! `axum::serve` sets no timer on its connections, so hyper's default
//! header-read timeout never applies (hyper logs "has default, but no timer
//! set") and an idle or slowly-dribbling socket is held forever; it also
//! accepts without limit. [`serve_bounded`] runs the same router with:
//!
//! - a cap on open connections — past it a new connection is closed at
//!   once instead of holding a task and a socket;
//! - a header-read deadline on every request, including the wait for the
//!   next request on a kept-alive connection, so idle sockets close.
//!
//! Per-request deadlines (body reads, handler time) belong to each router,
//! because the right bound differs: an RPC `generatetoaddress` legitimately
//! runs for minutes, a wallet page never should.

use axum::Router;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

/// Connection bounds for [`serve_bounded`].
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Most connections open at once; further ones are closed on accept.
    pub max_connections: usize,
    /// A request's headers must arrive within this, counted from when the
    /// connection starts waiting for them (so it also closes idle
    /// kept-alive connections).
    pub header_read_timeout: Duration,
}

impl Limits {
    /// Defaults for a local single-user service.
    pub const LOCAL: Limits = Limits {
        max_connections: 64,
        header_read_timeout: Duration::from_secs(10),
    };
}

/// Refuse a non-loopback bind unless the operator opted in. Every MiniBTC
/// web surface defaults to `127.0.0.1`; the RPC holds a full-privilege
/// credential and the wallet UI holds keys, so exposing either must be a
/// deliberate flag, never a typo in an address. With the opt-in the bind is
/// allowed and logged as a warning.
pub fn check_bind(addr: SocketAddr, allow_remote: bool, flag: &str) -> Result<(), String> {
    if addr.ip().is_loopback() {
        return Ok(());
    }
    if allow_remote {
        tracing::warn!(%addr, "binding a non-loopback address ({flag} given)");
        return Ok(());
    }
    Err(format!(
        "refusing to listen on non-loopback address {addr}: pass {flag} to expose it beyond this machine"
    ))
}

/// Serve `router` on `listener` with `limits`. Runs until the task is
/// dropped; accept errors (usually fd exhaustion) back off and retry.
pub async fn serve_bounded(listener: TcpListener, router: Router, limits: Limits) {
    let open = Arc::new(Semaphore::new(limits.max_connections));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!("accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = open.clone().try_acquire_owned() else {
            tracing::debug!(%peer, "connection limit reached; closing");
            drop(stream);
            continue;
        };
        let service = TowerToHyperService::new(router.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let mut http = hyper::server::conn::http1::Builder::new();
            http.timer(TokioTimer::new())
                .header_read_timeout(limits.header_read_timeout);
            if let Err(e) = http.serve_connection(TokioIo::new(stream), service).await {
                tracing::debug!(%peer, "connection ended: {e}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_loopback_binds_without_the_opt_in() {
        let ok = ["127.0.0.1:18446", "[::1]:18446", "127.1.2.3:1"];
        for a in ok {
            assert!(check_bind(a.parse().unwrap(), false, "--x").is_ok(), "{a}");
        }
        let refused = [
            "0.0.0.0:18446",
            "[::]:18446",
            "192.168.1.5:18446",
            "10.0.0.1:1",
        ];
        for a in refused {
            let err = check_bind(a.parse().unwrap(), false, "--allow-remote-x").unwrap_err();
            assert!(err.contains("--allow-remote-x"), "{err}");
            assert!(check_bind(a.parse().unwrap(), true, "--x").is_ok(), "{a}");
        }
    }
}
