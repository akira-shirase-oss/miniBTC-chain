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
//!   next request on a kept-alive connection, so idle sockets close;
//! - a write-stall deadline: a client that stops reading its responses
//!   (while pipelining requests) loses the connection instead of holding
//!   it and its slot forever;
//! - a cap on requests per connection, after which the connection closes.
//!
//! Per-request deadlines (body reads, handler time) belong to each router,
//! because the right bound differs: an RPC `generatetoaddress` legitimately
//! runs for minutes, a wallet page never should.

use axum::Router;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
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
    /// A write may wait this long for the client to read; past it the
    /// connection is dropped. (Hyper has no write timeout of its own.)
    pub write_stall_timeout: Duration,
    /// Requests served on one connection; the last answer carries
    /// `Connection: close`.
    pub max_requests_per_connection: usize,
}

impl Limits {
    /// Defaults for a local single-user service.
    pub const LOCAL: Limits = Limits {
        max_connections: 64,
        header_read_timeout: Duration::from_secs(10),
        write_stall_timeout: Duration::from_secs(10),
        max_requests_per_connection: 1_000,
    };
}

/// A connection whose writes may stall for at most `stall`. Reads pass
/// through (the header deadline bounds them).
struct WriteDeadline {
    io: TcpStream,
    stall: Duration,
    waiting: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl WriteDeadline {
    /// The inner write is pending: start (or keep) the stall clock, and
    /// fail once it runs out.
    fn stalled<T>(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<T>> {
        let stall = self.stall;
        let sleep = self
            .waiting
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(stall)));
        match sleep.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "client stopped reading: write stalled",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn progressed<T>(&mut self, r: std::io::Result<T>) -> Poll<std::io::Result<T>> {
        self.waiting = None;
        Poll::Ready(r)
    }
}

impl AsyncRead for WriteDeadline {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
    }
}

impl AsyncWrite for WriteDeadline {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.io).poll_write(cx, buf) {
            Poll::Ready(r) => this.progressed(r),
            Poll::Pending => this.stalled(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.io).poll_write_vectored(cx, bufs) {
            Poll::Ready(r) => this.progressed(r),
            Poll::Pending => this.stalled(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.io).poll_flush(cx) {
            Poll::Ready(r) => this.progressed(r),
            Poll::Pending => this.stalled(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
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
        let inner = TowerToHyperService::new(router.clone());
        let served = Arc::new(AtomicUsize::new(0));
        let max = limits.max_requests_per_connection;
        // Count requests; the one that reaches the cap is answered with
        // `Connection: close`, after which hyper ends the connection.
        let service = hyper::service::service_fn(move |req| {
            let n = served.fetch_add(1, Ordering::Relaxed).saturating_add(1);
            let call = hyper::service::Service::call(&inner, req);
            async move {
                let mut res = call.await?;
                if n >= max {
                    res.headers_mut().insert(
                        axum::http::header::CONNECTION,
                        axum::http::HeaderValue::from_static("close"),
                    );
                }
                Ok::<_, std::convert::Infallible>(res)
            }
        });
        let io = WriteDeadline {
            io: stream,
            stall: limits.write_stall_timeout,
            waiting: None,
        };
        tokio::spawn(async move {
            let _permit = permit;
            let mut http = hyper::server::conn::http1::Builder::new();
            http.timer(TokioTimer::new())
                .header_read_timeout(limits.header_read_timeout);
            if let Err(e) = http.serve_connection(TokioIo::new(io), service).await {
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
