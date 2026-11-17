//! Listener rules shared by every MiniBTC web surface: the node RPC, the
//! explorer and the wallet UI.

use std::net::SocketAddr;

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
