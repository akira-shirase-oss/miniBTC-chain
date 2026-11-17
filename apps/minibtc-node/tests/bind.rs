//! The node refuses a non-loopback RPC address without `--allow-remote-rpc`.

use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Run `cmd`; `None` if it is still running after `within` (then killed).
fn exits_within(cmd: &mut Command, within: Duration) -> Option<Output> {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn minibtc-node: {e}"));
    let deadline = Instant::now() + within;
    loop {
        if child
            .try_wait()
            .unwrap_or_else(|e| panic!("poll child: {e}"))
            .is_some()
        {
            return Some(
                child
                    .wait_with_output()
                    .unwrap_or_else(|e| panic!("collect output: {e}")),
            );
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn a_non_loopback_rpc_address_is_refused_without_the_opt_in() {
    let dir = std::env::temp_dir().join(format!("mbtc-bind-node-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let out = exits_within(
        Command::new(env!("CARGO_BIN_EXE_minibtc-node")).args([
            "--datadir",
            dir.to_str().expect("utf-8 temp path"),
            "--listen",
            "127.0.0.1:0",
            "--rpc",
            "192.0.2.1:0", // TEST-NET-1: not on any interface, so nothing is ever exposed
        ]),
        Duration::from_secs(20),
    )
    .expect("the node must exit instead of serving RPC on a non-loopback address");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "non-zero exit: {stderr}");
    assert!(
        stderr.contains("--allow-remote-rpc"),
        "names the opt-in: {stderr}"
    );
    assert!(
        !dir.join(".cookie").exists(),
        "no credential is written for a refused RPC"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
