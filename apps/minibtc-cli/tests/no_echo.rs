//! Passphrase prompts must not echo. Echo is a terminal property, so this
//! drives the real CLI through a pseudo-terminal (Python's `pty`, run in
//! isolated mode) and checks that the typed passphrase never appears in
//! what the terminal shows. Skipped, with a note, when `python3` is absent.

use std::process::Command;

const DRIVER: &str = r#"
import os, pty, select, sys, tempfile, shutil, time
cli, secret = sys.argv[1], sys.argv[2]
d = tempfile.mkdtemp(prefix="mb-echo-")
open(os.path.join(d, ".cookie"), "w").write("u:p\n")
pid, fd = pty.fork()
if pid == 0:
    os.execv(cli, [cli, "--datadir", d, "--rpc-port", "1", "wallet", "create", "--name", "probe"])
out = b""
def read_until(pred, timeout):
    global out
    end = time.time() + timeout
    while time.time() < end and not pred():
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                return
            if not chunk:
                return
            out += chunk
read_until(lambda: b"passphrase" in out.lower(), 20)
os.write(fd, (secret + "\n").encode())
read_until(lambda: b"first address" in out, 20)
try:
    os.waitpid(pid, 0)
except ChildProcessError:
    pass
shutil.rmtree(d, ignore_errors=True)
sys.stdout.write(out.decode(errors="replace"))
"#;

#[test]
fn keystore_passphrase_prompt_does_not_echo() {
    let Ok(status) = Command::new("python3").arg("--version").output() else {
        eprintln!("skipped: python3 not available to drive a pseudo-terminal");
        return;
    };
    if !status.status.success() {
        eprintln!("skipped: python3 not usable");
        return;
    }
    let secret = "no-echo-probe-5c1e";
    let out = Command::new("python3")
        .args([
            "-I",
            "-c",
            DRIVER,
            env!("CARGO_BIN_EXE_minibtc-cli"),
            secret,
        ])
        .output()
        .unwrap_or_else(|e| panic!("run pty driver: {e}"));
    let shown = String::from_utf8_lossy(&out.stdout);
    assert!(
        shown.to_lowercase().contains("keystore passphrase"),
        "the prompt was not reached: {shown}"
    );
    assert!(
        shown.contains("first address"),
        "the wallet was not created after the prompt: {shown}"
    );
    assert!(
        !shown.contains(secret),
        "the passphrase was echoed to the terminal"
    );
}
