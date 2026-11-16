//! The watch-only file next to a wallet: `<datadir>/wallets/<name>.watch.json`.
//!
//! It lists the wallet's derived scripts (hashes of public keys, no keys or
//! seed) so tools without the passphrase — the CLI's `wallet draft`, the MCP
//! gate — can find the wallet's coins and recognise its change outputs.
//! Anything that decides which outputs are "change" for spend caps reads it
//! here, never from a draft or approval file.
//!
//! The file is public data, but it still maps every address to one wallet,
//! so it is written owner-only (0600) like the keystore, and atomically
//! (temp file + rename) so a reader never sees a half-written list.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Why the watch file could not be used.
#[derive(Debug, thiserror::Error)]
pub enum WatchError {
    /// Missing or unreadable.
    #[error("cannot read watch-only file {path}: {source}")]
    Io {
        /// The file.
        path: String,
        /// The I/O error.
        source: std::io::Error,
    },
    /// Not the expected JSON shape.
    #[error("watch-only file {0} is malformed")]
    Malformed(String),
    /// Deriving the scripts failed.
    #[error("derive watch scripts: {0}")]
    Wallet(#[from] crate::wallet::WalletError),
}

/// The scripts a watch file lists.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WatchSet {
    /// Every derived script (receive + change, gap window).
    pub scripts: HashSet<Vec<u8>>,
    /// Change scripts not yet issued, in derivation order.
    pub fresh_change: Vec<Vec<u8>>,
}

/// Where wallet `name`'s watch file lives under `datadir` (the caller has
/// validated `name`).
pub fn watch_file_path(datadir: &Path, name: &str) -> PathBuf {
    datadir.join("wallets").join(format!("{name}.watch.json"))
}

/// The watch file's content for `wallet`: primes the `gap` lookahead window
/// (both chains) and lists every derived script plus the change scripts
/// not yet issued. Pure; write it with [`write_watch_bytes`].
pub fn watch_json(wallet: &mut crate::Wallet, gap: u32) -> Result<Vec<u8>, WatchError> {
    wallet.prime_lookahead(gap)?;
    let (all, fresh_change) = wallet.watch_scripts();
    let hexes = |v: &[Vec<u8>]| -> Vec<String> {
        v.iter().map(|s| minibtc_crypto::hex_encode(s)).collect()
    };
    let v = serde_json::json!({
        "scripts": hexes(&all),
        "change_scripts": hexes(&fresh_change),
    });
    serde_json::to_vec_pretty(&v).map_err(|_| WatchError::Malformed("serialize".into()))
}

/// Write watch-file bytes owner-only and atomically: a `0600` temp file in
/// the same directory, flushed to disk, then renamed over `path`. Each write
/// gets its own temp name (file name + process id + a per-process counter),
/// so the CLI and the wallet UI writing at the same moment never share a
/// temp file; the last rename wins and the file is always one whole write.
pub fn write_watch_bytes(path: &Path, bytes: &[u8]) -> Result<(), WatchError> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let io = |source| WatchError::Io {
        path: path.display().to_string(),
        source,
    };
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "watch".into());
    // Relaxed: the counter only needs to be unique, not ordered.
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_file_name(format!(".{name}.{}.{seq}.tmp", std::process::id()));
    let result = write_new_file(&tmp, bytes).and_then(|()| std::fs::rename(&tmp, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.map_err(io)
}

/// Create `tmp` (0600, must not exist), write `bytes`, fsync.
fn write_new_file(tmp: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(tmp)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// [`watch_json`] + [`write_watch_bytes`].
pub fn write_watch_file(
    path: &Path,
    wallet: &mut crate::Wallet,
    gap: u32,
) -> Result<(), WatchError> {
    let bytes = watch_json(wallet, gap)?;
    write_watch_bytes(path, &bytes)
}

/// Read and decode a watch file.
pub fn read_watch_file(path: &Path) -> Result<WatchSet, WatchError> {
    let shown = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|source| WatchError::Io {
        path: shown.clone(),
        source,
    })?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|_| WatchError::Malformed(shown.clone()))?;
    let list = |key: &str| -> Result<Vec<Vec<u8>>, WatchError> {
        v[key]
            .as_array()
            .ok_or_else(|| WatchError::Malformed(shown.clone()))?
            .iter()
            .map(|s| {
                s.as_str()
                    .and_then(|h| minibtc_crypto::hex_decode(h).ok())
                    .ok_or_else(|| WatchError::Malformed(shown.clone()))
            })
            .collect()
    };
    Ok(WatchSet {
        scripts: list("scripts")?.into_iter().collect(),
        fresh_change: list("change_scripts")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn written_owner_only_atomically_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("w.watch.json");
        // A world-readable leftover must not stay world-readable.
        std::fs::write(&p, "{}").unwrap();
        let mut w = crate::Wallet::from_seed(&[5u8; 64], "", 0, 0, 0x6f, 100).unwrap();
        write_watch_file(&p, &mut w, 3).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "watch file must be owner-only");
        }
        assert!(
            !p.with_extension("json.tmp").exists(),
            "temp file renamed away"
        );
        let set = read_watch_file(&p).unwrap();
        assert_eq!(set.scripts.len(), 6, "3 receive + 3 change scripts");
        assert_eq!(set.fresh_change.len(), 3);
        let (all, _) = w.watch_scripts();
        assert!(all.iter().all(|s| set.scripts.contains(s)));
    }

    #[test]
    fn concurrent_writers_never_mix_or_fail() {
        // The CLI and the wallet UI can write the same watch file at once.
        // With one shared temp path their writes interleaved or the rename
        // found the temp file already moved.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("w.watch.json");
        let workers: Vec<_> = (0..8u8)
            .map(|t| {
                let p = p.clone();
                std::thread::spawn(move || {
                    let body = format!(
                        r#"{{"scripts":["{}"],"change_scripts":[]}}"#,
                        format!("{t:02x}").repeat(4_000)
                    );
                    (0..50)
                        .filter(|_| write_watch_bytes(&p, body.as_bytes()).is_err())
                        .count()
                })
            })
            .collect();
        let failures: usize = workers.into_iter().map(|w| w.join().unwrap()).sum();
        assert_eq!(failures, 0, "a concurrent write failed");
        let set = read_watch_file(&p).expect("final file is one whole write");
        assert_eq!(set.scripts.len(), 1);
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp files left behind");
    }

    #[test]
    fn reads_scripts_and_rejects_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("w.watch.json");
        std::fs::write(&p, r#"{"scripts":["51","aa"],"change_scripts":["aa"]}"#).unwrap();
        let w = read_watch_file(&p).unwrap();
        assert!(w.scripts.contains(&vec![0x51]));
        assert_eq!(w.fresh_change, vec![vec![0xaa]]);
        std::fs::write(&p, r#"{"scripts":"nope"}"#).unwrap();
        assert!(matches!(read_watch_file(&p), Err(WatchError::Malformed(_))));
        assert!(matches!(
            read_watch_file(&dir.path().join("missing.json")),
            Err(WatchError::Io { .. })
        ));
    }
}
