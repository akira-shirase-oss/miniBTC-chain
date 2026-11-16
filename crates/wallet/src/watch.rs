//! The watch-only file next to a wallet: `<datadir>/wallets/<name>.watch.json`.
//!
//! It lists the wallet's derived scripts (hashes of public keys, no keys or
//! seed) so tools without the passphrase — the CLI's `wallet draft`, the MCP
//! gate — can find the wallet's coins and recognise its change outputs.
//! Anything that decides which outputs are "change" for spend caps reads it
//! here, never from a draft or approval file.

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
