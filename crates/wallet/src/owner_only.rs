//! Owner-only files, written atomically.
//!
//! Keystores, the RPC `.cookie` and the watch-only file must never be
//! readable by other users, not even for the moment between creating a
//! file and changing its mode. [`write_owner_only`] creates a fresh temp
//! file in the target's directory with mode `0600` from the first byte
//! (`O_CREAT|O_EXCL`, so a planted file or symlink is never opened), sets
//! the mode again on the open handle and fails if that fails, writes and
//! fsyncs it, then renames it over the target. A symlink at the target is
//! replaced, never followed. Every error is returned — a caller that
//! cannot write the file owner-only must stop, not continue with a
//! readable one.

use std::io::Write;
use std::path::Path;

/// Write `bytes` to `path` owner-only (`0600` on Unix) and atomically.
/// Each call uses its own temp name (file name + process id + a counter),
/// so concurrent writers never share a temp file; the last rename wins.
pub fn write_owner_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    // Relaxed: the counter only needs to be unique, not ordered.
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_file_name(format!(".{name}.{}.{seq}.tmp", std::process::id()));
    let result = write_new_file(&tmp, bytes).and_then(|()| std::fs::rename(&tmp, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Create `tmp` (`0600`, must not exist), write `bytes`, fsync.
fn write_new_file(tmp: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(tmp)?;
    #[cfg(unix)]
    {
        // The umask can only clear bits, but make the mode exact and treat
        // a failure to set it as fatal.
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(bytes)?;
    f.sync_all()
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(p: &Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn written_owner_only_and_replaces_a_readable_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_owner_only(&path, b"new").unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        let left: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(left.len(), 1, "no temp file left behind");
    }

    #[test]
    fn a_symlink_at_the_target_is_replaced_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("elsewhere");
        std::fs::write(&elsewhere, b"untouched").unwrap();
        let path = dir.path().join("secret");
        std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
        write_owner_only(&path, b"s3cret").unwrap();
        assert!(!std::fs::symlink_metadata(&path).unwrap().is_symlink());
        assert_eq!(mode(&path), 0o600);
        assert_eq!(std::fs::read(&elsewhere).unwrap(), b"untouched");
    }

    #[test]
    fn an_unwritable_directory_is_an_error_and_leaves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let ro = dir.path().join("ro");
        std::fs::create_dir(&ro).unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o500)).unwrap();
        let res = write_owner_only(&ro.join("secret"), b"x");
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(res.is_err());
        assert_eq!(std::fs::read_dir(&ro).unwrap().count(), 0);
    }
}
