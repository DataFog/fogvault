//! Platform publication barriers. SQLite FULL and file sync are required on all
//! platforms. POSIX additionally syncs directory entries. Windows exposes no
//! portable directory fsync through std; process-crash/reopen is the supported
//! profile there, with directory-metadata power-loss durability unqualified.
use super::*;
#[cfg(unix)]
pub(super) fn directory_sync(path: &Path) -> Result<()> {
    std::fs::File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|_| Error::Storage)
}
#[cfg(windows)]
pub(super) fn directory_sync(path: &Path) -> Result<()> {
    // Validate the host namespace; do not pretend that checking it flushed it.
    if std::fs::metadata(path)
        .map_err(|_| Error::Storage)?
        .is_dir()
    {
        Ok(())
    } else {
        Err(Error::Storage)
    }
}
#[cfg(not(any(unix, windows)))]
pub(super) fn directory_sync(_: &Path) -> Result<()> {
    Err(Error::UnsupportedCapability)
}
