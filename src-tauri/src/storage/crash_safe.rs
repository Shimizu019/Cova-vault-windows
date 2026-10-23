//! Crash-safe file replacement for Windows.
//!
//! On Windows, `std::fs::rename` maps to `MoveFileExW` with
//! `MOVEFILE_REPLACE_EXISTING`, which atomically replaces an existing
//! destination without deleting it first. This avoids the race window where
//! the destination is removed and then the rename fails, leaving no file.
//!
//! The safe sequence is:
//! 1. Write complete contents to a temporary file in the *same directory*
//!    (same volume, so rename is atomic).
//! 2. Flush (and sync) the temporary file.
//! 3. Atomically rename the temporary file over the destination using the OS
//!    replacement API. The destination is never deleted first; if the rename
//!    fails, the original destination remains intact.
//! 4. Remove the temporary file on any failure so no stale staging file
//!    remains.
//!
//! If any step fails, the destination (if it existed) is preserved and the
//! temporary file is removed.

use std::fs;
use std::io::Write;
use std::path::Path;

use super::StorageError;

/// Write `contents` to `destination` crash-safely using `temp_path` as the
/// staging file.
///
/// `temp_path` must be in the same directory as `destination` (same volume).
/// The previous contents of `destination` are preserved if writing or
/// replacement fails.
pub fn crash_safe_replace(
    destination: &Path,
    temp_path: &Path,
    contents: &[u8],
) -> Result<(), StorageError> {
    // Step 1+2: write complete contents to temp file and flush.
    if let Err(e) = (|| -> Result<(), StorageError> {
        let mut file = fs::File::create(temp_path)
            .map_err(|e| StorageError::Io(format!("create temp file: {e}")))?;
        file.write_all(contents)
            .map_err(|e| StorageError::Io(format!("write temp file: {e}")))?;
        file.flush()
            .map_err(|e| StorageError::Io(format!("flush temp file: {e}")))?;
        file.sync_all()
            .map_err(|e| StorageError::Io(format!("sync temp file: {e}")))?;
        Ok(())
    })() {
        // Best-effort cleanup of a partially created temp file.
        let _ = fs::remove_file(temp_path);
        return Err(e);
    }

    // Step 3: atomically replace the destination with the temp file. On
    // Windows this maps to MoveFileExW(MOVEFILE_REPLACE_EXISTING) and never
    // deletes the destination first, so a failure leaves the original intact.
    if let Err(e) = fs::rename(temp_path, destination) {
        // Best-effort cleanup of the staging file.
        let _ = fs::remove_file(temp_path);
        return Err(StorageError::Io(format!("rename temp to destination: {e}")));
    }

    Ok(())
}

/// Write contents to a temporary file only (no replace). Used for
/// fault-injection tests where we want to simulate a partial write.
#[allow(dead_code)]
pub fn write_temp_only(temp_path: &Path, contents: &[u8]) -> Result<(), StorageError> {
    let mut file = fs::File::create(temp_path)
        .map_err(|e| StorageError::Io(format!("create temp file: {e}")))?;
    file.write_all(contents)
        .map_err(|e| StorageError::Io(format!("write temp file: {e}")))?;
    file.flush()
        .map_err(|e| StorageError::Io(format!("flush temp file: {e}")))?;
    Ok(())
}
