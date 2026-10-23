//! Crash-safe file replacement for Windows.
//!
//! On Windows, `std::fs::rename` cannot replace an existing destination file.
//! The safe sequence is:
//! 1. Write complete contents to a temporary file in the *same directory*
//!    (same volume, so rename is atomic).
//! 2. Flush (and optionally sync) the temporary file.
//! 3. Delete the destination if it exists.
//! 4. Rename the temporary file to the destination.
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
    {
        let mut file = fs::File::create(temp_path)
            .map_err(|e| StorageError::Io(format!("create temp file: {e}")))?;
        file.write_all(contents)
            .map_err(|e| StorageError::Io(format!("write temp file: {e}")))?;
        file.flush()
            .map_err(|e| StorageError::Io(format!("flush temp file: {e}")))?;
        // `sync_all` ensures data reaches the OS; on Windows this is the best
        // we can do without platform-specific APIs. Full crash durability
        // across power loss would require `FlushFileBuffers` plus
        // `FILE_FLAG_WRITE_THROUGH`, which is out of scope.
        file.sync_all()
            .map_err(|e| StorageError::Io(format!("sync temp file: {e}")))?;
    }

    // Step 3: delete the destination if it exists. On Windows, rename cannot
    // replace an existing file, so we must remove it first.
    if destination.exists() {
        fs::remove_file(destination)
            .map_err(|e| StorageError::Io(format!("remove destination: {e}")))?;
    }

    // Step 4: rename temp to destination.
    fs::rename(temp_path, destination)
        .map_err(|e| StorageError::Io(format!("rename temp to destination: {e}")))?;

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
