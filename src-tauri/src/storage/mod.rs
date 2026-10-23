//! Persistent encrypted vault storage layer.
//!
//! This module turns the versioned cryptographic core (Milestone 2) into a
//! persistent on-disk vault for Windows. It handles:
//! - Resolving the application-local data directory through Tauri path APIs
//! - Persisting `vault.meta.json` and `vault.data` using the existing format
//! - Crash-safe writes (temp file + flush + atomic replace)
//! - Vault lifecycle: create, unlock, lock, save
//! - Typed errors for missing files, malformed metadata, auth failures, and IO errors
//!
//! # Design
//!
//! The [`VaultService`] owns the vault directory and an optional active
//! session. All filesystem operations go through crash-safe helpers so that
//! a partial write can never corrupt an existing valid vault.
//!
//! The service is constructed with a `PathBuf` so that unit and integration
//! tests can use temporary directories instead of the real user data
//! directory.
//!
//! # Security
//!
//! - Master keys and derived keys live inside [`VaultService`] and are
//!   zeroized on lock/drop via [`zeroize::Zeroizing`].
//! - No key material is ever returned through the public API.
//! - Decrypted plaintext is held in memory only while the vault is unlocked.
//! - Passwords are never logged.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::crypto::{
    CryptoError, cipher,
    format::{Envelope, VaultMeta},
    kdf,
    kdf::KEY_LEN,
};

mod crash_safe;
pub use crash_safe::crash_safe_replace;

/// Errors produced by the storage layer.
///
/// Storage errors wrap underlying IO and crypto errors and add vault-lifecycle
/// specific variants (absent, incomplete, already exists, locked).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    /// An underlying filesystem operation failed.
    Io(String),

    /// JSON serialization/deserialization failed.
    Serialization(String),

    /// A cryptographic operation failed.
    Crypto(CryptoError),

    /// No vault files exist at the expected location.
    VaultAbsent,

    /// Vault files exist but are inconsistent or corrupted (e.g. metadata
    /// present but data missing, or vice versa).
    VaultIncomplete,

    /// A complete vault already exists and creation would overwrite it.
    VaultAlreadyExists,

    /// The vault is locked and the requested operation requires unlocking first.
    VaultLocked,

    /// The supplied password did not match the stored verifier.
    InvalidPassword,

    /// The operating system random number generator is unavailable.
    Randomness,
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "filesystem error: {msg}"),
            Self::Serialization(msg) => write!(f, "serialization error: {msg}"),
            Self::Crypto(err) => write!(f, "cryptographic error: {err}"),
            Self::VaultAbsent => write!(f, "no vault exists"),
            Self::VaultIncomplete => write!(f, "vault is incomplete or corrupted"),
            Self::VaultAlreadyExists => write!(f, "vault already exists"),
            Self::VaultLocked => write!(f, "vault is locked"),
            Self::InvalidPassword => write!(f, "invalid password"),
            Self::Randomness => write!(f, "system random number generator failed"),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<CryptoError> for StorageError {
    fn from(err: CryptoError) -> Self {
        StorageError::Crypto(err)
    }
}

impl From<std::io::Error> for StorageError {
    fn from(err: std::io::Error) -> Self {
        StorageError::Io(err.to_string())
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(err: serde_json::Error) -> Self {
        StorageError::Serialization(err.to_string())
    }
}

/// Current status of the vault on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultStatus {
    /// No vault files exist.
    Absent,

    /// Both metadata and data files exist; the vault is present but locked.
    Locked,

    /// Both metadata and data files exist but one or both are inconsistent
    /// or corrupted.
    Incomplete,
}

/// An active unlocked session holding decrypted state in memory.
///
/// The encryption key and decrypted payload are zeroized when the session
/// is dropped (via [`Drop`]).
struct ActiveSession {
    /// AES-256-GCM encryption key, zeroized on drop.
    encryption_key: Zeroizing<[u8; KEY_LEN]>,
    /// Currently decrypted vault payload.
    decrypted_payload: Vec<u8>,
    /// The validated vault metadata.
    vault_meta: VaultMeta,
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        // Zeroize decrypted plaintext before releasing memory.
        self.decrypted_payload.fill(0);
        // `Zeroizing` wrappers zeroize their contents on drop.
    }
}

impl fmt::Debug for ActiveSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActiveSession")
            .field("encryption_key", &"<redacted>")
            .field("decrypted_payload_len", &self.decrypted_payload.len())
            .field("vault_meta", &self.vault_meta)
            .finish()
    }
}

/// The vault storage service.
///
/// Owns the vault directory path and an optional active session. Construct
/// with any directory path; tests should use a temporary directory.
#[derive(Debug)]
pub struct VaultService {
    pub(crate) vault_dir: PathBuf,
    session: Option<ActiveSession>,
    /// Set to true when a vault operation (e.g. unlock) detects that the
    /// on-disk data is corrupted (AEAD authentication failure). Cleared on
    /// successful create/unlock.
    corrupted: bool,
}

impl VaultService {
    /// Create a new service for the given vault directory.
    pub fn new(vault_dir: PathBuf) -> Self {
        Self {
            vault_dir,
            session: None,
            corrupted: false,
        }
    }

    /// Return the vault directory path.
    pub fn vault_dir(&self) -> &Path {
        &self.vault_dir
    }

    /// Inspect the vault directory and report whether a vault is absent,
    /// locked, or incomplete/corrupted.
    pub fn status(&self) -> Result<VaultStatus, StorageError> {
        let meta_path = self.metadata_path();
        let data_path = self.data_path();

        let meta_exists = meta_path.exists();
        let data_exists = data_path.exists();

        match (meta_exists, data_exists) {
            (false, false) => Ok(VaultStatus::Absent),
            (true, true) => {
                // Validate metadata thoroughly (format version, KDF params, etc.)
                let meta_ok = self
                    .read_metadata_file()
                    .and_then(|m| m.validate().map_err(StorageError::Crypto))
                    .is_ok();

                let data_ok = self.read_envelope_file().is_ok();

                if meta_ok && data_ok && !self.corrupted {
                    Ok(VaultStatus::Locked)
                } else {
                    Ok(VaultStatus::Incomplete)
                }
            }
            _ => Ok(VaultStatus::Incomplete),
        }
    }

    /// Create a new vault with the given password.
    ///
    /// Fails with [`StorageError::VaultAlreadyExists`] if a complete vault
    /// already exists. Rejects empty passwords.
    pub fn create(&mut self, password: &str) -> Result<(), StorageError> {
        if password.is_empty() {
            return Err(StorageError::InvalidPassword);
        }
        if password.len() > kdf::MAX_PASSWORD_LEN {
            return Err(StorageError::InvalidPassword);
        }

        // Ensure the vault directory exists before writing.
        fs::create_dir_all(&self.vault_dir)
            .map_err(|e| StorageError::Io(format!("create vault dir: {e}")))?;

        self.corrupted = false;

        match self.status()? {
            VaultStatus::Locked => return Err(StorageError::VaultAlreadyExists),
            VaultStatus::Absent => {}
            VaultStatus::Incomplete => return Err(StorageError::VaultAlreadyExists),
        }

        let params = kdf::KdfParams::default();
        let salt = kdf::generate_salt()?;

        // Derive keys and verifier before touching the disk.
        let keys = kdf::derive_keys(password, &*salt, &params)?;
        let verifier = kdf::compute_verifier(&keys.verifier);

        let meta = VaultMeta::new(params, &*salt, &verifier);
        let meta_bytes = serde_json::to_vec_pretty(&meta)?;

        // Encrypt an initial empty vault payload.
        let envelope = cipher::seal(&keys.encryption, &meta_bytes, b"")?;

        // Persist both files crash-safely. Write the encrypted data first,
        // then the metadata. If the process crashes between the two writes,
        // we end up with data but no metadata, detected as `Incomplete`.
        self.write_data_atomic(&envelope.to_bytes())?;
        self.write_metadata_atomic(&meta_bytes)?;

        drop(keys);

        Ok(())
    }

    /// Unlock the vault with the given password.
    ///
    /// Loads and validates metadata, validates KDF parameters before any
    /// expensive key derivation, verifies the password against the stored
    /// verifier, then decrypts and authenticates the vault payload.
    pub fn unlock(&mut self, password: &str) -> Result<(), StorageError> {
        if self.session.is_some() {
            return Ok(());
        }

        let meta_bytes = self.read_metadata_bytes()?;
        let meta: VaultMeta = serde_json::from_slice(&meta_bytes)?;
        meta.validate()?;

        let salt = meta.salt_bytes()?;
        let expected_verifier = meta.password_verifier_bytes()?;

        meta.kdf_params.validate()?;

        let password_ok =
            kdf::verify_password(password, &salt, &meta.kdf_params, &expected_verifier)?;

        if !password_ok {
            return Err(StorageError::InvalidPassword);
        }

        let keys = kdf::derive_keys(password, &salt, &meta.kdf_params)?;

        let envelope = self.read_envelope_file()?;
        let decrypted_payload = match cipher::open(&keys.encryption, &envelope, &meta_bytes) {
            Ok(p) => p,
            Err(e) => {
                self.corrupted = true;
                return Err(StorageError::Crypto(e));
            }
        };

        self.corrupted = false;
        self.session = Some(ActiveSession {
            encryption_key: keys.encryption.clone(),
            decrypted_payload,
            vault_meta: meta,
        });

        Ok(())
    }

    /// Lock the vault, zeroizing the active session and releasing sensitive
    /// key material. Persisted encrypted files are left untouched.
    pub fn lock(&mut self) -> Result<(), StorageError> {
        self.session = None;
        Ok(())
    }

    /// Save the given payload as the new encrypted vault contents.
    ///
    /// Fails with [`StorageError::VaultLocked`] if the vault is not unlocked.
    pub fn save(&mut self, payload: &[u8]) -> Result<(), StorageError> {
        // Prepare the encrypted envelope from the current session WITHOUT
        // mutating the in-memory payload. Persist first; only update the
        // session's decrypted payload after a successful write so a failed
        // write leaves both the persisted vault and the in-memory state
        // unchanged.
        let envelope_bytes = {
            let session = self.session.as_ref().ok_or(StorageError::VaultLocked)?;
            let meta_bytes = serde_json::to_vec_pretty(&session.vault_meta)?;
            let envelope = cipher::seal(&session.encryption_key, &meta_bytes, payload)?;
            envelope.to_bytes()
        };

        self.write_data_atomic(&envelope_bytes)?;

        if let Some(session) = self.session.as_mut() {
            session.decrypted_payload = payload.to_vec();
        }

        Ok(())
    }

    /// Return the currently decrypted vault payload, or `VaultLocked` if the
    /// vault is not unlocked.
    pub fn decrypted_payload(&self) -> Result<&[u8], StorageError> {
        self.session
            .as_ref()
            .map(|s| s.decrypted_payload.as_slice())
            .ok_or(StorageError::VaultLocked)
    }

    // --- private helpers ---

    pub(crate) fn metadata_path(&self) -> PathBuf {
        self.vault_dir.join("vault.meta.json")
    }

    pub(crate) fn data_path(&self) -> PathBuf {
        self.vault_dir.join("vault.data")
    }

    fn read_metadata_bytes(&self) -> Result<Vec<u8>, StorageError> {
        let path = self.metadata_path();
        let bytes = fs::read(&path).map_err(|e| StorageError::Io(format!("read metadata: {e}")))?;
        Ok(bytes)
    }

    fn read_metadata_file(&self) -> Result<VaultMeta, StorageError> {
        let bytes = self.read_metadata_bytes()?;
        let meta: VaultMeta = serde_json::from_slice(&bytes)?;
        Ok(meta)
    }

    fn read_envelope_file(&self) -> Result<Envelope, StorageError> {
        let path = self.data_path();
        let bytes = fs::read(&path).map_err(|e| StorageError::Io(format!("read data: {e}")))?;
        let envelope = Envelope::parse(&bytes)
            .map_err(|e| StorageError::Io(format!("parse envelope: {e}")))?;
        Ok(envelope)
    }

    /// Write metadata crash-safely: temp file in same directory, flush, then
    /// atomic replace.
    fn write_metadata_atomic(&self, contents: &[u8]) -> Result<(), StorageError> {
        let dest = self.metadata_path();
        let temp = self.vault_dir.join("vault.meta.json.tmp");
        crate::storage::crash_safe::crash_safe_replace(&dest, &temp, contents)?;
        Ok(())
    }

    /// Write envelope data crash-safely.
    fn write_data_atomic(&self, contents: &[u8]) -> Result<(), StorageError> {
        let dest = self.data_path();
        let temp = self.vault_dir.join("vault.data.tmp");
        crate::storage::crash_safe::crash_safe_replace(&dest, &temp, contents)?;
        Ok(())
    }

    /// Remove any temporary files left behind by a failed write.
    #[allow(dead_code)]
    pub(crate) fn cleanup_temp_files(&self) -> Result<(), StorageError> {
        for temp in [
            self.vault_dir.join("vault.meta.json.tmp"),
            self.vault_dir.join("vault.data.tmp"),
        ] {
            if temp.exists() {
                let _ = fs::remove_file(&temp);
            }
        }
        Ok(())
    }
}

/// Return the decrypted payload held by the active session.
pub fn session_payload(service: &VaultService) -> Result<&[u8], StorageError> {
    service.decrypted_payload()
}

#[cfg(test)]
mod tests;
