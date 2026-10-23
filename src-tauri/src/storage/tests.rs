//! Unit and integration tests for the vault storage layer.

#[test]
fn incomplete_creation_is_not_silently_reset() {
    let dir = test_dir();
    let mut service = test_service(&dir);
    fs::create_dir_all(&service.vault_dir).unwrap();
    let params = kdf::KdfParams::default();
    let salt = kdf::generate_salt().unwrap();
    let keys = kdf::derive_keys("password", &*salt, &params).unwrap();
    let verifier = kdf::compute_verifier(&keys.verifier);
    let meta = VaultMeta::new(params, &*salt, &verifier);
    let meta_bytes = serde_json::to_vec_pretty(&meta).unwrap();
    let envelope = cipher::seal(&keys.encryption, &meta_bytes, b"").unwrap();
    let data_path = service.data_path();
    fs::write(&data_path, envelope.to_bytes()).unwrap();
    assert_eq!(service.status().unwrap(), VaultStatus::Incomplete);
    let result = service.create("new-password");
    assert!(matches!(result, Err(StorageError::VaultAlreadyExists)));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn temp_files_are_not_treated_as_valid_vault_files() {
    let dir = test_dir();
    let mut service = test_service(&dir);
    service.create("password").unwrap();
    let temp_path = service.vault_dir.join("vault.data.tmp");
    fs::write(&temp_path, b"garbage temp data").unwrap();
    assert_eq!(service.status().unwrap(), VaultStatus::Locked);
    service.cleanup_temp_files().unwrap();
    assert!(!temp_path.exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn saving_and_recovering_payload() {
    let dir = test_dir();
    let mut service = test_service(&dir);
    service.create("password").unwrap();
    service.unlock("password").unwrap();
    service.save(b"important vault data").unwrap();
    let payload = service.decrypted_payload().unwrap();
    assert_eq!(payload, b"important vault data");
    service.lock().unwrap();
    drop(service);
    let mut new_service = test_service(&dir);
    assert_eq!(new_service.status().unwrap(), VaultStatus::Locked);
    new_service.unlock("password").unwrap();
    let recovered = new_service.decrypted_payload().unwrap();
    assert_eq!(recovered, b"important vault data");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn crash_safe_replace_preserves_destination_on_failure() {
    let dir = test_dir();
    let dest = dir.join("target.dat");
    let _temp = dir.join("target.dat.tmp");
    fs::write(&dest, b"original contents").unwrap();
    let bad_temp = dir.join("nonexistent_subdir").join("target.dat.tmp");
    let result = crash_safe_replace(&dest, &bad_temp, b"new contents");
    assert!(result.is_err());
    let contents = fs::read(&dest).unwrap();
    assert_eq!(contents, b"original contents");
    assert!(!bad_temp.exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn crash_safe_replace_preserves_destination_when_replace_fails() {
    // Replacement fails deterministically: `destination` is a directory, so
    // renaming a file over it cannot succeed. The original destination (the
    // directory and its contents) must remain untouched and the staging file
    // must be cleaned up.
    let dir = test_dir();
    let dest = dir.join("target.dat");
    let temp = dir.join("target.dat.tmp");
    fs::create_dir_all(&dest).unwrap();
    fs::write(dest.join("keep.txt"), b"original contents").unwrap();

    let result = crash_safe_replace(&dest, &temp, b"new contents");
    assert!(result.is_err());
    // Destination directory and its contents remain intact.
    assert!(dest.is_dir());
    assert_eq!(fs::read(dest.join("keep.txt")).unwrap(), b"original contents");
    // Staging file cleaned up.
    assert!(!temp.exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn crash_safe_replace_succeeds_and_replaces() {
    let dir = test_dir();
    let dest = dir.join("target.dat");
    let temp = dir.join("target.dat.tmp");
    fs::write(&dest, b"original contents").unwrap();
    let result = crash_safe_replace(&dest, &temp, b"new contents");
    assert!(result.is_ok());
    assert!(!temp.exists());
    let contents = fs::read(&dest).unwrap();
    assert_eq!(contents, b"new contents");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn zero_password_not_accepted() {
    let dir = test_dir();
    let mut service = test_service(&dir);
    assert!(matches!(
        service.create(""),
        Err(StorageError::InvalidPassword)
    ));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn unlock_after_lock_clears_session() {
    let dir = test_dir();
    let mut service = test_service(&dir);
    service.create("password").unwrap();
    service.unlock("password").unwrap();
    assert!(service.decrypted_payload().is_ok());
    service.lock().unwrap();
    assert!(service.decrypted_payload().is_err());
    service.unlock("password").unwrap();
    assert!(service.decrypted_payload().is_ok());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn detect_modified_metadata() {
    let dir = test_dir();
    let mut service = test_service(&dir);
    service.create("password").unwrap();
    let meta_path = service.metadata_path();
    let mut bytes = fs::read(&meta_path).unwrap();
    bytes[0] ^= 0xff;
    fs::write(&meta_path, &bytes).unwrap();
    assert_eq!(service.status().unwrap(), VaultStatus::Incomplete);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn detect_truncated_metadata() {
    let dir = test_dir();
    let mut service = test_service(&dir);
    service.create("password").unwrap();
    let meta_path = service.metadata_path();
    let bytes = fs::read(&meta_path).unwrap();
    fs::write(&meta_path, &bytes[..bytes.len() / 2]).unwrap();
    assert_eq!(service.status().unwrap(), VaultStatus::Incomplete);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn detect_modified_encrypted_data() {
    let dir = test_dir();
    let mut service = test_service(&dir);
    service.create("password").unwrap();
    let data_path = service.data_path();
    let mut bytes = fs::read(&data_path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    fs::write(&data_path, &bytes).unwrap();
    let result = service.unlock("password");
    assert!(result.is_err());
    assert_eq!(service.status().unwrap(), VaultStatus::Incomplete);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn detect_truncated_encrypted_data() {
    let dir = test_dir();
    let mut service = test_service(&dir);
    service.create("password").unwrap();
    let data_path = service.data_path();
    let bytes = fs::read(&data_path).unwrap();
    fs::write(&data_path, &bytes[..bytes.len() / 2]).unwrap();
    assert_eq!(service.status().unwrap(), VaultStatus::Incomplete);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn reject_unsupported_format_version() {
    let dir = test_dir();
    let mut service = test_service(&dir);
    service.create("password").unwrap();
    let meta_path = service.metadata_path();
    let mut meta: VaultMeta = serde_json::from_slice(&fs::read(&meta_path).unwrap()).unwrap();
    meta.format_version = 999;
    let tampered = serde_json::to_vec_pretty(&meta).unwrap();
    fs::write(&meta_path, &tampered).unwrap();
    assert_eq!(service.status().unwrap(), VaultStatus::Incomplete);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn reject_unreasonable_kdf_parameters() {
    let dir = test_dir();
    let mut service = test_service(&dir);
    service.create("password").unwrap();
    let meta_path = service.metadata_path();
    let mut meta: VaultMeta = serde_json::from_slice(&fs::read(&meta_path).unwrap()).unwrap();
    meta.kdf_params.m_cost = u32::MAX;
    let tampered = serde_json::to_vec_pretty(&meta).unwrap();
    fs::write(&meta_path, &tampered).unwrap();
    assert_eq!(service.status().unwrap(), VaultStatus::Incomplete);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn unlock_with_wrong_password_fails() {
    let dir = test_dir();
    let mut service = test_service(&dir);

    service.create("correct-password").unwrap();
    let result = service.unlock("wrong-password");
    assert!(matches!(result, Err(StorageError::InvalidPassword)));
    assert_eq!(service.status().unwrap(), VaultStatus::Locked);
    assert!(service.decrypted_payload().is_err());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn lock_and_unlock_repeatedly_preserves_data() {
    let dir = test_dir();
    let mut service = test_service(&dir);
    service.create("password").unwrap();
    service.unlock("password").unwrap();
    service.save(b"vault payload data").unwrap();
    let payload = service.decrypted_payload().unwrap();
    assert_eq!(payload, b"vault payload data");
    service.lock().unwrap();
    assert!(service.decrypted_payload().is_err());
    service.unlock("password").unwrap();
    let payload = service.decrypted_payload().unwrap();
    assert_eq!(payload, b"vault payload data");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn save_while_locked_is_rejected() {
    let dir = test_dir();
    let mut service = test_service(&dir);
    service.create("password").unwrap();
    let result = service.save(b"some data");
    assert!(matches!(result, Err(StorageError::VaultLocked)));
    let _ = fs::remove_dir_all(&dir);
}
//
// All tests use temporary directories, never the real user data directory.
// No real passwords or secrets are used.

use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::format::VaultMeta;
use crate::crypto::{cipher, kdf};

use super::*;

fn test_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "cova-vault-test-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create test dir");
    dir
}

fn test_service(dir: &Path) -> VaultService {
    VaultService::new(dir.join("vault"))
}

#[test]
fn status_returns_absent_when_no_vault_exists() {
    let dir = test_dir();
    let service = test_service(&dir);
    assert_eq!(service.status().unwrap(), VaultStatus::Absent);
}

#[test]
fn create_vault_persists_both_files() {
    let dir = test_dir();
    let mut service = test_service(&dir);

    let result = service.create("test-password-123");
    assert!(result.is_ok(), "create should succeed: {:?}", result);

    assert!(service.metadata_path().exists());
    assert!(service.data_path().exists());

    assert_eq!(service.status().unwrap(), VaultStatus::Locked);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn create_rejects_empty_password() {
    let dir = test_dir();
    let mut service = test_service(&dir);

    let result = service.create("");
    assert!(matches!(result, Err(StorageError::InvalidPassword)));
}

#[test]
fn create_rejects_duplicate() {
    let dir = test_dir();
    let mut service = test_service(&dir);

    service.create("test-password-123").unwrap();
    let result = service.create("another-password");
    assert!(matches!(result, Err(StorageError::VaultAlreadyExists)));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn unlock_with_correct_password_succeeds() {
    let dir = test_dir();
    let mut service = test_service(&dir);

    service.create("correct-password").unwrap();
    let result = service.unlock("correct-password");
    assert!(result.is_ok(), "unlock should succeed: {:?}", result);
    assert_eq!(service.status().unwrap(), VaultStatus::Locked);

    let _ = fs::remove_dir_all(&dir);
}
