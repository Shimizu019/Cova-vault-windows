//! Cova Vault - application shell (Milestone 1), cryptographic core
//! (Milestone 2), and persistent vault storage (Milestone 3).
//!
//! The shell boots the Tauri window, installs the logging plugin, and exposes
//! a narrow set of IPC commands for vault lifecycle operations
//! (create, unlock, lock, status, save). The full vault service lives in the
//! [`storage`] module.
//!
//! The [`crypto`] module is the versioned, self-contained cryptographic core
//! for the vault encryption format. It is deliberately independent of Tauri so
//! that it can be unit tested in isolation.

use std::path::PathBuf;

use std::sync::Mutex;
use zeroize::Zeroizing;

use tauri::Manager;
use tauri::generate_handler;

use crate::storage::VaultService;

/// The versioned cryptographic core (KDF, AEAD cipher and on-disk format).
pub mod crypto;

/// Persistent vault storage layer (create, unlock, lock, save).
pub mod storage;

/// Resolve the application-local vault directory.
///
/// Uses Tauri's `BaseDirectory::DataLocal` so the vault is stored in the
/// per-user application data directory on Windows
/// (`%LOCALAPPDATA%\com.covavault.windows\cova-vault\`).
fn resolve_vault_dir(app_handle: &tauri::AppHandle) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = app_handle
        .path()
        .resolve("cova-vault", tauri::path::BaseDirectory::LocalData)?;
    Ok(dir)
}

/// Tauri command: create a new vault with the given password.
///
/// Rejects if a vault already exists or the password is empty.
#[tauri::command]
fn create_vault(
    password: String,
    service: tauri::State<'_, Mutex<VaultService>>,
) -> Result<(), String> {
    // Best-effort zeroization: wrap the IPC-supplied password so it is wiped
    // when it goes out of scope. The password necessarily crosses the IPC
    // boundary from the WebView; it is never logged or persisted as plaintext.
    let password = Zeroizing::new(password);
    let mut service = service.lock().map_err(|e| e.to_string())?;
    service.create(&password).map_err(|e| e.to_string())
}

/// Tauri command: unlock the vault with the given password.
#[tauri::command]
fn unlock_vault(
    password: String,
    service: tauri::State<'_, Mutex<VaultService>>,
) -> Result<(), String> {
    let password = Zeroizing::new(password);
    let mut service = service.lock().map_err(|e| e.to_string())?;
    service.unlock(&password).map_err(|e| e.to_string())
}

/// Tauri command: lock the vault and release sensitive key material.
#[tauri::command]
fn lock_vault(service: tauri::State<'_, Mutex<VaultService>>) -> Result<(), String> {
    let mut service = service.lock().map_err(|e| e.to_string())?;
    service.lock().map_err(|e| e.to_string())
}

/// Tauri command: check the current vault status on disk.
#[tauri::command]
fn vault_status(service: tauri::State<'_, Mutex<VaultService>>) -> Result<String, String> {
    let service = service.lock().map_err(|e| e.to_string())?;
    let status = service.status().map_err(|e| e.to_string())?;
    Ok(format!("{status:?}"))
}

/// Tauri command: save the given payload as the new encrypted vault contents.
#[tauri::command]
fn save_vault(
    payload: String,
    service: tauri::State<'_, Mutex<VaultService>>,
) -> Result<(), String> {
    let mut service = service.lock().map_err(|e| e.to_string())?;
    service.save(payload.as_bytes()).map_err(|e| e.to_string())
}

/// Build and run the Tauri application.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(
            tauri_plugin_log::Builder::default()
                .level(log::LevelFilter::Info)
                .build(),
        )
        .setup(|app| {
            let vault_dir = resolve_vault_dir(app.handle())?;
            // Ensure the vault directory exists.
            std::fs::create_dir_all(&vault_dir).map_err(tauri::Error::Io)?;
            app.manage(Mutex::new(VaultService::new(vault_dir)));
            Ok(())
        })
        .invoke_handler(generate_handler![
            create_vault,
            unlock_vault,
            lock_vault,
            vault_status,
            save_vault
        ])
        .run(tauri::generate_context!())
        .expect("error while building tauri application");
}
