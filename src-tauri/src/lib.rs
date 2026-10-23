//! Cova Vault - application shell (Milestone 1) and cryptographic core
//! (Milestone 2).
//!
//! The shell is deliberately minimal: it boots the window and installs the
//! logging plugin. No vault persistence or UI logic lives here yet, and no
//! custom IPC commands are exposed to the frontend.
//!
//! The [`crypto`] module is the versioned, self-contained cryptographic core
//! for the vault encryption format. It is deliberately independent of Tauri so
//! that it can be unit tested in isolation.

/// The versioned cryptographic core (KDF, AEAD cipher and on-disk format).
pub mod crypto;

/// Build and run the Tauri application.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(
            tauri_plugin_log::Builder::default()
                .level(log::LevelFilter::Info)
                .build(),
        )
        .run(tauri::generate_context!())
        .expect("error while building tauri application");
}
