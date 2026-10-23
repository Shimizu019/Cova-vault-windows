//! Cryptographic core for the Cova Vault.
//!
//! This module implements the versioned, authenticated vault encryption
//! format described in `docs/CRYPTOGRAPHIC-DESIGN.md`. It is deliberately
//! self-contained: no Tauri, filesystem or UI code may be referenced from
//! here, so that the cryptographic core can be unit tested in isolation and
//! reasoned about independently of the application shell.
//!
//! # Layout
//!
//! - [`kdf`] — password based key derivation (Argon2id) and purpose separated
//!   subkey expansion (HKDF-SHA256).
//! - [`cipher`] — AES-256-GCM authenticated encryption of the vault payload.
//! - [`format`] — the versioned on-disk format (`vault.meta.json` and
//!   `vault.data`).
//!
//! # Design rules
//!
//! 1. **No secret ever touches the public metadata.** The salt, the KDF
//!    parameters and the password verifier are public values.
//! 2. **Untrusted parameters are bounded before use.** KDF parameters come
//!    from a file an attacker may control, so they are validated before any
//!    memory is allocated or any CPU time is burned.
//! 3. **Failures are typed, not panics.** Every fallible operation returns
//!    [`CryptoError`].

pub mod cipher;
pub mod format;
pub mod kdf;

use std::fmt;

/// Errors produced by the cryptographic core.
///
/// The variants are intentionally coarse. In particular, authentication
/// failures are reported as a single opaque variant so that callers cannot
/// accidentally distinguish "wrong key" from "tampered ciphertext" through
/// error handling alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// The stored metadata document is structurally invalid.
    InvalidMetadata,

    /// The stored metadata declares a format version this build cannot read.
    UnsupportedFormatVersion {
        /// The version this build understands.
        expected: u32,
        /// The version found in the file.
        found: u32,
    },

    /// The stored metadata declares a cipher suite this build cannot read.
    UnsupportedCipherSuite(u8),

    /// The stored metadata declares a KDF this build cannot use.
    UnsupportedKdf(String),

    /// The `vault.data` envelope is structurally invalid.
    MalformedEnvelope,

    /// A KDF parameter is outside the accepted bounds.
    ///
    /// `field` names the offending parameter and `value` is its numeric
    /// value.
    InvalidKdfParams {
        /// Name of the offending parameter, e.g. `"m_cost"`.
        field: &'static str,
        /// The rejected value.
        value: u64,
    },

    /// The salt has the wrong length.
    InvalidSaltLength(usize),

    /// The stored password verifier has the wrong length.
    InvalidVerifierLength(usize),

    /// The password exceeds the maximum accepted length.
    PasswordTooLong,

    /// Key derivation failed for an unspecified reason.
    KeyDerivation,

    /// The operating system random number generator is unavailable.
    Randomness,

    /// The ciphertext failed authentication.
    ///
    /// This covers both a wrong key and a tampered ciphertext. The two cases
    /// are deliberately not distinguished.
    AuthenticationFailed,

    /// The payload could not be encrypted (e.g. it is implausibly large).
    EncryptionFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMetadata => write!(f, "invalid vault metadata"),
            Self::UnsupportedFormatVersion { expected, found } => write!(
                f,
                "unsupported format version {found} (expected {expected})"
            ),
            Self::UnsupportedCipherSuite(id) => {
                write!(f, "unsupported cipher suite id {id}")
            }
            Self::UnsupportedKdf(name) => write!(f, "unsupported kdf '{name}'"),
            Self::MalformedEnvelope => write!(f, "malformed vault envelope"),
            Self::InvalidKdfParams { field, value } => {
                write!(f, "invalid kdf parameter '{field}' = {value}")
            }
            Self::InvalidSaltLength(len) => write!(f, "invalid salt length {len}"),
            Self::InvalidVerifierLength(len) => {
                write!(f, "invalid password verifier length {len}")
            }
            Self::PasswordTooLong => write!(f, "password is too long"),
            Self::KeyDerivation => write!(f, "key derivation failed"),
            Self::Randomness => write!(f, "the system random number generator failed"),
            Self::AuthenticationFailed => write!(f, "ciphertext authentication failed"),
            Self::EncryptionFailed => write!(f, "encryption failed"),
        }
    }
}

impl std::error::Error for CryptoError {}
