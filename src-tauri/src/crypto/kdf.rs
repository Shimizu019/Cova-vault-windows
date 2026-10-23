//! Password-based key derivation and purpose-separated subkey derivation.
//!
//! # Key hierarchy
//!
//! ```text
//! password ──Argon2id(salt, m, t, p)──> master key (32 bytes)
//!                                            │
//!                                            ├─HKDF-SHA256(info=".../enc")──> encryption key (32 bytes)
//!                                            ├─HKDF-SHA256(info=".../ver")──> verifier key  (32 bytes)
//!                                            └─HKDF-SHA256(info=".../mac")──> backup MAC key (32 bytes)
//! ```
//!
//! The master key is derived **only** from the password, the salt and the
//! public KDF parameters. Every other secret is derived from the master key
//! with HKDF-SHA256 using a distinct `info` label, so that a key used for
//! encryption can never be replayed as a key used for verification (and vice
//! versa).
//!
//! # Password verification
//!
//! Password verification is **not** performed with a fast password hash such
//! as MD5, SHA-1 or a plain SHA-256 digest. Instead:
//!
//! 1. The password is stretched with the *same* Argon2id parameters and salt
//!    that are used for decryption, producing the master key.
//! 2. A dedicated verifier key is derived from the master key via HKDF.
//! 3. The verifier value is `HMAC-SHA256(verifier_key, VERIFIER_CONTEXT)`.
//!
//! Because step 1 is the expensive part, the verifier cannot be forged by an
//! attacker who does not know the password, and it cannot be brute-forced
//! faster than the vault itself can be unlocked. The stored verifier is an
//! HMAC tag over a fixed constant, so it does not leak any information about
//! the password beyond what an offline dictionary attack against the Argon2id
//! hash already reveals.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::CryptoError;

/// Length in bytes of every derived key in this design.
pub const KEY_LEN: usize = 32;

/// Length in bytes of the Argon2id salt.
pub const SALT_LEN: usize = 16;

/// Baseline Argon2id memory cost in KiB (19 MiB).
///
/// This is the OWASP-recommended minimum for Argon2id and the documented
/// baseline for this project. See `docs/CRYPTOGRAPHIC-DESIGN.md` for the
/// benchmark that selected the shipped value.
pub const BASELINE_M_COST_KIB: u32 = 19 * 1024;

/// Baseline Argon2id time cost (number of passes over memory).
pub const BASELINE_T_COST: u32 = 2;

/// Baseline Argon2id degree of parallelism.
pub const BASELINE_P_COST: u32 = 1;

/// Upper bound on accepted memory cost, in KiB (1 GiB).
///
/// Metadata is attacker-controlled input. Without an upper bound a hostile
/// `vault.meta.json` could request an arbitrarily large allocation and
/// exhaust memory before any password check happens.
pub const MAX_M_COST_KIB: u32 = 1024 * 1024;

/// Upper bound on accepted time cost.
pub const MAX_T_COST: u32 = 16;

/// Upper bound on accepted degree of parallelism.
pub const MAX_P_COST: u32 = 16;

/// Lower bound on accepted memory cost, in KiB.
///
/// Argon2 requires at least `8 * p_cost` blocks; this bound additionally
/// rejects absurdly weak values well below the baseline.
pub const MIN_M_COST_KIB: u32 = 8;

/// Upper bound on the accepted Argon2id password length, in bytes.
///
/// Argon2 itself accepts far longer passwords, but bounding the length keeps
/// the cost of the KDF predictable and prevents a huge buffer from being fed
/// in from the UI layer.
pub const MAX_PASSWORD_LEN: usize = 1024;

/// HKDF `info` label for the payload encryption key.
pub const INFO_ENCRYPTION: &[u8] = b"cova-vault/v1/hkdf/encryption-key";

/// HKDF `info` label for the password verifier key.
pub const INFO_VERIFIER: &[u8] = b"cova-vault/v1/hkdf/verifier-key";

/// HKDF `info` label for the backup authentication key.
pub const INFO_BACKUP_MAC: &[u8] = b"cova-vault/v1/hkdf/backup-mac-key";

/// Fixed context string that is HMAC'd to produce the stored verifier.
pub const VERIFIER_CONTEXT: &[u8] = b"cova-vault/v1/password-verifier";

/// Argon2id parameters, stored verbatim in `vault.meta.json`.
///
/// These parameters are public. They must be validated before they are used
/// to derive a key, because they directly control how much memory and time
/// an unlock attempt consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Number of passes over memory.
    pub t_cost: u32,
    /// Degree of parallelism.
    pub p_cost: u32,
    /// Length of the derived key in bytes.
    pub output_len: u32,
}

impl Default for KdfParams {
    /// The documented baseline: Argon2id, 19 MiB, 2 iterations, parallelism 1.
    fn default() -> Self {
        Self {
            m_cost: BASELINE_M_COST_KIB,
            t_cost: BASELINE_T_COST,
            p_cost: BASELINE_P_COST,
            output_len: KEY_LEN as u32,
        }
    }
}

impl KdfParams {
    /// Validate these parameters against the accepted bounds.
    ///
    /// Returns [`CryptoError::InvalidKdfParams`] for anything unreasonable.
    /// This must run *before* Argon2 is invoked.
    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.m_cost < MIN_M_COST_KIB || self.m_cost > MAX_M_COST_KIB {
            return Err(CryptoError::InvalidKdfParams {
                field: "m_cost",
                value: u64::from(self.m_cost),
            });
        }
        if self.t_cost < 1 || self.t_cost > MAX_T_COST {
            return Err(CryptoError::InvalidKdfParams {
                field: "t_cost",
                value: u64::from(self.t_cost),
            });
        }
        if self.p_cost < 1 || self.p_cost > MAX_P_COST {
            return Err(CryptoError::InvalidKdfParams {
                field: "p_cost",
                value: u64::from(self.p_cost),
            });
        }
        if self.output_len != KEY_LEN as u32 {
            return Err(CryptoError::InvalidKdfParams {
                field: "output_len",
                value: u64::from(self.output_len),
            });
        }
        Ok(())
    }

    /// Convert into the `argon2` crate's parameter representation.
    fn to_argon2(self) -> Result<Params, CryptoError> {
        Params::new(
            self.m_cost,
            self.t_cost,
            self.p_cost,
            Some(self.output_len as usize),
        )
        .map_err(|_| CryptoError::InvalidKdfParams {
            field: "argon2-params",
            value: 0,
        })
    }
}

/// A freshly derived set of purpose-separated keys.
///
/// The master key is dropped as soon as the subkeys have been derived, so it
/// is never retained in memory longer than necessary.
#[derive(Clone)]
pub struct DerivedKeys {
    /// Key used to encrypt and decrypt the vault payload (AES-256-GCM).
    pub encryption: Zeroizing<[u8; KEY_LEN]>,
    /// Key used to compute the password verifier (HMAC-SHA256).
    pub verifier: Zeroizing<[u8; KEY_LEN]>,
    /// Key reserved for backup authentication (HMAC-SHA256).
    pub backup_mac: Zeroizing<[u8; KEY_LEN]>,
}

impl Drop for DerivedKeys {
    fn drop(&mut self) {
        // `Zeroizing` already zeroes on drop; this explicit call keeps the
        // intent obvious and guarantees the wipe even if the wrapper type is
        // ever changed.
        self.encryption.zeroize();
        self.verifier.zeroize();
        self.backup_mac.zeroize();
    }
}

impl std::fmt::Debug for DerivedKeys {
    /// Never print key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DerivedKeys")
            .field("encryption", &"<redacted>")
            .field("verifier", &"<redacted>")
            .field("backup_mac", &"<redacted>")
            .finish()
    }
}

/// Generate a cryptographically random salt using the OS CSPRNG.
///
/// Returns [`CryptoError::Randomness`] if the operating system random number
/// generator is unavailable.
pub fn generate_salt() -> Result<Zeroizing<[u8; SALT_LEN]>, CryptoError> {
    let mut salt = Zeroizing::new([0u8; SALT_LEN]);
    getrandom::fill(salt.as_mut()).map_err(|_| CryptoError::Randomness)?;
    Ok(salt)
}

/// Derive the master key from a password and salt using Argon2id.
///
/// The KDF parameters are validated first, so an attacker-supplied metadata
/// file cannot request an unbounded amount of work.
pub fn derive_master_key(
    password: &str,
    salt: &[u8],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    params.validate()?;
    if salt.len() != SALT_LEN {
        return Err(CryptoError::InvalidSaltLength(salt.len()));
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err(CryptoError::PasswordTooLong);
    }

    let argon2_params = params.to_argon2()?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut master = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), salt, master.as_mut())
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(master)
}

/// Expand a master key into the three purpose-separated subkeys.
fn expand_keys(master: &[u8; KEY_LEN]) -> Result<DerivedKeys, CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, master);

    let mut encryption = Zeroizing::new([0u8; KEY_LEN]);
    let mut verifier = Zeroizing::new([0u8; KEY_LEN]);
    let mut backup_mac = Zeroizing::new([0u8; KEY_LEN]);

    hk.expand(INFO_ENCRYPTION, encryption.as_mut())
        .map_err(|_| CryptoError::KeyDerivation)?;
    hk.expand(INFO_VERIFIER, verifier.as_mut())
        .map_err(|_| CryptoError::KeyDerivation)?;
    hk.expand(INFO_BACKUP_MAC, backup_mac.as_mut())
        .map_err(|_| CryptoError::KeyDerivation)?;

    Ok(DerivedKeys {
        encryption,
        verifier,
        backup_mac,
    })
}

/// Derive the full key set from a password and salt.
pub fn derive_keys(
    password: &str,
    salt: &[u8],
    params: &KdfParams,
) -> Result<DerivedKeys, CryptoError> {
    let master = derive_master_key(password, salt, params)?;
    expand_keys(&master)
}

/// Compute the password verifier for a derived verifier key.
///
/// The verifier is `HMAC-SHA256(verifier_key, VERIFIER_CONTEXT)`.
pub fn compute_verifier(verifier_key: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(verifier_key)
        .expect("HMAC accepts keys of any length");
    mac.update(VERIFIER_CONTEXT);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&tag);
    out
}

/// Compute the password verifier for a password, salt and parameter set.
pub fn compute_password_verifier(
    password: &str,
    salt: &[u8],
    params: &KdfParams,
) -> Result<[u8; KEY_LEN], CryptoError> {
    let keys = derive_keys(password, salt, params)?;
    Ok(compute_verifier(&keys.verifier))
}

/// Verify a password against a stored verifier in constant time.
///
/// Returns `Ok(false)` when the password is wrong; it must not be
/// distinguishable from an error in timing by the caller.
pub fn verify_password(
    password: &str,
    salt: &[u8],
    params: &KdfParams,
    expected_verifier: &[u8],
) -> Result<bool, CryptoError> {
    if expected_verifier.len() != KEY_LEN {
        return Err(CryptoError::InvalidVerifierLength(expected_verifier.len()));
    }
    let actual = compute_password_verifier(password, salt, params)?;
    Ok(actual.ct_eq(expected_verifier).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> KdfParams {
        KdfParams {
            m_cost: BASELINE_M_COST_KIB,
            t_cost: BASELINE_T_COST,
            p_cost: BASELINE_P_COST,
            output_len: KEY_LEN as u32,
        }
    }

    #[test]
    fn derive_master_key_is_deterministic() {
        let params = test_params();
        let salt = [0x11u8; SALT_LEN];
        let k1 = derive_master_key("correct horse battery staple", &salt, &params).unwrap();
        let k2 = derive_master_key("correct horse battery staple", &salt, &params).unwrap();
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn different_passwords_derive_different_keys() {
        let params = test_params();
        let salt = [0x22u8; SALT_LEN];
        let k1 = derive_master_key("password one", &salt, &params).unwrap();
        let k2 = derive_master_key("password two", &salt, &params).unwrap();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn different_salts_derive_different_keys() {
        let params = test_params();
        let k1 = derive_master_key("same password", &[0x33u8; SALT_LEN], &params).unwrap();
        let k2 = derive_master_key("same password", &[0x44u8; SALT_LEN], &params).unwrap();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn derive_keys_produces_distinct_subkeys() {
        let params = test_params();
        let keys =
            derive_keys("correct horse battery staple", &[0x55u8; SALT_LEN], &params).unwrap();
        assert_ne!(*keys.encryption, *keys.verifier);
        assert_ne!(*keys.encryption, *keys.backup_mac);
        assert_ne!(*keys.verifier, *keys.backup_mac);
    }

    #[test]
    fn compute_verifier_is_deterministic() {
        let params = test_params();
        let salt = [0x66u8; SALT_LEN];
        let keys = derive_keys("correct horse battery staple", &salt, &params).unwrap();
        let v1 = compute_verifier(&keys.verifier);
        let v2 = compute_verifier(&keys.verifier);
        assert_eq!(v1, v2);
    }

    #[test]
    fn compute_password_verifier_matches_compute_verifier() {
        let params = test_params();
        let salt = [0x77u8; SALT_LEN];
        let keys = derive_keys("correct horse battery staple", &salt, &params).unwrap();
        let v1 = compute_password_verifier("correct horse battery staple", &salt, &params).unwrap();
        let v2 = compute_verifier(&keys.verifier);
        assert_eq!(v1, v2);
    }

    #[test]
    fn verify_password_accepts_correct_password() {
        let params = test_params();
        let salt = [0x88u8; SALT_LEN];
        let verifier =
            compute_password_verifier("correct horse battery staple", &salt, &params).unwrap();
        let result =
            verify_password("correct horse battery staple", &salt, &params, &verifier).unwrap();
        assert!(result);
    }

    #[test]
    fn verify_password_rejects_wrong_password() {
        let params = test_params();
        let salt = [0x99u8; SALT_LEN];
        let verifier =
            compute_password_verifier("correct horse battery staple", &salt, &params).unwrap();
        let result = verify_password("wrong password", &salt, &params, &verifier).unwrap();
        assert!(!result);
    }

    #[test]
    fn verify_password_rejects_wrong_verifier_length() {
        let params = test_params();
        let salt = [0x10u8; SALT_LEN];
        let result = verify_password("password", &salt, &params, &[0u8; 16]);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidVerifierLength(16))
        ));
    }

    #[test]
    fn verify_password_does_not_leak_password_in_error() {
        let params = test_params();
        let salt = [0x20u8; SALT_LEN];
        let verifier = [0x42u8; KEY_LEN];
        // Any error must not contain the password string.
        let result = verify_password("s3cr3t-p4ssw0rd!", &salt, &params, &verifier);
        if let Err(e) = result {
            let msg = format!("{e}");
            assert!(
                !msg.contains("s3cr3t-p4ssw0rd"),
                "error message leaked password: {msg}"
            );
        }
    }

    #[test]
    fn reject_excessive_memory_cost() {
        let params = KdfParams {
            m_cost: MAX_M_COST_KIB + 1,
            t_cost: 1,
            p_cost: 1,
            output_len: KEY_LEN as u32,
        };
        assert!(
            matches!(params.validate(), Err(CryptoError::InvalidKdfParams { field, .. }) if field == "m_cost")
        );
    }

    #[test]
    fn reject_insufficient_memory_cost() {
        let params = KdfParams {
            m_cost: MIN_M_COST_KIB - 1,
            t_cost: 1,
            p_cost: 1,
            output_len: KEY_LEN as u32,
        };
        assert!(
            matches!(params.validate(), Err(CryptoError::InvalidKdfParams { field, .. }) if field == "m_cost")
        );
    }

    #[test]
    fn reject_excessive_time_cost() {
        let params = KdfParams {
            m_cost: BASELINE_M_COST_KIB,
            t_cost: MAX_T_COST + 1,
            p_cost: 1,
            output_len: KEY_LEN as u32,
        };
        assert!(
            matches!(params.validate(), Err(CryptoError::InvalidKdfParams { field, .. }) if field == "t_cost")
        );
    }

    #[test]
    fn reject_zero_time_cost() {
        let params = KdfParams {
            m_cost: BASELINE_M_COST_KIB,
            t_cost: 0,
            p_cost: 1,
            output_len: KEY_LEN as u32,
        };
        assert!(
            matches!(params.validate(), Err(CryptoError::InvalidKdfParams { field, .. }) if field == "t_cost")
        );
    }

    #[test]
    fn reject_excessive_parallelism() {
        let params = KdfParams {
            m_cost: BASELINE_M_COST_KIB,
            t_cost: 1,
            p_cost: MAX_P_COST + 1,
            output_len: KEY_LEN as u32,
        };
        assert!(
            matches!(params.validate(), Err(CryptoError::InvalidKdfParams { field, .. }) if field == "p_cost")
        );
    }

    #[test]
    fn reject_wrong_output_length() {
        let params = KdfParams {
            m_cost: BASELINE_M_COST_KIB,
            t_cost: 1,
            p_cost: 1,
            output_len: 16,
        };
        assert!(
            matches!(params.validate(), Err(CryptoError::InvalidKdfParams { field, .. }) if field == "output_len")
        );
    }

    #[test]
    fn accept_baseline_params() {
        let params = test_params();
        assert!(params.validate().is_ok());
    }

    #[test]
    fn reject_password_too_long() {
        let params = test_params();
        let salt = [0x30u8; SALT_LEN];
        let long_password = "x".repeat(MAX_PASSWORD_LEN + 1);
        let result = derive_master_key(&long_password, &salt, &params);
        assert!(matches!(result, Err(CryptoError::PasswordTooLong)));
    }

    #[test]
    fn reject_wrong_salt_length() {
        let params = test_params();
        let result = derive_master_key("password", &[0u8; 8], &params);
        assert!(matches!(result, Err(CryptoError::InvalidSaltLength(8))));
    }

    #[test]
    fn random_salt_is_unique() {
        let s1 = generate_salt().unwrap();
        let s2 = generate_salt().unwrap();
        assert_ne!(s1, s2);
        assert_eq!(s1.len(), SALT_LEN);
    }
}
