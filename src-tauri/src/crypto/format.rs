//! Versioned vault format: metadata (`vault.meta.json`) and encrypted payload
//! (`vault.data`).
//!
//! # Threat model and format layout
//!
//! The vault is stored as **two files** in the vault directory:
//!
//! ```text
//! vault.meta.json   non-secret, versioned metadata + KDF parameters + salt
//! vault.data        versioned, authenticated envelope holding the ciphertext
//! ```
//!
//! The *entire* vault payload (all records) is encrypted as one AEAD message.
//! There is deliberately **no** per-record encryption scheme: mixing the two
//! would make the key hierarchy ambiguous and would break the "one
//! authenticated blob" property that this format relies on for tamper
//! detection. Per-record encryption may be added later as a new format
//! version, never as a silent change to version 1.
//!
//! ## Envelope (`vault.data`)
//!
//! ```text
//! magic      : b"COVAVLT"      (8 bytes)
//! version    : u8               (format version, currently 1)
//! alg id     : u8               (cipher suite id, currently 1 = AES-256-GCM)
//! reserved   : [u8; 2]          (must be zero)
//! nonce      : [u8; 12]         (96-bit GCM nonce, unique per message)
//! ciphertext : [u8; ..]         (ciphertext || 16-byte GCM tag)
//! ```
//!
//! The header (everything up to and including the nonce) is *also* fed to
//! AES-GCM as additional authenticated data, so the magic bytes, the format
//! version, the algorithm id and the nonce cannot be modified without
//! invalidating the authentication tag.
//!
//! ## Authenticated data
//!
//! The AAD is the full envelope header prefixed with a domain-separation
//! label, and additionally binds the *metadata* that describes the vault
//! (format version, cipher id and KDF parameters). Changing the stored KDF
//! parameters therefore invalidates the tag as well, which prevents
//! "downgrade" style tampering where an attacker rewrites `vault.meta.json`
//! to weaker parameters and re-derives a different key.

use serde::{Deserialize, Serialize};

use crate::crypto::CryptoError;
use crate::crypto::kdf::KdfParams;

/// Magic bytes at the start of `vault.data`.
///
/// The ASCII tag `COVAVLT` padded to eight bytes with a NUL. The padding
/// keeps the header a fixed size while leaving room for a longer tag in a
/// future format version.
pub const ENVELOPE_MAGIC: [u8; 8] = *b"COVAVLT\0";

/// Current envelope format version.
pub const ENVELOPE_VERSION: u8 = 1;

/// Identifier for the cipher suite used by this format version.
pub const CIPHER_SUITE_AES_256_GCM: u8 = 1;

/// Length of the AES-GCM nonce in bytes.
pub const NONCE_LEN: usize = 12;

/// Length of the AES-GCM authentication tag in bytes.
pub const TAG_LEN: usize = 16;

/// Size of the fixed envelope header (magic + version + alg + reserved + nonce).
pub const HEADER_LEN: usize = ENVELOPE_MAGIC.len() + 1 + 1 + 2 + NONCE_LEN;

/// Domain separation label mixed into the AEAD associated data.
///
/// Binds the ciphertext to this application and to this purpose so that a
/// ciphertext produced elsewhere (or for another purpose) cannot be replayed
/// into the vault.
pub const AAD_LABEL: &[u8] = b"cova-vault/v1/envelope";

/// Version of the `vault.meta.json` document format.
pub const META_FORMAT_VERSION: u32 = 1;

/// Identifier for the password-based key derivation function.
pub const KDF_ARGON2ID: &str = "argon2id";

/// Identifier for the HKDF subkey derivation function.
pub const KDF_HKDF_SHA256: &str = "hkdf-sha256";

/// Non-secret, versioned metadata describing how the vault payload is
/// encrypted.
///
/// This document is written to `vault.meta.json`. It contains no secret
/// material: the salt is public, the KDF parameters are public, and the
/// password verification value is an HMAC over a key derived from the
/// password, not the password itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMeta {
    /// Version of this metadata document format.
    pub format_version: u32,

    /// Human-readable identifier of the vault format family.
    pub format: String,

    /// Identifier of the KDF used to turn the password into a master key.
    pub kdf: String,

    /// Parameters of the password-based key derivation function.
    pub kdf_params: KdfParams,

    /// Random salt (hex encoded) used by the password-based KDF.
    ///
    /// This is public by construction: it is stored in cleartext and only
    /// serves to make derived keys unique per vault.
    pub salt: String,

    /// Identifier of the KDF used to derive the password verification key.
    pub verifier_kdf: String,

    /// Hex encoded HMAC-SHA256 tag over the domain-separated verifier input.
    ///
    /// See [`crate::crypto::kdf::compute_password_verifier`] for the exact
    /// construction.
    pub password_verifier: String,
}

impl VaultMeta {
    /// Build metadata for a newly created vault.
    ///
    /// `salt` must be a freshly generated random salt and `verifier` the value
    /// returned by [`crate::crypto::kdf::compute_password_verifier`] for the
    /// same password and salt.
    pub fn new(kdf_params: KdfParams, salt: &[u8], verifier: &[u8; 32]) -> Self {
        Self {
            format_version: META_FORMAT_VERSION,
            format: "cova-vault".to_owned(),
            kdf: KDF_ARGON2ID.to_owned(),
            kdf_params,
            salt: hex_encode(salt),
            verifier_kdf: KDF_HKDF_SHA256.to_owned(),
            password_verifier: hex_encode(verifier),
        }
    }

    /// Decode the hex-encoded salt.
    pub fn salt_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        hex_decode(&self.salt).ok_or(CryptoError::InvalidMetadata)
    }

    /// Decode the hex-encoded password verifier.
    pub fn password_verifier_bytes(&self) -> Result<[u8; 32], CryptoError> {
        let raw = hex_decode(&self.password_verifier).ok_or(CryptoError::InvalidMetadata)?;
        raw.try_into().map_err(|_| CryptoError::InvalidMetadata)
    }

    /// Validate every field of this metadata document.
    ///
    /// This must be called **before** any expensive key derivation so that a
    /// malformed or hostile file cannot force the application to burn CPU time
    /// or allocate large amounts of memory.
    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.format_version != META_FORMAT_VERSION {
            return Err(CryptoError::UnsupportedFormatVersion {
                expected: META_FORMAT_VERSION,
                found: self.format_version,
            });
        }
        if self.kdf != KDF_ARGON2ID {
            return Err(CryptoError::UnsupportedKdf(self.kdf.clone()));
        }
        if self.verifier_kdf != KDF_HKDF_SHA256 {
            return Err(CryptoError::UnsupportedKdf(self.verifier_kdf.clone()));
        }
        self.kdf_params.validate()?;
        // Salt must decode and must be a sane length.
        let salt = self.salt_bytes()?;
        if salt.is_empty() || salt.len() > 64 {
            return Err(CryptoError::InvalidMetadata);
        }
        // Verifier must decode to exactly 32 bytes.
        self.password_verifier_bytes()?;
        Ok(())
    }
}

/// A parsed, versioned `vault.data` envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Envelope format version.
    pub version: u8,
    /// Cipher suite identifier.
    pub cipher_suite: u8,
    /// 96-bit AEAD nonce.
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext with the authentication tag appended.
    pub ciphertext: Vec<u8>,
}

impl Envelope {
    /// Parse a `vault.data` byte stream into an [`Envelope`].
    ///
    /// Structural problems (bad magic, truncated buffer, unsupported version
    /// or cipher suite) are reported as errors; the authentication tag is
    /// **not** checked here because that requires the key.
    pub fn parse(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < HEADER_LEN + TAG_LEN {
            return Err(CryptoError::MalformedEnvelope);
        }
        if bytes[..ENVELOPE_MAGIC.len()] != ENVELOPE_MAGIC {
            return Err(CryptoError::MalformedEnvelope);
        }
        let version = bytes[8];
        if version != ENVELOPE_VERSION {
            return Err(CryptoError::UnsupportedFormatVersion {
                expected: u32::from(ENVELOPE_VERSION),
                found: u32::from(version),
            });
        }
        let cipher_suite = bytes[9];
        if cipher_suite != CIPHER_SUITE_AES_256_GCM {
            return Err(CryptoError::UnsupportedCipherSuite(cipher_suite));
        }
        if bytes[10] != 0 || bytes[11] != 0 {
            return Err(CryptoError::MalformedEnvelope);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[12..HEADER_LEN]);

        Ok(Self {
            version,
            cipher_suite,
            nonce,
            ciphertext: bytes[HEADER_LEN..].to_vec(),
        })
    }

    /// Serialise this envelope back into its on-disk byte representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.ciphertext.len());
        out.extend_from_slice(&ENVELOPE_MAGIC);
        out.push(self.version);
        out.push(self.cipher_suite);
        out.push(0);
        out.push(0);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// The envelope header that is authenticated as additional data.
    pub fn header_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN);
        out.extend_from_slice(&ENVELOPE_MAGIC);
        out.push(self.version);
        out.push(self.cipher_suite);
        out.push(0);
        out.push(0);
        out.extend_from_slice(&self.nonce);
        out
    }
}

/// Lowercase hexadecimal encoding.
pub fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// Decode a lowercase or uppercase hexadecimal string.
pub fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() / 2);
    for [hi, lo] in bytes.as_chunks::<2>().0 {
        let hi = (*hi as char).to_digit(16)?;
        let lo = (*lo as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(version: u8, cipher: u8) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ENVELOPE_MAGIC);
        bytes.push(version);
        bytes.push(cipher);
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(&[0u8; NONCE_LEN]);
        bytes.extend_from_slice(&[0u8; TAG_LEN]);
        bytes
    }

    #[test]
    fn hex_round_trip() {
        let data = [0x00u8, 0x0f, 0xff, 0xa5];
        let encoded = hex_encode(&data);
        assert_eq!(encoded, "000fffa5");
        assert_eq!(hex_decode(&encoded).unwrap(), data);
    }

    #[test]
    fn hex_decode_rejects_invalid() {
        assert!(hex_decode("abc").is_none());
        assert!(hex_decode("zz").is_none());
        assert!(hex_decode("").is_some());
    }

    #[test]
    fn envelope_round_trip() {
        let envelope = Envelope {
            version: ENVELOPE_VERSION,
            cipher_suite: CIPHER_SUITE_AES_256_GCM,
            nonce: [7u8; NONCE_LEN],
            ciphertext: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        };
        let bytes = envelope.to_bytes();
        assert_eq!(bytes.len(), HEADER_LEN + TAG_LEN);
        assert_eq!(Envelope::parse(&bytes).unwrap(), envelope);
    }

    #[test]
    fn envelope_rejects_bad_magic() {
        let mut bytes = header(ENVELOPE_VERSION, CIPHER_SUITE_AES_256_GCM);
        bytes[0] = b'X';
        assert!(matches!(
            Envelope::parse(&bytes),
            Err(CryptoError::MalformedEnvelope)
        ));
    }

    #[test]
    fn envelope_rejects_truncated() {
        assert!(matches!(
            Envelope::parse(&[0u8; 4]),
            Err(CryptoError::MalformedEnvelope)
        ));
        assert!(matches!(
            Envelope::parse(&[0u8; HEADER_LEN + TAG_LEN - 1]),
            Err(CryptoError::MalformedEnvelope)
        ));
    }

    #[test]
    fn envelope_rejects_unknown_version() {
        let bytes = header(99, CIPHER_SUITE_AES_256_GCM);
        assert!(matches!(
            Envelope::parse(&bytes),
            Err(CryptoError::UnsupportedFormatVersion { .. })
        ));
    }

    #[test]
    fn envelope_rejects_unknown_cipher_suite() {
        let bytes = header(ENVELOPE_VERSION, 42);
        assert!(matches!(
            Envelope::parse(&bytes),
            Err(CryptoError::UnsupportedCipherSuite(42))
        ));
    }

    #[test]
    fn envelope_rejects_nonzero_reserved() {
        let mut bytes = header(ENVELOPE_VERSION, CIPHER_SUITE_AES_256_GCM);
        bytes[10] = 9;
        assert!(matches!(
            Envelope::parse(&bytes),
            Err(CryptoError::MalformedEnvelope)
        ));
    }

    #[test]
    fn envelope_header_is_authenticated_prefix() {
        let envelope = Envelope {
            version: ENVELOPE_VERSION,
            cipher_suite: CIPHER_SUITE_AES_256_GCM,
            nonce: [3u8; NONCE_LEN],
            ciphertext: vec![9, 9],
        };
        let bytes = envelope.to_bytes();
        assert_eq!(&bytes[..HEADER_LEN], &envelope.header_bytes()[..]);
    }
}
