//! AES-256-GCM authenticated encryption for the vault payload.
//!
//! This module provides [seal] and [open], which encrypt and decrypt the
//! complete vault payload as a single AEAD message. The envelope header
//! (magic, version, algorithm, reserved bytes, nonce) and the canonical
//! metadata bytes are bound into the additional authenticated data (AAD), so
//! that neither can be modified without invalidating the authentication tag.
//!
//! No key material is ever returned to the caller: the encryption key is
//! accepted as a [Zeroizing] reference and the decrypted plaintext is
//! returned as an owned Vec<u8> for the caller to handle.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use getrandom::fill as getrandom_fill;
use zeroize::Zeroizing;

use crate::crypto::CryptoError;
use crate::crypto::format::Envelope;
use crate::crypto::format::{
    AAD_LABEL, CIPHER_SUITE_AES_256_GCM, ENVELOPE_MAGIC, ENVELOPE_VERSION, HEADER_LEN, NONCE_LEN,
};
use crate::crypto::kdf::KEY_LEN;

/// Build the fixed-size envelope header from a nonce.
fn build_header(nonce: &[u8; NONCE_LEN]) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[..ENVELOPE_MAGIC.len()].copy_from_slice(&ENVELOPE_MAGIC);
    header[8] = ENVELOPE_VERSION;
    header[9] = CIPHER_SUITE_AES_256_GCM;
    header[10] = 0;
    header[11] = 0;
    header[12..HEADER_LEN].copy_from_slice(nonce);
    header
}

/// Build the additional authenticated data (AAD) for an envelope.
fn build_aad(header: &[u8], metadata: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_LABEL.len() + HEADER_LEN + metadata.len());
    aad.extend_from_slice(AAD_LABEL);
    aad.extend_from_slice(header);
    aad.extend_from_slice(metadata);
    aad
}

/// Encrypt a vault payload and return an [Envelope].
pub fn seal(
    encryption_key: &Zeroizing<[u8; KEY_LEN]>,
    metadata: &[u8],
    plaintext: &[u8],
) -> Result<Envelope, CryptoError> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom_fill(&mut nonce).map_err(|_| CryptoError::Randomness)?;
    let header = build_header(&nonce);
    let aad = build_aad(&header, metadata);
    let cipher =
        Aes256Gcm::new_from_slice(&**encryption_key).map_err(|_| CryptoError::EncryptionFailed)?;
    let nonce_obj: Nonce<_> = Nonce::try_from(&nonce[..]).map_err(|_| CryptoError::Randomness)?;
    let ciphertext_with_tag = cipher
        .encrypt(
            &nonce_obj,
            Payload {
                aad: &aad,
                msg: plaintext,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;
    Ok(Envelope {
        version: ENVELOPE_VERSION,
        cipher_suite: CIPHER_SUITE_AES_256_GCM,
        nonce,
        ciphertext: ciphertext_with_tag,
    })
}

/// Decrypt a vault payload from an [Envelope].
pub fn open(
    encryption_key: &Zeroizing<[u8; KEY_LEN]>,
    envelope: &Envelope,
    metadata: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if envelope.version != ENVELOPE_VERSION || envelope.cipher_suite != CIPHER_SUITE_AES_256_GCM {
        return Err(CryptoError::MalformedEnvelope);
    }
    let header = build_header(&envelope.nonce);
    let aad = build_aad(&header, metadata);
    let cipher =
        Aes256Gcm::new_from_slice(&**encryption_key).map_err(|_| CryptoError::EncryptionFailed)?;
    let nonce_obj: Nonce<_> =
        Nonce::try_from(&envelope.nonce[..]).map_err(|_| CryptoError::Randomness)?;
    let plaintext = cipher
        .decrypt(
            &nonce_obj,
            Payload {
                aad: &aad,
                msg: &envelope.ciphertext,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    Ok(plaintext)
}

/// Low-level: encrypt plaintext with a caller-supplied nonce and AAD.
pub fn encrypt(
    encryption_key: &Zeroizing<[u8; KEY_LEN]>,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        Aes256Gcm::new_from_slice(&**encryption_key).map_err(|_| CryptoError::EncryptionFailed)?;
    let nonce_obj: Nonce<_> = Nonce::try_from(&nonce[..]).map_err(|_| CryptoError::Randomness)?;
    cipher
        .encrypt(
            &nonce_obj,
            Payload {
                aad,
                msg: plaintext,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)
}

/// Low-level: decrypt ciphertext_with_tag with a caller-supplied nonce and AAD.
pub fn decrypt(
    encryption_key: &Zeroizing<[u8; KEY_LEN]>,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        Aes256Gcm::new_from_slice(&**encryption_key).map_err(|_| CryptoError::EncryptionFailed)?;
    let nonce_obj: Nonce<_> = Nonce::try_from(&nonce[..]).map_err(|_| CryptoError::Randomness)?;
    cipher
        .decrypt(
            &nonce_obj,
            Payload {
                aad,
                msg: ciphertext_with_tag,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::{
        BASELINE_M_COST_KIB, BASELINE_P_COST, BASELINE_T_COST, KdfParams, derive_keys,
    };

    fn test_params() -> KdfParams {
        KdfParams {
            m_cost: BASELINE_M_COST_KIB,
            t_cost: BASELINE_T_COST,
            p_cost: BASELINE_P_COST,
            output_len: KEY_LEN as u32,
        }
    }

    fn test_key(password: &str, salt: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
        let params = test_params();
        let keys =
            derive_keys(password, salt, &params).expect("key derivation must succeed in tests");
        keys.encryption.clone()
    }

    fn test_metadata() -> Vec<u8> {
        serde_json::to_vec(&super::super::format::VaultMeta::new(
            test_params(),
            &[0x42u8; 16],
            &[0x00u8; 32],
        ))
        .expect("metadata serialisation must succeed in tests")
    }

    #[test]
    fn seal_open_round_trip() {
        let key = test_key("correct horse battery staple", &[1u8; 16]);
        let metadata = test_metadata();
        let plaintext = b"this is the vault payload";
        let envelope = seal(&key, &metadata, plaintext).expect("seal must succeed");
        let decrypted = open(&key, &envelope, &metadata).expect("open must succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_rejected() {
        let key = test_key("correct horse battery staple", &[1u8; 16]);
        let wrong_key = test_key("wrong password", &[1u8; 16]);
        let metadata = test_metadata();
        let plaintext = b"vault payload";
        let envelope = seal(&key, &metadata, plaintext).expect("seal must succeed");
        let result = open(&wrong_key, &envelope, &metadata);
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn modified_ciphertext_rejected() {
        let key = test_key("correct horse battery staple", &[1u8; 16]);
        let metadata = test_metadata();
        let plaintext = b"vault payload";
        let mut envelope = seal(&key, &metadata, plaintext).expect("seal must succeed");
        let last = envelope.ciphertext.len() - 1;
        envelope.ciphertext[last] ^= 0xff;
        let result = open(&key, &envelope, &metadata);
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn modified_nonce_rejected() {
        let key = test_key("correct horse battery staple", &[1u8; 16]);
        let metadata = test_metadata();
        let plaintext = b"vault payload";
        let mut envelope = seal(&key, &metadata, plaintext).expect("seal must succeed");
        envelope.nonce[0] ^= 0xff;
        let result = open(&key, &envelope, &metadata);
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn modified_metadata_rejected() {
        let key = test_key("correct horse battery staple", &[1u8; 16]);
        let plaintext = b"vault payload";
        let mut metadata = test_metadata();
        let envelope = seal(&key, &metadata, plaintext).expect("seal must succeed");
        metadata[0] ^= 0xff;
        let result = open(&key, &envelope, &metadata);
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn different_nonces_per_call() {
        let key = test_key("correct horse battery staple", &[1u8; 16]);
        let metadata = test_metadata();
        let plaintext = b"vault payload";
        let env1 = seal(&key, &metadata, plaintext).expect("seal must succeed");
        let env2 = seal(&key, &metadata, plaintext).expect("seal must succeed");
        assert_ne!(env1.nonce, env2.nonce);
    }

    #[test]
    fn low_level_encrypt_decrypt_round_trip() {
        let key = test_key("correct horse battery staple", &[1u8; 16]);
        let mut nonce = [0u8; NONCE_LEN];
        getrandom_fill(&mut nonce).unwrap();
        let aad = b"cova-vault/test-aad";
        let plaintext = b"low-level test payload";
        let ciphertext = encrypt(&key, &nonce, aad, plaintext).expect("encrypt must succeed");
        let decrypted = decrypt(&key, &nonce, aad, &ciphertext).expect("decrypt must succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn low_level_wrong_aad_rejected() {
        let key = test_key("correct horse battery staple", &[1u8; 16]);
        let mut nonce = [0u8; NONCE_LEN];
        getrandom_fill(&mut nonce).unwrap();
        let plaintext = b"low-level test payload";
        let ciphertext =
            encrypt(&key, &nonce, b"aad-one", plaintext).expect("encrypt must succeed");
        let result = decrypt(&key, &nonce, b"aad-two", &ciphertext);
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn empty_plaintext_supported() {
        let key = test_key("correct horse battery staple", &[1u8; 16]);
        let metadata = test_metadata();
        let envelope = seal(&key, &metadata, b"").expect("seal must succeed");
        let decrypted = open(&key, &envelope, &metadata).expect("open must succeed");
        assert_eq!(decrypted, b"");
    }
}
