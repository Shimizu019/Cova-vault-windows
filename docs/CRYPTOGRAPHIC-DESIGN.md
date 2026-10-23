# Cova Vault Cryptographic Design

## Scope

This document describes the cryptographic core of Cova Vault for Windows
(Milestone 2). It covers key derivation, authenticated encryption, and the
on-disk format. It deliberately excludes UI, IPC, persistence, and installer
concerns, which are handled by other milestones.

No unverified security claims are made. Parameter choices are documented with
their rationale and a benchmark reference.

---

## Threat Model

- Attacker controls `vault.meta.json` and `vault.data`. Both files may be
  read, modified, or replaced by an attacker with file-system access.
- Attacker does not know the user's password. The password never leaves
  the Rust backend; the WebView/frontend never sees it.
- Goal of the attacker: decrypt vault contents, forge valid vaults, or
  downgrade security parameters without detection.

---

## File Layout

A vault directory contains two files:

| File | Purpose | Secret? |
|------|---------|---------|
| `vault.meta.json` | Versioned metadata, KDF params, salt, password verifier | No |
| `vault.data` | AEAD-encrypted vault payload | Yes (ciphertext) |

---

## Key Hierarchy

```
password ──Argon2id(salt, m, t, p)──> master key (32 bytes)
                                            │
                                            ├─HKDF-SHA256(info=".../enc")──> encryption key (32 bytes)
                                            ├─HKDF-SHA256(info=".../ver")──> verifier key  (32 bytes)
                                            └─HKDF-SHA256(info=".../mac")──> backup MAC key (32 bytes)
```

1. Master key is derived from the password, salt, and public KDF
   parameters using Argon2id.
2. Subkeys are derived from the master key via HKDF-SHA256 with distinct
   `info` labels, ensuring purpose separation: an encryption key can never be
   replayed as a verifier key, and vice versa.
3. The master key is zeroized immediately after subkey expansion.

---

## Password Verification

Password verification does not use a fast hash. Instead:

1. The password is stretched with the same Argon2id parameters and salt
   used for decryption, producing the master key.
2. A verifier key is derived from the master key via HKDF-SHA256
   (`info="cova-vault/v1/hkdf/verifier-key"`).
3. The stored verifier is `HMAC-SHA256(verifier_key, "cova-vault/v1/password-verifier")`.

Verification recomputes the verifier and compares in constant time
(`subtle::ConstantTimeEq`). Because step 1 is the expensive part, the verifier
cannot be brute-forced faster than the vault itself can be unlocked. The
verifier is an HMAC tag over a fixed constant, so it leaks no password
information beyond what an offline dictionary attack against Argon2id already
reveals.

---

## Authenticated Encryption

The entire vault payload is encrypted as a single AES-256-GCM message.
### Envelope (`vault.data`)

```
magic      : b"COVAVLT\0"   (8 bytes)
version    : u8              (1)
alg id     : u8              (1 = AES-256-GCM)
reserved   : [u8; 2]         (must be zero)
nonce      : [u8; 12]        (96-bit GCM nonce, random per message)
ciphertext : [u8; ..]        (ciphertext || 16-byte GCM tag)
```

### Additional Authenticated Data (AAD)

The AAD binds the envelope header and the metadata:

```
AAD = domain_label || header_bytes || metadata_bytes
```

where `domain_label = "cova-vault/v1/envelope"`.

Binding the metadata into the AAD prevents an attacker from rewriting
`vault.meta.json` (e.g. to weaker KDF parameters) while leaving the ciphertext
intact � any change to the metadata invalidates the GCM tag.

A fresh 96-bit nonce is generated via `getrandom` (OS-backed RNG) for every
encryption. Nonces are never reused with the same key.

---

## Format Versioning

- `vault.meta.json` format version: 1
- Envelope format version: 1
- Cipher suite ID: 1 (AES-256-GCM)
- KDF ID: argon2id
- Verifier KDF ID: hkdf-sha256

Unsupported versions or cipher suites are rejected outright. There are no
silent fallbacks or upgrade paths. Per-record encryption or other structural
changes may be introduced as a new format version, never as a modification to
version 1.

---

## KDF Parameters (Baseline)

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Algorithm | Argon2id | OWASP-recommended; resistant to GPU/ASIC attacks |
| Memory    | 19 MiB | Documented baseline; see benchmark below |
| Iterations| 2 | Documented baseline |
| Parallelism| 1 | Single-threaded desktop target |
| Salt length| 16 bytes | Sufficient for uniqueness per vault |
| Password max| 1024 bytes | Bounds KDF cost predictability |

Bounds enforced before any KDF work:
- Memory: 8 KiB � 1 GiB
- Time: 1 � 16 passes
- Parallelism: 1 � 16 lanes

---

## Baseline Benchmark

The baseline parameters (19 MiB, 2 iterations, 1 lane) were selected as the
OWASP-recommended minimum for Argon2id. A benchmark should be run on target
hardware to confirm the unlock latency is acceptable (target: under ~1 second
on the minimum supported device). If the benchmark shows the baseline is too
slow or too fast, the parameters may be adjusted as a non-breaking change to
the documented baseline (the format version remains 1; only the stored
`kdf_params` change).

---

## Failure Behavior

All fallible operations return `CryptoError`. There are no panics in the
cryptographic core for expected error conditions.

Authentication failures (wrong key, tampered ciphertext, tampered nonce,
tampered header, tampered metadata) are reported as a single opaque
`CryptoError::AuthenticationFailed` variant. The two cases are deliberately
not distinguishable through error handling alone, preventing oracle-style
attacks.

Error messages contain no secret material (no passwords, no keys).

---

## Key Material Handling

- All keys are held in `zeroize::Zeroizing` wrappers and zeroized on drop.
- No key material is returned to the caller or exposed to the WebView.
- Decrypted plaintext is returned as an owned `Vec<u8>`; the caller is
  responsible for zeroizing it after use.
- The master key is zeroized immediately after subkey derivation.

---

## No-Backdoor Policy

The cryptographic core contains no backdoors, key escrow, or recovery
mechanisms. If the password is lost, the vault is unrecoverable. This is
intentional: any recovery mechanism would weaken the security model.

---

## Dependencies

All cryptographic crates are RustCrypto-maintained and dual licensed under
MIT OR Apache-2.0 (except `subtle`, which is BSD-3-Clause):

| Crate | Version | Purpose |
|-------|---------|---------|
| `argon2` | 0.6 | Argon2id password hashing |
| `aes-gcm` | 0.11 | AES-256-GCM authenticated encryption |
| `hkdf` | 0.13 | HKDF-SHA256 subkey derivation |
| `hmac` | 0.13 | HMAC-SHA256 for password verifier |
| `sha2` | 0.11 | SHA-256 (used by hkdf/hmac) |
| `getrandom` | 0.4 | OS-backed random nonce/salt generation |
| `zeroize` | 1.9 | Zeroizing secrets on drop |
| `subtle` | 2.6 | Constant-time comparison |

---

## Files

- `src-tauri/src/crypto/mod.rs` � `CryptoError` enum and module wiring
- `src-tauri/src/crypto/kdf.rs` � Argon2id KDF, HKDF subkeys, verifier
- `src-tauri/src/crypto/cipher.rs` � AES-256-GCM seal/open, AAD binding
- `src-tauri/src/crypto/format.rs` � `vault.meta.json` and `vault.data` format
