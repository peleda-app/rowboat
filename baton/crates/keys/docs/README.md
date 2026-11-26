# baton-keys

Key material for groups. A pure library (no I/O beyond the operating system's random source).

| Item | Guarantees |
| --- | --- |
| `KemSecret`, `KemPublic` | an X-Wing key pair (X25519 + ML-KEM-768, the hybrid post-quantum KEM of `draft-connolly-cfrg-xwing-kem`); the secret is a 32-byte seed, wiped on drop, hidden from `Debug`; public keys are validated on construction and deserialization |
| `seal_box(recipient, aad, plaintext)` / `open_box(secret, aad, box)` | HPKE (RFC 9180) base mode single shot with X-Wing, HKDF-SHA256 and ChaCha20-Poly1305, `info = "baton-box/v1"`; opens only for the matching secret and the same `aad`; fresh encapsulation per box; plaintexts up to 4 KiB |
| `RecoveryRoot` | 32 random bytes kept offline; `keys()` derives an Ed25519 signing key and an X-Wing key with HKDF-SHA256 (salt `baton-recovery/v1`, labels `sign`, `kem`), the same root always deriving the same keys; `public()` gives what the group log records, a `RecoveryPublic` whose signing key signs its KEM key (`verify()`), so nobody can pair someone's recovery signing key with their own KEM key |

HPKE comes from the `hpke` crate (MIT OR Apache-2.0, the same version the app's push payloads use); X-Wing and ML-KEM from RustCrypto through it.

Tests: `cargo test -p baton-keys`: boxes open only for their key and associated data, fresh encapsulation, size limit, deterministic and separated recovery derivation, public key validation, hidden secrets, property tests (any flipped bit in the encapsulation or ciphertext refuses, arbitrary boxes never open).
