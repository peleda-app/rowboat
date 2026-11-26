# baton-seal

Sealing bytes at rest: a versioned XChaCha20-Poly1305 envelope with 256-bit keys, HKDF-SHA256 subkeys per purpose and associated data that binds every envelope to its purpose and object id. A pure library: no I/O beyond the operating system's random source, no global state. Used by `vault-file`, `snapshot-file` and later the journal and database sealing.

## Format

Envelope v1: `0x01 || nonce (24 random bytes) || ciphertext || tag (16)`, so it adds `OVERHEAD` = 41 bytes.

- Encryption key: `HKDF-SHA256(ikm = key, salt = none, info = "baton-seal/v1 subkey " || purpose)`.
- Associated data: `"baton-seal/v1" || u32be(len(purpose)) || purpose || u32be(len(object)) || object`.

## API

| Item | Guarantees |
| --- | --- |
| `Key::generate()`, `from_bytes`, `from_slice` | 32 bytes; overwritten with zeros on drop; `Debug` prints `Key(<redacted>)`; no `PartialEq` |
| `Key::expose()` | the raw bytes, only for storing the key in a vault |
| `Key::derive(purpose)` | deterministic, independent subkeys per purpose |
| `Context::new(purpose, object)` | what an envelope is bound to; length-prefixed so `("ab", "c")` and `("a", "bc")` differ |
| `seal(key, context, plaintext)` | fresh random nonce per call; output is `plaintext.len() + OVERHEAD` bytes |
| `open(key, context, sealed)` | plaintext (wiped on drop) only for the same key and context and unchanged bytes; otherwise `Invalid`, `Truncated` or `UnsupportedVersion(v)` |
| `Envelope::decode` / `encode` | checks version first, then the minimum length; does not authenticate |

XChaCha20's 192-bit nonce makes random nonces safe for any realistic number of messages per key.

Tests: every bit of an envelope flipped, every truncation, unknown versions, wrong key, purpose or object, and property tests over random plaintexts and random inputs.

## Dependencies

`chacha20poly1305` 0.11, `hkdf` 0.13, `sha2` 0.11 (RustCrypto, MIT OR Apache-2.0), `getrandom` 0.4 (MIT OR Apache-2.0), `zeroize`.
