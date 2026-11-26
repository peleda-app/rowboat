# skein-storage-sealed

An implementation of `skein-storage`'s `Objects` that seals every value before handing it to another object store (files, memory, S3), so a store that is copied, backed up or read by someone else holds only ciphertext.

```rust
let files: Arc<dyn Objects> = Arc::new(FsObjects::open(dir)?);
let objects: Arc<dyn Objects> = Arc::new(SealedObjects::new(files, key)); // key: Zeroizing<[u8; 32]>
let storage = Storage::over(objects);
```

## Format and guarantees

- A sealed value is `version (1) || nonce (24) || XChaCha20-Poly1305 ciphertext and tag`. The nonce is random per write; the associated data is a fixed context, the format version and the full object key.
- A value moved or copied to another key, cut, extended, bit-flipped, with its version byte changed, or sealed under another key does not open: `get` fails with `StorageError::Corrupt`, whose text names the key and never the value. Nothing that was not sealed for that key under that key is ever returned.
- Keys are not sealed: they hold tenant, account and mailbox ids, record paths and blob hashes, never content. `list` and `delete` pass through.
- Versions and compare-and-swap pass through: a version is the inner store's version of the sealed bytes, so every write gives a new version even for equal values.
- The key is the caller's: it is held zeroized on drop, never written anywhere by this crate. Losing it loses every value; the caller must refuse to create a new key over existing data.
- Replays of an older sealed value at the same key (rollback by whoever controls the inner store) are not detected here; the journal's hash chain and attested heads cover the journal, and control records are not authenticated against rollback.

## Tests

`cargo test -p skein-storage-sealed`: the whole `all_over_objects` conformance suite over memory storage, the attack tests above (moved, truncated, extended, bit-flipped, foreign-key and downgraded values), a check that the inner store never holds a plaintext canary, and a property test that any value round-trips and any garbage is refused.
