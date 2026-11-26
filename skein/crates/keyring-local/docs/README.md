# skein-keyring-local

`LocalKeyring`: a random 256-bit data key per tenant, wrapped with XChaCha20-Poly1305 by a master key from a local file and stored as the tenant's control record `keys/data`, and a random 256-bit data key per account, wrapped by a key derived from its tenant's data key (BLAKE3 `derive_key`, context `skein keyring-local account key wrap v1`) and stored as `keys/accounts/{account}`.

Sealed bytes are `version || nonce (24) || ciphertext and tag`:

| Scope | Version | Associated data |
| --- | --- | --- |
| tenant | `1` | `tenant \0 context` |
| account | `2` | `tenant \0 account \0 context` |

The wrapped key records bind their own place as associated data (`tenant \0 skein data key v1`, `tenant \0 account \0 skein account key v1`), so a record copied to another tenant or account does not unwrap.

- `open_or_create(path, control)` creates the master key file with mode `0600` when missing. Losing it makes every tenant's sealed data unreadable; back it up separately from the data.
- `with_cache_ttl(ttl)` (default one minute): how long tenant and account keys are kept in memory, and so how long a key destroyed on another node, directly or through its tenant, keeps working here. An account key is never kept longer than the cached tenant key it was unwrapped with, so this bound holds for account keys too.
- `destroy` writes a tombstone instead of deleting, so a destroyed scope cannot get a fresh key by accident. Destroying a tenant also shreds every account key of it, copies in backups included, because account keys cannot be unwrapped without the tenant's key.
- An account key is created on first use of the account scope; creating it reads the tenant key first, so a destroyed tenant gives `Destroyed` for every account.

Bytes sealed before account scopes (version 1 under the tenant key) still open under the tenant scope; `skein_keyring::open_account` reads them for account secrets, and `skein-accounts` and `skein-oauth` seal them again under the account key on first read.

Limits: no key rotation yet; KMS and Vault backends are planned as separate crates.
