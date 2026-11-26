# skein-keyring

The contract for sealing secrets and content with a key per tenant or per account.

A `KeyScope` names whose key seals: `KeyScope::Tenant(tenant)` for secrets of no single account (webhook secrets, sign-ins in progress), `KeyScope::Account(tenant, account)` for one account's credentials, grants and content. An account's key belongs to its tenant: destroying the tenant's key destroys it too.

| Item | Guarantees |
| --- | --- |
| `Keyring::seal(scope, context, plaintext)` | random nonce per call; bound to the scope and the context |
| `Keyring::open(scope, context, sealed)` | plaintext only for the same scope and context; any changed byte, another context, another account of the same tenant, the tenant scope for account bytes and the other way round is `Invalid` without revealing anything |
| `Keyring::destroy(scope)` | from then on `Destroyed` for that scope, for good; a tenant scope takes all its account scopes with it, an account scope affects no other scope; other instances follow within their cache lifetime |
| `open_account(ring, tenant, account, context, sealed)` | opens under the account scope and, only when that is `Invalid`, under the tenant scope with the same context; returns `Opened::Legacy` for bytes sealed before account scopes existed so the caller can seal them again. A destroyed account stays `Destroyed`. Removed in a later release |

Concurrent first use of a scope from several nodes ends with one key.

## Implementing the contract

An implementation keeps one key per scope however it likes (wrapped data keys, a KMS, a vault, keys derived from another key hierarchy), as long as the guarantees above hold. Account keys must become unusable when their tenant's key is destroyed, including on instances that never saw the account before.

Conformance: `testing::keyring(a, b)` (feature `testing`) with two keyrings over the same key store and a cache lifetime of zero. It checks the tenant scope, account scope isolation (an account's bytes never open under another account, the same account id of another tenant or the tenant scope; tenant bytes never open under an account), context binding, every flipped, missing and extra byte, destruction per scope and through the tenant, and the `open_account` fallback.
