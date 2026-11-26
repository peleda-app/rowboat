# skein-accounts

Account records, sealed credentials, and the account directory the engine runs from.

| Item | Guarantees |
| --- | --- |
| `AccountRecord` | provider kind (`imap`, `jmap`, `gmail`, `graph`), provider settings, `Auth` (`password` or `oauth { client }`), include/exclude mailboxes, `paused`, optional `send` (`SendSettings { kind: smtp | gmail | graph | jmap | ses, settings }`); stored at control path `accounts/{account}` in a versioned envelope (version 2; version 1 records read as having no `send`); never holds a secret |
| `AccountRecord::sender()` | `send` when set, else the provider's own API for Gmail, Graph and JMAP with the account's settings; `None` for IMAP without `send`. `null` settings are the account's settings; SMTP settings without a `username` key take the account's |
| `Accounts::{put, get, list, delete}` | per tenant; `delete` also removes the sealed passwords and send key (the account's key stays, so the id can be used again) |
| secrets sealed before account scopes | passwords and send keys sealed under the tenant scope by an earlier version are read through `skein_keyring::open_account` and sealed again under the account's scope with a compare-and-swap on first read; a failed re-seal is logged and retried on the next read |
| `Accounts::set_password` | sealed by the keyring under the account's scope (`KeyScope::Account`) at `credentials/{account}/password`, bound to that path |
| `Accounts::set_send_key` | an access key id, secret and optional session token, sealed at `credentials/{account}/send-key`; the sender of an account whose `send.kind` is `ses` signs with it (`Credentials::AccessKey`) instead of the account's own credentials; replaced by the next call, never returned |
| `PimSettings`, `PimFactory`, `Directory::with_pim` | an account's calendars and contacts: `kind` `dav`, `google`, `graph` or `jmap` with that provider's settings, and `auth` `password` for a separate sealed password (`set_pim_password`), otherwise the account's own credentials; the directory builds a lazily signed-in provider for accounts that have them, using the account's own credentials |
| `OAuthClients` | the operator's named OAuth clients |
| `ProviderFactory` | builds a provider from a record and resolved credentials; implemented by the composition root, the only place that knows provider crates |
| `SenderFactory` | builds a sender from a record, its sender kind and settings, and resolved credentials; implemented by the composition root |
| `build_in(tenant, …)` on all three factories | the same as `build` for an account of `tenant`; `Directory` and `Senders` always call it, so a factory can share per-account state (the binary's Graph throttle) between an account's providers and sender. The default ignores `tenant` and calls `build` |
| `Senders` | the engine's `SenderDirectory`: reads the record and resolves credentials each time the engine is about to send, which only happens on the owner; `Ok(None)` for a missing account or one without a sender; a missing password or revoked grant is `SendError::Auth`, as is a missing send key for kind `ses`; a transient failure `Unavailable` |
| `TenantRegistry` | the tenants that exist, as empty objects under `system/tenants/`; adding is idempotent, removing leaves the tenant's data alone |
| `Directory` | the engine's `AccountDirectory` for every registered tenant; skips paused accounts; credentials are resolved when a provider connects or watches, which only happens on the account's owner, so OAuth refreshes happen in one place and listing never refreshes |

Errors when connecting: a missing password, a revoked or missing OAuth grant → `MailError::Auth` (the engine records `reauth_required`); an unknown OAuth client → `MailError::Config`; a transient token endpoint failure → `MailError::Network`.

The lazy mail provider passes push subscriptions (`subscribe`, `renew`, `unsubscribe`) through to the real provider, so push works for directory accounts.
