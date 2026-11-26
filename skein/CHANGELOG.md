# Changelog

All notable changes to Skein are recorded here. Every crate and the `rowboat` image share one version.

## [Unreleased]

### Removed

- The web portal (`apps/portal`), the `portal` feature of the `skein` binary with its `rust-embed` assets, the portal stage of the Docker image and the `rowboat:*-headless` image variant.
- The HTTP management API of `skein-server`: tenants, API keys, accounts and credentials, OAuth sign-in and its callback, journal, snapshot, heads and blob reads, the Server-Sent Events hint stream, blob uploads, commands and webhook management, with its key auth, scopes, IP allowlists, trusted proxies, CORS and account host policy.
- `openapi.json`, its generation with `utoipa` and the `openapi` features of `skein-core`, `skein-storage` and `skein-accounts`.
- The TypeScript client `@peleda-app/skein-client` (`packages/client`).
- The `skein-view` binary, its HTTP API, its HTTP follower and its Docker image `rowboat-view`.
- `skein admin-key` and the config keys `server.admin_key_hashes`, `trusted_proxies`, `cors`, `account_hosts` and `[portal]`.
- The API reference pages of the documentation site (`starlight-openapi`).

### Changed

- `skein-server` is the node's only inbound HTTP: `GET /v1/health` and the Gmail Pub/Sub and Microsoft Graph push receivers, with a new shared rate limit (`push_rate_per_second`, 429 with `Retry-After`). `router(signal, push, &config)` replaces `router` and `router_with_push`; `hash_token` replaces `hash_key`.
- `skein-view` is a library (`skein/crates/view`): a `Follower` reads a tenant's journals straight from the storage contracts, verifying every segment through the hash chain and refusing rolled-back heads and swapped history, into the same SQLite database with its query API.
- The `skein` binary is managed through subcommands that write through the same stores: `tenant`, `account`, `journal` (blobs, commands, events) and `webhook`; `push-token` makes the Gmail push secret. `[server.webhooks]` moved to `[webhooks]`; OAuth clients no longer need `redirect_url`.
- Command checks moved to `skein_engine::{check_command, submit_command, cancel_command}`; account record and secret checks and tenant purging to `skein_accounts::admin`.
