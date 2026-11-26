# Documentation

- [Plan](PLAN.md)
- [Requirements](REQUIREMENTS.md): what Skein needs from object storage, and which self-hosted servers meet it
- [Live tests](LIVE.md)
- [Releasing](RELEASING.md): versions, the changelog and the release pipeline
- [Migration](MIGRATION.md): breaking changes per minor release and what integrators must do
- [Fuzzing](../fuzz/README.md): fuzz targets for everything that parses provider or file input

## Coordination

Leases on accounts, node liveness and signals (previews, hints, shared counters) come from Baton, the coordination library Skein uses. Skein's libraries depend only on its contract crates (`baton-core`, `baton-state`, `baton-lease`, `baton-signal`); the binary picks `baton-lease-cas` over `skein_storage::ControlState` (or over in-memory state for one process) and `baton-signal-local`. `skein_core::coordination` maps tenants to Baton groups and accounts to lease keys. Baton is the `baton/` layer of the same repository, reached by path; Docker images build from the repository root (see [Migration](MIGRATION.md)).

## Journal integrity

The journal is a hash chain: every segment names the previous one by BLAKE3 hash and each account's head names the last one, optionally attested by an application's `HeadAttestor`. Segments from any source can be verified from a trusted head, and comparing heads detects rollback and withheld events. See the [storage README](../crates/storage/docs/README.md#tamper-evident-journal).

## Account keys and read tiers

The keyring seals under a `KeyScope`, a tenant or one account with its own key, and destroying a tenant destroys its accounts' keys; account credentials and grants are sealed under the account's key. Storage can read segments and blobs from untrusted read-only tiers after local storage, verifying every byte by hash ([skein-storage-tiered](../crates/storage-tiered/docs/README.md)). Upgrade notes are in [MIGRATION.md](MIGRATION.md).

## Modules

| Module | |
| --- | --- |
| [skein-core](../crates/core/docs/README.md) | ids, hashes, events, commands |
| [skein-storage](../crates/storage/docs/README.md) | storage contracts and conformance |
| [skein-storage-memory](../crates/storage-memory/docs/README.md) | objects in memory |
| [skein-storage-fs](../crates/storage-fs/docs/README.md) | objects as files |
| [skein-storage-s3](../crates/storage-s3/docs/README.md) | objects in S3-compatible storage |
| [skein-storage-tiered](../crates/storage-tiered/docs/README.md) | segments and blobs from untrusted read-only tiers after local storage, verified by hash |
| [skein-keyring](../crates/keyring/docs/README.md) | sealing with per-tenant and per-account keys |
| [skein-keyring-local](../crates/keyring-local/docs/README.md) | tenant keys wrapped by a local master key, account keys wrapped under them |
| [skein-mail](../crates/mail/docs/README.md) | mail provider contract, fake server, conformance |
| [skein-mail-imap](../crates/mail-imap/docs/README.md) | IMAP |
| [skein-mail-gmail](../crates/mail-gmail/docs/README.md) | Gmail API |
| [skein-mail-graph](../crates/mail-graph/docs/README.md) | Microsoft Graph mail |
| [skein-mail-jmap](../crates/mail-jmap/docs/README.md) | JMAP mail |
| [skein-pim](../crates/pim/docs/README.md) | calendar and contacts provider contract, fake server, conformance |
| [skein-pim-dav](../crates/pim-dav/docs/README.md) | CalDAV and CardDAV |
| [skein-pim-graph](../crates/pim-graph/docs/README.md) | Microsoft Graph calendars and contacts |
| [skein-pim-jmap](../crates/pim-jmap/docs/README.md) | JMAP calendars and contacts |
| [skein-pim-google](../crates/pim-google/docs/README.md) | Google Calendar API and People API |
| [skein-itip](../crates/itip/docs/README.md) | reading and building iTIP and iMIP |
| [skein-send](../crates/send/docs/README.md) | sending contract, fake sender, conformance |
| [skein-send-smtp](../crates/send-smtp/docs/README.md) | SMTP submission |
| [skein-send-gmail](../crates/send-gmail/docs/README.md) | Gmail API `messages.send` |
| [skein-send-graph](../crates/send-graph/docs/README.md) | Microsoft Graph `sendMail` |
| [skein-send-jmap](../crates/send-jmap/docs/README.md) | JMAP `EmailSubmission` |
| [skein-send-ses](../crates/send-ses/docs/README.md) | Amazon SES v2 `SendEmail` with raw MIME |
| [skein-throttle](../crates/throttle/docs/README.md) | per-key request gate: concurrency cap and shared `Retry-After` pause |
| [skein-engine](../crates/engine/docs/README.md) | journal writer, commands, node loop |
| [skein-accounts](../crates/accounts/docs/README.md) | account records, sealed credentials, directory |
| [skein-oauth](../crates/oauth/docs/README.md) | OAuth scopes, PKCE, tokens, sealed grants |
| [skein-oauth-http](../crates/oauth-http/docs/README.md) | token endpoint over HTTPS |
| [skein-server](../crates/server/docs/README.md) | the only inbound HTTP: Gmail and Graph push receivers, health |
| [skein-webhooks](../crates/webhooks/docs/README.md) | signed webhooks: endpoints, delivery in log order, SSRF rules |
| [skein-push](../crates/push/docs/README.md) | Gmail and Graph push: notification routing, hints, subscription renewal |
| [skein-sse](../crates/sse/docs/README.md) | Server-Sent Events parser (JMAP push) |
| [skein-telemetry](../crates/telemetry/docs/README.md) | logging and OpenTelemetry |
| [skein-metrics](../crates/metrics/docs/README.md) | Prometheus counters |
| [skein-view](../crates/view/docs/README.md) | mail database: envelopes, JWZ threads, search, calendars and contacts in SQLite, followed straight from storage |
| [skein (binary)](../apps/skein/docs/README.md) | config, composition, `serve`, management subcommands |
| [skein-docs](../apps/docs/docs/README.md) | documentation site (Astro Starlight) |
| [skein-load](../tests/load/docs/README.md) | load scenarios and request budget |
| [skein-integration](../tests/integration/docs/README.md) | container and live suites |
