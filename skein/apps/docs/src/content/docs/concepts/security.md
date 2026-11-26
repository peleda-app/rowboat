---
title: Tenants and security
description: Tenants, sealing with per-tenant keys, the little that listens on the network, and what is never logged.
sidebar:
  order: 9
---

## Tenants and management

- Every account belongs to a tenant, an id from the integrator's side (1–64 characters of `[a-z0-9_-]`, not starting with `_`, which is reserved for Skein's own coordination records).
- There is no management API and no API keys. Tenants, accounts, credentials, commands and webhooks are managed by whoever can run the binary with the node's config and master key file (`skein tenant`, `skein account`, `skein journal`, `skein webhook`); in Peleda, the node will be managed through Baton commands.
- Secrets are read from stdin, never from arguments or the config file.

## Sealing

Credentials, OAuth grants and webhook secrets are sealed through the `Keyring` contract under a key scope: an account's passwords, send key and OAuth grant under that account's own key, webhook secrets under the tenant's key. An account's sealed bytes never open under another account or under the tenant's key. `keyring-local` keeps a random 256-bit data key per tenant, wrapped with XChaCha20-Poly1305 by a master key from a local file, and a random key per account, wrapped by a key derived from its tenant's. Losing the master key file makes every tenant's sealed data unreadable, so back it up separately from the data.

Purging a tenant (`skein tenant remove {t} --purge --confirm {t}`) destroys its key and with it the keys of all its accounts, which makes everything sealed for it unreadable for good, including copies in backups, and deletes its journal, blobs and commands. It cannot be undone, and the tenant id cannot be registered again.

## Network exposure

- **Only push and health listen.** The inbound listener serves `GET /v1/health` and the Gmail Pub/Sub and Microsoft Graph push receivers, nothing else. Each receiver checks its provider's proof (Graph's `clientState`, the Gmail secret and optionally Pub/Sub's OIDC token) and only wakes the account's worker; it never calls a provider. Gmail and Graph each have a rate limit (`server.push_rate_per_second`), answered with 429 and `Retry-After`; a Gmail push counts only once its secret matches, so forged requests cannot crowd out genuine ones.
- **Listener limits.** Slow clients are dropped after 30 seconds without headers, stalled bodies after 30 seconds without data, and at most 4096 connections are served at once (see [Configuration](/rowboat/deploy/run/configuration/#listener-limits)). TLS is left to a reverse proxy.
- **Response headers.** Every answer carries `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, a restrictive `Content-Security-Policy` and `Cache-Control: no-store`.
- **Metrics** are served without authentication on their own listener; keep it on an internal address.

## Reviews and reporting

The former HTTP API was reviewed against the OWASP API Security Top 10; the findings that still apply (listeners, push, command bounds, import) are marked in [`docs/SECURITY-REVIEW.md`](https://github.com/peleda-app/rowboat/blob/main/skein/docs/SECURITY-REVIEW.md). Every parser of untrusted provider answers and files has a coverage-guided fuzz target, run in CI on changes and weekly (see [`fuzz/README.md`](https://github.com/peleda-app/rowboat/blob/main/skein/fuzz/README.md)).

Report vulnerabilities privately through [GitHub security advisories](https://github.com/peleda-app/rowboat/security/advisories/new), never in a public issue. How releases are signed and how to verify them is in [Releases and verification](/rowboat/deploy/run/releases/).

## What is never logged

Logs, metrics and trace attributes carry ids, counts and timings only, never message content, subjects, addresses, passwords or tokens. Webhooks are signed with HMAC-SHA256 and carry a timestamp against replay. Every command is recorded in the journal with its origin.
