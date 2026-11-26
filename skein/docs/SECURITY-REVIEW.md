# Security review: OWASP API Security Top 10 (2023)

> **Superseded in part, 2026-11-25.** The HTTP management API (tenants, keys, accounts, OAuth callback, journal, blobs, commands, webhooks, the SSE stream), the portal and `skein-view`'s HTTP API were removed by the maintainer's decision. What this review says about them is history; the parts that still apply are the push routes and listeners in `skein-server` (findings 1, 3, 4 and 8, with the tests now in `crates/server/src/tests.rs` and `push_tests.rs`), command field bounds (finding 5, now `skein_engine::check_command` with its tests in `crates/engine/src/submit_tests.rs`), `skein-webhooks`, `skein-oauth-http`, `skein-push` and `skein import` (finding 7). The unauthenticated push routes now also have rate limits (`push_rate_per_second`, one bucket per receiver, Gmail counted only after its secret), which bound the storage reads in the residual risk below. Finding 2 (account hosts) no longer applies: accounts are written only by the operator through the binary's subcommands. `skein-view` is a library that verifies the journal it reads (see its README).

Scope: request handling in `skein-server` (the `/v1` API, OAuth callback, push routes), `skein-webhooks`, `skein-oauth-http`, `skein-push`, the listeners in `apps/skein`, the portal headers in `apps/skein/src/portal.rs`, `skein import`, and the API of `apps/view`. Connector crates (`mail-*`, `pim-*`, `itip`) were read only where requests leave the node (redirects, URLs), not reviewed for parsing.

Severity: **High** (cross-tenant access or secret disclosure), **Medium** (denial of service or reaching internal networks with ordinary access), **Low** (defense in depth, bounded impact), **Info** (no exploit, worth knowing).

## Findings and fixes

| # | Severity | Category | Finding | Fix |
| --- | --- | --- | --- | --- |
| 1 | Medium | API4 | `axum::serve` sets no hyper timer, so the 30 s header read timeout never applied: a client could open connections and trickle headers forever (slow-loris), with no cap on connections, on the API, metrics and `skein-view` listeners. | `skein_server::serve` (and a copy in `apps/view/src/listen.rs`) serves with hyper-util and a Tokio timer: 30 s header read timeout, at most 4096 connections, graceful shutdown with a 30 s bound. Tests: `the_listener_drops_clients_that_send_headers_slowly`, `the_listener_serves_at_most_its_connection_limit`, view `clients_that_send_headers_slowly_are_dropped`. |
| 2 | Medium | API7 | A tenant key with the `accounts` scope can point an account's IMAP/SMTP host, JMAP, DAV, Gmail or Graph API address at loopback, private networks or cloud metadata, and the node connects there (blind SSRF, credentials sent along). | Opt-in `ServerConfig::account_hosts` (`[server.account_hosts]` in the binary): every `host` value and `http(s)` URL host in `settings`, `send.settings` and `pim.settings` must be, or resolve only to, public addresses or allowed networks; 400 `host_not_allowed` never repeats the host. Off by default, since self-hosted mail servers often sit on private networks. Test: `account_hosts_follow_the_policy_when_one_is_set`. Residual risk below. |
| 3 | Low | API4 | Request bodies had no read timeout: a client could hold a connection by sending a blob one byte at a time. | Every request body is wrapped in an idle timeout (30 s between frames); a stalled body fails with 400. Test: `a_body_that_stalls_is_given_up`. |
| 4 | Low | API8 / API3 | API answers had no `X-Content-Type-Options`, framing or CSP headers; the Graph `validationToken` is reflected as `text/plain`; the OAuth callback page had no CSP; answers showing a new key or webhook secret had no `Cache-Control: no-store`. `skein-view` likewise. | A response layer on both APIs adds `nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` and `Cache-Control: no-store` unless the route set its own (blobs keep `private, immutable`). Tests: `answers_carry_security_headers` (server and view), `blobs_keep_their_own_cache_policy`. |
| 5 | Low | API4 / API8 | Free-form command fields (mailbox, collection and item ids, `if_version`, `save_to_sent`, flags) were bounded only by the 1 MiB body and could carry CR/LF towards provider protocols; connectors check most of them, but not all at the boundary. | `fields_ok` refuses ids over 1024 bytes or with control characters (`invalid_id`), more than 10000 items (`too_many_items`), more than 100 flags or flags over 256 bytes or with control characters (`invalid_flags`), more than 100 labels (`invalid_labels`). Tests: `oversized_or_unprintable_command_fields_are_refused` and the property tests below. |
| 6 | Low | API4 | The per-process key lookup cache pruned only expired entries, so a flood of distinct made-up keys within 30 s grew memory without bound (and the docs claimed guessed keys never reach storage). | Hard cap of 100000 entries; when full and nothing expired, lookups are not cached. Docs corrected. Test: `the_key_cache_is_bounded`. |
| 7 | Low | API4 | `skein import` read decompressed lines with `BufRead::lines`, so a small zstd file expanding into one endless line could exhaust memory. | Lines are read with a 256 MiB cap; a longer line stops the import. Test: `a_file_that_decompresses_into_one_huge_line_is_refused`. |
| 8 | Info | API4 | The Gmail push OIDC key set was buffered completely before its 256 KiB size check (the URL is operator configuration). | `Content-Length` is checked first and the body is read in chunks under the cap. Test: `an_oversized_key_set_is_never_used`. |
| 9 | Info | Docs | `skein-server` docs still said Pub/Sub OIDC verification was not done. | Corrected. |

## What was checked

### API1 Broken object level authorization

- Every route with `{t}` goes through `Authed<N>`, which reads the raw `t` path parameter and answers 404 when it differs from the key's tenant, before the scope check; all storage calls take the tenant from the path, so ids (accounts, commands, blobs, webhooks, keys) are always looked up inside that tenant. Blobs are per tenant by design, so `{a}` in the blob route is not an access boundary.
- New table-driven tests in `crates/server/src/security_tests.rs` derive every keyed route from the OpenAPI document and fill its parameters with real objects of tenant `globex`: with an all-scope key of `acme` every route with `{t}` answers 404 (admin routes without `{t}` 403), and `globex`'s objects are unchanged afterwards; with a `globex` key lacking the route's scope every route answers 403; without a key every documented route answers 401, which proves it is routed. A route with an unknown parameter or tag fails the test until it is given a value, so a new documented route is covered automatically. Disabling the tenant check in `auth.rs` makes the test fail.
- Result: no cross-tenant access found. Tenant keys are tenant-wide (no per-account scoping), as documented.

### API2 Broken authentication

- Constant-time comparisons: admin key hashes (fold over all hashes without early exit), tenant key hashes (compared against an all-zero hash when the record is missing), OAuth `state`, Graph `clientState` hashes (a dummy comparison when the subscription is unknown), the Gmail push path secret (hashed, then compared), `skein-view` token hashes (OR over all hashes), webhook signatures (`hmac::verify_slice`). No other secret comparison exists in scope.
- Key hashing: keys carry 256 random bits, so a fast hash (BLAKE3) is appropriate; only the hash is stored. All authentication failures answer the same 401 body; a malformed key is refused without a storage lookup, which only reveals the public key format.
- OAuth: PKCE S256, `state` is the tenant plus 256 random bits, the pending sign-in is sealed with the tenant's key, taken with a compare-and-swap delete (single use), expires after 10 minutes, and the client's redirect URL must equal the server's callback.
- Pub/Sub OIDC: RS256 only, key from the configured JWKS (no redirects), issuer, audience, `exp`, and the verified service account email are all required.

### API3 Broken object property level authorization

- Every JSON body and query type of the server uses `deny_unknown_fields`, as do `skein-view`'s queries. `CommandBody` does not: it is a journal type whose `#[serde(other)]` fallback keeps old nodes able to read newer commands; stray fields are dropped and never stored, so they cannot assign anything. The OAuth callback query accepts unknown parameters because providers add their own.
- Answers never hold passwords, tokens, key hashes or webhook secrets (new keys and secrets are shown once, now with `no-store`). Account `settings` are returned as stored; the docs say never to put secrets there.
- Errors: deserializer messages are repeated only when they name a field without quoting a value; storage, keyring and signal errors become a generic 500 and are logged without content.

### API4 Unrestricted resource consumption

- Body limits: 1 MiB JSON (`DefaultBodyLimit` on the whole API router, fallback included), 50 MiB blobs (route layer), 64 KiB push bodies; `skein-view` routes take no bodies (axum's 2 MB default applies). Enforced while reading.
- Headers: hyper's defaults (about 400 KiB buffered, 100 headers on HTTP/1.1; HTTP/2 header list limits); bearer tokens over 512 bytes are refused.
- Pages and lengths: events `limit` 1 to 5000; view lists 1 to 200, search 1 to 100 with `q` at most 1000 bytes and 16 terms, threads at most 1000 messages, mailbox filter at most 1024 bytes; ids are 1 to 64 characters, command and key ids ULIDs, blob hashes 64 hex digits; mailbox paths and labels at most 1000 bytes; passwords 4096 bytes, OAuth tokens 16 KiB, account settings 64 KiB each, `ip_allow` 100 entries, webhook URLs 2048 bytes and filters 100 entries; Graph posts at most 1000 items.
- Streams: at most 8 live streams per tenant key per node; keep-alives every 15 s; admin keys are not capped.
- Rate limits: per key, shared across nodes where the signal backend has counters.
- Decompression: `reqwest` is built without gzip or brotli, so answers are never decompressed implicitly; `pim-graph` cursors decompress with a bound; journal segments and snapshots are decompressed from Skein's own storage (trusted); `skein import` is now bounded (finding 7).
- Timeouts: header read and body idle timeouts (findings 1 and 3); outgoing webhook, OAuth and OIDC requests have total timeouts.

### API5 Broken function level authorization

- Admin routes (`/v1/tenants`, keys, register, unregister and purge) need an admin key; tenant keys get 403 `admin_only`, or 404 for another tenant. Purging needs `confirm` to repeat the tenant id. Covered by the scope walk above.

### API6 Unrestricted access to sensitive business flows

- Sending mail needs the blob uploaded first and a checked envelope (at most 500 recipients); commands are idempotent by id. No further flow limits beyond the per-key rate limit.

### API7 Server side request forgery

- Webhooks: `https` only (loopback `http` only when allowed), no credentials in the URL, IP literals judged directly, names resolved by a resolver that applies the policy at connect time (no DNS rebinding), no redirects, no proxy, answers read up to 4 KiB.
- OAuth token endpoints and the OIDC key set: operator configuration, `https` only (loopback `http` for tests), no redirects, answers capped (64 KiB, 256 KiB).
- DAV: credentialed requests follow redirects only to origins already allowed for sign-in; well-known discovery follows same-origin redirects. JMAP (`pim-jmap`): well-known redirects are followed without credentials and never from `https` to `http`; the session itself is not redirected with credentials. JMAP (`mail-jmap`): redirects are followed up to a limit without downgrade (reqwest drops `Authorization` on cross-host redirects), and the session's `apiUrl` and `downloadUrl` may name another host, as the JMAP specification allows.
- Account settings: finding 2.

### API8 Security misconfiguration

- CORS is off by default on both APIs, so other origins cannot read answers. `[server.cors]` (Skein) and `[http.cors]` (`skein-view`) turn it on for exact origins, or for `*` only when written out on purpose; origins with paths, user info or wildcards in the host are refused at startup. Credentials are never allowed (keys and tokens travel in `Authorization`, never in cookies), so `*` grants a page nothing it could not do with a stolen key anyway. Preflight is answered before routing and key checks; every other request still needs its key. Tests: `cors_is_off_by_default`, `cors_preflight_needs_no_key_and_names_what_is_allowed`, `cors_answers_allowed_origins_only`, `cors_wildcard_and_the_stream` (server), `preflight_skips_the_token_and_other_origins_get_nothing` (view).
- Portal (`apps/skein/src/portal.rs`): HTML answers already carry a CSP with `script-src 'self'`, `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` and `nosniff` on files. `connect-src` allows any `http(s)` origin so the portal can reach an API elsewhere; with scripts limited to the same origin this is acceptable. Empty 404, 405 and 304 answers carry no headers, which is harmless.
- API and view answers: finding 4. The OAuth callback also keeps `Referrer-Policy: no-referrer` and `no-store`.
- `skein-view --insecure-no-auth` is refused unless it listens on loopback; metrics have no auth and the docs say to keep them internal.

### API9 Improper inventory management

- The OpenAPI document is generated from the handlers and a test fails when the committed `openapi.json` drifts. The new BOLA walk relies on it: every documented keyed route is tested, and the 401 walk proves every documented route is routed. A route added to the router without documenting it is not caught automatically; review keeps `paths(...)` in `openapi.rs` complete.

### API10 Unsafe consumption of APIs

- Provider answers are size-capped in the token endpoint (64 KiB), webhooks (4 KiB read), OIDC (256 KiB). `skein-view` streams `/raw` from Skein and caps blobs it parses (`max_blob_bytes`).

### Logs

- Every `info!`, `warn!` and `debug!` in scope was read: they carry tenant, account, key, command and webhook ids, counts, statuses and error kinds. Errors logged with `%e` are storage, keyring, push and webhook errors whose texts name object keys (Gmail push keys use a hash of the address) or kinds, never content, addresses or tokens. `skein-view` logs request errors whose URLs hold only ids.

### Property tests

`crates/server/src/security_tests.rs` throws arbitrary bytes and JSON at the command route (always 4xx, or 202 for a valid command), arbitrary mailbox paths and labels (accepted exactly when clean), arbitrary idempotency keys (accepted exactly when a canonical ULID), arbitrary path segments and query strings (never 5xx). `apps/view/src/api_tests.rs` does the same for the view's list, search and raw query strings and path segments (only 200 or 400, never 5xx).

## Accepted risks

- **Account hosts are unrestricted by default** and the check runs when the record is written: a name re-pointed afterwards, or a hostile JMAP server naming internal API addresses, is not caught. Where tenants are untrusted, set `account_hosts` and restrict the node's egress with a firewall. Full enforcement needs a resolver hook in each connector.
- **OAuth sign-in links are not bound to a browser session.** Whoever holds an `accounts` key can start a sign-in and hand the link to someone else; the person who consents connects their mailbox to that account. This is inherent to an API where the integrator obtains consent; integrators must give the link only to the account's owner.
- **Unauthenticated push routes cost storage reads.** A Graph post can name up to 1000 subscriptions, each looked up in storage, without a key. Answers say nothing, and push only wakes accounts, but on object storage that is cost amplification. Rate limit `/v1/push/` at the reverse proxy.
- **Admin keys** are not rate limited and hold unlimited streams; they are operator credentials.
- **Rate limits and stream caps apply after key lookup**, so requests with unknown keys are not rate limited; they hit the bounded cache, then storage.
- **Per-node limits**: stream caps and, without shared counters, rate limits are per node.
- **Gmail push without OIDC** relies on the secret in the path alone; configure `gmail_push_oidc` in production.
- **TLS and per-client connection limits** are left to a reverse proxy.
