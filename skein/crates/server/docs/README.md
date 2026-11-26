# skein-server

The node's only inbound HTTP, on axum: the Gmail Pub/Sub and Microsoft Graph change notification receivers and a health check. There is no management API: tenants, accounts, commands and webhooks are managed through the `skein` binary's subcommands today and through Baton commands from the app later. The receivers hold no state of their own; they read a `skein_push::PushRegistry` and publish hints on a Baton `Signal`.

## Public API

- `ServerConfig` — settings; `Default` gives the defaults below. `validate()` returns the first problem: a Gmail push token hash that is not 64 lowercase hex digits, OIDC settings without an `https` key address (or loopback), audience or email, a zero rate. Call it at startup.
- `hash_token(secret)` — the BLAKE3 hex hash the config holds instead of the Gmail push secret.
- `router(signal, push, &config)` — `GET /v1/health`, plus the push routes when `push` is `Some(registry)`. Every other path is 404.
- `serve(listener, router, shutdown)` — serves a router like `axum::serve` with `ConnectInfo<SocketAddr>`, but closes connections whose request headers take longer than `HEADER_READ_TIMEOUT` (30 s) and serves at most `MAX_CONNECTIONS` (4096) at once; on shutdown, requests in flight get up to 30 seconds. The binary also uses it for its metrics listener.
- `oidc` — `OidcConfig` (audience, service account email, key set address; `GOOGLE_JWKS` in production) and the verifier behind it.

| Setting | Default | |
| --- | --- | --- |
| `gmail_push_token_hash` | none (Gmail push answers 404) | hash of the secret in `{public_url}/v1/push/gmail/{secret}` |
| `gmail_push_oidc` | none | also require Pub/Sub's signed OIDC token |
| `push_rate_per_second` | 100 | Graph notifications and authenticated Gmail pushes accepted per second, each with its own budget, bursts of as many |

## Routes

| Route | Who | |
| --- | --- | --- |
| `GET /v1/health` | anyone | `ok`; never rate limited |
| `GET, POST /v1/push/graph?validationToken=` | Graph | echoes the token as `text/plain` (1 to 1024 printable characters, else 400) |
| `POST /v1/push/graph` | Graph | change and lifecycle notifications → 202 |
| `POST /v1/push/gmail/{secret}` | Pub/Sub | Gmail notifications → 204; 404 for a wrong secret or without a configured hash; 401 without a valid OIDC token when one is required |

The paths keep their `/v1` prefix because Graph subscriptions and Pub/Sub push subscriptions are registered with these addresses (`skein-push` builds the Graph one from `public_url`).

## Push

Each provider's own proof is checked; no key is needed:

- **Graph:** a notification counts only when its subscription id and `clientState` match a registered subscription (constant-time hash comparison). The answer is 202 whatever matched, so it says nothing about which ids exist; only a body that does not parse is 400.
- **Gmail:** the `{secret}` path segment must hash to `gmail_push_token_hash` (constant time). Every envelope behind a valid secret is acknowledged with 204, unknown or malformed ones too, so Pub/Sub does not deliver them again. With `gmail_push_oidc` every request must also carry the OIDC token Pub/Sub signs (`Authorization: Bearer`): RS256 only, a key from Google's published set (cached for an hour, refetched for unknown key ids at most once a minute, read with a 256 KiB cap), issuer `accounts.google.com`, the configured audience, and the configured, verified service account email. Anything else is 401.

Bodies are limited to 64 KiB (413), enforced while reading. The routes never call a provider: they read the registry and publish a hint on the signal topic `push/{account}` in the group of the account's tenant, where the account's worker listens. Logs carry counts only. Setup and renewal are described in [`skein-push`](../../push/docs/README.md).

## Limits and security notes

- Gmail and Graph each have a token bucket of `push_rate_per_second` requests, refilled continuously; over it the answer is 429 with `Retry-After: 1`, which both Graph and Pub/Sub retry. A Gmail push spends a token only after its path secret matches, so requests with a wrong secret (404) cannot spend the budget of genuine ones. A Graph notification has no secret before its body is read, so every notification POST spends a Graph token (validation requests do not): a flood can delay Graph pushes, which then fall back to polling, but never Gmail ones. The buckets bound the registry reads a flood can cause.
- A request body that sends nothing for 30 seconds fails, so slow uploads cannot hold a connection; `serve` adds the header read timeout and the connection cap.
- Every answer carries `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` and `Cache-Control: no-store`.
- Secrets never appear in answers, logs or errors; `ServerConfig`'s `Debug` shows only the hash.
- Put a reverse proxy in front for TLS.

## Tests

`src/tests.rs`: health, nothing else served (every former management path is 404 or 405), security headers, a stalled body given up (paused clock), the rate limit and its refill (paused clock), wrong-secret and Graph floods not spending the Gmail budget, config validation, the slow-header listener and the connection cap. `src/push_tests.rs`: Graph validation, client states, the Gmail secret and OIDC token (forged, wrong audience, wrong email, expired, oversized key set), body limits, and push off without a registry or secret.
