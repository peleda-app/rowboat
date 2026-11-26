# skein-webhooks

Signed webhooks over the journal. A tenant configures endpoints; the node that owns an account posts the account's new events to every matching endpoint in batches, signed with HMAC-SHA256, at least once and in log order per endpoint and account. Requests go only to `https` addresses on public hosts, connecting to the very address that was checked. The binary's `skein webhook` subcommands configure endpoints through `WebhookStore`; `apps/skein` adds `WebhookDelivery` to the engine's `RunConfig::observers`.

## Public API

- `WebhookStore::new(control, log, keyring)` — endpoints at tenant control path `webhooks/{id}` and cursors at `webhook-cursors/{endpoint}/{account}`, both versioned records written with compare-and-swap.
  - `create(tenant, NewEndpoint { url, events, accounts }, policy)` → `(Endpoint, secret)`. Checks the address with `WebhookPolicy::check` (a host that does not resolve is refused), checks the filters (known event types, 1–100 entries each), generates a lowercase ULID id and a secret, seals the secret with the keyring (context `webhooks/{id}`). Every account that already has a log starts at its current head, so an endpoint gets changes from its creation on; accounts that get a log later start at the beginning.
  - `get`, `list` — never open the secret. `get` answers `None` for anything that is not a lowercase ULID.
  - `update(tenant, id, EndpointPatch { url, events, accounts, paused }, policy)` — `Some(None)` clears a filter. Resuming a paused endpoint clears its pause reason and the failure state of every cursor, so the next run tries at once. Retries on concurrent changes.
  - `rotate(tenant, id)` → the new secret; requests signed from then on use it.
  - `delete(tenant, id)` → `false` when missing; removes the endpoint, then its cursors.
  - `deliveries(tenant, id)` → one `DeliveryState { account, cursor }` per account.
  - `secret(tenant, endpoint)` opens the secret; `ping(tenant, id, transport)` sends one signed `"ping": true` batch and returns the status code or the `SendError`.
- `WebhookDelivery::new(store, transport)`, `.with_clock(clock)` — `deliver(tenant, account)` → `DeliveryReport { batches, events, failures, waiting }`; implements `skein_engine::AccountObserver`.
- `WebhookPolicy { allow_http_loopback, allowed_networks, timeout }`, `Network` (`10.20.0.0/16`, `fd00::5`) — where requests may go; `parse(url)` checks without resolving, `check(url)` also resolves; `address_allowed(ip)`.
- `Transport` — one `POST`, answering any status code; `HttpTransport::new(policy)` is the real one.
- `sign(secret, timestamp, body)`, `verify(secret, timestamp, body, header, now)`, `new_secret()`, `VerifyError`, header names and `TOLERANCE_SECS`.
- `Endpoint`, `Cursor`, `Batch`, `Compacted`, `EVENT_TYPES`, `event_type(body)`.
- `SendError` (`invalid_url`, `address_refused`, `unresolved`, `timeout`, `unreachable` from `kind()`), `WebhookError`. Messages never hold the address, the payload or the secret.

## Requests

Every request is a `POST` with `Content-Type: application/json`, `User-Agent: Skein-Webhooks/<version>` and:

| Header | |
| --- | --- |
| `Skein-Webhook-Id` | the batch id; a retried batch keeps its id (derived from endpoint, account and the range of the log it covers) |
| `Skein-Timestamp` | when it was signed, Unix seconds |
| `Skein-Signature` | `v1=<lowercase hex HMAC-SHA256(secret, "{timestamp}.{body}")>` |

The HMAC key is the UTF-8 bytes of the whole secret as shown, `whsec_` included. The secret is `whsec_` and 32 random bytes in unpadded base64url.

The body:

```json
{
  "endpoint": "01jd8m3r9yq7k2c5x4v6b0n1tw",
  "tenant": "acme",
  "account": "box",
  "events": [
    {"v": 1, "seq": 41, "at": 1732147200000, "account": "box", "key": "...", "body": {"type": "first_sync_completed"}},
    {"v": 1, "seq": 42, "at": 1732147201000, "account": "box", "key": "...", "body": {"type": "mailbox_deleted", "mailbox": "m7"}}
  ]
}
```

- `events` are journal events exactly as `GET .../events` serves them, in log order, at most 100 per batch. They are consecutive except where the endpoint's `events` filter leaves some out.
- A compaction notice, sent when the endpoint's cursor is behind the first event the log still holds: `{"endpoint", "tenant", "account", "events": [], "compacted": {"first": N}}`. Load the latest snapshot (`GET .../snapshot`), then read on from it; batches resume at `N`.
- A test request from the API: `{"endpoint", "tenant", "events": [], "ping": true}`.

Answer `2xx` to accept a batch. The answer's body is ignored (at most 4 KiB is read); redirects are not followed, so a `3xx` counts as a failure.

## Verifying requests

1. Read the raw body bytes before parsing them.
2. Refuse if `Skein-Timestamp` is not digits or is more than 5 minutes from your clock (replays).
3. Compute `HMAC-SHA256(key = secret, message = timestamp + "." + body)`, hex-encode it in lowercase, and compare it in constant time with each `v1=` entry of `Skein-Signature` (entries are separated by commas or spaces; ignore other versions). Refuse if none matches.
4. Deduplicate: delivery is at least once, so the same batch may arrive again (same `Skein-Webhook-Id`). Record each event's `(account, seq)` (or its `key`) and skip those already applied; `seq` only grows per account.

In Rust, with this crate:

```rust
let ok = skein_webhooks::verify(
    &secret,                      // "whsec_..."
    headers["skein-timestamp"],   // raw header value
    &body,                        // raw body bytes
    headers["skein-signature"],
    now_unix_seconds,
);
match ok {
    Ok(()) => { /* parse body, skip (account, seq) already applied */ }
    Err(_) => { /* answer 400 or 401 and do nothing */ }
}
```

Pseudo-code for other languages:

```
ts  = header("Skein-Timestamp")
sig = header("Skein-Signature")
if not ts.isdigits() or abs(now() - int(ts)) > 300: reject
expected = hex(hmac_sha256(key = utf8(secret), msg = utf8(ts) + "." + raw_body))
if not any(constant_time_equals(expected, v[3:]) for v in split(sig, ", ") if v.startswith("v1=")): reject
for event in json(raw_body).events:
    if seen(event.account, event.seq): continue
    apply(event); remember(event.account, event.seq)
```

## Delivery and retries

- The owner of an account delivers it right after its worker ran (commands, then sync), through `RunConfig::observers`. Endpoints are served concurrently, each at most 20 batches per run; the rest goes on the next run.
- A `2xx` moves the cursor past the batch and clears the failure state. Events left out by the filter move the cursor without a request.
- Any other answer, a timeout, a refused address or a connection error keeps the cursor and backs off that endpoint for that account only: 10 s after the first failure, doubling up to 1 h (`backoff_secs`). The retry happens on the first run of the account's worker after the wait, so it may come later than the wait itself (at most the worker's interval).
- After 3 days of failures in a row for any account, the endpoint is paused with a reason (`paused_reason`, which names the account and the last error kind). `skein webhook resume` (`EndpointPatch { paused: Some(false) }`) resumes it and clears every backoff; delivery continues from the cursors, so nothing is lost while the log still holds the events, and a compaction notice covers the rest.
- Paused endpoints get nothing; their cursors stay.
- Per account the order is the log's order; there is no order across accounts or endpoints.

## Address rules

- `https` only. Plain `http` only to a loopback address or `localhost`, and only when `allow_http_loopback` is set (tests, single-machine setups).
- No user name or password in the address; the fragment is dropped; at most 2048 bytes.
- The host, or every address it resolves to, must be public. Refused: `0.0.0.0/8`, `10/8`, `100.64/10` (CGNAT), `127/8`, `169.254/16`, `172.16/12`, `192.0.0/24`, `192.0.2/24`, `192.168/16`, `198.18/15`, `198.51.100/24`, `203.0.113/24`, multicast, `240/4` and broadcast; `::`, `::1`, `fe80::/10`, `fec0::/10`, `fc00::/7`, `ff00::/8`, `2001:db8::/32`, `2001::/32` (Teredo), `2002::/16` (6to4), `100::/64`, `::/96`. IPv4-mapped (`::ffff:a.b.c.d`) and NAT64 (`64:ff9b::/96`) addresses are judged by their IPv4 address. `localhost` and `*.localhost` must resolve to loopback.
- `allowed_networks` lists exceptions explicitly, such as an internal receiver at `10.20.0.0/16`.
- Checked at creation and on every change of `url` (resolution must succeed then), and again on every request: the HTTP client resolves names through a resolver that applies the policy and connects only to the addresses it approved, so a name cannot be re-pointed to an internal address between the check and the connection. If any resolved address is refused, the request is refused.
- No proxy, no redirects, no cookies, no credentials; 10 s per request (`timeout`).
- Logs carry endpoint and account ids, status codes, counts, timings and error kinds; never URLs, payloads or secrets.

## Limits

- A cursor is created lazily for accounts without a log at creation time; deleting an endpoint while its owner is delivering may leave a cursor record behind, which is harmless and removed with the tenant.
- Delivery waits for the worker's next run; there is no separate timer for retries.
