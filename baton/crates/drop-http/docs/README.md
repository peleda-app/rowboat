# baton-drop-http

The drop service (`baton_drop::DropService`) over HTTP/1.1, for `apps/drop` and `batond`. HTTP adds no format of its own: bodies are raw `baton_drop::wire` bytes, so every security rule stays in `baton-drop`.

## Routes

| Route | Body | Answer |
| --- | --- | --- |
| `GET /v1/info` | none | `200`, the encoded `ServiceInfo` |
| `POST /v1/request` | one encoded request | `200`, the encoded reply (refusals by the service included) |

`504` means the service did not answer within `max_wait + reply_margin`: the request may or may not have been executed (a stuck store finishing it later), so clients must not treat it as never sent. Any other status means the request never reached the service: `413` body over `DropService::max_request()` (declared or counted while reading, chunked included), `408` body not received within `body_timeout`, `429` the client's rate or in-flight limit, `503` the server's in-flight cap, `404`/`405` unknown route or method. Replies carry `cache-control: no-store`.

## API

- `router(service, HttpConfig, clock) -> axum::Router`: the routes; `clock` (milliseconds) drives the rate limiter, so tests inject a manual one.
- `serve(listener, router, &HttpConfig, tls, shutdown)`: HTTP/1.1 only, keep-alive, a header timeout on every request (new or kept-alive connection), a write timeout (a reply that makes no progress for `write_timeout` closes its connection, so a client that never reads cannot hold a slot and its reply), at most `max_connections` connections (more wait in the listen backlog) and, with `ClientIp::Peer`, at most `max_connections_per_client` from one client (more are closed at once), TLS when given an `Arc<rustls::ServerConfig>` with the handshake bounded by the header timeout and done off the accept loop; on `shutdown` it stops accepting and lets requests in flight (long polls included) finish for up to `shutdown_grace`.
- `forwarded_for(headers)`: the last address of the last `X-Forwarded-For` header.

## Limits (`HttpConfig::default()`)

| Setting | Default | Guards against |
| --- | --- | --- |
| `header_timeout` | 10 s | slow headers (slowloris), slow TLS handshakes, idle kept-alive connections |
| `body_timeout` | 10 s | slow bodies |
| `reply_margin` | 10 s | a stuck store (requests fail with `504`, outcome unknown, after `max_wait` + this) |
| `write_timeout` | 30 s without progress | clients that never read their replies |
| `max_connections` | 4,096 | connection floods; slow clients are cut off by the timeouts and free their slot |
| `max_connections_per_client` | 64 | one client taking every connection slot (not applied behind a proxy) |
| `max_in_flight` | 2,048 | request floods; beyond it `503` at once, never queued; waiting long polls are not counted |
| `max_polls` | 1,024 | long polls waiting at once; a take beyond it returns at once, so long polls never starve short requests |
| `rate` | 20 requests/s, burst 100, 16 in flight, 4 waiting polls, 65,536 clients tracked | one client using everything; long polls count in the client's in flight |
| `client_ip` | `Peer` | `ForwardedFor` only behind a proxy that sets the header (the nearest proxy's entry is used, so a client cannot pick its own) |
| `shutdown_grace` | 35 s | |

A client is an IPv4 address or an IPv6 /64. The rate limiter keeps one token bucket and one in-flight counter per client; when `max_tracked` clients are tracked it drops idle ones (full bucket, nothing in flight) at most once a second, and if none is idle new clients share one overflow budget, so memory stays bounded under an address flood. A take that asks to wait (`wire::wait_ms`, read before the service verifies anything, only to pick a budget) moves from the in-flight budget to the long-poll budget when `max_polls` and the client's `polls` share allow, and otherwise runs as a short request that returns at once (`DropService::handle_with(raw, false)`). Long polls are bounded four times: by the client's in-flight and poll limits, by `max_polls`, and by the service's own `max_waiters`, `max_waiters_per_box` and `max_wait`.

## Logging

Nothing logs box ids, keys, content or client addresses: the only events are connection errors at debug level (kind and whether it was a timeout). `tests/logs.rs` captures every event at trace level during normal use and attacks and checks none of them carries the box id, keys, content or `127.0.0.1`.

## Tests

`cargo test -p baton-drop-http`: limiter unit and property tests (burst plus rate never exceeded, clock going back mints nothing, bounded table under 10,000 addresses), and attack tests against a real server on 127.0.0.1 (`tests/attacks.rs`): oversized bodies (declared, counted, chunked), 40 connections that never finish their headers while others are served, every connection held by slow clients and freed by the header timeout, a slow body cut with `408`, rate limits recovering with the manual clock, `X-Forwarded-For` per client and spoofing, long polls capped in time, per-client and server-wide in-flight caps (slow bodies hold the server's), sixteen long polls on four boxes not starving a put, a client that sends a 4 MiB take and never reads losing its connection to the write timeout, the per-client connection cap, waiters beyond the service cap returning at once, malformed bodies and non-HTTP bytes. The mailbox suite over HTTP runs in `mailbox-drop` (memory store) and `apps/drop` (redb store). Load: `mise run load-baton -- drop_http`.
