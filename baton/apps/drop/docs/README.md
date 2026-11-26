# baton-drop-service (`drop`)

The drop service as a standalone program: `baton-drop`'s rules over a redb store, served over HTTP/1.1 by `baton-drop-http`, with optional TLS, an expiry sweeper and graceful shutdown on SIGINT/SIGTERM. The library target (`baton_drop_service`) exposes `start(config, clock)`, so `batond` runs the same service in its own process.

## Running

```
drop --config /etc/baton-drop/drop.toml
drop --realm drop.example.com --tokens-file /etc/baton-drop/tokens [--listen 127.0.0.1:8470] [--data-dir ./drop-data] [--open]
```

Flags override the file. The process logs startup, shutdown and sweep counts only: never box ids, keys, content or client addresses.

## Configuration

```toml
listen = "127.0.0.1:8470"        # default; for a reverse proxy in front
data_dir = "/var/lib/baton-drop"  # holds drop.redb; created 0700, the file 0600
realm = "drop.example.com"        # required: the host name clients configure
sweep_secs = 300

[admission]                       # at least one of open, tokens_file, work_difficulty
open = false                      # only behind other access control
tokens_file = "/etc/baton-drop/tokens"   # one token per line (16 to 256 bytes), # comments; must be 0600
work_difficulty = 12              # argon2id hashcash, 1 to 24 leading zero bits; 0 = off
work_memory_kib = 1024            # 8 to 4096
work_passes = 1                   # 1 to 3

[limits]                          # all optional
max_message = 65536               # at most 1 MiB
max_box_bytes = 67108864
max_box_messages = 10000
max_ttl_days = 30                 # at most 30
max_wait_secs = 30                # longest long poll, at most 300
max_waiters = 10000
max_boxes = 100000                # whole store
max_total_bytes = 8589934592      # whole store, message bytes
untrusted_box_bytes = 1048576     # boxes made by proof of work or on an open service
untrusted_box_messages = 1000
untrusted_ttl_days = 7
max_untrusted_boxes = 50000       # of max_boxes
max_untrusted_total_bytes = 2147483648   # of max_total_bytes

[http]                            # all optional
header_timeout_secs = 10
body_timeout_secs = 10
write_timeout_secs = 30           # a reply making no progress this long closes its connection
max_connections = 4096
max_connections_per_client = 64   # not applied with behind_proxy
max_in_flight = 2048              # waiting long polls not counted
max_polls = 1024                  # long polls waiting at once; more return at once
rate_per_second = 20              # per IPv4 address or IPv6 /64; 0 = off
rate_burst = 100
per_client_in_flight = 16
per_client_polls = 4
max_tracked_clients = 65536
behind_proxy = false              # take the client address from X-Forwarded-For

[tls]                             # optional; PEM files, the key must be 0600
cert = "/etc/baton-drop/cert.pem"
key = "/etc/baton-drop/key.pem"
```

Unknown keys are refused. The proof-of-work salt is generated on first start and kept in the store, so challenges stay the same across restarts.

## TLS or reverse proxy

With `[tls]` the service terminates TLS itself (rustls, aws-lc-rs, TLS 1.2 and 1.3, ALPN `http/1.1`); certificates are read at start, so renewing one needs a restart. Without it, put a TLS-terminating reverse proxy in front, listen on loopback, and set `behind_proxy = true` so rate limits apply per client (the proxy must append the client address to `X-Forwarded-For`; the service uses the last entry). The proxy should allow request bodies of `max_message + 8 KiB` and read timeouts above `max_wait_secs`.

## Store (`RedbDropStore`)

One redb file (`drop.redb`). Tables: `boxes` (box id to a versioned box record), `messages` (box id ‖ message id, big endian, to `stored_at ‖ bytes`), `totals` (boxes and message bytes, in all and of boxes made by proof of work or on an open service, for the store-wide limits) and `settings` (the proof-of-work salt). Records use `baton_drop::record`, whose decoders refuse unknown versions, trailing bytes, out-of-range policies and counters (fuzz target `drop_record`), so a corrupted record is a backend error, never a belief. Every call is one write or read transaction on a blocking thread; creations, puts, acks, writer changes, deletions and sweeps are durable when they return; marking a box used on a take commits without a flush (a crash can only make a box look idle earlier). A full store refuses creations and puts with a quota error after dropping the box's expired messages; boxes anybody can create (proof of work, open) also stop at their own share (`max_untrusted_boxes`, `max_untrusted_total_bytes`), so they never lock out token holders. The sweeper (every `sweep_secs`) removes idle boxes and the expired front of each box's messages in short transactions of at most 256 boxes and 4,096 messages (`StoreLimits::sweep_boxes`, `sweep_messages`), so puts and takes wait for one batch at most, never for a whole sweep.

## Limits

Those of `DropConfig::new` and `HttpConfig::default()` (see `crates/drop/docs/README.md` and `crates/drop-http/docs/README.md`), plus the store-wide `max_boxes` and `max_total_bytes` and the shares of boxes anybody can create. The replay cache is in memory (see the drop README for why a restart is harmless). Graceful shutdown waits for requests in flight up to `max_wait_secs + 5`.

## Tests

`cargo test -p baton-drop-service`: `baton_drop::testing::store` on the redb store (twice on one file across a reopen), restart persistence, store-wide limits and totals, boxes made by work or on an open service kept within their share while token holders still create and put, a sweep in batches of two boxes and three messages removing everything, a corrupted record, settings; configuration parsing and flags; and `tests/service.rs` on 127.0.0.1: the `baton-mailbox` suite through `mailbox-drop` against the whole service on a temporary directory (token and proof of work, the salt surviving a restart), messages surviving a restart, TLS with its own certificate (untrusted certificate and plain HTTP refused), a long poll finishing during graceful shutdown, the sweeper emptying the store, and startup refusing group-readable token files, short tokens, missing admission, out-of-range work and an empty realm, with the data directory `0700` and the store `0600`.
