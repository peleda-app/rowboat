---
title: Configuration
description: Every section of skein.toml, with defaults.
sidebar:
  order: 2
---

`skein serve` reads one TOML file. Unknown keys are refused, so a typo does not silently fall back to a default. Secrets never go into the file: every secret is read from the environment variable named by a `*_env` key, and missing or empty variables stop the start. The annotated example lives in the repository as [`apps/skein/skein.example.toml`](https://github.com/peleda-app/rowboat/blob/main/skein/apps/skein/skein.example.toml).

## `[node]`

| Key | Default | |
| --- | --- | --- |
| `id` | required | unique per node: `[a-z0-9_-]` |
| `weight` | `1` | relative share of accounts; `0` never syncs, only receives push |
| `always_on` | `true` | an always-on node is a server in its lease profile; a node with `false` gets accounts only while no always-on node is alive |

## `[storage]`

`kind` is one of `memory` (tests only), `fs` (one machine) or `s3` (shared, stateless nodes).

```toml
[storage]
kind = "fs"
path = "/data/skein"
```

```toml
[storage]
kind = "s3"
endpoint = "https://s3.example.org"   # omit for AWS S3
bucket = "skein"
region = "us-east-1"
prefix = "prod"
access_key_id_env = "SKEIN_S3_ACCESS_KEY_ID"
secret_access_key_env = "SKEIN_S3_SECRET_ACCESS_KEY"
# allow_http = true                   # only honoured for loopback endpoints
```

See [Storage](/rowboat/deploy/storage/) for what each backend guarantees.

## `[keyring]`

| Key | Default | |
| --- | --- | --- |
| `master_key_file` | required | created with mode `0600` when missing; back it up separately from the data |
| `cache_ttl_secs` | `60` | how long a tenant's or account's data key stays in memory, and so how long a key destroyed on another node (directly or through its tenant) keeps working here |

## `[server]`

The only inbound HTTP: `GET /v1/health` and the Gmail and Graph push receivers. There is no management API; manage the node with its [subcommands](/rowboat/deploy/run/binary/).

| Key | Default | |
| --- | --- | --- |
| `enabled` | `true` | `false` turns the listener off, and push with it |
| `listen` | `127.0.0.1:8080` | address of the listener, such as `0.0.0.0:8080` |
| `public_url` | none | where providers reach the listener; push subscriptions point there |
| `push_rate_per_second` | `100` | Graph notifications and authenticated Gmail pushes accepted per second, each with its own budget; more get 429 with `Retry-After` |

### Listener limits

The inbound and the metrics listener close a connection whose request headers take longer than 30 seconds to arrive (slow-loris), serve at most 4096 connections at once (more wait in the backlog), and fail a request body that pauses for 30 seconds. Push bodies are limited to 64 KiB. On shutdown, requests in flight get up to 30 seconds. These are fixed; put a reverse proxy in front for TLS.

### `[server.push]`

| Key | |
| --- | --- |
| `enabled` | subscribe Gmail and Graph accounts to push (needs `public_url`) and route the push receivers; `true` by default |
| `gmail_topic` | `projects/{p}/topics/{t}` for Gmail watches |
| `gmail_token_env` | environment variable with the secret in the Pub/Sub push URL `{public_url}/v1/push/gmail/{secret}`; `skein push-token` makes one; without it Gmail push answers 404 |
| `gmail_oidc_audience`, `gmail_oidc_email` | also require Pub/Sub's signed OIDC token |

## `[webhooks]`

Where outgoing webhook endpoints may point.

| Key | Default | |
| --- | --- | --- |
| `allow_http_loopback` | `false` | loopback receivers, for tests |
| `allowed_networks` | `[]` | private networks receivers may live in, such as `10.20.0.0/16` |
| `timeout_secs` | `10` | per request |

## `[engine]`

| Key | Default | |
| --- | --- | --- |
| `enabled` | `true` | |
| `ownership` | | `single` for one node (leases in memory); `storage` coordinates nodes through leases and heartbeats in shared storage (fs or s3, never memory) |
| `heartbeat_secs` | `10` | must be the same on every node sharing a store; with `ownership = "storage"` a node with a different value refuses to start while others run (see [multiple nodes](/rowboat/deploy/run/multiple-nodes/)) |
| `interval_secs` | `300` | sync interval for providers without push |
| `snapshot_every_events` | `5000` | new snapshot after this many events |
| `retain_days` | `7` | events covered by a snapshot older than this are compacted away |
| `send_undo_secs` | `0` | hold every send this long so it can be cancelled; at most 3600 |

## `[metrics]`

| Key | |
| --- | --- |
| `listen` | serves `/metrics` in the Prometheus text format, without authentication; must be a loopback address such as `127.0.0.1:9464` (use `otlp_metrics` to export elsewhere) |

## `[telemetry]`

| Key | Default | |
| --- | --- | --- |
| `filter` | `info` | `RUST_LOG`-style filter |
| `json` | | JSON lines instead of text on stderr |
| `otlp_endpoint` | none | OTLP gRPC collector, such as `http://otel-collector:4317`; needs a build with `otel` |
| `otlp_metrics` | `false` | also export the counters over OTLP |
| `otlp_metrics_interval_secs` | `60` | at least 10 |

## `[[oauth.clients]]`

One table per OAuth client; see [OAuth clients](/rowboat/providers/auth/oauth-clients/).

| Key | |
| --- | --- |
| `name` | what account records refer to |
| `provider` | `google` or `microsoft` |
| `client_id` | |
| `client_secret_env` | environment variable with the secret |
| `microsoft_tenant` | one Entra ID tenant, or `organizations`, `consumers`, `common` |
| `access` | `{ mail = "none" \| "imap" \| "api", mail_write, send, calendar = "read" \| "write", contacts = "read" \| "write" }` |
| `redirect_url` | optional; the node only refreshes tokens it was handed with `skein account grant` |
