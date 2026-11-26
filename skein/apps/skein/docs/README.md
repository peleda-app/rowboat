# skein (binary)

The only place that picks implementations. It reads a TOML config (see [`skein.example.toml`](../skein.example.toml)), builds storage (memory, files or S3), the local keyring, leases and liveness (Baton's `lease-cas` over in-memory state for a single node, or over control records in the storage through `ControlState`), in-process signals (`baton-signal-local`), the token endpoint, every mail provider and every sender (SMTP, Gmail, Graph, JMAP, Amazon SES, chosen per account by `AccountRecord::sender`; SES signs with the sealed send key instead of the account credentials), then runs a node (`skein-engine`) and its inbound listener (`skein-server`: provider push and a health check) until `SIGTERM` or Ctrl-C, giving running work 30 seconds to stop.

There is no management API. Tenants, accounts, credentials, commands and webhooks are managed with the subcommands below, which open the same storage and master key file as the node and write through the same stores (`TenantRegistry`, `Accounts`, `TokenManager`, `CommandQueue`, `WebhookStore`) with the same checks (`skein_accounts::admin`, `skein_engine::check_command`). They work while the node runs, with `fs` or `s3` storage; `memory` storage lives only inside `skein serve`. With `fs` storage `skein serve` opens the directory as its owner and refuses to start while another server holds it, and the subcommands (and export, import, copy) open it shared beside the server, every write compare-and-swap between the processes (see [skein-storage-fs](../../../crates/storage-fs/docs/README.md)). The app will manage its node through Baton commands instead.

## Commands

Every command takes `-c skein.toml` (or `SKEIN_CONFIG`). Secrets are read from stdin, never from arguments, so they stay out of shell history and process lists; stdin must be a pipe or a file (`< secret.txt`), and a command that reads a secret refuses a terminal, where typing would show it.

| Command | |
| --- | --- |
| `skein serve` | runs a node and the inbound listener |
| `skein check-config` | checks the file and the secrets it names |
| `skein push-token` | prints a new random secret for the Gmail Pub/Sub push address |
| `skein tenant add <t>` | registers a tenant (idempotent); a purged id is refused |
| `skein tenant list` | registered tenants, one per line |
| `skein tenant remove <t>` | unregisters: nodes stop syncing it, its data stays |
| `skein tenant remove <t> --purge --confirm <t>` | deletes every account, credential, OAuth grant, journal, blob and command of the tenant and destroys its keyring key; **irreversible**, and the id cannot be registered again |
| `skein account put --tenant t <a> --file a.json` | stores a record read as JSON (`-` for stdin): `provider`, `settings`, `auth`, optional `include`, `exclude`, `paused`, `send`, `pim`; never secrets. Checked by `check_record`: settings objects of at most 64 KiB, SES settings (region, `https` endpoint origin, hostname `message_id_domain`), a configured OAuth client |
| `skein account list --tenant t` | every record with its health, one JSON object per line |
| `skein account show --tenant t <a>` | one record with its health |
| `skein account remove --tenant t <a>` | deletes the record, passwords, send key and OAuth grant; the journal stays |
| `skein account password --tenant t <a> [--pim]` | seals the password (or, with `--pim`, the calendars and contacts password) from the first line of stdin; 1 to 4096 bytes |
| `skein account send-key --tenant t <a> --access-key-id ID` | seals an SES access key: the secret on the first line of stdin, an optional session token on the second |
| `skein account grant --tenant t <a> [--expires-at ms]` | stores OAuth tokens obtained elsewhere: the access token on the first line of stdin, an optional refresh token on the second |
| `skein journal put-blob --tenant t --file m.eml` | stores the bytes as a blob and prints its hash, for `append`, `send`, `put_object` and `respond_invitation` |
| `skein journal get-blob --tenant t <hash> --out m.eml` | writes a blob to a new file readable only by its owner (an existing path or symlink is refused); the bytes are checked against the hash |
| `skein journal submit --tenant t <a> --file c.json` | queues `{"id"?, "body"}` after `check_command` and the blob check; prints `{"id", "duplicate"}`; the id is the idempotency key |
| `skein journal cancel --tenant t <a> <id>` | cancels a queued command that has not started (idempotent) |
| `skein journal events --tenant t <a> [--from 1] [--limit 100]` | events of the journal, one JSON object per line, at most 1000 |
| `skein webhook add --tenant t --url U [--events a,b] [--accounts x,y]` | adds an endpoint; prints it with its signing secret, shown only now |
| `skein webhook list --tenant t` | endpoints without secrets |
| `skein webhook pause/resume/rotate/remove --tenant t <id>` | pauses, resumes (clearing backoff), replaces the secret (printed once), removes |
| `skein export --tenant t --out t.ndjson.zst` | writes every object of a tenant to a file; sealed records stay sealed |
| `skein import --tenant t --in t.ndjson.zst` | reads an export into the configured storage; never overwrites, refuses objects of another tenant |
| `skein copy --from a.toml --to b.toml --tenant t` | copies a tenant between storages directly; never overwrites |

A command queued from the command line reaches the account's owner on its next round: hints travel in process, so the owner sees it after at most `engine.interval_secs`, or sooner when the provider pushes a change. Export, import and copy run while no node writes the tenant; the target keeps working with the same master key file. Import decompresses as it reads and stops at a line longer than 256 MiB, so a crafted file cannot exhaust memory; lines before it stay imported.

## Inbound listener

`[server]` configures the only inbound HTTP: `listen` (default `127.0.0.1:8080`), `public_url` (where providers reach it; push subscriptions point there), `push_rate_per_second` (default 100) and `[server.push]`:

- `enabled` (default true) subscribes Gmail and Graph accounts to push when `public_url` is set, and routes `/v1/push/graph` and `/v1/push/gmail/{secret}`.
- `gmail_topic`, the Pub/Sub topic Gmail publishes to.
- `gmail_token_env` names the variable holding the secret in the Pub/Sub push address (make one with `skein push-token`); without it Gmail push answers 404.
- `gmail_oidc_audience` and `gmail_oidc_email` (both or neither) also require Pub/Sub's signed OIDC token.

The listener serves `GET /v1/health` and the push routes, nothing else; see [skein-server](../../../crates/server/docs/README.md) for the checks and limits. `server.enabled = false` turns it off (no push then).

## Metrics

`[metrics] listen = "127.0.0.1:9464"` serves `/metrics` in the Prometheus text format on its own listener without authentication; any address other than a loopback one fails `check-config`. With `[telemetry] otlp_endpoint` set (in a build with the `otel` feature), `otlp_metrics = true` also pushes the same counters over OTLP gRPC every `otlp_metrics_interval_secs` (default 60, at least 10; a smaller value fails `check-config`), with OpenTelemetry names such as `skein.sync.runs`; the Prometheus endpoint keeps working either way. On shutdown the counters are exported once more before the process exits.

## Outgoing webhooks

`[webhooks]` sets where endpoints may point: `allow_http_loopback` (tests and single-machine setups), `allowed_networks` (private networks such as `10.20.0.0/16`) and `timeout_secs` (default 10). The owner of an account delivers its events to the tenant's endpoints after each run; see [skein-webhooks](../../../crates/webhooks/docs/README.md).

## Microsoft Graph throttling

Graph limits requests per mailbox across mail, calendars and contacts (four at a time per app, and a `429` or `503` with `Retry-After` holds the whole mailbox). The node keeps one `skein-throttle` registry keyed by tenant and account, and the Graph mail provider, the Graph calendars and contacts provider and the Graph sender of an account all go through the same gate: at most four requests at a time, and a `Retry-After` given to one (capped at 10 minutes) holds the others too. The gate is in process, which is enough because an account's provider work runs only on its owner.

## Config rules

- Secrets only through `*_env` keys (S3 secret key, OAuth client secrets, the Gmail push secret); missing or empty variables stop the start.
- `engine.ownership = "storage"` needs shared storage (fs or s3), never memory. `single` keeps leases in memory (tokens are microseconds of wall-clock time, so a restarted node still outranks its earlier tokens); `storage` keeps lease records under each tenant's control path `baton/` and heartbeats in the reserved group `_nodes`, with a time-to-live of three heartbeats. Leases reuse one liveness answer per heartbeat interval (`CasLeases::reuse_alive_for`), so the cost of checking who is alive does not grow with the number of accounts. `engine.heartbeat_secs` must be the same on every node: at startup the node compares it with the value agreed in shared storage (record `skein/heartbeat` of `_nodes`) and refuses to start while a node with another value is heartbeating; when none is, its own value becomes the agreed one. On shutdown the node releases its leases.
- `engine.send_undo_secs` (default 0, at most 3600) holds every `send` and `respond_invitation` that long after it was submitted, so `skein journal cancel` can still stop it.
- Unknown keys are refused, so a typo does not silently fall back to a default; the removed management settings (`server.admin_key_hashes`, `trusted_proxies`, `cors`, `account_hosts`, `server.webhooks`, `[portal]`) are refused too.
- OAuth clients need no `redirect_url`: the node only refreshes tokens it was handed with `skein account grant`.

## Listeners

The inbound and metrics listeners use `skein_server::serve`, not plain `axum::serve`: a client must send a request's headers within 30 seconds or the connection is closed (slow-loris), at most 4096 connections are served at once (more wait in the backlog), and request bodies that pause for 30 seconds fail. On shutdown requests in flight get up to 30 seconds. Put a reverse proxy in front for TLS.

## Image

`docker build -t rowboat -f rowboat/skein/Dockerfile .` (from the folder holding rowboat with its siblings rinse and bento, the workspace's path dependencies) builds a Debian slim image that runs `skein serve` as uid 10001 with `/data` as a volume and `/etc/skein/skein.toml` as the config path. Mount the config read-only and pass secrets as environment variables; run the management subcommands with `docker exec`. Releases publish it as `ghcr.io/peleda-app/rowboat:X.Y.Z` for `linux/amd64` and `linux/arm64`, and attach archives of the binary for Linux (musl), macOS and Windows to the GitHub release. See [Releasing](../../../docs/RELEASING.md).

## Tests

Unit tests for the config, factories, heartbeats and export/import. `tests/cli.rs` runs the built binary against a config with file storage: tenants (idempotent add, reserved ids refused, unregister, purge only with confirmation and final), account records (checked, another account's id refused), passwords and grants sealed (the secret is found nowhere under the data directory), list and show with health, removal; blobs round-trip; commands queued idempotently, refused when dirty or missing their blob, cancelled; webhooks with their secret shown once, never stored in clear, refused for a non-public address; memory storage refused; and the same sequence the container suite runs (tenant, account, passwords, blob, submit, events, get-blob, show) against a running `skein serve` on the same directory, which picks up the new account on its next heartbeat, while a second `skein serve` on that directory is refused. The container suite drives a running node through the same subcommands (`skein/tests/integration/tests/binary.rs`).

## Limits

Signals are in-process (`baton-signal-local`): hints from push receivers reach this node's workers only; a shared backend for several nodes comes with Baton's mesh. A subscriber keeps at most 16 undelivered hints.
