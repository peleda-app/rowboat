# rowboat (the server)

Peleda's headless multi-tenant server (GROUP.md, "The headless server"). One process per host serves many tenants; each tenant is one person's group, and the server is that group's `server` node. Every tenant is its own `rowboat-node` (`Profile::Server`, class `Server`) over its own directories and keys. There is no management API: the operator has the command line below, the owner administers the server from the app through Baton commands.

## Command line

`rowboat [--config PATH] <command>`; the configuration is `/etc/rowboat/rowboat.toml` unless `--config` or `ROWBOAT_CONFIG` says otherwise (see `rowboat.example.toml`).

| Command | What it does |
| --- | --- |
| `serve [--yes]` | Runs every bound tenant, the push receivers and `GET /v1/health` until SIGTERM or SIGINT, then hands every tenant's accounts back, tells each group's devices it is leaving, and stops. On a host with no tenant it first creates one and shows its invite: on stdout when stdout is a terminal, otherwise (a container, a service manager: stdout is a log) only in `<secrets_dir>/first-run-invite.txt` (mode 0600, deleted once the invite is used or ends), whose path is logged (`first_run_invite = false` turns that off). A second `serve` over the same data directory is refused. |
| `invite --tenant new\|<id> [--rebind] [--yes]` | Prints a server invite for a new tenant, or an unbound one: the QR code drawn in the terminal, the short code, the pairing address the code is typed with, the server's node id and the expiry (10 minutes). Waits until a device adopts the tenant, prints the fingerprint, then binds the tenant to that device's group and exits. Interactive, it asks the operator to confirm the fingerprint too; `--yes` (or no terminal) leaves the confirmation to the app. |
| `tenants [--json]` | Lists tenants: id, `bound`/`unbound`/`stopping`/`damaged`, group, node id, link port. |
| `tenants remove <id> [--yes]` | Deletes a tenant's data (in the bucket too, with `[s3]`), keys and binding; asks for the tenant id unless `--yes`. A running `serve` stops the tenant first (handing its accounts back). |
| `status [--json]` | Whether `serve` runs, and what it last reported per tenant (state, group, accounts, accounts it leads, peers). |

The invite's QR code and short code carry its secret until it is used or expires, so they go to stdout only when it is a terminal (or the first-run file), never into the logs. The QR code is drawn light on dark (half blocks); a phone camera reads either way round. The CLI and `serve` share no socket: `invite` and `tenants remove` work on the tenant's directory while `serve` runs, `serve` picks up new bound tenants within 5 s, and a stop marker (`tenants/<id>/stop`) asks it to release a tenant (`--rebind`, `remove`); `status` reads the file `serve` writes every 5 s.

## Tenants

```
<data_dir>/host/objects/              the host lock and the push registry (system/push/...)
<data_dir>/host/status.json           what `serve` last reported: ids and counts only
<data_dir>/tenants/<id>/tenant.json   id, creation time, link port
<data_dir>/tenants/<id>/binding.json  group, genesis hash, node id; written once adopted
<data_dir>/tenants/<id>/node/         the node's data directory: sealed objects and its lock
<secrets_dir>/tenants/<id>/           the node's keys (rowboat-keystore-file, 0600 files)
<cache_dir>/tenants/<id>/view/        the mail database, cleared on every start and stop
```

- **Ids** are 1 to 32 characters of `[a-z0-9-]` (never `new`), so no id leaves the tenants directory; `invite --tenant new` picks `t` and 12 random base32 characters.
- **Binding.** A tenant is bound to the genesis hash of the first group whose device completes its invite. Another invite for a bound tenant is refused before anything is shown; the bound node itself refuses to issue one (it has peers, and an adopted node accepts only terms of its own group even with none). On every start the node must match its binding (adopted, the same group, genesis and node id), or the tenant does not start; an adopted node whose binding is missing (a crash right after the adoption) gets it rewritten from the node. Only `invite --rebind` moves a tenant: it deletes the tenant's data (in the bucket first, with `[s3]`) and keys (logged as an operator action) and issues a new invite to a fresh identity (question 56).
- **Identity.** One node identity per tenant (question 49 asks for one per host; see DECISIONS.md).
- **Sealing.** Every object of a tenant is sealed by its node under keys derived from its master key, kept with its identity in the secrets directory, apart from the data directory (the configuration refuses either inside the other), so a copy of the data alone opens nothing. Credentials are sealed by the node's keyring as on a desktop. The mail database holds mail in the clear while the server runs, which is why it lives in the cache directory (a memory file system in the container), is deleted when a tenant stops and is rebuilt from the sealed journal on every start (question 74). The default `cache_dir` is `<data_dir>/cache`, where a crash leaves it in the data volume until the next start; `serve` warns about that default.
- **S3.** With `[s3]`, every tenant's objects live under `{prefix}/tenants/{id}/` in the bucket instead of the data directory, sealed exactly as on disk; the data directory keeps only the lock. One prefix must serve one host. A rebind or removal deletes everything under the tenant's prefix before its keys.
- **Links.** Each tenant keeps one UDP port of `link.ports` for its node's link (recorded at creation, so devices find it at the same address after a restart); pairing endpoints take free ports of the range off every tenant's link port. Hints carry `link.advertise` (and `link.relays`). With `ports = "any"` the address changes on every start.

## Running

- **Listener.** `skein-server`'s router once for the host: `GET /v1/health`, and with `[listener.push] enabled` the Gmail and Graph receivers over the host's push registry. Every tenant's node shares one signal bus (topics are scoped to its group) and records its subscriptions in that registry.
- **Content.** Messages are rendered with `rinse-mail-direct` in process (question 75).
- **Shutdown.** SIGTERM or SIGINT: each tenant stops taking leases and hands what it leads back at a clean point with its state offered, waits up to `shutdown.handback_secs` (15 s) for another node to hold each such account, then, only if every account it led is now held by another node, stops arbitrating its group's leases and sends every device of the group a signed leaving notice (`Node::announce_leaving`), and shuts down. After an unfinished hand-back (a worker still busy, say with a send) no notice goes out: the devices take over by silence after the delay and report what was queued as uncertain instead of repeating it. A device that gets the notice and finds the server no longer answering takes the accounts over at once under a fallback arbiter among the devices (GROUP.md, "When the server is silent"), instead of after the five-minute takeover delay a crash or a cut-off server costs; when the server is back it first follows the devices' journals and then takes the accounts back. The next start believes the devices that took over meanwhile. Devices and the server should share the takeover delay (5 minutes by default on both): the server believes a device's fallback grants only after a gap of half that in its heartbeats.
- **Logs.** `skein-telemetry`'s subscriber on stderr (JSON by default): tenant, group and node ids, counts and kinds only (SEC-3).

## Container

`Dockerfile` (build from the folder holding rowboat, rinse and bento: `docker build -t rowboat -f rowboat/apps/rowboat/Dockerfile .`) and `compose.example.yaml`: data and secrets in separate volumes, the cache on tmpfs, port 8080 and the UDP range published, `stop_grace_period` long enough for the hand-back. `FEATURES=test-roots` builds the container suite's image, whose configuration may add a test CA (`tls.test_ca`) to the mail providers' roots; other builds refuse that setting.

## Tests

- Unit: configuration rules and defaults (the example file parses), CLI parsing (hostile tenant ids never parse, no API flag), tenant ids, layout, ports and strict record decoding, the QR drawing, the endpoints' port choice.
- `tests/server.rs` (in process, `rowboat-endpoint-memory`, Skein's fakes): a desktop adopts a tenant by the first run, the tenant takes the account over, the status file reports it, shutdown hands the account back, a restart keeps identity, group, binding file and the lease under a higher token; tenants never share storage or keys (no group or account id of one tenant in another's directory, no password or subject at rest, swapped keys open nothing and the tenants do not start); a bound tenant refuses a second invite, its node issues none, a binding naming another group or genesis stops it, only a rebind moves it; an unbound tenant does not run, a removed one is gone; a tenant kept in a bucket (in-memory `object_store`) is sealed there and restarts.
- `tests/logs.rs`: the debug logs of a whole adoption, sync and shutdown carry no subject, address, password, body, invite payload or short code.
- `tests/integration` (`mise run it`): the container, adopted from an in-process desktop over loopback, takes the lease and syncs from GreenMail.
- Fuzz: `fuzz/` target `server_records` (tenant records and bindings).
