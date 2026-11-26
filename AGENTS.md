# Agent guide

Read [docs/RULES.md](docs/RULES.md) first: the rules of every repository of the workspace, synced from dojo. Then [docs/PLAN.md](docs/PLAN.md). [docs/DECISIONS.md](docs/DECISIONS.md) records what was decided and why; [docs/QUESTIONS.md](docs/QUESTIONS.md) lists what the maintainer still has to decide.

rowboat is Peleda's node: the coordination of a person's or team's nodes, the mail, calendar and contacts engine, and the node built on both, embedded by the Peleda app on devices and run as a headless server. It has no web interface and no HTTP management API; the app manages the node through Baton commands. Public and source-available under the PolyForm Noncommercial License 1.0.0 (commercial use needs a license from the maintainer), every crate `publish = false`; contributions need the signed [CLA](CLA.md).

Status: the repository was formed on 2026-11-25 from `skein` (this repository's history), `baton` and `smereka`. The two layers below are members of one Cargo workspace with one `Cargo.lock` at the root; their fuzz crates (`baton/fuzz`, `skein/fuzz`, and `fuzz/` for the node layer) stay separate workspaces on their pinned nightly. The web portal, the TypeScript client, `openapi.json` and the HTTP management API were removed the same day: the only inbound HTTP left is `skein-server`'s push receivers and health check, the `skein` binary is managed through its subcommands until the node takes Baton commands, and `skein-view` is a library (`skein/crates/view`) that follows a journal straight from storage. The node layer's phase 0 and 1 crates exist (`crates/`: `rowboat-api`, `rowboat-keystore` with `-memory`, `rowboat-discover` with `-table`, `-autoconfig`, `-srv` and `-net` (discovery probes every server it offers through the node's `ServerProber`), `rowboat-spam` with `-signals`, `rowboat-category` with `-bento`, `rowboat-compose`, `rowboat-node`; `tests/load`; `tests/integration` (the node against Dovecot, Stalwart and GreenMail in containers over TLS with a test CA); the root `fuzz/` workspace), built from [docs/NODE.md](docs/NODE.md); `apps/` (the headless server) does not exist yet. The node depends by path on the open siblings `../rinse` (`rinse-mail`, and `rinse-mail-direct` for tests) and `../bento`.

## Layers

| Path | What | Packages |
| --- | --- | --- |
| `baton/` | coordination: groups, capabilities and keys, leases with priority and fencing, commands, signals, peer fetch, transports; knows nothing about mail | `baton-*`, `batond` |
| `skein/` | the mail engine: providers, the journal and its storage, commands, keyring, push receivers, the `skein-view` mail database | `skein-*` |
| `crates/`, `apps/` | the node: composes Baton, Skein and the other repositories into Peleda's node (`rowboat-node` and its contracts); the headless server binary (not yet) | `rowboat-*` |

Dependencies point down the table: the node depends on Skein and Baton, Skein depends on Baton's contract crates, Baton depends on neither. Each layer keeps its own `AGENTS.md` and `docs/`; their rules defer to this file and to `docs/RULES.md`.

Crate directories drop the prefix, package names keep it: `skein/crates/storage-s3` is `skein-storage-s3`, `baton/crates/link-iroh` is `baton-link-iroh`. Crates keep their `skein-` and `baton-` names; the node's own crates are `rowboat-*`.

## Checks

- `mise run check` at the root: the unsafe scan (`scripts/check-unsafe.sh`, synced from dojo with `unsafe-allowlist.txt`), `cargo fmt`, the three fuzz workspaces formatted and compiled on stable, `cargo clippy` and `cargo test` over the whole workspace, the `skein-telemetry/otel` feature build, then `dojo check .` (dojo is the sibling repository `../dojo`). A change is done only when it passes.
- Other tasks, all from the root (`mise tasks` lists them): `load-baton`, `load-skein` and `load-node` (or `load` for all at their default sizes), `fuzz-baton`, `fuzz-skein` and `fuzz-node` (`-- <target> [secs]`, `-- all [secs]`, `-- build`), `fuzz-all`, `it` and `it-down` (Skein's and the node's container suites over one compose stack), `live` (real accounts), `deny`. The documentation site (`skein/apps/docs`) is a separate bun project built by its own workflow.
- Run cargo through `mise exec -- cargo ...` at the root; narrow `cargo test --workspace` with `--test` or a name filter rather than `-p`, which builds another artifact set.

## Rules for this repository

- **No HTTP management API.** The node is managed through Baton commands from the app. The only inbound HTTP is the Gmail Pub/Sub and Microsoft Graph change notification receivers (with their authenticity checks) and a health check.
- **Baton stays generic.** Nothing in `baton/` names mail, accounts, Skein or Peleda; Skein and the node plug in through Baton's public contracts.
- **Skein uses only Baton's contract crates** in its libraries (`baton-core`, `baton-state`, `baton-lease`, `baton-signal`); implementations are picked by composition roots.
- **Untrusted message content is parsed only in rinse** (`../rinse`), on servers and devices alike.
- **Never depend on private repositories.** rowboat is noncommercial: it may depend only on open and noncommercial siblings.
