# Agent guide

Read [../docs/RULES.md](../docs/RULES.md) and [../AGENTS.md](../AGENTS.md) first: this is the `skein/` layer of rowboat, and the rules and conventions there govern it; when this guide and those files disagree, they win. Then read [docs/PLAN.md](docs/PLAN.md).

Skein connects to mail, calendar and contacts providers, turns every change into an append-only journal with the original bytes of every object, and carries out write commands placed next to that journal. Rust for the libraries and the binary, Astro Starlight for the documentation site.

Status: early development. Storage, the keyring, the mail, calendar, contacts and sending contracts with their providers (IMAP, Gmail, Graph, JMAP, DAV, SMTP, SES), the engine, the push receivers and the `skein-view` mail database exist; leases, liveness and signals come from Baton, the coordination layer next to Skein (`../baton`). There is no web portal and no HTTP management API: the binary is managed through its subcommands, the node will take Baton commands. Run `mise run check` before considering a change done, and `mise run it` for the container suites.

## Layout

- `crates/*` — Rust libraries: contracts and their implementations
- `apps/skein` — the binary, the only place that picks implementations
- `crates/view` — `skein-view`, the mail database over the journal (a library)
- `crates/server` — `skein-server`, the push receivers and health check, the only inbound HTTP
- `apps/docs` — the documentation site (a separate bun project)
- `tests/integration` — the real binary against servers in local containers
- `docs/` — project-wide docs; every crate, app and package also has its own `docs/` folder

Crate directories drop the prefix, package names keep it: `crates/storage-s3` is `skein-storage-s3`.

## Modules and contracts

The module rules of `../docs/RULES.md` apply; how they look in Skein:

- **Contract crates** (`skein-storage`, `skein-mail`, `skein-pim`, `skein-send`, `skein-keyring`) hold only traits, the types in their signatures and their error type. No I/O, no provider code.
- **Coordination comes from Baton.** Leases, liveness and signals are Baton's contracts (`baton-lease`, `baton-signal`, over `baton-state` and `baton-core`); libraries depend only on those contract crates, and only the composition roots and tests pick Baton implementations (`baton-lease-cas`, `baton-state-memory`, `baton-signal-local`). `skein_core::coordination` is the one mapping from tenants and accounts to Baton's groups and lease keys; Skein does not grow a second implementation of anything Baton owns.
- **Implementation crates** are named `<contract>-<kind>` and depend on their contract and `skein-core`, never on another implementation.
- **One composition root.** Only `apps/skein` depends on implementation crates (tests aside); the engine receives contracts as `Arc<dyn Trait>` through a builder and never checks which implementation it got.
- **Extension points are public contracts.** Implementations may live outside this repository; contract changes follow semver.
- **Object-safe traits.** Every contract trait is `Send + Sync` and usable as `dyn Trait`; async methods use `#[async_trait]`; no generic parameters on contract methods.
- **Nothing leaks.** No provider SDK, driver or protocol library types cross a contract boundary, including in errors.
- **Errors per contract.** One `thiserror` enum per contract; libraries never return `anyhow::Error`; only binaries may use `anyhow`.
- **Conformance tests.** Every contract ships a suite behind its `testing` feature, and every implementation runs it.
- **Guarantees, not mechanics.** Every public trait, method and type gets a doc comment that says what it guarantees: ordering, idempotency, what happens when something is missing, concurrency.
- **Small modules.** A crate has one job.

## Docs

Every crate and app has `docs/README.md`: what it does, its public API with guarantees, for a contract what an implementation must do and how to run the conformance suite, for an implementation its config, limits and provider quirks. A change to behavior or public API updates its docs in the same change.

## Rules

These restate `../docs/RULES.md` where it matters most here, plus Skein's own:

- **English** in every file: code, comments, docs, commit messages.
- **No real data.** Tests, fixtures and docs use invented messages, events and contacts, addresses on `example.com`/`example.org` and made-up names. Fixtures are hand-written files in the crate's `tests/fixtures/`.
- **Never log content or secrets.** Logs, metrics and trace attributes carry ids, counts and timings, never message content, subjects, addresses, passwords or tokens.
- **Original bytes are the truth.** Every message, event and contact is stored as the provider gave it, addressed by its BLAKE3 hash; parsed fields are derived.
- **Comments are rare.** Doc comments on the public API are required; inside function bodies, comment only what a reader cannot infer.
- **Tests sit next to the code** in `#[cfg(test)]` modules and never touch the network; providers are tested against in-process fakes. Only `tests/integration` reaches containers on this machine.
- **Dependencies** go in `[workspace.dependencies]` in the root `Cargo.toml`.
- **Commits and PR titles:** one line in Conventional Commits form with the module as scope (`feat(mail-imap): ...`), no body.
