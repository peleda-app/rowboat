# Agent guide

Read [../docs/RULES.md](../docs/RULES.md) and [../AGENTS.md](../AGENTS.md) first: this is the `baton/` layer of rowboat, and the rules and conventions there govern it; when this guide and those files disagree, they win. Then read [docs/PLAN.md](docs/PLAN.md) first, then [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), and [docs/SECURITY.md](docs/SECURITY.md) before touching anything that handles keys, capabilities, leases or commands. [docs/TRANSPORTS.md](docs/TRANSPORTS.md) explains every transport and why it is or is not built in; [docs/QUESTIONS.md](docs/QUESTIONS.md) lists what the maintainer still has to decide.

Baton is a library for the nodes of one person or one team (phones, desktops, always-on servers) to talk to each other and coordinate: group membership, per-resource capabilities and keys, leases with priority and fencing, commands to the leaseholder, signals, objects from peers, pluggable transports. It has no storage of its own (durable state goes through contracts the application implements), never talks to mail providers or object storage, and knows nothing about mail: applications define resources, command classes, workers and where things are stored. Rust; its crates are members of rowboat's root Cargo workspace.

Status: early development, phases 0, 1, 4, 5, 6 and 8 done: `baton-core`, `baton-state`(`-memory`), `baton-lease`, `baton-lease-cas`, `baton-lease-quorum`, `baton-liveness-mesh`, `baton-signal`(`-local`, `-mesh`), `baton-mesh`(`-memory`, `-link`), `baton-group`, `baton-keys`, `baton-command`, `baton-fetch`, and `baton-seal`, `baton-identity`, `baton-link*` moved from the app; phase 8: `baton-mailbox`, `baton-wake`, `baton-drop`, `baton-mailbox-memory`, `baton-wake-mailbox`, `baton-drop-http`, `baton-mailbox-drop`, `apps/drop` (`baton-drop-service`, binary `drop`), `baton-lease-server`, `baton-group-server` and `apps/batond` (the blind server; its embedded iroh relay and wake sending are deferred). Run `mise run check` before considering a change done; `mise run load-baton` and `mise run fuzz-baton` for load and fuzz runs. Nothing is released; every crate is `publish = false` under the repository's PolyForm Noncommercial license.

## Layout (planned)

- `crates/*` — contracts and implementations
- `apps/batond` — the headless node for the blind server role (group logs, lease arbiter, drop; relay and wake sending deferred) without any resource key
- `apps/drop` — the store-and-forward drop service
- `tests/integration` — real binaries with local relays and drop servers in containers
- `docs/` — project-wide docs; every crate and app also has its own `docs/README.md`

Crate directories drop the prefix, package names keep it: `crates/link-iroh` is `baton-link-iroh`.

## Modules and contracts

The module rules of `../docs/RULES.md` apply; how they look in Baton:

- **Contract crates** (`baton-link`, `baton-mesh`, `baton-mailbox`, `baton-wake`, `baton-lease`, `baton-keys`, `baton-state`, ...) hold only traits, the types in their signatures and their error type. No I/O, no third-party SDK types.
- **Implementation crates** are named `<contract>-<kind>` (`link-iroh`, `mailbox-drop`, `lease-quorum`) and depend on their contract, never on another implementation.
- **Libraries** that are neither (`baton-seal`, `baton-group`, `baton-identity`) are pure: no I/O, no global state.
- **Composition roots** (`baton-node`'s builder, `apps/*`, and applications embedding Baton) are the only places that pick implementations; everything else receives `Arc<dyn Trait>`.
- **Object-safe traits.** `Send + Sync`, usable as `dyn Trait`, async methods through `#[async_trait]`, no generic parameters on contract methods.
- **Nothing leaks.** No library types (iroh, openmls, nostr, ...) cross a contract boundary, including in errors.
- **Errors per contract.** One `thiserror` enum per contract; libraries never return `anyhow::Error`; only binaries may.
- **Conformance suites.** Every contract ships a suite behind its `testing` feature, and every implementation runs it. Security properties (refusing non-members, replay, rollback, fencing) are part of the suites, not left to each implementation's own tests.
- **Guarantees, not mechanics.** Every public trait, method and type has a doc comment saying what it guarantees.
- **Docs per module.** Every crate and app has `docs/README.md`: what it does, its public API with guarantees, for a contract what an implementation must do and how to run the conformance suite, for an implementation its config, limits and platform notes. A change to behavior or API updates the docs in the same change.
- **Dependencies** go in `[workspace.dependencies]` in the root `Cargo.toml`.

## Tests are part of every change

A change without tests is not done. Every change ships, in the same change:

- **Unit and property tests** next to the code for everything it adds or changes (`proptest` for anything that parses, orders, merges or derives).
- **Conformance suites** for every contract, run by every implementation.
- **Security tests** wherever the code is a place an attacker could push on: anything that parses bytes from another node or a store, checks a signature, a capability, a membership, a fence or a sequence number, derives or wraps keys, or decides who leads. Each test is an attack written down: forged or replayed frames, a non-member or revoked sender, a lower fence, a lease signed by a node without `lead`, a stale or forked head, truncated, oversized and bit-flipped input, wrong context or key. A security property claimed in SECURITY.md without a test that tries to break it is a bug.
- **Vulnerability tests** for every bug found: the failing input becomes a regression test (and a fuzz corpus entry where a fuzz target exists) before the fix.
- **Fuzz targets** (`cargo fuzz`, in `fuzz/`) for every decoder of untrusted bytes.
- **Load tests** where throughput, contention or timing matter: many concurrent contenders on one lease, many leases at once, signal fan-out, large groups, slow or partitioned peers. They live in `tests/load` and run with `mise run load-baton`; each states the numbers it expects so a regression is visible.

Tests never touch the network beyond loopback and never sleep on wall-clock time where a manual clock can be injected.

## Rules

- **English** in every file: code, comments, docs, commit messages.
- **Application-agnostic.** No crate names mail, calendars, accounts, Skein or any application concept. Resources, command classes and jobs are opaque names and bytes defined by the application. Baton never depends on Skein.
- **Skein depends on Baton's contract crates** (`baton-core`, `baton-state`, `baton-lease`, `baton-signal`) and on `baton-lease-cas` for its built-in arbiter and nothing else from here. Keep them small and I/O-free, and treat every change to them as a semver change for Skein.
- **One implementation of each thing.** Before adding a function, check the table in [docs/PLAN.md](docs/PLAN.md#one-implementation-of-each-thing): if Skein or another repository already owns it, use theirs; if Baton owns it, they must not grow a second one.
- **No storage of its own.** No library crate opens files or databases or talks to object storage (`state-file` for examples and tests excepted; `apps/drop` is a standalone service with its own embedded store). Durable state goes through `baton-state`'s `StateStore` and `SecretStore`; only test implementations (`state-memory`, `state-file` for examples) live here.
- **Ciphertext everywhere outside a node.** Anything that leaves a node (state handed to the application for storage, relays, mailboxes, wake channels, the blind server) is sealed under a resource, node or recovery key and signed. Transports and stores never see plaintext.
- **Every wire format is versioned and signed.** Frames, group log entries, key boxes, leases, commands, results and signals carry a version byte and a context-bound signature.
- **Check, then commit.** A replay counter, a fence or a head is recorded only after every check on the message passed, including who the caller expects the sender to be.
- **No real data.** Tests, fixtures and docs use invented resources and `example.com`/`example.org`.
- **Never log content or secrets.** Logs, metrics and traces carry ids, counts and timings only. Resource names are application data: log their pseudonymous ids.
- **`unsafe` is denied** workspace-wide.
- **Comments are rare.** Doc comments on the public API; inside bodies only what a reader cannot infer.
- **Commits and PR titles:** one line in Conventional Commits form with the module as scope, no body.
