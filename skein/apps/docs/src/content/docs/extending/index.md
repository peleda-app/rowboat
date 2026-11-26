---
title: Extension points
description: The contracts an application can implement to run Skein where this repository does not.
sidebar:
  order: 1
---

Skein is built so that an application can run it in places this repository does not cover by supplying its own implementations of public contracts, without forking.

| Contract | Crate | Built in | What another implementation can do |
| --- | --- | --- | --- |
| `Objects`, or `ControlStore`, `Log`, `BlobStore`, `CommandQueue` | `skein-storage` | `s3`, `fs`, `memory` | keep the journal in another store, keep replicas elsewhere |
| `HeadAttestor` | `skein-storage` | `NoAttestor` (attests nothing) | sign every journal head, so heads and segments read from untrusted storage or another source can be verified |
| `SegmentSource` | `skein-storage` | every `Log` | hand out journal segments from a cache or replica; callers verify them against a trusted head |
| `ReadTier` | `skein-storage` | `StorageTier` in `skein-storage-tiered` (another `Storage`) | serve segments and blobs from a mirror, a backup or another store; `skein-storage-tiered` asks tiers after local storage and verifies every byte by hash |
| `Leases`, `Liveness` | `baton-lease` (Baton) | `lease-cas` over `ControlState` or in-memory state | decide ownership among nodes without object storage |
| `NodeProfile` | `baton-lease` (Baton) | `skein_engine::node_profile` from config | report class, capacity and whether the node can run, so leases go to capable nodes |
| `Signal` | `baton-signal` (Baton) | `baton-signal-local` | carry hints and previews over its own transport |
| `Keyring` | `skein-keyring` | `keyring-local` | keep tenant and account keys in a KMS, a vault or another key hierarchy |
| `MailProvider` | `skein-mail` | IMAP, Gmail, Graph, JMAP | add a mail provider |
| `PimProvider` | `skein-pim` | DAV, Google, Graph, JMAP | add a calendar and contacts provider |
| `Sender` | `skein-send` | SMTP, Gmail, Graph, JMAP | add a sending service |
| `TokenEndpoint` | `skein-oauth` | `oauth-http` | post to token endpoints another way |
| `AccountObserver` | `skein-engine` | webhook delivery | run something after every successful run of an account |
| HTTP routes | `skein-server` | `skein_server::router(state)` | merge its own routes next to Skein's |

## Rules that keep this working

- **Object-safe traits.** Every contract trait is `Send + Sync`, usable as `dyn Trait`, with `#[async_trait]` for async methods and no generic parameters on methods.
- **One composition root.** The engine receives every contract as `Arc<dyn Trait>` and never checks which implementation it got. Only the binary picks implementations; an extended application builds its own binary.
- **Nothing leaks.** No provider SDK, driver or protocol library types cross a contract boundary, including in errors.
- **Errors per contract.** One `thiserror` enum per contract; libraries never return `anyhow::Error`.
- **Guarantees, not mechanics.** Every public trait, method and type documents what it guarantees: ordering, idempotency, what happens when something is missing, concurrency.
- **Semver.** Contract changes follow semver, since implementations outside this repository cannot be fixed in the same change.
- **Conformance.** Every contract ships a suite behind its `testing` feature; an outside implementation proves it keeps the contract by passing it. See [Conformance suites](/rowboat/extending/conformance/).

The engine treats the absence of object storage as a normal configuration: the journal can live in any `Log` and `BlobStore`.

The crates are not published, so the Rust API docs are built locally with `cargo doc`.
