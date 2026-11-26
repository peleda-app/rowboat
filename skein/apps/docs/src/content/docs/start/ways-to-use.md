---
title: Ways to use it
description: Library, headless node managed from the command line, or extended with your own implementations.
sidebar:
  order: 2
---

Skein is one set of crates and one binary. Pick how much of it you run. There is no web panel and no HTTP management API; in Peleda, the node will be managed through Baton commands from the app.

## 1. Rust library

Depend on `skein-engine` and the providers you need, and give the engine storage contracts: the in-memory ones (`skein-storage-memory`), files (`skein-storage-fs`) or S3 (`skein-storage-s3`). The engine receives every contract as `Arc<dyn Trait>` through its constructor and never checks which implementation it got.

Leases and signals come from Baton, the coordination library Skein uses: for one process, Baton's `CasLeases` over in-memory state (`baton-state-memory`) and `LocalSignal` (`baton-signal-local`); for several, `CasLeases` and `CasLiveness` over `skein_storage::ControlState`.

```rust
let engine = Engine::new(storage, leases, signal, node_profile(node_id, 1, true));
engine.sync_account(&AccountConfig::new(tenant, account), &provider).await?;
engine.run_commands(&config, &provider).await?;
```

`skein_engine::run` adds the node loop: heartbeats, account assignment, one worker per owned account that syncs on push, on command hints and on an interval. Commands are queued with `skein_engine::submit_command`, which runs the same checks the command line does. To read the journal into a mail database, embed [`skein-view`](/rowboat/consumers/skein-view/). See the [engine README](https://github.com/peleda-app/rowboat/blob/main/skein/crates/engine/docs/README.md).

## 2. Headless node

Run the `skein` binary or container. Manage tenants, accounts, credentials, commands and webhooks with its subcommands (`skein tenant`, `skein account`, `skein journal`, `skein webhook`). Its only inbound HTTP is the Gmail and Graph push receivers and a health check. Programs read the journal from the storage, receive [webhooks](/rowboat/consumers/webhooks/), and queue commands through the command line or the library. See [Deployment](/rowboat/deploy/).

## 3. Extended

An application composes Skein's crates with its own implementations of the extension contracts (storage, leases and liveness, node profile, signals, providers) and builds its own binary. Each contract ships a conformance suite that an outside implementation runs to prove it keeps the contract. See [Extending](/rowboat/extending/).
