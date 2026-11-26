---
title: Composing your own binary
description: Building an application from Skein's crates with your own implementations.
sidebar:
  order: 3
---

An extended application does what `apps/skein` does: it picks implementations and hands them to the engine and the server as trait objects.

1. **Storage.** Implement `Objects` and build the typed stores with `Storage::over`, or implement the typed traits directly.
2. **Keyring, leases, liveness, signals.** Use the built-in implementations or your own. Leases, liveness and signals are Baton's contracts (`baton_lease::{Leases, Liveness}`, `baton_signal::Signal`); the binary uses `baton_lease_cas::{CasLeases, CasLiveness}` over `skein_storage::ControlState`, with the liveness wrapped in `skein_engine::OneGroupLiveness` and given to both the leases and the node loop, and `baton_signal_local::LocalSignal`.
3. **Accounts.** `skein-accounts` reads account records and resolves credentials only when the owner connects. It builds providers through `ProviderFactory`, `PimFactory` and `SenderFactory`, which your composition root implements; that is where your own provider crates plug in.
4. **Engine.** `Engine::new(storage, leases, signal, node_profile(node_id, weight, always_on))`, then `skein_engine::run(engine, directory, RunConfig::new(liveness), shutdown)`. `RunConfig::observers` takes `AccountObserver`s that run after every successful run of an account.
5. **Push receivers.** Mount `skein_server::router(signal, Some(push_registry), &config)` next to your own routes, or serve it with `skein_server::serve`; it answers only the Gmail and Graph push routes and `GET /v1/health`.

Read `apps/skein/src` in the repository as the reference composition: [apps/skein README](https://github.com/peleda-app/rowboat/blob/main/skein/apps/skein/docs/README.md).
