---
title: Signals
description: Everything that is cheap to lose, and why losing it is harmless.
sidebar:
  order: 7
---

Baton's `Signal` contract (`baton-signal`) carries data that is cheap to lose. Nothing in it may be needed for correctness: if every signal is lost, everything keeps working, only slower, through polling. Every signal lives in the group of its tenant (`skein_core::coordination::group`).

## What goes through it

- previews and head hints (see [previews and hints](/rowboat/concepts/delivery/));
- command hints that wake an account's worker (`commands/{account}`), and push hints (`push/{account}`);
- OAuth access tokens, sealed (refresh tokens stay sealed in durable storage);
- shared counters for API rate limits.

Node liveness is not a signal: it goes through Baton's `Liveness` contract next to the leases (see [ownership and fencing](/rowboat/concepts/ownership/)).

## Contract

| Operation | Guarantees |
| --- | --- |
| `publish` / `subscribe` | group-scoped topics; at most once, in order per publisher, no delivery guarantee; a slow subscriber never blocks publishers |
| `put` / `get` / `delete` | group-scoped values, never returned after their time-to-live |
| `incr` | optional atomic counters shared by every process on the backend; a backend without them answers `None` and callers count per process |

Names are `[a-zA-Z0-9_.:/-]`, 1–200 bytes; payloads and values at most 64 KiB. Baton's signal suite (`baton_signal::testing::signal`) checks every implementation.

## Implementations

| Implementation | Status |
| --- | --- |
| `baton-signal-local` | one process: broadcast channels (a subscriber keeps at most 16 undelivered messages), an in-memory map with expiry, counters, all bounded |
| a shared backend for several nodes | planned in Baton |

With `baton-signal-local`, previews and hints reach consumers through that node's API only.
