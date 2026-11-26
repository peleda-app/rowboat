---
title: Reading the journal
description: Checkpoints, verified segments, snapshots and compaction for programs that follow the journal.
sidebar:
  order: 1
---

A consumer reads each account's journal at its own pace with its own checkpoint: the `seq` of the last event it applied. Skein keeps no state per consumer. Consumers read the storage contracts directly (`skein-storage`, over the same object storage the node writes); there is no HTTP API for it. [`skein-view`](/rowboat/consumers/skein-view/) is a complete consumer to embed or copy from.

## Reading verified

- `Log::heads(tenant)` lists every account with its head; `Log::signed_head(tenant, account)` gives the head with its tip (the last segment) and attestation. Check it with `verify_head` and the `HeadAttestor` your writers use.
- `Chain::new(&*log, &head)` walks the segments back from the tip, verifying each against the hash the newer one names. Walk back to the segment holding `checkpoint + 1`, then apply forward. `Log::read(tenant, account, from, limit)` reads committed events without verification, for trusted storage.
- Keep the last segment you applied in full. The next segment you apply must name it as its predecessor, and a head at your checkpoint must point at it; a head behind your checkpoint is a rollback. `skein-view` does exactly this.
- Store your checkpoint in the same transaction as the changes you derived from the events. Applying an event must be idempotent by `seq`.

## Starting and falling behind

- When the chain reaches a segment the journal no longer has, it was compacted: load `Log::latest_snapshot`, rebuild your state from it, and read events from `snapshot.seq + 1`. Readers that fall behind by less than the retention window (`retain_days`, default 7) never see this.
- `Log::read` from a compacted position fails with `StorageError::Compacted { first }`.

## Knowing when to read

| Way | Latency | |
| --- | --- | --- |
| poll `Log::heads` every few seconds | up to the interval | one listing for every account of a tenant |
| the engine's `heads/{account}` hints on the Baton `Signal` | immediate, in the same process | hints may be lost; keep polling at a slower rate |
| [webhooks](/rowboat/consumers/webhooks/) | after each run | the events themselves, signed, to an HTTPS endpoint |

## Content

Events point at blobs. `BlobStore::get` returns the original bytes and checks them against their hash, so a hash never names other bytes. Blobs may expire (by a lifecycle rule); bring one back with a `refetch` command.

## Your own writes

Events caused by a command carry its id in `origin`. Use it to recognize your own writes when they come back from the provider. See [Writing a consumer](/rowboat/consumers/writing-a-consumer/).
