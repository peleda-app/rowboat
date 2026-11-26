---
title: Writing a consumer
description: A consumer loop that builds a projection from the journal and writes through commands.
sidebar:
  order: 2
---

A consumer is any program that turns the journal into something useful: an archive, a search index, a thread view, a mail server. This page sketches one in Rust over the storage contracts; [`skein-view`](/rowboat/consumers/skein-view/) is the full version, with verification and rebuilds.

## 1. Catch up

```rust
async fn catch_up(storage: &Storage, db: &Db, t: &TenantId, a: &AccountId) -> anyhow::Result<()> {
    let head = storage.log.head(t, a).await?;
    loop {
        let from = db.checkpoint(a)? + 1;
        if from > head.0 {
            return Ok(());
        }
        let events = match storage.log.read(t, a, Seq(from), 1000).await {
            Ok(events) => events,
            Err(StorageError::Compacted { .. }) => {
                let snapshot = storage.log.latest_snapshot(t, a).await?.context("no snapshot")?;
                db.rebuild(a, &snapshot)?;            // replace state, checkpoint = snapshot.seq
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        db.transaction(|tx| {
            for event in &events {
                apply(tx, storage, t, event)?;
            }
            tx.set_checkpoint(a, events.last().map(|e| e.seq.0))
        })?;
    }
}
```

## 2. Apply events

- `message_added`: read the blob with `storage.blobs.get(t, &blob)` and store what you need from it.
- `message_removed`, `flags_changed`, `labels_changed`: update the membership.
- `resync_required`: this mailbox or collection is listed again from scratch; the listing follows as ordinary `message_added` or `object_upserted` events.
- Skip event types you do not know: newer writers may add types.
- Never parse what you do not need. The blob is the truth; derived fields can be recomputed.

## 3. Stay current

Poll `storage.log.heads(t)` and catch up the accounts whose head moved. In the node's process, also subscribe to `heads/{account}` on the Baton `Signal` in the tenant's group (`skein_core::coordination::group`) and catch up at once; hints may be lost, so keep polling.

## 4. Write through commands

```rust
let command = Command { id: CommandId::generate(), account, created_at, trace: None, body };
skein_engine::submit_command(&storage, &*signal, &tenant, &command).await?;
```

`submit_command` runs the checks every command must pass, refuses a command whose blob is not stored yet, treats the id as the idempotency key and hints the owner. From the command line, `skein journal submit` does the same. Keep the id: the outcome arrives as `write_applied`, `conflict`, `write_failed` or `write_uncertain` with `origin` equal to it, and the provider's own change event carries the same `origin`. Handle `write_uncertain` explicitly: read the current state from later events before deciding to try again. The command shapes are in the [core README](https://github.com/peleda-app/rowboat/blob/main/skein/crates/core/docs/README.md).
