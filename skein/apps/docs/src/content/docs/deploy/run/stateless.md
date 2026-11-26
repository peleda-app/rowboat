---
title: Stateless deployment
description: No local disk and no database on a server; what lives where.
sidebar:
  order: 3
---

With S3 storage, a Skein node needs no local disk and no database. Everything durable lives in object storage with compare-and-swap; everything in memory is cheap to lose. Any node can be killed at any time.

| State | Where | Lost when the node dies? |
| --- | --- | --- |
| accounts, sealed credentials, OAuth grants, webhooks | `control/` in object storage | no |
| provider cursors, lease records, node heartbeats and fencing tokens | `control/` | no |
| journal, snapshots, blobs, queued commands | object storage | no |
| previews, hints, access token cache, rate-limit counters | signals | yes, harmlessly |
| provider connections, push subscriptions' renewal | the account's owner | taken over by another node |

The one local file is the keyring's master key (`keyring.master_key_file`). Every node of a deployment needs the same one; mount it from a secret store. Losing it makes every tenant's sealed data unreadable.

## Write order makes crashes harmless

A sync writes blobs, then previews, then events, then the cursor. A crash before the cursor moves makes the next owner fetch the same changes again, and the repeated events are dropped by their keys. A command that may have reached the provider before a crash is reported `write_uncertain`, never run twice. See [journal and events](/rowboat/concepts/journal/#how-a-sync-writes).

## Storage cost

Costs follow mail volume, not the number of accounts: heartbeats are per node, and consumers poll one heads resource per tenant. As an estimate, ten people each receiving and sending 150 messages a day cause about 8,000–10,000 PUT requests a day, mostly blobs, and a buffer of 10–15 GB with 30-day blob retention.

## Limits today

Signals are in-process (`baton-signal-local`): previews and hints reach consumers in the process of the node that owns the account. A shared backend for several nodes is planned. Correctness does not depend on it; without it consumers fall back to polling heads.
