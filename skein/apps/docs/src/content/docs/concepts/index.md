---
title: Overview
description: The pieces Skein is made of and how they fit together.
sidebar:
  order: 1
---

Skein's model is small:

- An **account** is credentials plus whose data they reach. It belongs to a **tenant**, an id from the integrator's side.
- Exactly one **node** owns an account at a time. It holds the provider connections, writes the account's **journal** and runs its **commands**. See [ownership and fencing](/rowboat/concepts/ownership/).
- The journal is a numbered sequence of **events** per account. Content is stored separately as **blobs** addressed by BLAKE3. See [journal and events](/rowboat/concepts/journal/) and [blobs](/rowboat/concepts/blobs/).
- **Snapshots** fold the journal into the current state of an account, so old events can be **compacted** away. See [snapshots and compaction](/rowboat/concepts/snapshots/).
- Consumers change things by placing **commands** next to the journal; outcomes come back as events, including an honest "uncertain". See [commands and outcomes](/rowboat/concepts/commands/).
- Everything cheap to lose (previews, hints, access tokens, counters) goes through **signals**. See [signals](/rowboat/concepts/ephemeral/) and [previews and hints](/rowboat/concepts/delivery/).

## Object layout

Everything durable lives under one tenant prefix in object storage:

```
tenants/{t}/
├── control/      accounts, sealed credentials, cursors, owners, webhooks
├── heads/{a}     committed head, highest fencing token, tip hash, attestation
├── log/{a}/      zstd NDJSON segments of events, hash-chained
├── snapshots/{a}/
├── blobs/{hash}
└── commands/{a}/{ulid}
```

The exact keys are described in the [storage README](https://github.com/peleda-app/rowboat/blob/main/skein/crates/storage/docs/README.md).

## Change feed

Each provider maps its own change mechanism onto one model: a cursor per collection, a batch of changes, and an explicit reset when the provider stops accepting the cursor.

| Provider | Cursor | Push |
| --- | --- | --- |
| IMAP | `UIDVALIDITY`, `UIDNEXT`, `HIGHESTMODSEQ` (`CONDSTORE`); a compact UID snapshot | `IDLE`, `NOTIFY` |
| JMAP | `Email/changes` states | EventSource |
| Gmail API | `historyId` | Pub/Sub `watch`, polling otherwise |
| Microsoft Graph | delta links | subscriptions, polling otherwise |
| CalDAV, CardDAV | `sync-collection` tokens, ETag listings otherwise | none yet |
| Google Calendar, People | `syncToken` | polling |

Cursors are opaque and never hold credentials. An expired Gmail `historyId`, a Graph `410`, a new `UIDVALIDITY` or an invalid sync token becomes a reset (`resync_required` in the journal), followed by a full listing.
