---
title: skein-view
description: A mail, calendar and contacts database over the journal, as a library the app embeds.
sidebar:
  order: 6
---

`skein-view` is a library (`skein/crates/view`) that keeps envelopes, threads, full-text search, parsed content, calendars, events and contacts in SQLite with FTS5, following one tenant's journal straight from Skein's storage contracts. The Peleda app will embed it next to its node to answer lists, threads and search. All parsing of journal content for display lives here, so Skein's core stays dumb, and everything the database holds can be rebuilt from the journal and the original bytes. It listens on no network; its former binary, REST API and SSE follower are gone.

It is also a worked example of everything in this section: it reads with its own checkpoint, [verifies every segment](/rowboat/consumers/#reading-verified), handles [snapshots and compaction](/rowboat/consumers/#starting-and-falling-behind) and never writes anything back.

```rust
let store = Arc::new(Store::open(Path::new("view.sqlite"))?);
let follower = Follower::new(storage, tenant, store.clone())
    .with_signal(signal)           // optional: wake on the engine's heads/{account} hints
    .with_attestor(attestor);      // optional: the head attestor the journal's writers use
tokio::spawn(follower.run(Timing::default(), stop));

let inbox = store.messages("box", Some("INBOX"), None, 50)?;
let threads = store.threads("box", None, None, 50)?;
let found = store.search("box", &fts_query("garden report").unwrap(), 20)?;
```

## Following

- Every head is checked with the `HeadAttestor` (`NoAttestor` by default). Segments are read through the hash chain from the head and checked against the hash the chain names, one segment in memory at a time.
- The last segment applied in full is stored with the account. A newer journal must link to it, and a head behind the checkpoint is refused: storage cannot roll back, reorder or swap events under the database. Nothing is applied when a check fails.
- Each page of events is applied in one transaction with the checkpoint, so every event is applied exactly once.
- Originals are read from the blob store and checked against their hash; a missing, oversized or mismatching one is kept as unavailable (listed with metadata, without parsed fields).
- When the journal no longer has the events after the checkpoint (compaction), the account is rebuilt from the latest snapshot and following goes on from its `seq`.
- `Follower::run` syncs every account every `poll` (5 s); with a signal it reads an account as soon as its head hint arrives and syncs hinted accounts every `safety` (300 s) as well.

## Reads

| Call | |
| --- | --- |
| `accounts()` | followed accounts with checkpoint, head, lag and whether the first sync completed |
| `mailboxes(a)` | mailboxes with total and unread counts |
| `messages(a, mailbox, before, limit)` | envelopes newest first by `(sort_date, id)`; pass the last row's `(sort_date, id)` as `before` |
| `message(a, id)` | the envelope plus references, memberships, attachments, text, unsanitized HTML and the iMIP summary |
| `threads(a, mailbox, before, limit)`, `thread(a, id, limit)`, `tree(links)` | JWZ threads and the reply tree |
| `search(a, fts, limit)` | full-text search; build `fts` with `fts_query(text)` |
| `collections(a)`, `objects(a, collection, after, range, limit)`, `object(a, id)`, `search_contacts(a, fts, limit)` | calendars and contacts with parsed fields, a time range filter, contact search |

Every list returns at most the given limit and never more than 1000 rows. Message and object ids are the BLAKE3 hash of the original bytes, stable across rebuilds; the originals themselves are read from the blob store.

## Security

- `html` is the message's HTML exactly as sent. Sanitize it (and block remote content) before rendering; in Peleda, display goes through rinse.
- The database holds subjects, addresses, bodies, event summaries and contact details in plain text. Keep it on an encrypted disk; the file is created with mode 0600.

The full description, including parsing, calendars and contacts, threads and the schema, is in the [skein-view README](https://github.com/peleda-app/rowboat/blob/main/skein/crates/view/docs/README.md).
