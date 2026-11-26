# skein-view

A mail database over Skein's journal, as a library: envelopes, threads, full-text search, parsed content, calendars, events and contacts in SQLite with FTS5, followed straight from Skein's storage contracts. The Peleda app will embed it next to its node to answer its lists, threads and search; nothing here listens on the network (the former `skein-view` binary, its HTTP API and its HTTP follower are gone). Skein's engine stays dumb: all parsing of journal content for display lives here, and everything the database holds can be rebuilt from the journal and the original bytes.

```rust
let store = Arc::new(Store::open(Path::new("view.sqlite"))?);
let follower = Follower::new(storage, tenant, store.clone())
    .with_signal(signal)            // optional: wake on the engine's `heads/{account}` hints
    .with_attestor(attestor);       // optional: the head attestor the journal's writers use
tokio::spawn(follower.run(Timing::default(), stop));
let page = store.messages("box", Some("INBOX"), None, 50)?;
```

## Public API

| Item | Guarantees |
| --- | --- |
| `Store::open(path)` | opens or creates the database (mode 0600 on Unix), WAL mode, one write and one read-only connection, schema migrated in place; a newer schema is `StoreError::TooNew` |
| `Store::{accounts, mailboxes, messages, message, has_message, threads, thread, search}` | mail reads; lists newest first by `(sort_date, id)`, pass the last row's `(sort_date, id)` (threads: `(latest.sort_date, id)`) as `before` for the next page |
| `Store::{collections, has_collection, objects, object, search_contacts}` | calendar and contact reads; objects by item id, pass the last item as `after`; `Range` limits events to those overlapping `[from, to)` |
| every list | at most the given limit and never more than `MAX_LIMIT` (1000) rows, whatever limit is asked |
| `Store::{note_head, checkpoint, tip, has_content, insert_content, has_object, insert_object, apply_page, apply_page_to, rebuild}` | the write side the follower uses: each page of events, or a rebuild from a snapshot, is applied together with the account's checkpoint in one transaction |
| `Store::{messages_where, threads_where, search_where}` with `Filter` | the same reads narrowed by mailboxes (any of a list), unread, flagged (some membership has `\Flagged`), attachments and a tag; filter values are bound parameters, never SQL |
| `Store::{suggest_addresses, knows_address}` | the per-account address book filled when a message is parsed (address in lower case, latest display name, counts as sender and recipient); suggestions match the address or name prefix case-insensitively (`%` and `_` are literal), most used first, at most `MAX_SUGGESTIONS` (50); `knows_address` is true only for a `To` or `Cc` of a message in a `sent` mailbox, never for addresses only seen in received mail |
| `Store::{mailbox_role, knows_blob, blobs_of, forget_account}` | a mailbox's role; whether any account names a blob; an account's blobs in pages; removing everything of one account in one transaction |
| `Envelope::{flagged, tags}` | whether some membership is flagged; the parser's tags, sorted |
| `Follower::new(storage, tenant, store)` | follows every account of one tenant; `with_accounts`, `with_page_size` (200 by default), `with_max_blob_bytes` (64 MiB by default), `with_attestor`, `with_signal`, `with_parser`, `with_observer` |
| `MessageParser`, `MailParser`, `ParseContext`, `ParseError` | the parser hook: `parse(raw, context)` gives a `Parsed` or `Refused` (stored as unavailable) or `Unavailable` (the page is left for the next round, `FollowError::Parser`); `MailParser` is the built-in `mail-parser` path; the hook's `version()` is stored with each message |
| `Follower::reparse_stale(limit)`, `REPARSE_PER_ROUND` | parses again, with the current parser, at most `limit` stored messages another parser version produced (or, available, with no version recorded), oldest first; replaces envelope, body, attachments, invitation, tags and the search entry, keeps threads, memberships and the address book; a refused message becomes unavailable; one whose original is gone keeps its content and gets the current version; `run` does `REPARSE_PER_ROUND` (50) after every round. `Store::stale_messages`, `Store::replace_parsed`, `Store::mark_parsed` are the store's halves |
| `ViewObserver`, `PageReport` | called after every committed page and rebuild, in commit order: account, checkpoint, head, messages added (the first 256 by mailbox, message id and whether `\Seen` was set), touched mailboxes (at most 64, else `Many`), whether mailboxes changed, first sync, and command outcomes (command id, kind, a one-word reason) |
| `Follower::sync_once`, `Follower::sync_account` | bring the accounts up to their heads now; one failing account does not stop the others in `sync_once` |
| `Follower::run(timing, stop)` | follows until `stop` turns true, see below |
| `fts_query(text)` | the FTS5 query for user text, `None` when there is nothing to search |
| `tree(links)`, `Link`, `Node` | the reply tree of a thread's messages |
| `subject_key` | the normalized subject threads group by |

Original bytes are not copied into the database: read them from Skein's blob store (`Storage::blobs`), whose `get` checks them against their hash.

## Following the journal

The follower reads the storage contracts directly, the same `Storage` the node writes (on a device, the node's local storage; on a server, the shared one).

- **Verified like an untrusted tier.** For each account the follower reads the signed head and checks it with the `HeadAttestor` (`NoAttestor` by default, which accepts every well-formed head). It then walks the hash chain back from the head with `skein_storage::Chain` until the segment holding `checkpoint + 1`, keeping only the segment references, and reads those segments forward again, checking every one with `verify_segment` against the hash the chain named: header, account, range, link and numbering. Memory holds one segment at a time.
- **No rollback, no swapped history.** The last segment applied in full is stored with the account (`tip`). The segment holding `checkpoint + 1` must name it as its predecessor, and a head at the checkpoint must point at it; otherwise the account fails with `IntegrityError::Fork`. A head behind the checkpoint is `IntegrityError::Rollback`. Nothing is applied in either case and the checkpoint stays.
- **Exactly once.** Each page is applied in one SQLite transaction that also advances the checkpoint (and, on a segment's last page, the tip); events at or before the checkpoint are skipped and a gap fails the whole page, so a crash or retry never applies an event twice or skips one.
- **Content first.** Before a page is applied, the original bytes of every `message_added` and `object_upserted` blob not yet stored are read from the blob store and parsed into their own small transaction. A blob that is missing, larger than `max_blob_bytes`, or does not match its hash is stored as unavailable: the message or object is listed with its metadata but without parsed fields.
- **Compaction.** When the chain reaches a segment the journal no longer has, the account is rebuilt from the latest snapshot: content for every message and object in it is stored, then one transaction replaces the account's mailboxes, memberships, collections and placements with the snapshot's, sets the checkpoint to its `seq` and clears the tip. A rebuild only moves a follower forward: a snapshot at or before the checkpoint is `IntegrityError::Rollback` (a follower past the snapshot never needs it, so a missing later segment is withheld history, not compaction) and one past the attested head is `IntegrityError::Mismatch`; nothing changes in either case and the tip stays. Snapshots are not chained, so a rebuild of a follower behind the snapshot trusts storage as far as the snapshot goes; following goes on from `seq + 1` with verified segments. Binding snapshots to the chain is an open question. A follower already past the snapshot reads on without the compacted segments, since the link check needs only the next segment's predecessor reference.
- **When.** `run` syncs every account every `Timing::poll` (5 s by default). With a signal it subscribes each account to the engine's `heads/{account}` hints in the tenant's group and reads an account as soon as a hint arrives; hints carry no delivery guarantee, so hinted accounts are still synced every `Timing::safety` (300 s by default), and new accounts are looked for every `poll`.
- **Mail events.** `mailbox_upserted` and `mailbox_deleted` maintain mailboxes (deleting one drops its memberships). `message_added` adds or replaces the membership (mailbox, item) with its flags and labels; the same blob in several mailboxes (Gmail labels, IMAP copies) is one message with several memberships. `message_removed` drops the membership, and the message once no membership is left. `flags_changed` and `labels_changed` replace a membership's set. `first_sync_completed` is recorded per account.
- **Calendar and contact events.** `collection_upserted` and `collection_deleted` maintain calendars and address books (deleting one drops its objects). `object_upserted` adds or replaces the placement (collection, item) with its version (ETag, `changeKey`); an object for a collection never described gets one named by its id, an address book for contact formats and a calendar otherwise. As with messages, the same blob in several collections is one object with several placements, and it is dropped once no placement is left. `object_removed` drops the placement.
- **Resync.** `resync_required` empties the mailbox (domain `mail`), the collection (`calendar`, `contacts`) or both (no domain), as the listing that follows adds back what is still there.
- **Ignored.** `itip_received` (the same facts are read from the message bytes, see Parsing), command outcomes, health, capabilities and event types this build does not know only move the checkpoint.
- **Failures.** An account that fails (storage down, a refused segment, a gap) is logged with its id and the error and retried next round; the others go on. Logs carry account ids, blob hashes, counts and sequence numbers, never content, subjects, addresses or keys.

## Parsing

A parser hook (`Follower::with_parser`) replaces everything below: the Peleda node passes one that renders through rinse's sandboxed workers, so nothing in its process parses message bytes. Whatever a hook returns, the store keeps at most 8 tags that pass `valid_tag` (`[a-z0-9._-]{1,64}`), sorted and without repeats. Schema version 4 adds `tags`, the parser version and the address book; messages stored before, and messages parsed by another parser version, are parsed again in the background, `REPARSE_PER_ROUND` at a time.


`mail-parser` reads `Message-ID`, `In-Reply-To` and `References` (angle brackets stripped), the decoded subject, `From`/`To`/`Cc` (name and address, groups flattened), `Date`, the size, RFC 8621 `hasAttachment` and the attachment list (part index in document order, name, content type, decoded size), a text body (plain text parts, or text made from HTML when there is no plain part; capped at 1 MiB), the HTML body as written (dropped above 2 MiB, never cut), and a 200-character snippet. Lists sort by `sort_date`: the event's `received_at`, else `Date`, else when the event was written.

A message carrying an iMIP calendar part (RFC 6047) gets `itip`: method, component, UID, sequence, organizer and attendees as `skein-itip` reads them. Messages stored before schema version 2 lack it until the account is rebuilt.

## Calendars and contacts

Objects are parsed by their media type into `format`:

| `content_type` | `format` | |
| --- | --- | --- |
| `text/calendar` | `icalendar` | the master `VEVENT`/`VTODO`/`VJOURNAL` (the first without `RECURRENCE-ID`); UID, summary, organizer and attendees through `skein-itip`'s reader |
| `text/vcard` | `vcard` | `FN` (else `N`), `EMAIL`, `TEL`, first `ORG` component, `UID` |
| `application/json; profile=google-calendar-event` | `google_event` | Google Calendar event |
| `application/json; profile=google-people-person` | `google_person` | Google People person |
| `application/json; profile=graph-event` | `graph_event` | Microsoft Graph event (`isCancelled` gives `CANCELLED`) |
| `application/json; profile=graph-contact` | `graph_contact` | Microsoft Graph contact |
| `application/jscalendar+json` | `jscalendar` | JMAP JSCalendar event or task |
| `application/jscontact+json` | `jscontact` | JMAP JSContact card |
| anything else | `other` | metadata only; the original stays in the blob store |

Parsed fields: `kind` (`event`, `task`, `contact`, `other`), `uid`, `summary`, `start` and `end` (milliseconds, UTC, end exclusive), `all_day`, `tzid`, `recurring`, `status` (upper case), `organizer` and `attendees` (addresses, lower case), `full_name`, `emails`, `phones`, `org`. Lists keep at most 100 entries, texts 1000 characters; objects above 4 MiB keep only their metadata.

- **Times.** UTC times are exact. A time with `TZID` uses the offset of the object's own `VTIMEZONE` for that id, taking its `STANDARD` part (daylight saving time is not applied, so summer times may be an hour off); a zone the object does not define, a floating time, and zone-named times in Graph and JSCalendar objects are taken as UTC. `tzid` keeps the zone as written so clients can convert exactly. Dates (`VALUE=DATE`, Google `date`, JSCalendar `showWithoutTime`) are all-day from midnight UTC; an all-day event without an end lasts one day, a timed one without an end or duration is a moment. A task's end is its `DUE`, and its start falls back to it.
- **Recurrence is not expanded.** `recurring` says the object has `RRULE`/`RDATE` (Google `recurrence`, Graph `recurrence`, JSCalendar `recurrenceRules`); `start` and `end` are the first instance's. Overridden instances are part of the same object and not described.

## Threads

JWZ grouping without the tree. Each message joins the thread of any message sharing its `Message-ID`, an `In-Reply-To` id or a `References` id. Ids that are only referenced are remembered, so a reply that arrives before its parent leaves the parent's id behind and the parent joins the same thread later. When a message's ids reach several threads, they are merged into the oldest. A message with no reference ids whose subject carries a reply prefix (`Re:`, `Fwd:`, list tags, as `mail_parser::thread_name` strips them) joins the newest thread with the same normalized subject; messages with the same subject and no prefix stay apart. Threads never split when messages leave, and a thread id may disappear when its thread is merged into another.

`tree` builds the JWZ container tree of a thread's messages (steps 1 to 4 of the algorithm) on demand: each message hangs under the last id of its `References`, or else its `In-Reply-To`, and consecutive `References` ids are linked unless already placed; links that would make a loop are skipped. Ids that are referenced but not here become placeholders (`{message_id, children}` without `id`): one without children is dropped, one below another container is replaced by its children, and a root one with a single child gives way to it. Messages sharing a `Message-ID` stay apart (the later one as if it had none). Siblings and roots are ordered by the oldest message under them. A node is `{id, message_id, children}`; `children` is left out when empty.

## Search

SQLite FTS5 (`unicode61`, diacritics folded) over subject, names, addresses and text body for messages, and over full name, organization and addresses for contacts. User text is never passed as FTS syntax: each whitespace-separated term is quoted, all terms must match, and a trailing `*` makes a term a prefix. `fts_query` returns `None` for text with nothing searchable, and anything FTS5 still refuses is `StoreError::BadQuery`, never a panic.

## Schema

The database records its schema version in SQLite's `user_version`. On open, every migration after it is applied in order, each in one transaction with the new version, so an older database is upgraded in place and a crash leaves it at the last whole step; a database from a newer build is refused. Version 1 holds mail; version 2 adds `itip` on messages, collections, objects, placements and the contact index; version 3 adds each account's last verified journal segment (`tip`). Everything can still be rebuilt from the journal by deleting the file.

## Security

- **HTML is unsanitized.** `html` is the message's HTML exactly as sent, scripts and remote images included. Callers must sanitize it (and block remote content) before rendering; in Peleda, display goes through rinse.
- **The database holds mail, events and contacts.** Subjects, addresses, bodies, attachment names, event summaries, attendees, contact names and phone numbers are stored in plain text in the file and its `-wal`/`-shm` files. Keep it on an encrypted disk, readable only by its user; the file is created with mode 0600.
- **Journal integrity** is checked as described above; the snapshot used after compaction and the parsed content of a blob are as trustworthy as the storage and the original bytes.

## Tests

Unit tests next to the parser, the calendar and contact parser, the store, threads and search. `src/e2e.rs` follows a journal written through Skein's storage contracts into a fresh database and checks every read (paging, threads and the tree, search, flags and removals), the rebuild after compaction (fresh followers and one past the snapshot), calendars and contacts through a rebuild, signal hints and polling, the account filter, the row cap, and attacks: a bit-flipped segment, a rolled-back head, a swapped history (fork), a missing later segment with an older forged snapshot (no rollback), a forged snapshot past the head, a head the attestor refuses, and a corrupt or oversized original.

## Limits and what is not done

- Recurring events are not expanded, time zones are approximated as described above, and the fields of provider JSON objects are a common subset; everything else is in the original bytes.
- `itip_received` events are not stored; invitations are read from the message bytes instead.
- Thread listing groups all of an account's messages on every request, fine for mailboxes up to some hundred thousand messages; read at most 1000 messages per thread for the tree.
- Threads never split; subject grouping applies only to unreferenced messages with a reply prefix.
- Attachments are listed but not stored on their own; take the part from the original.
