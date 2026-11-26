# skein-pim

The calendar and contacts provider contract. A provider maps its change mechanism (DAV sync
tokens or ETag listings, Google sync tokens, Graph delta links, JMAP states) onto one model: per
collection, an opaque cursor and a batch of changes since it. Objects are the provider's original
iCalendar or vCard bytes; nothing is parsed or rewritten.

## API

- `PimProvider::connect() -> Box<dyn PimSession>`: signs in; changes nothing on the server.
- `PimSession::collections()`: every address book and calendar as `skein_core::CollectionInfo`
  (`id`, `kind: calendar | address_book`, `name`, `color`, `read_only`, `components`), each once,
  with stable ids; scheduling outboxes are left out, and a scheduling inbox is listed only when
  the provider is asked to, with `role: schedule_inbox`.
- `PimSession::changes(collection, cursor, limit) -> PimChanges { changes, cursor, more }` with
  `PimChange::{Reset { reason }, Upserted { item, version }, Removed { item }}`:
  - without a cursor, every object as `Upserted`, in pages of about `limit` with `more`;
  - with the previous cursor, exactly what changed since; nothing reported twice, nothing lost;
  - an invalid or unreadable cursor gives `Reset` followed by a full listing;
  - `Removed` may name an item the caller never saw (removed during a listing); callers ignore it.
- `PimSession::fetch(collection, items) -> Vec<RawObject { item, version, bytes, content_type }>`:
  the exact bytes of each object still present, each at most once, vanished ones left out;
  `version` belongs to exactly those bytes.
- `PimSession::apply(&PimWrite) -> WriteOutcome`:
  - `PimWrite::Put { collection, item: None, bytes, key, .. }` creates an object without ever
    overwriting one; the same `key` (the command id) makes at most one object, and repeating a
    create that succeeded answers with that object;
  - `PimWrite::Put { item: Some(..), if_version, .. }` replaces it; a version other than
    `if_version` is `Conflict { current }` and changes nothing;
  - `PimWrite::Delete { item, if_version, .. }`; a gone object counts as `Applied`;
  - `PimWrite::Respond { item, answer, attendee, comment, if_version, notify }` sets one
    attendee's participation status (the named one, or the account's own) through the
    provider's own way of answering; only that answer and comment change. `attendee_not_found`
    when nobody matches, `not_a_calendar` for address books; an applied one returns the object
    read back;
  - `notify` on `Put`, `Delete` and `Respond` asks a scheduling server to tell attendees or the
    organizer; without it the provider asks the server not to, where it can;
  - `Applied { item, current }`: for a put, `current` is the object read back as the server
    holds it, with its version; servers may rewrite objects, so its bytes need not equal the sent
    ones;
  - `Failed { reason }` (refused for good) and `Conflict` changed nothing; a `PimError::Network`
    means the outcome is unknown.
- `PimSession::scheduling(collection) -> Scheduling::{Server, Client}`: whether the server sends
  iTIP messages itself when a write asks it to (Google Calendar, Graph, JMAP, CalDAV with
  `calendar-auto-schedule`), or tells nobody, so the writer must mail them. Defaults to `Client`.
- `PimSession::addresses()`: the account's own calendar addresses, lower case without `mailto:`;
  empty when the provider cannot tell. Used to find the account's attendee and to check that it
  organizes an event.
- `PimError::{Auth, Config, Throttled { retry_after }, NotFound, Protocol, Network}`; messages
  never hold names, contents, addresses or secrets.

Every trait is object-safe, `Send` (sessions) or `Send + Sync` (providers), with `#[async_trait]`.

## Implementing a provider

Map the provider's cursor onto `Cursor` (opaque bytes, never credentials), report every change
since it, return the original bytes, and honour the version preconditions. Then run the
conformance suite against an in-process fake of the protocol:

```rust
skein_pim::testing::conformance(provider, control, "/calendars/ada/work/", CollectionKind::Calendar).await;
```

`control` implements `PimServerControl` (put, remove, invalidate cursors where the server has
them, read, contents) on the
fake server. The suite checks listing in pages, exact bytes and versions, incremental upserts and
removals, reset on an invalid and on an unreadable cursor, vanished objects left out, idempotent
creates by key, `if_version` conflicts on replace and delete, and deletes of gone objects.

## Testing

The `testing` feature has `FakePim`, an in-memory server and provider (`FakePim::standard()` holds
an empty calendar `CALENDAR` and address book `ADDRESS_BOOK`), with failure injection
(`fail_next`, `lose_next_answer`, `set_read_only`), counters, `fill` and `sample` objects.
Scheduling: `set_server_schedules`, `set_addresses`, and `notifies()` (the `notify` flag of every
write it received); `Respond` edits iCalendar objects with `skein-itip`.
