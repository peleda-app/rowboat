# skein-pim-jmap

Calendars and contacts on JMAP servers behind the [`skein-pim`](../../pim/docs/README.md)
contract: JMAP for Contacts (RFC 9610, `urn:ietf:params:jmap:contacts`) and JMAP Calendars
(draft-ietf-jmap-calendars, `urn:ietf:params:jmap:calendars`), such as Stalwart or Fastmail.
Ported from Holtmail's `collection-jmap` (session handling, listings, changes with membership
checks, canonical bytes, idempotent creates by `uid`, `ifInState` retries); the iCalendar and
vCard conversion is left out, since Skein keeps the server's JSON.

## Config

```rust
let provider = JmapPimProvider::new(
    JmapPimSettings::new("https://jmap.example.com", "ada@example.com"),
    Credentials::Password { secret },   // or Credentials::AccessToken { token }
)?;
```

- `JmapPimSettings { url, username, roots }`, also read from JSON with `from_json` (the same keys
  as the JMAP mail settings). `Debug` hides the user name; the provider's hides the credentials.
- `session_url(input)`: `https://` is added when the scheme is missing, an address without a path
  gets `/.well-known/jmap`; only `https`, or `http` to loopback; no credentials in the address.
- `Credentials::Password` is HTTP Basic as `username` (`Config` without one),
  `Credentials::AccessToken` a bearer token (`Config` when empty).
- `with_timeout(d)`: two minutes per request by default.

## Session

A session address under `/.well-known/` is followed through its redirects (at most five, never
from https to http) **without credentials**; the session is then asked with credentials, and a
redirect of that request is refused. The session must offer contacts or calendars with a primary
account (`Config` otherwise); a kind it does not offer is left out and its collection ids are
`NotFound`. Its `apiUrl` must be on the session's own origin (`Protocol` otherwise, before
anything is sent there), so credentials never reach another host; `downloadUrl`, `uploadUrl` and
the event source are not used. `maxObjectsInGet` (capped at 500) and `maxCallsInRequest` (16) are
respected.

## Collections and objects

| Collection id | JMAP |
| --- | --- |
| `addressbook/<id>` | an `AddressBook` of the contacts account; `name`; read-only when `myRights.mayWrite` is false |
| `calendar/<id>` | a `Calendar` of the calendars account; `name`, `color`; read-only when neither `mayWriteAll` nor `mayWriteOwn`; components `VEVENT` |

Every object is the JSContact card (`application/jscontact+json`, `CARD_MEDIA_TYPE`) or
JSCalendar event (`application/jscalendar+json`, `EVENT_MEDIA_TYPE`) from the server's `/get`
answer, written again with the keys of every object sorted, compact, with `serde_json`'s escapes;
values, array order and every property stay the server's. Neither JMAP specification offers the
iCalendar or vCard bytes of an object: Stalwart 0.16 has no `blobId` on `ContactCard` or
`CalendarEvent` (only `…/parse` to read blobs in), so the JSON is the original. Stalwart writes
the keys of one unchanged object in a different order on every answer; without sorting, every
read would look like a new version. Recurring events come as the master with its
`recurrenceOverrides`, never expanded.

`version` is a BLAKE3 hash of those bytes (32 hex digits): JMAP keeps no version per object, so
equal versions mean equal objects. Objects over 16 MiB are left out of fetches with a warning.

## Changes

- Without a cursor: one request checks the collection (`AddressBook/get` / `Calendar/get`), takes
  the item state (`ContactCard/get` / `CalendarEvent/get` with no ids) and starts
  `…/query` with `inAddressBook` / `inCalendar`, paged 1 000 at a time; a listing whose
  `queryState` moves while it is paged starts again (five times at most), so no object slips past
  a shifted position. A page equal to the one before is `Protocol`, and so are more than a million
  ids.
- With a cursor: `…/changes` from its state with `maxChanges` set to the limit, next to a check
  that the collection still exists (`NotFound` otherwise). Created and updated ids are checked
  with a `/get` of `id` and the collection map: those in the collection are `Upserted`, the others
  (moved to another collection) `Removed`, and destroyed ids `Removed`. Changes are per account, so
  `Removed` can name ids that were never in this collection; consumers ignore those. `Upserted`
  carries no version.
- `cannotCalculateChanges`, and `invalidArguments` for a state the server cannot read (Stalwart's
  answer to a malformed state), are `Reset { reason: "state" }` and a full listing; an unreadable
  cursor or one for another collection is `Reset { reason: "cursor" }`.
- Changes beyond `limit` stay in the cursor; `hasMoreChanges` is `more`.
- Method errors `forbidden`, `accountNotFound`, `accountNotSupportedByMethod` are `Auth`; others
  `Protocol` with the error type only.

## Writes

`PimWrite::Put` takes a JSContact or JSCalendar object (anything else is
`Failed { reason: "not_json" }`, more than 16 MiB `too_large`). Server-set properties are never
sent: `id`, `blobId`, `created`, `updated`, `isOrigin`, `utcStart`, `utcEnd`, `baseEventId`, and
the collection map, which a create sets to only the target collection.

- **Create** is idempotent by `uid`: the object's own, else the command id, which the object then
  carries. A `/query` for that `uid` in the collection comes first; an object there that holds
  every property sent is the earlier create and the answer, any other is `Conflict` with its
  version, so a new object never silently replaces an old one. Then `/set` `create`. A create
  refused because the `uid` is taken (`alreadyExists`, or Stalwart's `invalidProperties` naming
  `uid`, seen when its query index lags behind a busy server) looks again, up to five times over
  about 1.5 s, and answers as above; still nothing is `Conflict { current: None }`.
- **Replace** reads the object, compares its version with `if_version` (`Conflict` with the
  current version when it differs, `Conflict { current: None }` when the object is gone or in
  another collection), then sends a `/set` patch of every top-level property that differs, and
  `null` for properties the new object lacks, except `uid`, `@type`, `version`, server-set
  properties, the collection map and booleans (JSCalendar gives them defaults and Stalwart refuses
  `null` for them). With `if_version` the patch carries `ifInState` from that read; a
  `stateMismatch` caused by any other object is answered by reading and comparing again, five
  times at most, then `Throttled`.
- **Delete** reads the object the same way; one already gone, or in another collection, is
  `Applied`, and so is `notDestroyed: notFound`.
- An applied put is read back and returned as `Applied.current`.
- On calendars every `/set` carries `sendSchedulingMessages` set to the write's `notify`, so the
  server tells attendees only when asked; address books get no such argument.
- Per-object errors are `Failed` with the JMAP error type (`forbidden`, `invalidProperties`, …);
  method errors `accountReadOnly`, `forbidden`, `invalidArguments` are `Failed`,
  `requestTooLarge` is `too_large`, others `Protocol`. A request that went out without an
  answer is `Uncertain`.

## Scheduling

`scheduling(collection)` is `Server` for calendars and `Client` for address books, after a check
that the collection exists (`NotFound` otherwise): a JMAP server sends iTIP messages itself when
a `/set` asks with `sendSchedulingMessages`.

`addresses()` reads `ParticipantIdentity/get` of the calendars account and keeps every `mailto:`
value of each identity's `calendarAddress` (JSCalendar-bis, as Stalwart answers) and `sendTo`
(RFC 8984), without the scheme and in lower case; a server that answers
`unknownMethod` contributes none. The session's `username` is added when it is an address. Each
address appears once.

`PimWrite::Respond` on an address book is `Failed { reason: "not_a_calendar" }`. On a calendar it
reads the event like a replace (`Conflict` with the current version when `if_version` differs,
`Conflict { current: None }` when the event is gone or in another collection) and looks for the
participant in `participants`: with `attendee`, the one whose `mailto:` `calendarAddress`,
`sendTo.imip` or `email` equals it, ignoring case and a `mailto:` prefix; without, one reached at any of `addresses()`. A
participant with the `attendee` role wins over others with the same address (an organizer listed
twice). No match is `Failed { reason: "attendee_not_found" }` with nothing sent. The write is a
`/set` patch of `participants/<id>/participationStatus` (`accepted`, `declined`, `tentative`)
and, with a comment, `participants/<id>/participationComment`, with `sendSchedulingMessages` from
`notify` and `ifInState` from the read when `if_version` is given, retried on another object's
`stateMismatch` as for a replace. Instances in `recurrenceOverrides` that are not excluded and
change participants themselves get the same answer: a whole `participants` map there (as
Stalwart stores it) is patched on the participant reached at the same address, and a patch key
`participants/<id>/participationStatus` is replaced. An applied answer
returns the event read back as `Applied.current`.

## Limits and safety

- 1 MiB for the session, 64 MiB per API answer.
- Busy reads (`429`, or `503`/`504` with `Retry-After`) are tried three times within about ten
  seconds, then `Throttled { retry_after }`; a busy `/set` is `Throttled` at once.
- `401` and `403` are `Auth`.
- Logs carry counts only; error texts name the host and status or the JMAP error type, never
  ids, names, addresses or secrets.

## Tests

`src/tests.rs` runs an in-process fake JMAP server (axum) with a well-known redirect, a session
with or without calendars, `AddressBook`/`Calendar` `/get` with rights, `ContactCard` and
`CalendarEvent` `/get`, `/query` (with `uid`), `/changes` with a floor for
`cannotCalculateChanges` and `/set` with `ifInState`, a forced `stateMismatch` from another
object, and a read-only calendar. The contract's `conformance` suite assumes iCalendar and vCard
text stored byte for byte; a JMAP server completes every object with its id and collection map,
so the crate runs `json_conformance`, the same checks with JSON objects where a create must keep
every property sent instead of the exact bytes. It passes for a calendar and an address book,
with two objects per page and with one. Further tests cover names, colors and access, a session
without calendars, canonical bytes, a card moved to another address book, unknown states, retries
after another object's change and conflicts after the object's own, refused writes, waiting on
`503`, an API address on another origin refused with nothing sent there, an oversized session,
refused passwords and bad settings. The fake also records `sendSchedulingMessages` per `/set`,
applies patch paths into nested objects and answers `ParticipantIdentity/get` or `unknownMethod`;
tests cover `notify` on creates, replaces and deletes (and its absence on address books),
`scheduling`, answers by a named attendee (by `calendarAddress`, `sendTo` and `email`, with a comment) and by the
account's own identity, unknown attendees, stale versions, gone events and address books, and
`addresses` with and without `ParticipantIdentity`.

Against Stalwart 0.16 in the integration stack, `pim_jmap_round_trip_against_stalwart` in
[`tests/integration/tests/it.rs`](../../../tests/integration/tests/it.rs) makes a fresh address
book and calendar, then for each: an empty first listing, a create and its repeat, the change,
bytes stable across reads, a stale update and a stale delete conflicting, an update, an object
made outside Skein, a delete reported as `Removed`, and a reset listing; then `scheduling`,
`addresses`, and an answer to a recurring invitation (Stalwart wants JSCalendar-bis
`recurrenceRule` and keeps participants by `calendarAddress`) that also reaches an instance with
its own answer.
