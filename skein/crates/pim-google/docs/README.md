# skein-pim-google

Calendars and contacts on Google behind the [`skein-pim`](../../pim/docs/README.md) contract:
Google Calendar API v3 for calendars, People API v1 for the account's contacts. Tested against an
in-process fake of both APIs with a JSON version of the contract's conformance suite (see
[Conformance](#conformance)).

## Config

`GoogleProvider::new(GoogleSettings, Credentials)`:

| Setting | Default | |
| --- | --- | --- |
| `calendar_url` | `https://www.googleapis.com/calendar/v3` | Calendar API root |
| `people_url` | `https://people.googleapis.com/v1` | People API root |
| `calendars` | `true` | list and read calendars |
| `contacts` | `true` | list and read the `contacts` address book |

`GoogleSettings::from_json` reads them from JSON. Only `Credentials::AccessToken` is accepted; a
password, an empty token, a non-https address (plain http only to loopback), an address with a
user name or password, or both kinds switched off is `Config` before anything is sent.
`with_timeout` (default one minute) and `with_rate(calendar_per_minute, people_per_minute)`
(defaults 300 and 60, bursts of ten) tune the client. `Debug` never shows the token.

Refreshing the token is the caller's job; a refused token is `PimError::Auth`.

## Scopes

| Access | Scope |
| --- | --- |
| calendars, read and write | `https://www.googleapis.com/auth/calendar` |
| contacts, read and write | `https://www.googleapis.com/auth/contacts` |

They are what `skein_oauth::Access { calendar: Some(Rw::Write), contacts: Some(Rw::Write), .. }`
asks Google for. With `calendar.readonly` / `contacts.readonly` reading works and writes are
`Failed { reason: "insufficient_scope" }`.

## Collections

- Every calendar of `calendarList.list` (hidden ones included, deleted ones left out): id = the
  calendar id, name = `summaryOverride` or `summary`, color = `backgroundColor`, `read_only` when
  `accessRole` is `reader` or `freeBusyReader`, components `["VEVENT"]`.
- One address book, `contacts` (`skein_pim_google::CONTACTS`): the `people/me` connections. Other
  contact groups and "other contacts" are not read. Calendar ids always contain `@`, so they never
  collide with it.

## Object formats

Google has no per-object iCalendar or vCard export, so objects are Google's JSON resources:

| Kind | `content_type` | Item id | Version |
| --- | --- | --- | --- |
| event | `application/json; profile=google-calendar-event` | event id | `etag` |
| contact | `application/json; profile=google-people-person` | `people/c…` resource name | `etag` |

Bytes are exact: from a listing page each resource is the byte slice of that page (split with
`serde_json`'s `RawValue`, never re-serialized); objects not in the last page come from
`events.get` or `people.batchGet` (200 per request), again as sliced bytes. Contacts carry the
person fields in `READ_FIELDS` (names, nicknames, email addresses, phone numbers, addresses,
organizations, birthdays, events, relations, URLs, biographies, user-defined fields, photos,
metadata).

## Changes

- **Calendars:** `events.list` with `showDeleted=true`, `singleEvents=false`, `maxResults` up to
  the limit (at most 2500), paged with `pageToken`; the last page's `nextSyncToken` goes into the
  cursor. Recurring events are one item with their exceptions as separate items (Google's
  `singleEvents=false` view). Cancelled events are `Removed` in incremental runs and left out of
  full listings.
- **Contacts:** `people.connections.list` with `requestSyncToken=true`, `pageSize` up to the limit
  (at most 1000); persons with `metadata.deleted` are `Removed` in incremental runs.
- A refused token is `Reset` and a full listing in the same call: `sync_token_expired` for `410`
  (and People's `400 EXPIRED_SYNC_TOKEN`), `invalid_token` for another `400` to a token,
  `invalid_cursor` for a cursor that is not ours or belongs to the other API.
- Cursors are small JSON (`{"v":1,"f":"e"|"c","s":sync,"p":page}`) and never hold credentials.

## Writes

| Write | Calendar | Contacts |
| --- | --- | --- |
| create | `events.insert` with an id made from the command key (`skein` + base32hex) | `people.createContact` |
| replace | `events.update` with `If-Match` | `people.updateContact` with the etag in the body and `updatePersonFields=UPDATE_FIELDS` |
| delete | `events.delete` with `If-Match` | read the etag, compare, `people.deleteContact` |
| respond | `events.get`, then `events.patch` of `attendees` with `If-Match` | `Failed { reason: "not_a_calendar" }` |

- Every calendar write carries `sendUpdates=all` when `notify` is set and `sendUpdates=none`
  otherwise, so Google mails the attendees (or, for an answer, the organizer) only when asked.

- Every answer to a put is `Applied.current` with the bytes Google sent back.
- Bodies are sent unchanged except: an event create gets `"id"` and a contact replace gets
  `"etag"`, spliced in right after the opening brace with every other byte kept; only a body
  that already holds another `id`/`etag` is re-serialized.
- `412` (calendar) and `400 FAILED_PRECONDITION` (People) are `Conflict` with the current etag;
  a replace of a gone object is `Conflict { current: None }`; deleting a gone or cancelled object
  is applied.
- Event creates are idempotent across sessions: a repeat meets `409`, the event with that id is
  read and answered as applied (a cancelled one is `Conflict`, a `409` for another reason such as
  a taken `iCalUID` is `Failed { reason: "duplicate" }`). Contact creates are idempotent within
  one session only (the People API has no client-chosen ids); a contact create whose answer is
  lost is `Uncertain`.
- A replace sets every field in `UPDATE_FIELDS`, so a field missing from the object is cleared;
  every such field is also read, so the consumer always sees what a replace would clear. Photos
  change only through Google's photo calls.
- A respond reads the event, finds the attendee whose `email` matches `attendee` (ignoring
  case), or the one marked `"self": true` without it, sets its `responseStatus` (`accepted`,
  `declined`, `tentative`) and `comment` when given, and patches the whole `attendees` array back
  under `If-Match`: `if_version` when given, otherwise the etag it just read, so a concurrent
  change to another attendee is never overwritten (a `412` without `if_version` reads and tries
  again, up to three times). A stale `if_version` is `Conflict` with the current etag before
  anything is sent; a gone or cancelled event is `Conflict { current: None }`; no matching
  attendee is `Failed { reason: "attendee_not_found" }`. `Applied.current` is the event Google
  sent back. The answer applies to the item it names, the whole series for a recurring event.
- `Failed` reasons: `too_large` (over 4 MiB, or `413`), `invalid_object` (not a JSON object, or
  `400`), `invalid_key`, `not_in_collection`, `read_only` (`403 requiredAccessLevel`),
  `insufficient_scope`, `forbidden`, `duplicate`, `attendee_not_found`, `not_a_calendar`,
  `refused_{status}`.

## Scheduling

- `scheduling` is `Server` for calendars (Google sends invitations, updates and answers itself
  when a write asks with `notify`) and `Client` for the address book; a disabled kind or an empty
  id is `NotFound`. Unknown calendar ids are not checked, so they are `Server`.
- `addresses` reads `calendarList/primary` and returns its id in lower case when it contains `@`
  (the primary calendar's id is the account's address); empty when there is no primary calendar,
  its id is not an address, or calendars are switched off (then nothing is sent).

## Security and limits

- The token goes only to the origins of `calendar_url` and `people_url`, each API only to its
  own; every path segment is percent-encoded. Redirects are never followed (a `3xx` is
  `Protocol`).
- 32 MiB per answer (a listing page or one object), 64 KiB per error body, 4 MiB per object sent.
- Request timeouts (one minute by default, connect at most 30 s).
- Per-user token-bucket limiters per API, shared by a provider's clones and sessions.
- `429`, and `403` with `rateLimitExceeded`, `userRateLimitExceeded`, `quotaExceeded`,
  `RATE_LIMIT_EXCEEDED` or `RESOURCE_EXHAUSTED`, are `Throttled { retry_after }` from
  `Retry-After` seconds; `401` is `Auth`; `403` with a missing scope on a read is `Auth`; 5xx is
  `Network`.
- Error messages from Google are never read (they can echo names and addresses); only the reason
  codes are. Logs carry status codes, counts and timings, never ids of people, names, addresses,
  event or contact content, or the token.

## Quirks

- The People API is eventually consistent: a contact just created may take minutes to show in
  `connections.list`; a later sync picks it up.
- People sync tokens expire after about seven days; Calendar sync tokens at Google's discretion.
  Both lead to a `Reset`.
- `people.deleteContact` takes no precondition, so a delete with a version is a read and a compare
  first; a change between the two is not caught.
- Deleted events stay as cancelled events and keep their ids, so a create key whose event was
  deleted can never create again.

## Conformance

`skein_pim::testing::conformance` builds iCalendar and vCard text, changes an object by appending
a property line and expects a create to store exactly the bytes sent. None of that holds for JSON
resources that Google completes with `id`, `etag`, `kind` and metadata, so the crate runs the same
steps in `src/suite.rs` with JSON objects: changed objects are other objects, and a create is
checked by its content and by `Applied.current` being byte for byte what the server holds. Every
other check (paging, exact bytes, versions, no repeats, removals, `Reset` after expiry and for an
unreadable cursor, idempotent creates, `Conflict` on stale versions, deleting a gone object) is
kept. `cargo test -p skein-pim-google` runs it for a calendar and for the address book.
