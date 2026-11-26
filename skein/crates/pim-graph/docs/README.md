# skein-pim-graph

Calendars and contacts of Microsoft 365, Outlook.com and Hotmail accounts through Microsoft
Graph, behind the [`skein-pim`](../../pim/docs/README.md) contract. Ported from Holtmail's
`collection-graph` (reading, collections, series masters, idempotent creates); the iCalendar and
vCard conversion is left out, since Skein keeps Graph's own JSON.

## Config

```rust
let provider = GraphPimProvider::new(
    GraphPimSettings { api_url: None, user: None, roots: TlsRoots::default() },
    Credentials::AccessToken { token },
)?;
```

- `GraphPimSettings { api_url, user, roots }`, also read from JSON with `from_json` (the same keys
  as the Graph mail settings; other keys are ignored). `api_url` defaults to
  `https://graph.microsoft.com/v1.0` (a national cloud's address works too); only `https`, or
  plain `http` to a loopback address, and no credentials in it. `user` missing (or `me`) reads
  the token's own account (`/me`); a user id or user principal name reads `/users/{id}`, for
  app-only tokens. `Debug` hides the user.
- Only `Credentials::AccessToken` (`Calendars.Read`, `Contacts.Read`; `.ReadWrite` for writes);
  a password or an empty token is `Config`. Refreshing the token is someone else's job.
- `with_timeout(d)`: two minutes per request by default.
- `with_throttle(throttle)`: every request waits for a slot of the `skein-throttle` gate and for
  any pause in effect, holding the slot until its answer is read; a busy answer with
  `Retry-After` pauses the gate for every holder (the account's mail and sending providers too).
  Without one, requests go out at once.

## Collections

| Collection id | What | Name |
| --- | --- | --- |
| `contacts` (`DEFAULT_CONTACTS`) | the default contacts folder, `/me/contacts` | `Contacts` |
| `contacts/<folder id>` | every folder of `/me/contactFolders` and their `childFolders`, any depth (1 000 at most) | the folder path, `Work/Clients` |
| `calendars/<calendar id>` | every calendar of `/me/calendars` | `name`; `hexColor` as the color, `canEdit: false` as read-only, components `VEVENT` |

A `403` on a listing is `Auth` (the token lacks the scope). Ids with `/` are skipped.

## Changes

- **Contact folders** follow Graph's delta query: `…/contacts/delta?$select=id,changeKey`, paged
  with `Prefer: odata.maxpagesize` set to the caller's limit; the cursor holds the next
  `@odata.nextLink` or the final `@odata.deltaLink`. `@removed` entries are `Removed` (left out
  in a first round, which has nothing to remove). A link Graph refuses (`410 Gone` for
  `syncStateNotFound` / `resyncRequired`, `404`, `400`), and a stored link on another origin
  (never asked), is `Reset { reason: "delta_expired" | "cursor" }` and a full round.
- **Calendars** have no usable delta in Graph v1.0: event delta exists only for `calendarView`,
  which needs a time window and expands series into occurrences, so it can neither keep series
  masters nor cover all time. Each round lists `…/calendars/{id}/events?$select=id,changeKey,type`
  (single events and series masters, never occurrences) and compares every `changeKey` with the
  ones the cursor holds; the cursor therefore holds every known event id (zstd-compressed JSON).
  The suite's `invalidate` has nothing to invalidate for calendars.
- Changes beyond `limit` stay in the cursor, so a page never exceeds it. An unreadable cursor, or
  one made for another collection, is `Reset { reason: "cursor" }`. `Upserted.version` is the
  `changeKey`.
- A listing stops with `Protocol` after 10 000 pages or a million objects, and when an
  `@odata.nextLink` names a page it already gave.

## Objects

Every object is the body of its `GET` exactly as Graph sent it, `@odata.context` and
`@odata.etag` included: `application/json; profile=graph-event` (`EVENT_MEDIA_TYPE`) or
`application/json; profile=graph-contact` (`CONTACT_MEDIA_TYPE`). Graph has no iCalendar export
for events (there is no `$value` for them) and no vCard export for contacts, so the JSON is the
original. `version` is the `changeKey` in it.

- Contacts: `GET …/contacts/{id}` (or below the folder).
- Events: `GET /me/calendars/{c}/events/{id}`. A series master (known from the listing's `type`,
  or from a first plain `GET`) is asked with `$select` of the event's fields plus
  `cancelledOccurrences` and `$expand=exceptionOccurrences`, which Graph gives only when asked by
  the master's id; the stored JSON then holds the master, its recurrence, the cancelled
  occurrences and every changed occurrence in full.
- Four requests at a time; a `404` leaves the object out. Every request sends
  `Prefer: IdType="ImmutableId"`, so ids survive moves between folders. Graph's body stays in its
  own content type (HTML unless the event was made as text).

## Writes

`PimWrite::Put` takes a Graph JSON object (anything else is `Failed { reason: "not_json" }`, more
than 4 MiB `too_large`). Properties Graph sets itself are dropped before sending, so an object
fetched, changed and put back is accepted: every `@odata.*` annotation, `id`, `changeKey`,
`createdDateTime`, `lastModifiedDateTime`, `parentFolderId`, `iCalUId`, `uid`, `seriesMasterId`,
`type`, `webLink`, `isOrganizer`, `responseStatus`, `bodyPreview`, `isCancelled`,
`originalStart`, `occurrenceId`, `cancelledOccurrences`, `exceptionOccurrences`,
`hasAttachments`, `isDraft`, `transactionId`.

| Write | Graph |
| --- | --- |
| create in a calendar | `POST …/calendars/{c}/events` with `transactionId` set to the command id, so Graph answers a repeat with the event it already made |
| create in a contact folder | first a lookup of the command id in a single-value extended property (`String {3b8e5f1a-9c2d-4e7b-a6f0-5d1c8b2e7a94} Name SkeinCreateKey`, `CREATE_KEY_PROPERTY`) with `$filter=singleValueExtendedProperties/Any(…)`, answering with the contact found; else `POST` with that property added |
| replace | `PATCH` with `If-Match: W/"<changeKey>"` when `if_version` is given (bare or `W/"…"`): Graph merges, so properties missing from the object keep their value |
| delete | `DELETE` with the same `If-Match`; `404` counts as deleted |
| respond | `POST …/events/{id}/accept`, `/decline` or `/tentativelyAccept` with `{"comment": …, "sendResponse": notify}` (no `comment` when none is given); contact folders are `Failed { reason: "not_a_calendar" }` |

- `notify` cannot change what Graph sends for puts and deletes: Exchange sends meeting requests,
  updates and cancellations itself whenever the organizer changes or deletes an event with
  attendees, and offers no switch to suppress them. Puts and deletes ignore `notify`; only an
  answer honours it, through `sendResponse`.
- A respond with `if_version` or `attendee` first reads the event: a `changeKey` other than
  `if_version` is `Conflict` with the current one, and an `attendee` not among the event's
  `attendees` (`emailAddress.address`, ignoring case) is `Failed { reason: "attendee_not_found" }`,
  both before anything is sent. Graph answers only as the mailbox user, so a named attendee is
  checked, not impersonated. A `400` for an event the user organizes (`isOrganizer`, read after
  the refusal) is `Failed { reason: "not_invited" }`; another `400` keeps Graph's code. A gone
  event is `Conflict { current: None }`. An applied answer is read back with `GET` and returned
  as `Applied.current`; for a series master it applies to the whole series.

- `412` is `Conflict` with the `changeKey` read afterwards (`None` when the object is gone; a
  `412` on delete for a gone object is `Applied`). A replace of a gone object is
  `Conflict { current: None }`.
- An applied put is read back with `GET` and returned as `Applied.current`.
- `403` is `Failed { reason: "forbidden" }` (a calendar without `canEdit`); `400`, `409`, `413`,
  `422` are `Failed` with Graph's error code (such as `ErrorInvalidProperty`), never its message,
  which may quote the object. A `404` for the collection on create is `NotFound`.
- `5xx` without `Retry-After`, a timeout or a broken answer after the request went out are
  `Uncertain`; a connection that never opened is `Network`.

## Scheduling

- `scheduling` is `Server` for every calendar (Graph sends the meeting messages) and `Client` for
  contact folders; an id that names no collection is `NotFound`.
- `addresses` reads the mailbox user (`/me`, or `/users/{id}` with `user` set) with
  `$select=mail,userPrincipalName` and returns both in lower case, each once, keeping only values
  with `@`; empty when the user is not found. It needs `User.Read` (or `User.Read.All` for
  app-only tokens); a `403` there is `Auth`.

## Security and limits

- The token goes only to the origin of `api_url`. `@odata.nextLink`, `@odata.deltaLink` and
  stored links on any other origin are refused before anything is sent; redirects are never
  followed.
- 64 MiB per listing page, 16 MiB per object answer (more is `Protocol`), 4 MiB per write.
- Busy reads (`429`, or `503`/`504` with `Retry-After`) are tried three times within about ten
  seconds, then `Throttled { retry_after }`; busy writes are `Throttled` at once (creates are safe
  to repeat through `transactionId` and the key lookup). With a throttle, a busy answer's
  `Retry-After` also pauses the shared gate (at most 10 minutes), and a read gives up with
  `Throttled` at once when that pause outlasts its own next wait instead of trying again.
- `401` is `Auth`.
- Logs carry counts and status codes only, never ids, names, objects or the token; error texts
  name the host and status.

## Tests

`src/tests.rs` runs an in-process fake Graph (axum) with the default contacts folder, nested
contact folders, a writable and a read-only calendar, delta links with generations, paging of two
items per page, `transactionId` deduplication, the create-key property and its `$filter`, `If-Match`
against `W/"<changeKey>"`, `429` with `Retry-After`, links to another host and pages that repeat.
The contract's `conformance` suite assumes iCalendar and vCard text that the server stores byte
for byte; Graph completes every object with its own properties, so the crate runs
`json_conformance`, the same checks with JSON objects where a create must keep every property
sent instead of the exact bytes. It passes for a calendar, a contact folder, the default contacts
folder and, through `/users/{id}`, a nested folder. Further tests cover folder paths, colors and
access, series masters fetched with their exceptions, throttling of reads and writes, a shared throttle (waiting out another holder's pause, a long
`Retry-After` pausing it and ending the retries), links to
another host refused with nothing sent there (a second fake counts requests), a stored link on
another host resetting, repeated pages, oversized objects, refused tokens, refused writes with a
plain reason, an object fetched, edited and put back, answers through `accept`/`decline`/
`tentativelyAccept` (`sendResponse`, comment, `changeKey` check, unknown attendee, organizer's
own event, contact folders), `scheduling` and `addresses` for `/me` and `/users/{id}`.

No live test against a real Microsoft 365 account yet.
