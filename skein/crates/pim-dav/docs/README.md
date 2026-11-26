# skein-pim-dav

Calendars and contacts on CalDAV (RFC 4791) and CardDAV (RFC 6352) servers behind the
[`skein-pim`](../../pim/docs/README.md) contract. Runs the contract's conformance suite against an
in-process fake DAV server in four modes (sync-collection, sync paged by the server, ETag listing
with and without `getctag`, GET instead of multiget).

## Config

`DavConfig { calendars, contacts, username, credentials, timeout, allow_insecure_plain, roots,
schedule_inbox }`;
`DavConfig::at(url, username, credentials)` points both kinds at one address. An address may be a
server (its well-known address is asked), a DAV root, a principal, a home set or one collection.
`Credentials::Password` is sent as HTTP Basic with `username`, `Credentials::AccessToken` as a
bearer token. `Debug` shows neither the user name nor the secret. `schedule_inbox` also lists the
principal's scheduling inbox (off by default).

## Guarantees

- **Discovery:** RFC 6764 well-known lookup without credentials, then `current-user-principal`
  and `calendar-home-set` / `addressbook-home-set`; collections are children whose `resourcetype`
  is `calendar` or `addressbook` (scheduling inboxes and outboxes are left out). Ids are
  percent-decoded paths, so differently encoded answers give one id. `read_only` comes from
  `current-user-privilege-set` (none of `all`, `write`, `write-content`); without the property a
  collection counts as writable.
- **Changes:** `sync-collection` (RFC 6578) with the sync token in the cursor. A refused token
  (`valid-sync-token`, or 400/403/409/412 to a token) is `Reset` and a full listing. A server
  without `sync-collection` is read with a `getctag` check and a `PROPFIND` ETag listing; the
  cursor then holds every known ETag. A server that truncates (`507` on the collection) is paged.
  Changes read from the server but beyond `limit` stay in the cursor, so a page never exceeds it.
  An unreadable cursor is `Reset`.
- **Bytes:** `calendar-multiget` / `addressbook-multiget` in batches of 50, with line ends kept
  exactly as sent; one `GET` each where multiget is refused or a batch fails with 5xx. `version`
  is the `getetag` sent with the bytes (a weak `GET` ETag is dropped).
- **Writes:** create is `PUT` with `If-None-Match: *` to a name made from the command id, so a
  repeated create cannot make a second object; a `412` whose current bytes equal ours is answered
  as applied. Replace is `PUT` with `If-Match`; delete is `DELETE` with `If-Match`; `412` is
  `Conflict` with the current ETag, a gone object counts as deleted. `403/405/409/413/415/422/507`
  are `Failed` with the DAV precondition name (such as `need-privileges`) or `refused_{status}`.
  After a successful `PUT` the object is read back with `GET` and returned as `Applied.current`:
  Radicale, for one, reorders properties and still answers with a strong ETag, so the answer's
  tag never vouches for the sent bytes.

## Scheduling (RFC 6638)

- `scheduling(collection)` sends `OPTIONS` to the calendar once per session: `Server` when the
  `DAV` header lists `calendar-auto-schedule`, else `Client`. Address books are always `Client`.
- `addresses()` reads `calendar-user-address-set` from the current user principal (only
  `mailto:` entries), once per session; empty when the server does not say.
- `Respond` reads the object, checks `if_version`, sets the attendee's `PARTSTAT` (the named one,
  or the first attendee among the principal's addresses) with `skein-itip`, and writes it back
  with `If-Match`. A scheduling server then sends the `REPLY` itself; with `notify` off the write
  carries `Schedule-Reply: F` (section 8.1). On a server without scheduling the engine mails the
  `REPLY`.
- Organizer writes are sent unchanged: a scheduling server tells attendees whether or not
  `notify` is set.
- With `schedule_inbox`, the principal's `schedule-inbox-URL` (on the account's own origin) is
  listed as a calendar with `role: schedule_inbox`; its objects are the iTIP messages the server
  delivered and can be removed with `delete_object`.
- Not done: free-busy queries through the scheduling outbox.

## Security and limits

- https only; plain http only to loopback unless `allow_insecure_plain`.
- Credentials go only to the origins of the configured addresses. Redirects, home sets,
  principals and well-known answers leading to another origin are not followed with them.
- 64 MiB per listing or report answer, 16 MiB per object (larger objects are left out of fetches
  with a warning and refused on write as `too_large`), a million objects per collection.
- XML: only the five predefined entities and character references; any `DOCTYPE` is refused, so
  no entity is ever expanded; at most 64 levels and a million elements.
- Busy servers (`429`, `503`, `504`) are tried three times within about ten seconds, then
  `Throttled { retry_after }`.
- Logs carry counts and status codes only, never paths, names, objects or credentials.

## Quirks handled

Radicale (well-known redirect to `/`, sync tokens), sabre/dav servers that answer a whole multiget
with 500 when one object is broken (falls back to `GET`), servers that send `getctag` in other
namespaces, servers without `sync-collection`, `getctag` or multiget.

Not yet: WebDAV-Push, servers without ETags (listing then re-reads every object each run).
