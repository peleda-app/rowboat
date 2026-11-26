---
title: CalDAV and CardDAV
description: Calendars and contacts on CalDAV (RFC 4791) and CardDAV (RFC 6352) servers.
sidebar:
  order: 1
---

`skein-pim-dav` keeps the exact iCalendar and vCard bytes of every object.

## Settings (`pim.kind = "dav"`)

| Field | Meaning |
| --- | --- |
| `calendars` | address for calendars: a server (its well-known address is asked), a DAV root, a principal, a home set or one collection |
| `contacts` | the same for address books |
| `username` | optional; defaults to the account's |

A password is sent as HTTP Basic, an access token as a bearer token. https only; plain http only to loopback.

## Behavior

- **Discovery:** RFC 6764 well-known lookup without credentials, then `current-user-principal` and the home sets. Credentials never go to another origin.
- **Changes:** `sync-collection` (RFC 6578) with the sync token in the cursor; a refused token is a reset. Servers without it are read with `getctag` and an ETag listing.
- **Bytes:** `calendar-multiget` and `addressbook-multiget` in batches of 50, with one `GET` each where multiget fails.
- **Writes:** create is `PUT` with `If-None-Match: *` to a name made from the command id; replace and delete use `If-Match`; `412` is a conflict. After a `PUT` the object is read back, since servers may rewrite it.
- **Scheduling:** `calendar-auto-schedule`, `calendar-user-address-set`, `Schedule-Reply` and the scheduling inbox (RFC 6638). See [Scheduling](/rowboat/providers/scheduling/).

## Limits

64 MiB per report answer, 16 MiB per object; XML without `DOCTYPE`; busy servers (`429`, `503`, `504`) are retried three times within about ten seconds. Not yet: WebDAV-Push, free-busy through the scheduling outbox.

Tested against Radicale and Stalwart. Full details: [skein-pim-dav README](https://github.com/peleda-app/rowboat/blob/main/skein/crates/pim-dav/docs/README.md).
