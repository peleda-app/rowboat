---
title: The calendar and contacts model
description: Collections, objects, versions and conditional writes shared by every calendar and contacts provider.
sidebar:
  order: 0
  label: Model
---

Every calendar and contacts provider implements one contract, `skein-pim`. It maps the provider's change mechanism (DAV sync tokens or ETag listings, Google sync tokens, Graph delta links, JMAP states) onto one model: per collection, an opaque cursor and a batch of changes since it.

- **Collections** are calendars and address books: `id`, `kind` (`calendar` or `address_book`), `name`, `color`, `read_only`, `components`. A CalDAV scheduling inbox can be listed with `role: schedule_inbox`.
- **Objects** are the provider's original bytes: iCalendar or vCard where the provider has them, the provider's own JSON otherwise. Nothing is parsed or rewritten.
- **Versions** belong to exactly those bytes: an ETag, a Google `etag`, a Graph `changeKey`, or for JMAP a hash of the bytes.

## Journal

`collection_upserted`, `collection_deleted`, `object_upserted` (blob and version) and `object_removed`, folded into snapshots like mail.

## Writes

| Command | Guarantee |
| --- | --- |
| `put_object` without an item | creates without ever overwriting; the command id is the key, so a repeated create makes at most one object |
| `put_object` with an item and `if_version` | replaces; another version is `conflict` and changes nothing |
| `delete_object` | with `if_version`; a gone object counts as applied |
| `respond_object` | sets one attendee's participation status through the provider's own way of answering |

An applied put also journals the object as the server holds it, since servers may rewrite objects. `notify` on these commands asks for scheduling messages: see [Scheduling](/rowboat/providers/scheduling/).

## Credentials

The `pim` part of an account record uses the account's own credentials (the same OAuth grant covers mail, calendars and contacts) or, with `auth: "password"`, a separate password set through `PUT .../pim-password`.

Full contract: [skein-pim README](https://github.com/peleda-app/rowboat/blob/main/skein/crates/pim/docs/README.md).
