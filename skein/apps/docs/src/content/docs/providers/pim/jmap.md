---
title: JMAP calendars and contacts
description: JMAP for Contacts (RFC 9610) and JMAP Calendars, such as Stalwart or Fastmail.
sidebar:
  order: 4
---

`skein-pim-jmap` reads address books and calendars from a JMAP session.

## Settings (`pim.kind = "jmap"`)

The same keys as the [JMAP mail settings](/rowboat/providers/mail/jmap/) (`url`, `username`); an empty object uses the account's mail settings.

## Collections and objects

| Collection id | JMAP |
| --- | --- |
| `addressbook/<id>` | an `AddressBook` |
| `calendar/<id>` | a `Calendar` |

Neither JMAP specification offers the iCalendar or vCard bytes of an object, so objects are JSContact cards (`application/jscontact+json`) and JSCalendar events (`application/jscalendar+json`) from the server's `/get` answer, written with sorted keys so an unchanged object always has the same bytes. `version` is a hash of those bytes. Recurring events come as the master with its `recurrenceOverrides`.

## Changes and writes

- Paged `/query`, then `/changes` from the stored state; `cannotCalculateChanges` is a reset.
- Writes are `/set` with `ifInState`, retried on another object's `stateMismatch`; creates are idempotent by `uid`.
- `sendSchedulingMessages` follows `notify`.

Tested against Stalwart. Full details: [skein-pim-jmap README](https://github.com/peleda-app/rowboat/blob/main/skein/crates/pim-jmap/docs/README.md).
