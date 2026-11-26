---
title: Google Calendar and People
description: Calendars through Google Calendar API v3 and contacts through People API v1.
sidebar:
  order: 2
---

`skein-pim-google` reads every calendar of the account and its `people/me` connections.

## Settings (`pim.kind = "google"`)

| Setting | Default |
| --- | --- |
| `calendar_url` | `https://www.googleapis.com/calendar/v3` |
| `people_url` | `https://people.googleapis.com/v1` |
| `calendars` | `true` |
| `contacts` | `true` |

Only OAuth access tokens. Scopes: `calendar` and `contacts` (read and write) or their `.readonly` forms, with which writes fail with `insufficient_scope`.

## Objects

Google has no per-object iCalendar or vCard export, so objects are Google's JSON resources, as exact byte slices of Google's answers:

| Kind | Content type | Version |
| --- | --- | --- |
| event | `application/json; profile=google-calendar-event` | `etag` |
| contact | `application/json; profile=google-people-person` | `etag` |

Recurring events are one item with their exceptions as separate items. There is one address book, `contacts`.

## Changes and writes

- `events.list` and `people.connections.list` with sync tokens; an expired token is a reset and a full listing.
- Event creates use an id made from the command key, so they are idempotent across sessions; contact creates are idempotent within one session only, and a lost answer is `write_uncertain`.
- Replace and delete use the `etag`; a mismatch is a conflict.
- Calendar writes carry `sendUpdates=all` with `notify` and `sendUpdates=none` without it.

Rate limits default to 300 calendar and 60 People requests a minute. Full details: [skein-pim-google README](https://github.com/peleda-app/rowboat/blob/main/skein/crates/pim-google/docs/README.md).
