---
title: Microsoft Graph calendars and contacts
description: Calendars and contacts of Microsoft 365, Outlook.com and Hotmail accounts.
sidebar:
  order: 3
---

`skein-pim-graph` keeps Graph's own JSON, since Graph has no iCalendar export for events and no vCard export for contacts.

## Settings (`pim.kind = "graph"`)

| Field | Default | Meaning |
| --- | --- | --- |
| `api_url` | `https://graph.microsoft.com/v1.0` | national clouds work too |
| `user` | `me` | a user id or user principal name reads `/users/{id}`, for [app-only tokens](/rowboat/providers/auth/app-only/) |

Only OAuth access tokens: `Calendars.Read`, `Contacts.Read`, or `.ReadWrite` for writes.

## Collections

| Collection id | What |
| --- | --- |
| `contacts` | the default contacts folder |
| `contacts/<folder id>` | every contact folder, any depth |
| `calendars/<calendar id>` | every calendar |

## Changes

- Contact folders follow Graph's delta query.
- Calendars have no usable delta in Graph v1.0 (event delta exists only for `calendarView`, which expands series), so each round lists events and compares every `changeKey` with the cursor.
- Series masters are stored with their recurrence, cancelled occurrences and every changed occurrence.

## Objects

`application/json; profile=graph-event` and `application/json; profile=graph-contact`, the body of each `GET` exactly as Graph sent it; `version` is the `changeKey`. Requests send `Prefer: IdType="ImmutableId"`.

Graph calendars and contacts share the mailbox's [throttle gate](/rowboat/providers/mail/graph/#throttling) with mail and sending. Full details: [skein-pim-graph README](https://github.com/peleda-app/rowboat/blob/main/skein/crates/pim-graph/docs/README.md).
