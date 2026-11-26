---
title: Providers
description: Every provider Skein connects to, and how an account record selects them.
---

An account record names its mail provider, its settings and how it signs in. Calendars and contacts (`pim`) and sending (`send`) are optional parts of the same record.

```json
{
  "provider": "imap",
  "settings": { "host": "imap.example.com", "username": "ada@example.com" },
  "auth": { "type": "password" },
  "send": { "kind": "smtp", "settings": { "host": "smtp.example.com" } },
  "pim": { "kind": "dav", "settings": { "calendars": "https://dav.example.com/", "contacts": "https://dav.example.com/" } }
}
```

- `provider`: `imap`, `jmap`, `gmail` or `graph`.
- `auth`: `{"type": "password"}` (set with `PUT .../password`) or `{"type": "o_auth", "client": "<name>"}` with a configured [OAuth client](/rowboat/providers/auth/oauth-clients/).
- `include` / `exclude`: mailbox ids to sync or skip; `paused` stops syncing.
- `send`: `smtp`, `gmail`, `graph` or `jmap`. Without it, Gmail, Graph and JMAP accounts send through their own API; IMAP accounts cannot send.
- `pim`: `dav`, `google`, `graph` or `jmap`, with that provider's settings; `auth: "password"` uses a separate password set with `PUT .../pim-password`, otherwise the account's own credentials.

Records never hold secrets. Settings are a JSON object of at most 64 KiB.

## Mail

| Provider | Page | Push |
| --- | --- | --- |
| IMAP | [IMAP](/rowboat/providers/mail/imap/) | `IDLE`, `NOTIFY` |
| Gmail API | [Gmail](/rowboat/providers/mail/gmail/) | Pub/Sub |
| Microsoft Graph | [Graph mail](/rowboat/providers/mail/graph/) | change notifications |
| JMAP | [JMAP mail](/rowboat/providers/mail/jmap/) | EventSource |

## Calendars and contacts

| Provider | Page | Objects stored as |
| --- | --- | --- |
| CalDAV, CardDAV | [CalDAV and CardDAV](/rowboat/providers/pim/dav/) | iCalendar, vCard |
| Google Calendar, Google People | [Google](/rowboat/providers/pim/google/) | Google JSON |
| Microsoft Graph | [Graph calendars and contacts](/rowboat/providers/pim/graph/) | Graph JSON |
| JMAP Calendars, JMAP Contacts | [JMAP calendars and contacts](/rowboat/providers/pim/jmap/) | JSCalendar, JSContact |

## Sending

SMTP submission, the Gmail API, Graph `sendMail` and JMAP `EmailSubmission`: see [Sending](/rowboat/providers/send/).

## Common rules

- TLS verification can never be turned off; extra trust anchors can be added. Plain text is allowed only to loopback hosts.
- Credentials go only to the configured origin; redirects are not followed with credentials.
- Errors and logs never carry server text, names, addresses or content.
- Reading never changes the server.
