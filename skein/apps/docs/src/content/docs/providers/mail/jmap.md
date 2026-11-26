---
title: JMAP mail
description: JMAP servers such as Stalwart, Fastmail or Cyrus.
sidebar:
  order: 4
---

`skein-mail-jmap` (RFC 8620, RFC 8621) discovers the session, turns each mailbox into a change feed whose cursor holds the account's `Email` state, downloads each email's original bytes as a blob, writes with `Email/set` and `Email/import`, and watches the account through the session's event source.

## Settings

| Field | Meaning |
| --- | --- |
| `url` | the session address; an address without a path gets `/.well-known/jmap` |
| `username` | for a password sign-in (HTTP Basic) |

A password signs in with HTTP Basic; an access token (OAuth, or an API token such as Fastmail's) as a bearer token. The well-known address is followed without credentials; the session itself is asked with them, and a redirect of that request is refused.

## Ids and changes

- Mailbox ids are JMAP mailbox ids; an email in two mailboxes is a message in each, with the same id.
- Keywords become flags: `$seen` is `\Seen`, `$flagged` is `\Flagged`, and so on.
- A feed starts with a paged `Email/query`, then follows `Email/changes`. `cannotCalculateChanges` is a reset and a new listing.

## Writes

Flags and keywords, move and copy (by mailbox membership), delete (an email also in other mailboxes only leaves this one; destroying is permanent), delete to the trash, append through upload and `Email/import`, and mailbox create, rename and delete. Deletes send `ifInState` and retry on `stateMismatch`.

## Watching

The event source is opened with `types=Email,Mailbox`; each state change wakes the account. Without an event source, accounts are polled.

Tested against Stalwart. Full details: [skein-mail-jmap README](https://github.com/peleda-app/rowboat/blob/main/skein/crates/mail-jmap/docs/README.md).
