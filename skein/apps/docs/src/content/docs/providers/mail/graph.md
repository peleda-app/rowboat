---
title: Microsoft Graph mail
description: Microsoft 365, Outlook.com and Hotmail mailboxes through Microsoft Graph.
sidebar:
  order: 3
---

`skein-mail-graph` lists mail folders, turns each folder's message delta query into a change feed, downloads each message's original MIME bytes from `$value`, and carries out writes. Graph's JSON rendering of a message is never used. Useful where a tenant turned IMAP off.

## Settings

| Field | Default | Meaning |
| --- | --- | --- |
| `api_url` | `https://graph.microsoft.com/v1.0` | the Graph endpoint; national clouds need their own |

Only OAuth access tokens: `Mail.Read`, or `Mail.ReadWrite` for writes. Mail reads the token's own mailbox (`/me`).

## Ids and changes

- Every request sends `Prefer: IdType="ImmutableId"`, so a message keeps its id when it moves.
- Folders include hidden and child folders; search folders are left out. Roles come from well-known names (`inbox`, `sentitems`, `drafts`, `deleteditems`, `junkemail`, `archive`).
- The cursor holds the delta link and a hash of each known message id and its flags. A delta link Graph refuses (`404`, `410`, `400`) is a reset and a full listing.
- `isRead` is `\Seen`, a flagged `flag` is `\Flagged`, `isDraft` is `\Draft`.

## Writes

Flags (`\Seen` and `\Flagged` only), move, copy, delete for good (`permanentDelete`), delete to Deleted Items, append, and folder create, rename and delete. Each message is changed by its own request.

## Throttling

Graph limits requests per mailbox across mail, calendars and contacts: four at a time per app, and a `429` or `503` with `Retry-After` holds the whole mailbox. The binary gives an account's Graph mail, calendar, contacts and sending providers one shared gate (`skein-throttle`), so one of them cannot keep sending while another was told to back off.

## Push

With `server.push.enabled` and a public `https` URL, the owner subscribes each account to `me/messages` change notifications (4,200 minutes, renewed after about 1.9 days). Notifications reach `{public_url}/v1/push/graph` and are checked against the subscription's `clientState`. Without push, delta is polled.

Full details: [skein-mail-graph README](https://github.com/peleda-app/rowboat/blob/main/skein/crates/mail-graph/docs/README.md).
