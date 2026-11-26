---
title: Gmail
description: Gmail through the Gmail API, with labels, history and Pub/Sub push.
sidebar:
  order: 2
---

`skein-mail-gmail` signs in with an OAuth access token, shows labels as mailboxes next to a synthetic `ALL` mailbox, lists messages with `messages.list`, follows changes with `history.list`, and returns exact bytes from `messages.get?format=raw`. Reading never changes the server.

## Settings

| Field | Default | Meaning |
| --- | --- | --- |
| `api_url` | `https://gmail.googleapis.com` | API origin |
| `user` | `me` | `me` for the token's owner, or an address with domain-wide delegation |

## Mailboxes

| Mailbox id | Role | Label |
| --- | --- | --- |
| `ALL` | All | no; every message not in Spam or Trash |
| `INBOX`, `SENT`, `DRAFT`, `IMPORTANT` | Inbox, Sent, Drafts, none | yes |
| `TRASH`, `SPAM` | Trash, Junk | no |
| user label id (`Label_12`) | none | yes |

The engine skips label mailboxes when `ALL` is synced, so each message arrives once, from `ALL`, with its labels. `UNREAD` and `STARRED` are flags (`\Seen`, `\Flagged`).

## Changes

The cursor holds the history id and the known message ids (about six bytes per message). A history id Gmail no longer keeps (usually after about a week) is a reset and a new listing.

## Writes and scopes

| Operation | Least scope |
| --- | --- |
| reading | `gmail.readonly` |
| flags, labels, move, copy, delete to Trash, append | `gmail.modify` |
| label create, rename, delete | `gmail.labels` |
| delete for good (in `ALL`, `TRASH`, `SPAM`) | `https://mail.google.com/` |

A write refused for scope is `write_failed` with `insufficient_scope`.

## Quota

Gmail allows 250 quota units per user per second. Requests wait in a shared token bucket; a first listing runs at about 50 messages per second. `429` and rate-limit `403`s are throttling with `Retry-After`.

## Push

With a Cloud Pub/Sub topic configured, the account's owner calls `users.watch` and renews it about every 4.7 days; Gmail notifications reach `{public_url}/v1/push/gmail/{secret}` and wake the account's worker. Without a topic, accounts are polled. Setup: [Google OAuth client](/rowboat/providers/auth/google/#push-through-pubsub).

## Limits

No HTTP batch requests; messages over 64 MiB cannot be fetched; categories are not mailboxes. Full details: [skein-mail-gmail README](https://github.com/peleda-app/rowboat/blob/main/skein/crates/mail-gmail/docs/README.md).
