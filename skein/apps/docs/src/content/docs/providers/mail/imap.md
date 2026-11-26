---
title: IMAP
description: IMAP servers over TLS or STARTTLS, with CONDSTORE, IDLE and NOTIFY.
sidebar:
  order: 1
---

`skein-mail-imap` signs in over TLS or STARTTLS with `LOGIN` or `AUTHENTICATE XOAUTH2`, turns each mailbox into a change feed, returns the exact RFC 5322 bytes and watches mailboxes with `IDLE`. Reading uses `EXAMINE` and `BODY.PEEK[]`, so it never sets `\Seen`.

## Settings

| Field | Default | Meaning |
| --- | --- | --- |
| `host` | required | host name or IP address |
| `port` | 993 for `tls`, else 143 | |
| `security` | `tls` | `tls`, `starttls` or `plain` |
| `username` | required | often the address |
| `allow_insecure_plain` | `false` | allows `plain` to a host that is not loopback |

A password signs in with `LOGIN`, an OAuth access token with `XOAUTH2` (Gmail and Outlook over IMAP). STARTTLS that the server refuses is an error, never a fallback to plain text.

## Ids and changes

- Mailbox ids are decoded paths with `/` between levels; roles come from RFC 6154 attributes, `INBOX` or common names.
- Message ids are `{UIDVALIDITY}:{UID}`. On Gmail (`X-GM-EXT-1`) the id is `X-GM-MSGID` and labels come from `X-GM-LABELS`.
- The cursor holds `UIDVALIDITY`, `UIDNEXT`, `HIGHESTMODSEQ` and a compressed table of known UIDs and flags (about 65 KB for 100,000 messages).
- With `CONDSTORE`, an unchanged `HIGHESTMODSEQ` fetches nothing; without it, flags are compared in ranges. A new `UIDVALIDITY` is a reset and a full listing.

## Writes

Flags, keywords, move (`MOVE`, or `COPY` and `UID EXPUNGE` with `UIDPLUS`), copy, delete (only the named UIDs are expunged), delete to the trash, Gmail labels, append with `received_at`, and mailbox create, rename and delete. What a server allows is reported in `account_capabilities` from `PERMANENTFLAGS` and its extensions.

## Watching

With `IDLE`, one connection per mailbox for up to three mailboxes; with `NOTIFY`, one connection for many. `IDLE` is renewed every ten minutes. Servers without `IDLE` are polled.

## Limits

- `QRESYNC` and `VANISHED` are not used; removals come from a UID diff that `EXISTS` and `UIDNEXT` usually let it skip.
- `NAMESPACE` is not read: on servers that keep every mailbox under `INBOX.`, pass the full path.

Tested against GreenMail, Dovecot and Stalwart. Full details: [skein-mail-imap README](https://github.com/peleda-app/rowboat/blob/main/skein/crates/mail-imap/docs/README.md).
