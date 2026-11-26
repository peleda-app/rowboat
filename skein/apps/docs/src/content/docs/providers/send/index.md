---
title: Sending providers
description: SMTP submission, the Gmail API, Graph sendMail, JMAP EmailSubmission and Amazon SES behind one contract.
sidebar:
  order: 1
  label: Sending providers
---

Skein is not an MTA. A sender hands the exact bytes of a prebuilt RFC 5322 message, with an explicit envelope, to the account's sending service, which signs, queues and delivers it. The engine's queue semantics (scheduling, undo window, retries, dry run) are described in [Commands and outcomes](/rowboat/concepts/commands/#sending).

## The one distinction

Every sender reports whether a failed send may have reached the service. Only "uncertain" may have; every other error guarantees nothing was sent. The engine retries only the latter and journals the former as `write_uncertain`, never resending it.

## Choosing a sender

The account record's `send` part picks one; without it, Gmail, Graph and JMAP accounts send through their own API with the account's settings, and IMAP accounts have no sender.

```json
{ "send": { "kind": "smtp", "settings": { "host": "smtp.example.com", "security": "starttls" } } }
```

SMTP settings without a `username` take the account's.

## Providers

| Kind | How | Keeps a sent copy | Per-recipient results | DSN | Size limit |
| --- | --- | --- | --- | --- | --- |
| `smtp` | SMTP submission, implicit TLS (465) or `STARTTLS` (587), `AUTH PLAIN`, `LOGIN` or `XOAUTH2` | no: the engine appends to `save_to_sent` | yes | when the server offers `DSN` | the server's `SIZE` |
| `gmail` | `users.messages.send` with `raw` | yes, under `SENT` | no: one bad recipient refuses the message | no | 35 MiB |
| `graph` | `/me/sendMail` or `/users/{id}/sendMail` with base64 MIME | yes, in Sent Items | no | no | 3 MiB |
| `jmap` | upload, `Email/import` into Drafts, `EmailSubmission` with the explicit envelope | yes, moved to Sent | yes | when the server offers `DSN` | `maxSizeUpload` and `SIZE` |
| `ses` | Amazon SES v2 `SendEmail` with the raw message and the envelope recipients | no: the engine appends to `save_to_sent` | no: SES accepts or refuses the message | no | 40 MB after base64 (about 30 MB of message), 50 recipients |

Gmail and Graph read recipients from the header, so envelope recipients the header does not name are added in one `Bcc` field to the bytes the service receives (the service removes it from what recipients get). A header recipient missing from the envelope is refused before anything is sent.

## SMTP settings

| Field | Default | Meaning |
| --- | --- | --- |
| `host` | required | the name its certificate must carry |
| `port` | 465 for `tls`, 587 otherwise | |
| `security` | `tls` | `tls`, `starttls` or `plain` (loopback only) |
| `username` | the account's | |
| `helo` | `localhost` | `EHLO` name |

`STARTTLS` is required when configured; nothing, credentials included, is sent in plain text first.

## Gmail, Graph and JMAP settings

The same settings as the account's mail provider, plus `max_size` for Gmail and Graph, `user` for Graph (a user id or UPN for [app-only tokens](/rowboat/providers/auth/app-only/)), and `address` for JMAP (whose identity sends; wildcard identities `*@domain` match).

## Amazon SES

For mail from a service address at volume (notifications, support replies) while the account still reads its mailbox through its own provider. SES requests go over HTTPS on port 443 and are signed with AWS Signature Version 4.

| Field | Default | Meaning |
| --- | --- | --- |
| `region` | required | e.g. `eu-west-1` |
| `endpoint` | `https://email.{region}.amazonaws.com` | an HTTPS origin for services that copy the SES v2 API; plain HTTP only on loopback |
| `configuration_set` | none | SES configuration set for delivery, bounce and complaint events |
| `from_identity_arn` | none | sending authorization for an identity owned by another AWS account |
| `message_id_domain` | from the region on AWS endpoints | the domain in the `Message-ID` SES gives each message; needed with a custom `endpoint` |
| `max_size` | 30,000,000 | message bytes before base64 |

The access key is set apart from the record with `PUT .../accounts/{a}/send-key` (`access_key_id`, `secret_access_key`, optional `session_token`), stored sealed and never returned. Grant it `ses:SendEmail` and `ses:SendRawEmail` on the sending identity; the domain must be verified in SES with SPF, DKIM and DMARC records.

:::note[SES replaces the Message-ID]
SES writes its own `Message-ID` into every message it sends: the `MessageId` it answers, at `email.amazonses.com` in `us-east-1` and at `{region}.amazonses.com` elsewhere. Recipients' replies refer to that id, so Skein saves the sent copy with it: the copy's `Message-ID` is the one recipients got, the original stays in an `X-Skein-Original-Message-ID` header, and nothing else in the copy changes. `send_result` carries both as `message_id` and `provider_message_id`. The journaled command keeps the bytes the client submitted.

With a custom `endpoint` (an SES-compatible service) the domain is unknown: set `message_id_domain` to the domain that service uses, or the copy keeps the original `Message-ID` and replies may not thread with it.
:::

Any other transactional service that accepts SMTP (Postmark, Mailgun, SendGrid, Brevo, SES's own SMTP interface) works through the `smtp` kind, which carries the message bytes unchanged.

Each crate's README has the exact error mapping: [send](https://github.com/peleda-app/rowboat/blob/main/skein/crates/send/docs/README.md), [SMTP](https://github.com/peleda-app/rowboat/blob/main/skein/crates/send-smtp/docs/README.md), [Gmail](https://github.com/peleda-app/rowboat/blob/main/skein/crates/send-gmail/docs/README.md), [Graph](https://github.com/peleda-app/rowboat/blob/main/skein/crates/send-graph/docs/README.md), [JMAP](https://github.com/peleda-app/rowboat/blob/main/skein/crates/send-jmap/docs/README.md), [SES](https://github.com/peleda-app/rowboat/blob/main/skein/crates/send-ses/docs/README.md).
