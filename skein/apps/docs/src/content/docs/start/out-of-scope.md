---
title: Out of scope, and how to build it
description: What Skein deliberately leaves out of its core, and how each of those features can be built on top of it.
sidebar:
  order: 4
---

Skein's core is a transport. It fetches objects from providers, stores their original bytes in the journal, adds only what the provider itself says (ids, flags, mailboxes, labels, versions) and carries out commands. Everything that needs an opinion about the content lives outside the core.

"Out of scope" means "not in the core", not "impossible". Almost every item below is a consumer of the journal or an implementation of a contract. Two limits are real, and they are called out where they apply.

## Left out of the core

- **Bulk and marketing sending:** templates, campaigns, open and click tracking, bounce and complaint processing, IP warm-up.
- **Content decisions:** parsing for features, indexing, threading, merging edits and trust decisions such as spam or phishing verdicts.

Keeping these out has three reasons:

- **The journal stays the truth.** A parser can change or have a bug; because the original bytes are kept, any view built from them can be rebuilt from a [snapshot](/rowboat/concepts/snapshots/) and the journal.
- **The core stays small and nearly stateless**, so one node can carry thousands of accounts.
- **Consumers do not impose choices on each other.** A search index, an archive and a spam filter read the same bytes and keep their own state.

## The building blocks

| Block | What it gives you |
| --- | --- |
| [Journal](/rowboat/concepts/journal/) and [blobs](/rowboat/concepts/blobs/) | every change in order, with the exact bytes of every message, event and contact |
| head hints and [webhooks](/rowboat/consumers/webhooks/) | a hint seconds after a change, so a consumer reacts without polling |
| [Commands](/rowboat/concepts/commands/) | writes back to the provider (flags, labels, moves, appends, sends, calendar and contact edits) with clear outcomes |
| [Contracts](/rowboat/extending/) | your own implementation of a provider, a sender or storage, chosen per account |

A consumer follows the loop in [writing a consumer](/rowboat/consumers/writing-a-consumer/): catch up from a checkpoint, apply events, stay current on hints, write through commands.

## Parsing, search and threads

Read `message_added` events, fetch the blob, parse it and keep your own index.

- [skein-view](/rowboat/consumers/skein-view/) is a working example: it parses messages, builds a full-text index and JWZ threads in SQLite, and serves its own API.
- The same loop can feed any engine (Meilisearch, Elasticsearch, a vector index), extract orders, flights or invoices, or produce summaries.
- When the parser changes, drop the index and rebuild it from the snapshot and the journal. Nothing is lost, because the bytes never changed.

## Trust decisions: spam, phishing, authentication

A filter subscribes to hints, reads each new message, checks DKIM, SPF and DMARC, scores it, and acts through commands: `move` to the spam mailbox, `set_labels`, `set_flags`. The action happens at the provider, so every other client of the mailbox sees it.

:::caution[A real limit]
Skein is a client of the mailbox, not a mail server. By the time a message is in the journal the provider has already accepted it, so a filter can move it but cannot reject it during delivery. It acts seconds after delivery (push for Gmail and Graph, IDLE for IMAP).
:::

## Merging edits

Edits to events and contacts carry the version they were made against (see [versions and conflicts](/rowboat/concepts/commands/#versions-and-conflicts)).

1. The client sends `put_object` with the version it edited.
2. If the object changed meanwhile, the command ends in `conflict` and nothing changes.
3. The client reads the newer version from the journal, merges its change into it (field by field, or by asking the user) and sends `put_object` again with the new version.

Skein never merges, so every client can choose its own policy. A shared merge helper for iCalendar and vCard is planned as a separate library that clients may use; the engine will not call it.

## Bounces and complaints

- `send_result` already lists recipients the service refused while sending, with code and permanence.
- Later bounces arrive as delivery status notifications (RFC 3464) in the mailbox and appear in the journal like any message. A consumer parses them, matches them to the sent message by `Message-ID` and keeps its own suppression list.
- When sending through Amazon SES, its configuration sets can report deliveries, bounces and complaints to your endpoint; match them by the provider's message id.

## Sending through a transactional service

A personal mailbox has low daily limits, and Google and Microsoft forbid bulk sending through their APIs. Mail from a service address (notifications, support replies, tickets) can go out through a transactional service instead, while the account still reads its mailbox as usual. Replies land in the same mailbox, and the sent copy is saved there.

- **Any service with SMTP** (Amazon SES, Postmark, Mailgun, SendGrid, Brevo, your own Postfix): use the [SMTP sender](/rowboat/providers/send/) with the service's host and credentials. SMTP carries the message bytes unchanged.
- **Amazon SES over its API** (`skein-send-ses`): HTTPS on port 443 instead of an SMTP port, ordinary IAM keys including temporary ones, a definite answer on every request (accepted with a message id, throttled with a retry time, or refused with a code), and configuration sets for delivery events. Services that copy the SES v2 API can be reached through its endpoint override.
- **Services that only accept fields** (sender, recipients, subject, HTML, attachments) and not a raw message would lose custom headers, multipart structure, inline images and S/MIME or PGP signatures, because Skein hands over the exact bytes the client built. Use their SMTP interface instead.

Either way, the sending domain must be verified with the service: SPF, DKIM and DMARC records in DNS.

## Open and click tracking

Technically possible: a consumer builds the MIME message itself with a tracking pixel and rewritten links, uploads it as a blob and submits `send`. A small HTTP service of your own records the pixel loads and redirects the links.

Think twice before doing it. Privacy features such as Apple Mail Privacy Protection and Gmail's image proxy make "opens" unreliable, tracking from a personal mailbox looks bad to recipients, and in many jurisdictions it needs consent.

## Campaigns and IP warm-up

A campaign is orchestration above single messages: a recipient list and segments, a template with variables, a sending pace, unsubscribes, and a record of who got what. Warm-up is managing the reputation of specific IP addresses by raising volume slowly. Neither belongs in a sync service.

:::caution[A real limit]
A consumer could turn a campaign into many `send` commands, but sent through a personal mailbox they hit the provider's daily limits and terms of service, and they put the user's mailbox and domain at risk. Warm-up is impossible there, because the IP addresses belong to the provider.
:::

The workable split:

1. Run campaigns in a dedicated sending service (Amazon SES, Postmark, your own MTA with warmed-up addresses). Warm-up and reputation are that service's job.
2. Let Skein carry everything that comes back: replies and bounces land in the journal, and a consumer links them to the campaign.
3. Continue the personal conversation from the real mailbox with `send`.

## Summary

| Feature | Built as | Limit |
| --- | --- | --- |
| Search, threads, extraction | consumer of the journal | none |
| Spam and phishing verdicts | consumer acting through commands | cannot reject during delivery |
| Merging edits | client logic on `conflict` | none |
| Bounce processing | consumer of DSN messages and `send_result` | none |
| Service mail at volume | SMTP sender to a transactional service, or `skein-send-ses` | the domain must be verified with the service |
| Open and click tracking | consumer that builds the message, plus its own HTTP service | unreliable, needs consent |
| Campaigns and warm-up | a separate sending service; Skein carries replies | not through personal mailboxes |
