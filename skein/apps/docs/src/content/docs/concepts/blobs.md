---
title: Blobs
description: Original bytes addressed by their BLAKE3 hash.
sidebar:
  order: 3
---

Every message, event and contact is stored as the provider gave it, addressed by the BLAKE3 hash of its bytes. Parsed fields are derived; the original bytes are the truth.

| Content | Blob |
| --- | --- |
| Mail | the exact RFC 5322 message |
| CalDAV, CardDAV | the exact iCalendar or vCard object |
| Google Calendar, People | Google's JSON resource (`application/json; profile=google-calendar-event`, `…google-people-person`) |
| Microsoft Graph calendars and contacts | Graph's JSON (`application/json; profile=graph-event`, `…graph-contact`) |
| JMAP calendars and contacts | JSCalendar or JSContact JSON with sorted keys |
| Incoming iTIP | the decoded calendar part of a message |

Providers that have no per-object iCalendar or vCard export keep their own JSON as the original, so nothing is lost in conversion. See the provider pages for details.

## Guarantees

- `put` is idempotent: the same bytes give the same hash and are stored once.
- `get` never returns bytes that do not match the hash.
- Blobs are deduplicated within a tenant only, so one tenant cannot learn what another holds and a tenant can be deleted whole.
- A blob is written before any event that points at it.

## Retention

Skein is a buffer, not an archive. Long-term storage is a consumer's job. The engine does not expire blobs: use an object storage lifecycle rule on `tenants/*/blobs/` (for example 30 days). A consumer that needs a blob that has expired submits a `refetch` command; Skein downloads it from the provider again while the provider still has it.

## Reading and uploading

`BlobStore::get` returns the raw bytes and checks them against the hash (`skein journal get-blob` from the command line). Commands that carry content (`append`, `send`, `put_object`, `respond_invitation`) need their blob stored first with `BlobStore::put` (`skein journal put-blob`).
