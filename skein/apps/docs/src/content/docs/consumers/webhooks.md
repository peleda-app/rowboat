---
title: Webhooks
description: Signed batches of journal events posted to your endpoint, at least once and in log order.
sidebar:
  order: 3
---

A tenant configures endpoints; the node that owns an account posts the account's new events to every matching endpoint in batches, signed with HMAC-SHA256, at least once and in log order per endpoint and account.

## Endpoints

```bash
skein webhook add --tenant acme --url https://hooks.example.com/skein --events message_added,write_uncertain
```

The answer holds the secret (`whsec_…`) once. `--events` and `--accounts` are optional filters. An endpoint gets changes from its creation on. `skein webhook list`, `pause`, `resume`, `rotate` and `remove` manage endpoints; `[webhooks]` in the config says where they may point.

## Requests

| Header | |
| --- | --- |
| `Skein-Webhook-Id` | the batch id; a retried batch keeps it |
| `Skein-Timestamp` | Unix seconds when it was signed |
| `Skein-Signature` | `v1=<hex HMAC-SHA256(secret, "{timestamp}.{body}")>` |

```json
{
  "endpoint": "01jd8m3r9yq7k2c5x4v6b0n1tw",
  "tenant": "acme",
  "account": "box",
  "events": [
    {"v": 1, "seq": 41, "at": 1732147200000, "account": "box", "key": "…", "body": {"type": "first_sync_completed"}}
  ]
}
```

At most 100 events per batch, in the journal's own JSON form. When the endpoint fell behind compaction, it receives `"events": [], "compacted": {"first": N}`: load the snapshot and read on. A test request carries `"ping": true`.

Answer `2xx` to accept a batch. Redirects are not followed.

## Verifying

1. Read the raw body bytes before parsing.
2. Refuse if `Skein-Timestamp` is not digits or is more than 5 minutes from your clock.
3. Compute `HMAC-SHA256(key = secret, message = timestamp + "." + body)` in lowercase hex and compare it in constant time with each `v1=` entry of `Skein-Signature`. The key is the whole secret, `whsec_` included.
4. Deduplicate by `(account, seq)`: the same batch may arrive again.

```ts
import { createHmac, timingSafeEqual } from 'node:crypto'

function verify(secret: string, ts: string, body: Buffer, header: string, now = Date.now() / 1000) {
  if (!/^\d+$/.test(ts) || Math.abs(now - Number(ts)) > 300) return false
  const expected = Buffer.from(createHmac('sha256', secret).update(`${ts}.`).update(body).digest('hex'))
  return header.split(/[ ,]+/).some((v) => {
    if (!v.startsWith('v1=')) return false
    const got = Buffer.from(v.slice(3))
    return got.length === expected.length && timingSafeEqual(got, expected)
  })
}
```

## Retries

- Delivery runs after each run of the account's worker, at most 20 batches per endpoint per run.
- A failure backs off that endpoint for that account: 10 s, doubling up to 1 h.
- After 3 days of failures in a row the endpoint is paused with a reason; `PATCH {"paused": false}` resumes it from its cursors.

## Address rules

`https` to public addresses only, checked at creation and again on every request against the resolved address, so a name cannot be re-pointed to an internal address. Private networks can be allowed with `server.webhooks.allowed_networks`. Full details: [skein-webhooks README](https://github.com/peleda-app/rowboat/blob/main/skein/crates/webhooks/docs/README.md).
