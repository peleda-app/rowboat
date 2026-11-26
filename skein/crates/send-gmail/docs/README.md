# skein-send-gmail

The sending contract (`skein-send`) on Gmail through the Gmail API. `GmailSender` posts the message to `users.messages.send` as `raw` (base64url RFC 5322). Gmail keeps the sent copy under `SENT`, so `saves_to_sent()` is true. A successful send reports the Gmail message id as `provider_message_id`; `message_id` is `None`, since Gmail keeps the message's own `Message-ID`.

## Public API

- `GmailSender::new(settings, credentials)` takes only `Credentials::AccessToken` with `gmail.send` (or a broader scope). A password, an empty token, an address that is not `https` (plain `http` only to loopback) or holds credentials, a user that is not a plain path segment, or a zero size limit is `Invalid`, before anything is sent.
- `GmailSender::with_timeout(d)` (default 120 s).
- `GmailSendSettings::from_json` reads the same JSON as `skein-mail-gmail`'s settings; `MAX_SIZE` (35 MiB).

## Settings

| Field | Default | Meaning |
| --- | --- | --- |
| `api_url` | `https://gmail.googleapis.com` | API origin, optionally with a path prefix |
| `user` | `me` | User id in API paths |
| `max_size` | 35 MiB | Largest message handed over, counting an added `Bcc` field |

## Quirks

- Gmail takes the recipients from To, Cc and Bcc and picks the return path itself. Envelope recipients the header does not name are added in one `Bcc` field to the bytes Gmail receives (Gmail removes it from what recipients get). A header recipient missing from the envelope is `Invalid` before anything is sent, since Gmail would send to it.
- One bad recipient refuses the whole message (`Refused`, permanent); there are no per-recipient results. DSN is not available.
- Mapping: `401` and scope errors are `Auth`; `429`, and `403` or `503` with a rate-limit reason (`rateLimitExceeded`, `userRateLimitExceeded`, `dailyLimitExceeded`, `quotaExceeded`, `RATE_LIMIT_EXCEEDED`, `RESOURCE_EXHAUSTED`), are `Throttled` with `Retry-After` in seconds when given (an HTTP date is ignored); `413` is `TooLarge`; other `5xx` (a `503` without a rate-limit reason included, whatever its `Retry-After`) and a connection lost after the request left are `Uncertain`; a refused connection is `Unavailable`; other `4xx` are permanent refusals. Only machine-readable reasons are read from error bodies.
- The token goes only to `api_url`'s origin; redirects are never followed.
