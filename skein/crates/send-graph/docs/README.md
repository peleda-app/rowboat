# skein-send-graph

The sending contract (`skein-send`) on Microsoft 365 and Outlook.com through Microsoft Graph `sendMail`. `GraphSender` posts base64 MIME to `/me/sendMail` (or `/users/{id}/sendMail`). Graph keeps the sent copy in Sent Items, so `saves_to_sent()` is true. `sendMail` answers `202` without a body, so a report carries neither `message_id` nor `provider_message_id`.

## Public API

- `GraphSender::new(settings, credentials)` takes only `Credentials::AccessToken` with `Mail.Send`. A password, an empty token, an address that is not `https` (plain `http` only to loopback) or holds credentials, a malformed user or a zero size limit is `Invalid`, before anything is sent.
- `GraphSender::with_timeout(d)` (default 120 s).
- `GraphSender::with_throttle(throttle)`: `check` and `send` wait for a slot of the `skein-throttle` gate and for any pause in effect; a `429`, or `503` with `Retry-After`, pauses the gate for every holder (the account's mail, calendar and contacts providers too). The error returned is unchanged. Without one, requests go out at once.
- `GraphSendSettings::from_json` reads the same JSON as `skein-mail-graph`'s settings; `GRAPH_URL`, `MAX_SIZE` (3 MiB: Graph refuses requests over 4 MiB and base64 grows MIME by a third).

## Settings

| Field | Default | Meaning |
| --- | --- | --- |
| `api_url` | `https://graph.microsoft.com/v1.0` | Graph endpoint with its version |
| `user` | `/me` | A user id or UPN for app-only tokens (`/users/{id}`) |
| `max_size` | 3 MiB | Largest message handed over, counting an added `Bcc` field |
| `roots` | none | `TlsRoots` trusted besides the built-in roots; not serialized |

## Quirks

- Graph takes the recipients from To, Cc and Bcc and picks the return path. Envelope recipients the header does not name are added in one `Bcc` field in front of the bytes Graph receives, and only there. A header recipient missing from the envelope, or a message that already has a `Bcc` field while the envelope names more, is `Invalid` before anything is sent.
- One bad recipient refuses the whole message (`ErrorInvalidRecipients`, permanent `550`). DSN is not available.
- Mapping: `401` is `Auth`; `403` is `Auth` except `ErrorSendAsDenied` (`550`) and `ErrorMessageSubmissionBlocked` (`554`); `429` and `503` are `Throttled` with `Retry-After` in seconds when given (an HTTP date is ignored; `check` maps `429` the same way); `413` or `ErrorMessageSizeExceeded` is `TooLarge`; other `5xx` and a connection lost after the request left are `Uncertain`; a refused connection is `Unavailable`.
- The token goes only to `api_url`'s origin; redirects are never followed. Error texts carry Graph's code, never message content.
