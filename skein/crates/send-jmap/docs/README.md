# skein-send-jmap

The sending contract (`skein-send`) on JMAP servers (RFC 8620, RFC 8621, RFC 8621 §7 submission), such as Stalwart or Fastmail. `JmapSender` uploads the exact bytes as a blob, imports them into Drafts (Sent when there is no Drafts) with `$draft` and `$seen`, and creates an `EmailSubmission` with the explicit envelope in the same request. `onSuccessUpdateEmail` moves the email to Sent and clears `$draft`, so the server keeps the sent copy: `saves_to_sent()` is true. A successful send reports the `EmailSubmission` id as `provider_message_id`; `message_id` is `None`, since the server keeps the message's own `Message-ID`. After a definite failure the imported copy is destroyed again; after an uncertain one it is kept.

## Public API

- `JmapSender::new(settings, credentials)`: a password signs in with HTTP Basic as `username`, a token as a bearer token. An unusable address, a password without a user name or a bad extra root is `Invalid`, before anything is sent.
- `JmapSender::with_timeout(d)` (default 120 s).
- `JmapSendSettings::from_json` reads the same JSON as `skein-mail-jmap`'s settings plus `address`; `session_url(input)`.

## Settings

| Field | Default | Meaning |
| --- | --- | --- |
| `url` | required | Session resource, or a server address where `/.well-known/jmap` is asked |
| `username` | empty | User name for a password sign-in |
| `address` | the envelope's return path | Whose JMAP identity sends; wildcard identities `*@domain` match |
| `roots` | none | `TlsRoots` trusted besides the built-in roots; not serialized |

## Behavior and limits

- `check` needs mail submission for the account, a Sent mailbox and, with `address`, a matching identity.
- The size limit is the smaller of `maxSizeUpload` and the account's `SIZE` submission extension.
- DSN parameters (`RET`, `ENVID`, `NOTIFY`, `ORCPT`) go into the envelope only when the account's submission extensions include `DSN`.
- Per-recipient refusals come from `invalidRecipients` (the rest is submitted again without them) and from `deliveryStatus` with `delivered: no`.
- Mapping: failures before the API request are `Unavailable`/`Auth`/`Invalid`; once `Email/import` + `EmailSubmission/set` left, a lost connection, another `5xx`, an unreadable answer or `serverFail` is `Uncertain`; an HTTP `429` or `503` is `Throttled` with `Retry-After` in seconds when given (an HTTP date is ignored), at every stage, since the server refused the request; the `rateLimit` set error is `Throttled` without a wait; `serverUnavailable` is `Temporary`.
- Security: the well-known address is followed through redirects without credentials; requests with credentials never follow redirects; an `apiUrl` or `uploadUrl` on another origin than the session resource is `Invalid`, so credentials go nowhere else.
