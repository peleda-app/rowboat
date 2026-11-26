# skein-send-smtp

The sending contract (`skein-send`) over SMTP submission (RFC 6409). `SmtpSender` opens one connection per call, with implicit TLS (port 465) or `STARTTLS` (port 587), signs in with `AUTH PLAIN`, `LOGIN` or `XOAUTH2`, and hands the message over with `MAIL FROM`, `RCPT TO` and `DATA`. It does not keep a sent copy: `saves_to_sent()` is false, so the engine appends one when the command asks. Reports carry no ids: the reply to `DATA` has no standard message id, and the submission server is taken to keep the message's `Message-ID`.

## Public API

- `SmtpSender::new(settings, credentials: Option<Credentials>)`: a password signs in with `AUTH PLAIN` (`LOGIN` when `PLAIN` is not offered), an access token with `XOAUTH2`; no sign-in without a `username`. `Invalid` before anything is sent for plain text to a host that is not loopback, a user name without credentials, an empty host, a bad `EHLO` name or an extra root that is not a certificate.
- `SmtpSender::with_timeouts(command, data)`: connect, handshake and each reply (default 60 s); the reply after the whole message (default 600 s).
- `SmtpSettings::from_json`, `SmtpSettings::port()`, `Security::{Tls, Starttls, Plain}`.

## Settings

| Field | Default | Meaning |
| --- | --- | --- |
| `host` | required | Server host; the name its certificate must carry |
| `port` | 465 for `tls`, 587 otherwise | |
| `security` | `tls` | `tls`, `starttls` or `plain` (loopback only) |
| `username` | none | Sign in as; on an account record it defaults to the account's `username` |
| `helo` | `localhost` | `EHLO` name |
| `roots` | none | `TlsRoots` trusted besides the web PKI roots; not serialized |

## Behavior and limits

- `STARTTLS` is required when configured: a server that does not offer it is `Unavailable`, and nothing, credentials included, is sent in plain text first. There is no setting that allows plain text to a remote host.
- `SIZE` is used and enforced before sending; `8BITMIME` and `SMTPUTF8` are required for 8-bit and internationalized mail and used when offered.
- DSN (RFC 3461): when the envelope asks and the server offers `DSN`, `RET=FULL|HDRS` and `ENVID=` go on `MAIL FROM`, `NOTIFY=` and `ORCPT=rfc822;` (ASCII addresses) on each `RCPT TO`, all xtext-encoded. Without `DSN` the parameters are silently left out.
- Mapping: refused connection, TLS failure or a non-2xx greeting is `Unavailable`; a session that breaks before the final dot is `Temporary`; silence or a lost connection after the final dot is `Uncertain`; `4xx`/`5xx` replies are `Refused` with their code (SMTP has no requested delay, so `retry_after()` is always `None`, `421` and `451` included); per-recipient refusals land in the report; `552` is `TooLarge`; `530`/`535` are `Auth`.
- Dot-stuffing is done on the wire; the server receives the bytes unchanged.
- Replies are read line by line, each line capped at 4096 bytes and a multi-line reply at 128 lines; the `smtp_replies` fuzz target in `skein/fuzz` reads arbitrary server bytes through the same code.
