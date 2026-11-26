# rowboat-discover-autoconfig

`rowboat-discover` from the domain's own autoconfig file (the `clientConfig` format, version 1.1), the file many mail hosts publish for mail clients.

## Where it looks

For a domain `d`, in order, stopping at the first file that yields a candidate:

1. `https://autoconfig.d/mail/config-v1.1.xml`
2. `https://d/.well-known/autoconfig/mail/config-v1.1.xml`

Only the domain itself is asked. No query string is sent (other clients append the address; this source never does), and no third-party database is consulted, since that would tell a third party which domain is being set up. Fetching goes through an `HttpsFetcher` (`rowboat-discover-net` in the node, `testing::FakeFetcher` in tests): HTTPS with a verified certificate, no redirects, at most `MAX_FILE_BYTES` (64 KiB).

## Decoder

`parse(bytes, domain)` is a decoder of untrusted input with a fuzz target (`discover_autoconfig` in the root `fuzz/`). Limits: 64 KiB, UTF-8, nesting depth 16, 2,000 elements, text values of at most 255 bytes, at most 4 incoming and 4 outgoing servers; a `DOCTYPE` or an entity other than the five predefined ones gives no candidates (nothing is ever expanded). It never panics and is deterministic.

A server is used only when it is `imap` (incoming) or `smtp` (outgoing), with a valid host after `%EMAILDOMAIN%` is replaced, a port from 1 to 65535, socket type `SSL`, `TLS` or `STARTTLS` (plain is never used), user name `%EMAILADDRESS%` or `%EMAILLOCALPART%`, and password or OAuth 2.0 sign-in (`password-cleartext`, `password-encrypted`, `OAuth2`; a server that names none is taken as `password-cleartext`). Candidates pair every usable IMAP server with every usable SMTP server in document order, at most 16, `source = autoconfig`, `verified = false`.

## What the node adds

The node drops candidates with an IP literal or STARTTLS on a port other than 143 and 587 (`Candidate::fit_from_network`), probes both servers of every candidate before offering it, and marks `needs_confirmation` when a server lies outside the address's domain and the known providers, so the app shows it as "suggested by autoconfig".

Runs `rowboat_discover::testing::source`.
