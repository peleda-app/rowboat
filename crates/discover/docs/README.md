# rowboat-discover

The contract of mail server discovery: candidate IMAP and SMTP servers for the domain of an address, so the person types an address and a password and nothing else when the provider is known.

## API

| Item | Guarantees |
| --- | --- |
| `Domain::new`, `Domain::of_address` | lowercase ASCII host names only (`valid_host`: at least two labels of `[a-z0-9-]`, 1 to 63 bytes each, 253 in all); `Debug` shows the length only |
| `Endpoint`, `Security` | a checked host, a non-zero port, `Tls` or `StartTls`; plain text is not representable |
| `Candidate` | IMAP and SMTP endpoints, the user name form (`Address` or `LocalPart`), the sign-in hint (`Password`, `AppPassword`, `OAuthOnly`), an optional help topic id, the source (`Table`, `Guess`, `Autoconfig`, `Srv`), whether both servers answered a probe (`verified`) and `needs_confirmation` (a server outside the address's domain and the known providers; serde default `false`); `fit_from_network()`: no IP literal and STARTTLS only on 143 or 587 (`STARTTLS_PORTS`) |
| `within(host, domain)`, `is_ip_literal(host)` | pure host checks: `host` is the domain or under it; the last label is all digits |
| `DiscoverySource::lookup` | at most 16 valid candidates, best first, equal answers for equal domains; never sends a credential; a networked source bounds every call and fails with `Unavailable` |
| `Prober` | checks a server without signing in (TLS verified, greeting and capabilities read, never a credential); `Probed { password_sign_in, oauth }` or a kind: `TlsFailed`, `Insecure`, `Timeout`, `Unreachable`, `NotMail`; every call bounded in time and bytes |
| `HttpsUrl` | `https://` on a valid host (no IP literal) with a fixed path of `[A-Za-z0-9._~/-]`, no `..`, no query; `Debug` shows the length only |
| `HttpsFetcher::get(url, max_bytes)` | `GET` only, verified certificate, no redirect, no cookie or credential, never a truncated body (`TooLarge`), status other than 200 `Unavailable`, `max_bytes` at most `MAX_FETCH_BYTES` (256 KiB), bounded in time |
| `SrvResolver::srv(name)`, `valid_srv_name`, `SrvRecord` | records owned by `name` only, at most `MAX_SRV_RECORDS` (32), a missing name is empty, an invalid name `Invalid`, bounded in time |
| `DiscoverError` | `Invalid`, `Unavailable`, `Unreachable`, `Timeout`, `TlsFailed`, `Insecure`, `NotMail`, `TooLarge`; no input in any of them |
| `merge(answers)` | pure: sources in configured order, invalid candidates dropped, duplicates by `(imap, smtp)` dropped with the earlier kept, `OAuthOnly` kept so the app can say "coming later", at most 16 |

## Conformance

Feature `testing`:

- `testing::source(&source, &domains)`: bounded output, every candidate valid, equal answers on repeated lookups, odd but valid domains answered without a panic.
- `testing::fetcher(&fetcher, &url, body, &oversized)`: the body read whole, an oversized document `TooLarge` (never truncated), a cap above `MAX_FETCH_BYTES` `Invalid`.
- `testing::resolver(&resolver, name, records, missing)`: the records, an empty answer for a missing name, invalid names `Invalid`.
- Fakes for tests of callers: `FakeFetcher`, `FakeResolver`, `FakeProber` (fixed answers, every request recorded).
