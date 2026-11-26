# rowboat-discover-srv

`rowboat-discover` from the domain's DNS SRV records.

## Names asked

For a domain `d`: `_imaps._tcp.d` (IMAP over TLS) and `_imap._tcp.d` (IMAP with STARTTLS) from RFC 6186, `_submissions._tcp.d` (submission over TLS, RFC 8314) and `_submission._tcp.d` (submission with STARTTLS, RFC 6186). TLS names come first. Records come through an `SrvResolver` (`rowboat-discover-net` in the node, `testing::FakeResolver` in tests); the resolver sees only these names, which the system resolver would see anyway when the servers are probed.

## Rules

- `endpoints(records, security)` (pure, deterministic): targets of `.` (the service is not offered), invalid host names, IP literals and port 0 are dropped; records are ordered by priority (lower first), then weight (higher first), then target and port; repeats dropped; at most 4 per service kind.
- Candidates pair every IMAP server with every submission server, at most 16, user name form `address`, sign-in `password`, `source = srv`, `verified = false`.
- When no name could be resolved at all the source is `Unavailable` and the node goes on; names without records are simply empty.

The node drops candidates with STARTTLS on a port other than 143 and 587, probes both servers, and marks `needs_confirmation` when a server lies outside the address's domain and the known providers ("suggested by DNS").

Runs `rowboat_discover::testing::source`.
