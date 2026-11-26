# rowboat-discover-table

`rowboat-discover` from an embedded, reviewed table of well-known mail providers, and conventional host guesses for every other domain. No I/O.

- **Table.** Each entry lists the provider's domains (aliases included), its IMAP and SMTP endpoints as the provider publishes them, the user name form, whether it needs an app password (`AppPassword`) or only allows OAuth (`OAuthOnly`, kept so the app can say "coming later"), and a help topic id the app maps to a page. A table answer is one candidate with `source = table`; table entries are not probed (`add_account` signs in anyway). The table is checked by a test: valid endpoints and topics, no domain listed twice.
- **Guesses.** For any other domain: `imap.<d>:993` TLS with `smtp.<d>:465` TLS or `:587` STARTTLS, `mail.<d>:993` TLS with `mail.<d>:465` TLS, and `mail.<d>:143` with `mail.<d>:587` STARTTLS, in that order, all `verified = false`. A guess whose host would break the host rules (over 253 bytes) is left out. The node probes guesses when it has a `Prober` and returns only those that answered.

`TableSource::known_host(host)`: whether a host belongs to a provider the table knows (one of its servers, a name under a server's parent domain, or under one of its mail domains); `needs_confirmation(host, domain)` is the rule built on it: a host outside the address's domain and outside every known provider. The node marks such candidates `needs_confirmation`, and the app runs the same function on the servers a person is about to send a password to.

Changing the table is a reviewed change: hosts and ports come from each provider's own help pages.

Runs `rowboat_discover::testing::source`.
