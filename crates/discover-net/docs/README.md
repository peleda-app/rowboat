# rowboat-discover-net

The networked halves of discovery, implementing two of `rowboat-discover`'s contracts. The node's desktop profile composes them under `rowboat-discover-autoconfig` and `rowboat-discover-srv`.

## `Https` (`HttpsFetcher`)

`reqwest` with HTTPS only, the certificate verified against the platform's roots (plus `extra_roots` in tests), no redirect followed (a `3xx` is `Unavailable`), no cookie store, no credential, the fixed user agent `mail-client-autoconfig` (no version, so the request says nothing about the build), and the whole call within `timeout` (10 s). A status other than 200 is `Unavailable`; a body over the caller's cap is `TooLarge` (checked against `Content-Length` first, then while reading, never truncated). Timeouts are `Timeout`, failed connections `Unreachable`. `HttpsOptions::resolve` maps host names to loopback addresses in tests; the node never sets it.

## `UdpResolver` (`SrvResolver`)

One SRV question over UDP to the system's name servers (`UdpResolver::system` reads `nameserver` lines from `/etc/resolv.conf`, at most 3; on macOS that file describes the primary network service, so a VPN's split DNS is not seen), in order until one answers. Each question uses a random id from the operating system and a fresh socket (a random source port) connected to the server, so only that server's datagrams arrive; datagrams that are not the answer to this question (another id, name or type) are skipped, at most 8 per server. Each server gets `timeout` (3 s). No EDNS and no TCP fallback: a truncated answer is `Unavailable`.

`dns::parse_answer` is the decoder of untrusted answers (fuzz target `discover_dns` in the root `fuzz/`): at most 4 KiB; a response to a standard query with the same id and the same single question; `NXDOMAIN` is an empty answer, other error codes `Failed`; names with compression pointers that only point backwards, at most 16 jumps, at most 255 bytes; only `IN SRV` records owned by the asked name are kept (an extra or CNAME record cannot add hosts), at most 64 records read and 32 kept; a target with a byte outside letters, digits, `-` and `_` is dropped, the root target kept as an empty string. It never panics.

There is no DNSSEC validation: an answer is a suggestion. Every host it names is probed with a verified TLS certificate, and a host outside the address's domain and the known providers needs the person's confirmation.

## Tests

The fetcher runs `rowboat_discover::testing::fetcher` against loopback HTTPS servers signed by Skein's test CA, plus untrusted certificates, `404`, `302` and a silent server. The resolver runs `testing::resolver` against a loopback UDP server that also sends a forged datagram with another id, plus silent and truncating servers, and the reader's attack tests (wrong id, query instead of response, truncation, failure codes, pointer loops and forward pointers, lying lengths, targets past their record, overlong names, floods of records) and property tests over arbitrary and mutated bytes. No test leaves loopback.
