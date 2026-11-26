# skein-oauth-http

`HttpTokenEndpoint`: the `TokenEndpoint` of `skein-oauth` over HTTPS (reqwest, rustls). Plain HTTP only to loopback addresses (for tests); no redirects followed; answers capped at 64 KiB; errors never repeat the form (codes, secrets, tokens). `with_roots` adds extra trust anchors without turning verification off. Passes `skein_oauth::testing::conformance`. Ported from Holtmail's `holtmail-oauth-http`.
