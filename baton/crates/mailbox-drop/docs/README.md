# baton-mailbox-drop

A `baton_mailbox::Mailbox` on a drop service reached over HTTP(S) (`drop-http`, run by `apps/drop` or `batond`). It is `baton_drop::DropMailbox`, the one drop client, over `HttpExchange`, so signing, freshness stamps, nonces and reply checks are those of `baton-drop`.

## API

- `connect(base_url, realm, clock, &ClientConfig) -> DropMailbox`: fetches and checks the service info (the realm must equal `realm`, from the application's configuration, and every limit must be within the client's caps) and returns the client. `DropMailbox` implements `Mailbox`.
- `HttpExchange::new(base_url, &ClientConfig)`: the `baton_drop::Exchange` over reqwest, for composing by hand. Paths `v1/info` and `v1/request` are joined under the base URL, so a service behind a path prefix works when the base ends with `/`.

## Config (`ClientConfig::default()`)

| Setting | Default | Meaning |
| --- | --- | --- |
| `connect_timeout` | 10 s | TCP and TLS connect |
| `margin` | 15 s | how long a request may take beyond its long-poll wait (each request's timeout is `wait + margin`) |
| `allow_http` | false | plain `http` is accepted only to loopback (`127.0.0.0/8`, `::1`, `localhost`) unless this is set |
| `roots` | none | extra trusted root certificates (DER) besides the platform's, for a private deployment |

## Transport rules

HTTP/1.1, no redirects, no proxy, no credentials in the URL. Replies are read in chunks and refused once they exceed what the service's info allows (`max_reply`), and info replies beyond `wire::MAX_INFO`, whatever `content-length` says. Statuses map to `MailboxError`: `413` to `TooLarge`, `429` and `503` to `Busy` (never reached the service), `504` to `Unavailable` (outcome unknown: a put may have been stored), any other non-`200` and every transport failure to `Unavailable` (with a fixed message: no URL or address in errors).

## Tests

`cargo test -p baton-mailbox-drop` runs the `baton-mailbox` suite against a real `drop-http` server on 127.0.0.1 with the memory store, with a token and with proof of work, plus: wrong realm refused at connect, a dead server, servers sending oversized (declared and undeclared), garbage, redirect and `429` answers, a server that never answers (the client's timeout fires), and messages at and over the size limit. The suite against the redb store runs in `apps/drop`.
