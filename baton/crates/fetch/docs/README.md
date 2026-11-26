# baton-fetch

Objects by content hash: served to authorized peers over a link (protocol `fetch`), fetched from peers before the application's `Source`. Every byte is checked against its `ContentId` (BLAKE3) whoever served it.

## API

| Item | Guarantees |
| --- | --- |
| `ContentId::of`, `matches` | BLAKE3 of the bytes |
| `Source` (trait) | the application's last resort (Peleda: S3 directly or through presigned URLs); its answers are verified like a peer's |
| `LocalObjects` (trait) | what this node holds **for a resource**: it must return nothing for an object that belongs only to another resource, so a reader of one resource cannot fetch or probe another's |
| `serve(link, objects, authorize, config)` | answers a request with the object only if `authorize(peer, resource)` allows the link-authenticated peer (normally: its node holds `Read` in the group log), the object is held for that resource and fits `max_object`; otherwise "not here", so refusals and misses look the same. A request must arrive within `header_timeout` before any shared slot is taken; one peer may have `max_per_peer` requests open; `max_serving` are served at once; objects in memory stay within `serving_budget`; every request ends within `peer_timeout` |
| `Fetcher::fetch(resource, id, peers)` | asks `peers` in the given order (the caller puts the leaseholder first, then servers, desktops, connected phones), de-duplicated, `parallel` at a time, each within `peer_timeout`, skipping itself and peers that served wrong bytes for this resource within `liar_ttl` (`liars(resource)`); reads bodies in chunks, so an announced length allocates nothing up front; then the source within `source_timeout`; returns the bytes and their `Origin`, or `NotFound` |
| `FetchConfig` | `max_object` 64 MiB, `peer_timeout` 1.5 s, `header_timeout` 0.5 s, `source_timeout` 10 s, `parallel` 2, `max_serving` 16, `max_per_peer` 4, `serving_budget` 256 MiB, `liar_ttl` 10 min |

Objects are ciphertext sealed by the application under the resource's keys, so a peer serving them learns nothing it could not already read; the `authorize` check still keeps existence and size from nodes without `Read`.

## Tests

`cargo test -p baton-fetch`: a peer serving an object; a lying peer skipped, remembered and the next honest peer used; an unauthorized requester getting nothing and not marked as lied to; the source as the last step, its wrong bytes refused; a stalled peer costing only its timeout; oversized objects neither served nor accepted; garbage requests not stopping the server; and regression tests from the first review (idle streams from one peer not starving others, no probing of another resource's objects, liars marked per resource and for a limited time, a server announcing a huge object then stalling costing only the timeout, oversized objects refused on both sides). Load scenario `fetch` (1,000 objects of 256 KiB over the in-memory link, verified: about 1.2 GB/s on the maintainer's laptop).
