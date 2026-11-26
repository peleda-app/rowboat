# baton-link-memory

An in-process implementation of `baton-link` for tests. Links join a `MemoryLinkHub`; streams are `tokio::io::duplex` pipes. Trust is enforced exactly as the contract asks, on both ends, for every stream. Bytes are not encrypted because they never leave the process.

## API

- `MemoryLinkHub::new()`: an empty network, every link in one partition. Cloning shares it.
- `MemoryLinkHub::join(key, trust) -> MemoryLink`: joins a link; joining again with the same key closes the earlier link.
- `MemoryLinkHub::partition(groups)`: links in different groups cannot reach each other, and open streams between groups are severed now. Links in no group form one more partition.
- `MemoryLinkHub::heal()`: lets new streams through again; severed streams stay severed.
- `MemoryLink` implements `Link`. `add_hint` accepts and ignores hints (there is nothing to dial).

## Behavior

- `open` checks, in this order: link closed (`Closed`), local trust (`Untrusted`), the peer joined, open and in the same partition (`Unreachable`), the peer trusts us (`Rejected`), the peer listens for the protocol (`Rejected`).
- A severed stream fails every read and write with `ConnectionReset`; a dropped end gives the other end end-of-stream on read and an error on write.
- Each direction buffers `STREAM_BUFFER` (64 KiB); writers wait for readers beyond that.

## Tests

`cargo test -p baton-link-memory` runs `baton_link::testing::link` and a partition test (sever on split, `Unreachable` while split, new streams after healing).
