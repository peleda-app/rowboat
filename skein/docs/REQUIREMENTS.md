# Requirements

What Skein needs from the services it runs on. A service that misses a requirement may seem to work and then lose or duplicate data under concurrency, so check it before using it.

## Object storage (S3-compatible)

Skein keeps its journal, blobs, commands and control records in object storage through `skein-storage-s3`. Ownership of an account and the fencing of the journal rest on compare-and-swap, which S3 offers only through conditional writes.

### What the store must do

| Requirement | Why |
| --- | --- |
| `PutObject` with `If-None-Match: *` fails with `412` when the key exists | creating a record or a segment exactly once |
| `PutObject` with `If-Match: <etag>` fails with `412` when the object changed | compare-and-swap on log heads, cursors, owners, keys |
| The condition check and the write are one atomic step: of concurrent conditional writes with the same expectation, at most one succeeds | otherwise two nodes can both believe they own an account and both write to its journal |
| Read-after-write consistency | a node must see what another node just committed |
| `ListObjectsV2` with `prefix` and `start-after`, keys in ascending byte order | reading the journal in order, listing heads and commands |
| Case-sensitive keys | command ids are ULIDs and differ by case |
| ETags on `GetObject`, `HeadObject` and `PutObject` responses | they are the versions compare-and-swap compares |
| AWS Signature Version 4 | authentication |

Skein does not need: object versioning, multipart uploads, a key that is also a prefix of another key (`a` next to `a/b`), bucket policies or lifecycle rules (expiring blobs by lifecycle rules is optional).

### Checked servers

Every candidate is checked with the storage conformance suite, `crates/storage-s3/tests/endpoint.rs`, five to fifteen runs each (November 2026):

| Server | License | Result |
| --- | --- | --- |
| [RustFS](https://github.com/rustfs/rustfs) 1.0.6 (Rust) | Apache-2.0 | **passes** |
| [Versity S3 Gateway](https://github.com/versity/versitygw) v1.11.0, posix backend (Go) | Apache-2.0 | **passes** |
| moto server (AWS emulator, Python) | Apache-2.0 | passes; meant for tests only |
| SeaweedFS | Apache-2.0 | passes, but slow in tests (8–24 s per run) and a 1 GB image |
| MinIO (pgsty fork) | AGPL-3.0 | passes; upstream community MinIO is no longer maintained |
| Garage v2.1.0 | AGPL-3.0 | **fails**: ignores `If-None-Match: *` and overwrites |
| vercel-labs `emulate` | Apache-2.0 | **fails**: ignores `If-None-Match: *` and overwrites |
| s3s-fs v0.17.0 | Apache-2.0 | **fails**: checks `If-Match` without making it atomic; all concurrent writers win |

Hosted stores that support the conditional writes above: AWS S3, Cloudflare R2.

### Recommendation

For self-hosting, use **RustFS** or **Versity S3 Gateway**: CI checks both against the requirements on every change, so a release that breaks them is caught.

| | RustFS 1.0.6 | Versity S3 Gateway v1.11.0 |
| --- | --- | --- |
| What it is | distributed object store with erasure coding | S3 front end over a file system |
| Image | 429 MB | 112 MB |
| Memory idle / under test load | about 22 / 120 MiB | about 11 / 40 MiB |
| Speed in the test suites | about 4× slower | faster |
| Good for | storage that has to span several disks or machines | one machine or a shared file system; tests |

Any other store must pass `tests/endpoint.rs` pointed at it before it is used:

```bash
SKEIN_IT=1 SKEIN_IT_S3_ENDPOINT=https://s3.example.org SKEIN_IT_S3_BUCKET=skein-check \
  SKEIN_IT_S3_ACCESS_KEY=... SKEIN_IT_S3_SECRET_KEY=... cargo test -p skein-storage-s3 --test endpoint
```

Run it more than once: an atomicity bug often shows only in some runs.
