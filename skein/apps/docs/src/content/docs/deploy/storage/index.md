---
title: Storage requirements
description: What Skein needs from object storage, and which servers meet it.
sidebar:
  order: 1
  label: Requirements
---

Skein keeps its journal, blobs, commands and control records behind the storage contracts. Backends implement one small trait, `Objects` (key–value with compare-and-swap); the four typed stores the engine uses sit on top of it.

| Store | Holds | Needs |
| --- | --- | --- |
| `ControlStore` | accounts, sealed credentials, cursors, owners, keys, and through `ControlState` the records of Baton (the coordination library Skein uses for leases, liveness and signals) under `baton/` | compare-and-swap, listing by prefix |
| `Log` | per-account events, heads, snapshots | append by the owner only, fencing, ordered reads |
| `BlobStore` | content by BLAKE3 hash | idempotent put, hash-checked get |
| `CommandQueue` | write requests | ordered by ULID, idempotent by id |

| Backend | For |
| --- | --- |
| [S3](/rowboat/deploy/storage/s3/) | shared storage for stateless nodes |
| [Files](/rowboat/deploy/storage/fs/) | one node with a local disk |
| [Memory](/rowboat/deploy/storage/memory/) | tests and library mode |

## What an S3-compatible store must do

Ownership of an account and the fencing of the journal rest on compare-and-swap, which S3 offers only through conditional writes. A store that misses a requirement may seem to work and then lose or duplicate data under concurrency.

| Requirement | Why |
| --- | --- |
| `PutObject` with `If-None-Match: *` fails with `412` when the key exists | creating a record or a segment exactly once |
| `PutObject` with `If-Match: <etag>` fails with `412` when the object changed | compare-and-swap on heads, cursors, owners, keys |
| The condition check and the write are one atomic step | otherwise two nodes can both believe they own an account and both write its journal |
| Read-after-write consistency | a node must see what another node just committed |
| `ListObjectsV2` with `prefix` and `start-after`, keys in ascending byte order | reading the journal in order, listing heads and commands |
| Case-sensitive keys | command ids are ULIDs and differ by case |
| ETags on `GetObject`, `HeadObject` and `PutObject` responses | they are the versions compare-and-swap compares |
| AWS Signature Version 4 | authentication |

Skein does not need object versioning, multipart uploads, bucket policies or lifecycle rules (expiring blobs by a lifecycle rule is optional).

## Checked servers

Checked with the storage conformance suite, five to fifteen runs each (November 2026):

| Server | License | Result |
| --- | --- | --- |
| RustFS 1.0.6 | Apache-2.0 | **passes**; checked in CI |
| Versity S3 Gateway v1.11.0, posix backend | Apache-2.0 | **passes**; checked in CI |
| moto server | Apache-2.0 | passes; for tests only |
| SeaweedFS | Apache-2.0 | passes, but slow in tests and a 1 GB image |
| MinIO (pgsty fork) | AGPL-3.0 | passes; upstream community MinIO is no longer maintained |
| Garage v2.1.0 | AGPL-3.0 | **fails**: ignores `If-None-Match: *` and overwrites |
| vercel-labs `emulate` | Apache-2.0 | **fails**: ignores `If-None-Match: *` and overwrites |
| s3s-fs v0.17.0 | Apache-2.0 | **fails**: checks `If-Match` without making it atomic |

Hosted stores that support the conditional writes: AWS S3, Cloudflare R2.

For self-hosting, use **RustFS** (storage that spans several disks or machines) or **Versity S3 Gateway** (one machine or a shared file system; smaller and faster).

## Checking another store

Any other store must pass the endpoint suite before it is used. Run it more than once: an atomicity bug often shows only in some runs.

```bash
SKEIN_IT=1 SKEIN_IT_S3_ENDPOINT=https://s3.example.org SKEIN_IT_S3_BUCKET=skein-check \
  SKEIN_IT_S3_ACCESS_KEY=... SKEIN_IT_S3_SECRET_KEY=... \
  cargo test -p skein-storage-s3 --test endpoint
```
