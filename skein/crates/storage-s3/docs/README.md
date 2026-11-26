# skein-storage-s3

`Objects` from `skein-storage` in an S3-compatible bucket, through the `object_store` crate. Compare-and-swap uses the store's conditional writes, so it holds across processes and machines sharing the bucket. Everything else Skein stores sits on top through `Storage::over`.

## Public API

### `S3Config`

| Field | Meaning |
| --- | --- |
| `endpoint: Option<String>` | Endpoint URL for stores other than AWS S3 (`https://<account>.r2.cloudflarestorage.com`, `http://127.0.0.1:9000`); `None` means AWS S3 in `region`. |
| `bucket: String` | The bucket; it must exist. |
| `region: String` | The region, such as `us-east-1`; most S3-compatible stores accept any value. |
| `prefix: Option<String>` | Path inside the bucket under which every key is stored, such as `skein/prod`. Leading and trailing `/` are ignored; empty, `.` and `..` segments are refused. |
| `access_key_id: String` | Access key id. |
| `secret_access_key: String` | Secret access key. `Debug` prints `<redacted>` instead. |
| `allow_http: bool` | Allows a plain `http://` endpoint, and only when its host is `localhost` or a loopback address. Any other plain-HTTP endpoint is refused with `S3ConfigError::PlainHttp`. |

### `S3Objects`

- `S3Objects::new(&S3Config) -> Result<S3Objects, S3ConfigError>` builds the client. No request is made; a missing bucket or wrong credentials show up as `StorageError::Backend` on the first operation.
- `S3Objects::with_store(Arc<dyn ObjectStore>, prefix)` uses any `object_store` store, such as `InMemory` in tests. The store must support `PutMode::Create` and `PutMode::Update`.
- `impl Objects for S3Objects`:
  - `put` with `Expect::Absent` is a create-if-absent (`If-None-Match: *`), with `Expect::Version` an update-if-match (`If-Match` on the ETag), with `Expect::Any` a plain overwrite. A failed condition is `StorageError::Conflict`.
  - The `Version` is an opaque encoding of the ETag and, when the bucket has versioning, the object version id.
  - `delete` with `Expect::Any` deletes unconditionally and succeeds for a missing key. With `Expect::Version` or `Expect::Absent` it reads the current version first and then deletes; `object_store` has no conditional delete, so a write landing between the two is lost. The contract allows this race because callers only delete keys no one writes any more.
  - `list` lists under the prefix starting after `start_after` (`list_with_offset`), stops at `limit` and returns the keys sorted ascending. It relies on the store listing in byte order, as S3 does.
  - Backend errors carry only the kind of failure; the full `object_store` error, which can include the object path, is logged at debug level. Values are never logged.

### `S3ConfigError`

`PlainHttp`, `InvalidEndpoint`, `InvalidPrefix`, `Build(source)`.

## Which stores work

Conditional writes are required. AWS S3 (since 2024), Cloudflare R2 and MinIO support both `If-None-Match: *` and `If-Match` on `PutObject`. Any other S3-compatible store must pass the conformance suite (`tests/endpoint.rs` pointed at it) before it is used; a store that ignores the condition headers, or checks them without making the check and the write one atomic step, silently breaks compare-and-swap and therefore journal fencing.

See [docs/REQUIREMENTS.md](../../../docs/REQUIREMENTS.md) for what a store must do and which to pick. Self-hosted servers checked with `tests/endpoint.rs` (November 2026, five or more runs each):

| Server | License | Result |
| --- | --- | --- |
| RustFS 1.0.6 (Rust) | Apache-2.0 | passes; checked in CI |
| Versity S3 Gateway v1.11.0, posix backend (Go) | Apache-2.0 | passes; checked in CI and used by the other integration suites |
| moto server (November 2026, AWS emulator in Python) | Apache-2.0 | passes; image about 550 MB |
| SeaweedFS (November 2026) | Apache-2.0 | passes, but a run takes 8–24 s and the image is about 1 GB |
| MinIO (pgsty fork, 2026-08-04) | AGPL-3.0 | passes; no longer used, since upstream community MinIO is no longer maintained |
| vercel-labs `emulate` (npm, November 2026) | Apache-2.0 | ignores `If-None-Match: *` and overwrites |
| Garage v2.1.0 | AGPL-3.0 | ignores `If-None-Match: *` and overwrites |
| s3s-fs v0.17.0 | Apache-2.0 | checks `If-Match` but not atomically: all concurrent swaps win |

## Limits and quirks

- With single-part uploads the S3 ETag is the MD5 of the content, so writing identical bytes again yields the same version. Compare-and-swap still compares values correctly, but a version does not prove that no write happened in between, only that the value is the same. Enable bucket versioning if that matters. Baton state through `skein_storage::ControlState` does not have this problem: every record carries 16 random bytes, so every write has a new ETag.
- Every value is one `PutObject`; there is no multipart upload, so values are limited to 5 GiB by S3.
- Plain HTTP is for local containers only.

## Tests

- `cargo test -p skein-storage-s3` runs `skein_storage::testing::all_over_objects` against `object_store::memory::InMemory`, which supports conditional puts, with and without a prefix; the suite includes Baton's `StateStore` suite over `ControlState`.
- `tests/endpoint.rs` runs the same suite against a real endpoint under a fresh `skein-it/<ulid>` prefix. It runs only when `SKEIN_IT=1` and `SKEIN_IT_S3_ENDPOINT`, `SKEIN_IT_S3_BUCKET`, `SKEIN_IT_S3_ACCESS_KEY` and `SKEIN_IT_S3_SECRET_KEY` are set (`SKEIN_IT_S3_REGION` is optional), and prints a note and passes otherwise. The bucket must exist; the test does not clean up its prefix.
