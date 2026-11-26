# skein-storage-fs

`Objects` from `skein-storage` as files under one root directory. It suits a single node with a local disk: every write is atomic and flushed before it returns, and compare-and-swap holds between all tasks of the process that opened the directory. Everything else Skein stores (control records, the journal, blobs, commands) sits on top through `Storage::over`.

## Public API

### `FsObjects`

- `FsObjects::open(root) -> Result<FsObjects, OpenError>` creates `root` when missing (mode `0700` on unix), canonicalizes it and takes an exclusive advisory lock on `<root>/.lock`. The lock lives as long as the handle; dropping the handle releases it.
- `FsObjects::root()` is the canonical root directory.
- `impl Objects for FsObjects`, with these guarantees beyond the contract:
  - A write goes to a temporary file in the target directory, is fsynced, renamed over the object file, and the directory is fsynced. A crash leaves the old value or the new one, never a mix.
  - Every write gets a fresh random version (a ULID), even when the bytes are the same. The version lives in the object file's header, so a read always returns the value and the version that were written together.
  - Compare-and-swap is serialized per key inside the process (striped async locks).
  - Symbolic links inside the root are never followed: a read or write whose path crosses one fails with a backend error, and `list` skips them.
  - `list` walks the prefix directory recursively and returns keys in ascending byte order of the full key, honouring `start_after` and `limit` without reading subtrees that lie entirely before `start_after`.
  - Deleting the last object in a directory removes the empty directories up to the root.

### `OpenError`

- `Locked { root }` — another handle, in this process or another, holds the directory.
- `Io(io::Error)` — the directory or the lock file could not be created or opened.

## Config

Only the root directory. **One process per directory**: a second `open` of the same root fails with `OpenError::Locked` until the first handle is dropped. Advisory locks protect against other Skein processes, not against other programs writing into the directory.

## On-disk layout

- Key `a/b/c` is the file `<root>/a/b/c~obj`; every segment but the last is a directory. The `~obj` suffix cannot appear in a key segment, so a key can also be the prefix of other keys (`a/b` and `a/b/c` both exist).
- Upper-case letters in a segment are written as `^` plus the lower-case letter (`01JAB` becomes `01^j^a^b`), so keys that differ only in case stay apart on case-insensitive file systems such as the macOS default.
- An object file is the 9-byte magic `skein-fs\x01`, the 26-character version, then the value byte for byte. A file without that header reads as `StorageError::Corrupt`.
- Directories are `0700` and files `0600` on unix.
- Names starting with `.` (`.lock`, `.tmp-*`) and files without the `~obj` suffix are ignored by `list`.

## Limits and quirks

- A segment whose encoded name passes 255 bytes (128 characters with more than 123 upper-case letters) is refused with `StorageError::InvalidKey`.
- Temporary files left by a crash during a write (`.tmp-*`) are never read or listed; they are safe to delete while the store is closed.
- `list` reads every directory it descends into in full, so a single directory with very many objects costs a full `read_dir` per page.
- On macOS `sync_all` issues `F_FULLFSYNC`, which is slower than `fsync` on Linux but actually reaches the disk.
- Windows reserved names (`con`, `nul`, ...) are not handled; unix is the supported platform.

## Tests

`cargo test -p skein-storage-fs` runs `skein_storage::testing::all_over_objects` against a temporary directory (which includes Baton's `StateStore` suite over `ControlState`) plus tests for the lock, persistence across reopening, case handling, prefix/key overlap, pruning, stray files, symlinks and permissions. `tests/baton_leases.rs` runs Baton's lease and liveness suites with `lease-cas` over `ControlState` on a temporary directory.
