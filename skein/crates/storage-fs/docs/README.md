# skein-storage-fs

`Objects` from `skein-storage` as files under one root directory. It suits a single node with a local disk: every write is atomic and flushed before it returns, and compare-and-swap holds between all tasks and all processes using the directory, so the `skein` subcommands manage a running `skein serve` on the same directory. Everything else Skein stores (control records, the journal, blobs, commands) sits on top through `Storage::over`.

## Public API

### `FsObjects`

- `FsObjects::open(root) -> Result<FsObjects, OpenError>` opens the store as its owner: creates `root` when missing (mode `0700` on unix), canonicalizes it and takes an exclusive advisory lock on `<root>/.lock`. The lock lives as long as the handle; dropping the handle releases it. A second owner fails with `OpenError::Locked`, which is what keeps a second `skein serve` (or node) off a directory.
- `FsObjects::close()` waits for every operation in progress (one whose caller was cancelled included), then refuses every later one with `StorageError::Backend` and releases the owner lock, so the root can be opened again while clones of the handle still exist (a task that outlived its owner can no longer write). Calling it again does nothing.
- `FsObjects::open_shared(root) -> Result<FsObjects, OpenError>` opens the same store without the owner lock, beside a running owner or alone. Management tools (the `skein` subcommands, export, import, copy) use it.
- `FsObjects::root()` is the canonical root directory.
- `impl Objects for FsObjects`, with these guarantees beyond the contract:
  - A write goes to a temporary file in the target directory, is fsynced, renamed over the object file, and the directory is fsynced. A crash leaves the old value or the new one, never a mix.
  - Every write gets a fresh random version (a ULID), even when the bytes are the same. The version lives in the object file's header, so a read always returns the value and the version that were written together.
  - Compare-and-swap holds across processes. A `put` or `delete` takes its key's stripe (one of 64, by FNV-1a of the key, the same in every process and build) twice: an async lock inside the process, then an exclusive advisory lock (`flock` on unix, `LockFileEx` on Windows) on `<root>/.locks/<stripe>` for the read-compare-write only, released when the write is renamed into place. Reads take no lock: an object file is only ever replaced whole by rename, so a reader sees the old value or the new one.
  - A lock file that is not a plain file (a symbolic link, a directory) fails the write instead of being followed.
  - Symbolic links inside the root are never followed: a read or write whose path crosses one fails with a backend error, and `list` skips them.
  - Directories are created and pruned under `<root>/.locks/tree`: a `put` holds it shared while it creates the directories and writes the file, a `delete` holds it shared while it removes the file and syncs the directory, then exclusive while it prunes the directories left empty. So a delete in one stripe never removes a directory that a write or delete in another stripe is using.
  - `list` walks the prefix directory recursively and returns keys in ascending byte order of the full key, honouring `start_after` and `limit` without reading subtrees that lie entirely before `start_after`.
  - Deleting the last object in a directory removes the empty directories up to the root.

### `OpenError`

- `Locked { root }` — another owner handle, in this process or another, holds the directory. Shared handles never cause it.
- `Io(io::Error)` — the directory or the lock file could not be created or opened.

## Config

Only the root directory. **One owner, any number of shared handles**: a second `open` of the same root fails with `OpenError::Locked` until the first owner is dropped; `open_shared` always works. Advisory locks protect against other Skein processes, not against other programs writing into the directory, and need a local file system (advisory locks over NFS are not relied on).

The owner notices what another process wrote the next time it reads: the engine reads tenants and accounts every heartbeat and an account's command queue every round (at most `engine.interval_secs` after a submit), so nothing has to wake it. In-memory caches of the owner (the keyring's key cache, `keyring.cache_ttl_secs`) can lag that long behind a change made by a subcommand.

### Why per-operation locks

The HTTP management API is gone (`docs/DECISIONS.md`, 2026-11-25), so the subcommands are the only way to manage a running server, and a lock held for the life of the server shut them out. Every Skein store above `Objects` (control records, the journal head, blobs, the command queue) is already built from compare-and-swap, so making each read-compare-write atomic between processes is enough for several processes to share a directory without weakening anything: journal appends stay fenced through the head's compare-and-swap, commands are created with `Expect::Absent`, and two writers of the same key still see exactly one success.

## On-disk layout

- Key `a/b/c` is the file `<root>/a/b/c~obj`; every segment but the last is a directory. The `~obj` suffix cannot appear in a key segment, so a key can also be the prefix of other keys (`a/b` and `a/b/c` both exist).
- Upper-case letters in a segment are written as `^` plus the lower-case letter (`01JAB` becomes `01^j^a^b`), so keys that differ only in case stay apart on case-insensitive file systems such as the macOS default.
- An object file is the 9-byte magic `skein-fs\x01`, the 26-character version, then the value byte for byte. A file without that header reads as `StorageError::Corrupt`.
- Directories are `0700` and files `0600` on unix.
- `<root>/.locks/00` to `3f` are the stripe lock files and `<root>/.locks/tree` the directory lock (all empty).
- Names starting with `.` (`.lock`, `.locks`, `.tmp-*`) and files without the `~obj` suffix are ignored by `list`.

## Limits and quirks

- A segment whose encoded name passes 255 bytes (128 characters with more than 123 upper-case letters) is refused with `StorageError::InvalidKey`.
- Temporary files left by a crash during a write (`.tmp-*`) are never read or listed; they are safe to delete while the store is closed.
- `list` reads every directory it descends into in full, so a single directory with very many objects costs a full `read_dir` per page.
- On macOS `sync_all` issues `F_FULLFSYNC`, which is slower than `fsync` on Linux but actually reaches the disk.
- Windows reserved names (`con`, `nul`, ...) are not handled; unix is the supported platform.

## Tests

`cargo test -p skein-storage-fs` runs `skein_storage::testing::all_over_objects` against a temporary directory (which includes Baton's `StateStore` suite over `ControlState`) plus the same suite over a shared handle beside an owner, tests for the owner lock and shared handles, stable stripes, a symlinked lock file, persistence across reopening, case handling, prefix/key overlap, pruning, pruning beside writes to other keys of the same directory, stray files, symlinks and permissions. `tests/baton_leases.rs` runs Baton's lease and liveness suites with `lease-cas` over `ControlState` on a temporary directory. `tests/processes.rs` spawns four children of the test binary on one directory (one owner, three shared) and checks that concurrent compare-and-swap increments of a 64 KiB record lose no update and never read a torn record, that racing creates have exactly one winner per key, that journal appends with fence handovers keep one verified hash chain holding every acknowledged event exactly once and in order, and that concurrent command submissions are all queued once (a shared id is new for exactly one child). Without the stripe lock files the first three fail.
