---
title: Files
description: Objects as files under one directory, for a single node with a local disk.
sidebar:
  order: 3
---

`skein-storage-fs` stores objects as files under one root directory. It suits a single node with a local disk.

```toml
[storage]
kind = "fs"
path = "/data/skein"
```

## Guarantees

- Every write goes to a temporary file, is fsynced, renamed over the object and the directory fsynced: a crash leaves the old value or the new one, never a mix.
- Every write gets a fresh random version, even for the same bytes.
- Compare-and-swap is serialized per key inside the process.
- **One process per directory:** opening takes an exclusive advisory lock on `<root>/.lock`; a second process fails until the first stops.
- Symbolic links inside the root are never followed.
- Upper-case letters are escaped in file names, so keys that differ only in case stay apart on case-insensitive file systems.
- Directories are `0700` and files `0600` on unix.

## Limits

Unix is the supported platform. Temporary files left by a crash (`.tmp-*`) are never read and are safe to delete while the store is closed.

Full details: [skein-storage-fs README](https://github.com/peleda-app/rowboat/blob/main/skein/crates/storage-fs/docs/README.md).
