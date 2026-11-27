# rowboat-keystore-file

`rowboat-keystore` in a directory of files, for the headless server (`apps/rowboat`), which keeps every tenant's node keys in its own directory under the configured secrets directory, apart from the data directory.

- **Layout.** One file per item, named after the item (`rowboat.identity`, `rowboat.master`, ...), mode `0600`, in a directory created with mode `0700`.
- **Atomic writes.** A `put` writes a temporary file (`.<name>.<random>`; item names never start with `.`), syncs it, renames it over the item and syncs the directory. A failed or interrupted `put` leaves the previous item readable; a crash may leave a temporary file, never a torn item.
- **Refusals.** A symbolic link, a non-regular file, or a file readable by the group or others where an item should be is `Denied` for reads and writes, so a planted link cannot redirect a key and a key someone made readable is not used. A directory path that is not a directory is `Denied` at `open`. Items above `MAX_SECRET` are `Unsupported`.
- **Classes.** `Foreground` and `Background` are both readable whenever the process runs: a server has no screen lock. The class is not stored.

Runs `rowboat_keystore::testing::keystore` and `failed_put_keeps_the_old_item`, plus attack tests for planted links, readable files and oversized items.
