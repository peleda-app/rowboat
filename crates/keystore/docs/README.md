# rowboat-keystore

The contract of the device secret store: the only way the node reaches device secrets. The node keeps exactly two items in it, `rowboat.identity` (its Ed25519 secret) and `rowboat.master` (the master key its sealed objects and Skein's keyring derive from), both of class `Background`. It is deliberately smaller than the app's `peleda-vault`, which it maps onto one to one (`peleda-keystore-vault` in `../app`).

## API

| Item | Guarantees |
| --- | --- |
| `KeyName::new` | 1 to 64 characters of `[a-z0-9.-]`, not starting with `.`; anything else is `InvalidName` |
| `KeyClass` | `Foreground` (readable while the device is unlocked) or `Background` (from the first unlock until shutdown); never shared with extensions, synced or backed up |
| `Secret` | zeroized on drop, `Debug` shows only the length, no `Display` |
| `Keystore::get` | the secret, `None` when the item does not exist, `Locked` when it exists but cannot be read now; never another item's bytes |
| `Keystore::put` | atomic: a failed put leaves the old item readable; `Unsupported` when the class cannot be honoured or the secret is too large (every store takes `MAX_SECRET`, 16 KiB) |
| `Keystore::delete` | `true` when an item was removed |
| `KeystoreError` | `InvalidName`, `Locked`, `Denied`, `Unsupported`, `Backend`; no secret, path, name or platform text |

## Conformance

Every implementation runs, behind this crate's `testing` feature:

- `testing::keystore(&factory)`: missing items, round trip, replace, persistence across two instances from the factory, the largest secret, no cross-talk between items, delete and its persistence, refused names, error texts free of names;
- `testing::failed_put_keeps_the_old_item(store, arm)` when the store can inject a failing write.
