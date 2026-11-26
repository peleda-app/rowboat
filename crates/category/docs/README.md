# rowboat-category

The contract of the node's category hook: one category for a message as rinse rendered it. The node runs it inside its parser adapter, after `rinse_mail::verify_rendered`, and stores the answer as the tag `category.<id>` the app shows as a label and a filter. A category never moves, deletes or hides a message in phase 1.

| Item | Guarantees |
| --- | --- |
| `CategoryInput` | the verified `Rendered` and the account id |
| `Category::new` | `[a-z0-9._-]{1,55}`, so `tag()` is a valid view tag |
| `Categorizer::category` | synchronous, deterministic, never panics, no I/O, `None` when unsure |
| `Categorizer::version` | `[a-z0-9._-]{1,64}`; changes whenever an answer may change |

## Conformance

`testing::categorizer(&c, &rendered)` (feature `testing`): deterministic answers over messages the implementation's tests render (rinse's hostile corpus), no panic, a well-formed version, every category a valid tag.
