# rowboat-spam

The contract of the node's spam hook: a verdict for one message as rinse rendered it. The node runs it inside its parser adapter, after `rinse_mail::verify_rendered`, and stores the verdict as a tag (`spam.junk`, `spam.suspicious`) the app shows as a badge and a filter. A tag never moves, deletes or hides a message in phase 1.

| Item | Guarantees |
| --- | --- |
| `SpamInput` | the verified `Rendered`, the account id, whether the provider placed the message in a junk-role mailbox, and `receivers`: the domains whose servers receive the account's mail, the only authserv-ids whose results may raise trust |
| `SpamVerdict` | `Clean`, `Suspicious`, `Junk`, `NotChecked`; `tag()` gives the stored tag |
| `SpamFilter::verdict` | synchronous, deterministic, never panics, no I/O; never sees raw bytes |
| `SpamFilter::version` | `[a-z0-9._-]{1,64}`; changes whenever a verdict may change, so the node re-parses lazily |

Pellet's content verdicts need Pellet inside rinse's sandbox, since Pellet parses raw messages itself (question 41).

## Conformance

`testing::filter(&filter, &rendered, honours_junk)` (feature `testing`): deterministic verdicts in and out of a junk mailbox over messages the implementation's tests render (rinse's hostile corpus), no panic, a well-formed version, and `Junk` for junk placement when the filter honours placement.
