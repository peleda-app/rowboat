# Baton

Baton is a library for the nodes of one person or one team (phones, desktops, always-on servers) to talk to each other and coordinate, without trusting relays, mailboxes or the network in between.

- **Who is in the group and who may do what.** Member and device keys, pairing, a signed group log with roles, per-resource capabilities and key epochs. A team member can read and command a shared resource without being able to read anyone's private one. Revocation rotates keys.
- **Who does the work now.** A lease per resource or job with fencing tokens, like Kubernetes leases. An always-on server wins while it is reachable, desktops come next, phones only as a last resort. Work is handed over to a stronger node when one appears.
- **Commands and signals.** Signed commands delivered to the current leaseholder, checked against capabilities, delivered at least once (the worker deduplicates), answered with a result; signals, previews and presence between nodes.
- **Objects from peers.** "Give me the object with this hash" goes to reachable peers in priority order, then to a source the application plugs in.
- **Pluggable transports.** iroh for live connections, our small store-and-forward drop service for nodes that are offline, wake-up channels.
- **No storage of its own.** Baton keeps nothing on disk. Its durable state (group log, key boxes, replay and vote state) goes through contracts the application implements, so the application decides where it lives and can restore a group from scratch with its recovery root.

Baton does not talk to mail providers, does not store application data and does not know what a message is. Its first user is Peleda, a mail application that runs [Skein](../skein/README.md) on whichever node holds the lease for an account and keeps its journal in object storage; other applications plug in their own resources, commands and storage.

Status: early development (phases 0, 1, 4, 5, 6 and 8 done; phase 8 built mailbox, wake, the drop protocol, `mailbox-memory`, `wake-mailbox`, `drop-http`, `mailbox-drop`, the `drop` service, `lease-server`, `group-server` and `batond`, the blind server; an embedded iroh relay and wake sending from `batond` are deferred). Start with [docs/PLAN.md](docs/PLAN.md).

| Document | About |
| --- | --- |
| [PLAN](docs/PLAN.md) | goals, non-goals, the boundary with the application, phases, what moves here from existing code |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | contracts and implementations, group log, leases and priority, commands, peer fetch, state contracts, how an application plugs in |
| [SECURITY](docs/SECURITY.md) | threat model, identities, capabilities, keys, recovery from scratch, revocation, compromise analysis |
| [TRANSPORTS](docs/TRANSPORTS.md) | iroh, drop, SimpleX, Matrix, Nostr, MLS, and notes for applications that arbitrate through object storage |
| [QUESTIONS](docs/QUESTIONS.md) | open decisions for the maintainer |
| [DECISIONS](docs/DECISIONS.md) | implementation decisions taken while building, with reasons |

## License

Baton is the `baton/` layer of [rowboat](../README.md) and is covered by its [PolyForm Noncommercial License 1.0.0](../LICENSE.md); contributions need the [Contributor License Agreement](../CLA.md).
