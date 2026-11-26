# Skein

Skein connects to mail, calendar and contacts providers (IMAP, JMAP, Gmail API, Microsoft Graph, CalDAV, CardDAV, Google Calendar and People) and turns every change into an append-only journal in object storage, with the original bytes of every message, event and contact. It carries out write commands placed next to that journal. Consumers build their own databases from it.

Skein is the mail engine layer (`skein/`) of [rowboat](../README.md), Peleda's node. Leases, liveness and signals come from the coordination layer next to it, [Baton](../baton/README.md).

Status: early development. See [docs/PLAN.md](docs/PLAN.md) and the repository's [plan](../docs/PLAN.md).

## License

Covered by rowboat's [PolyForm Noncommercial License 1.0.0](../LICENSE.md); contributions need the [Contributor License Agreement](../CLA.md).
