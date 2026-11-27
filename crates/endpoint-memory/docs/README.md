# rowboat-endpoint-memory

`rowboat-endpoint` over `baton-link-memory`: every endpoint bound by one `MemoryEndpoints` (and its clones) reaches every other in process, routed by key; hints are empty. `hub()` exposes the `MemoryLinkHub` so tests can partition and heal the network.

Runs `rowboat_endpoint::testing::endpoints`.
