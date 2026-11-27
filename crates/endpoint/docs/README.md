# rowboat-endpoint

The contract of the factory of link endpoints. The node binds one long-lived endpoint for its own identity, trusting exactly the nodes its group log counts, and one short-lived endpoint with an ephemeral identity for every pending pairing invite, trusting anyone until the invite is used up or expires.

## API

- `Endpoints::bind(identity, trust) -> Endpoint`: a new `baton_link::Link` keyed by `identity` and trusting what `trust` allows, plus the `PeerHint` other endpoints dial it with.
- `EndpointError`: `Unavailable` (could not bind; may be retried), `Closed`.

## What an implementation must do

- The link's `local()` is the identity's key and the link keeps every guarantee of `baton_link::Link`.
- The hint is enough for another endpoint of the same factory to reach this one.
- Endpoints are independent: closing one never affects another.

Run the suite from the implementation's tests with the `testing` feature: `rowboat_endpoint::testing::endpoints(&factory).await` (on a multi-threaded runtime).
