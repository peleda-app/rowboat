---
title: Ownership and fencing
description: One owner per account, fencing tokens, and how accounts move between nodes.
sidebar:
  order: 6
---

Exactly one node owns an account at a time: it holds the provider connections, writes the account's journal and runs its commands. Ownership is a lease from Baton, the coordination library Skein uses for leases, liveness and signals (the `baton-lease` contract). A tenant is a Baton group of the same id and an account a lease key of the same id (`skein_core::coordination`).

## Assignment

- Liveness is per node, not per account: each node writes one heartbeat per interval in a group all nodes share, so the cost grows neither with the number of accounts nor with the number of tenants.
- Accounts go to live nodes with `baton_lease::preferred`: the strongest class first (a node with `always_on = true` is a server, any other a desktop, which only gets accounts while no always-on node is alive), then weighted rendezvous hashing over `(tenant, account, node)`. Every node with the same view computes the same preferred owner, and only a leaving node's accounts move.
- A node's weight comes from its profile (`[node] weight`); weight `0` never owns accounts and only serves the API.

## Fencing

- Taking an account over writes one lease record with a new fencing token by compare-and-swap. That happens only when the holder changes, and only once the old holder has dropped out of liveness and the record has not changed for a whole time-to-live on the new holder's own clock.
- Tokens only grow; no two grants share one. They start at the wall clock in microseconds, so a restarted node with in-memory leases still outranks its earlier tokens.
- Every write of a cursor, a log segment or the head checks the token. Storage refuses writes with a lower token than it has seen, forever, so a node that lost an account fails with `NotOwner` on its next write instead of corrupting the journal.
- A node whose heartbeats stop succeeding stops acting on its accounts four fifths of the time-to-live after its last successful one, before another node may take them over, so sends and provider writes, which storage cannot fence, stay single. A run that started before such a lapse never reaches a provider again, even after heartbeats recover: it ends and the next run takes the lease again, or finds it taken.
- A node that shuts down releases its leases, so its accounts move at once. A stronger node may ask for an account; the holder hands it over at the start of its next run.

## Implementations

| Implementation | For |
| --- | --- |
| Baton's `lease-cas` over in-memory state (`baton-state-memory`) | one process |
| Baton's `lease-cas` over `skein_storage::ControlState` | several nodes coordinating through compare-and-swap on control records: leases under each tenant's control path `baton/`, heartbeats in the reserved group `_nodes` |

In the binary: `engine.ownership = "single"` or `"storage"` (the latter needs shared storage, fs or S3). See [multiple nodes](/rowboat/deploy/run/multiple-nodes/).

## What lives with the owner

- Long-lived connections (IMAP IDLE, JMAP push) and push subscriptions (Gmail watch, Graph subscriptions). When a node disappears another takes its accounts over.
- OAuth refresh happens only on the owner: Microsoft rotates refresh tokens, so two nodes refreshing at once would invalidate each other. Access tokens are shared as signals.
- A local cache only speeds things up; correctness never depends on local disk on a server.
