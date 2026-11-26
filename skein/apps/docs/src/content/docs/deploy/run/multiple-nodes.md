---
title: Multiple nodes
description: Spreading accounts over nodes that share one bucket.
sidebar:
  order: 4
---

Several nodes can share one S3 bucket. File storage allows one server per directory (see [files](/rowboat/deploy/storage/fs/)), so it suits one node. Set on every node:

```toml
[node]
id = "node-2"      # unique per node
weight = 1

[storage]
kind = "s3"
# the same bucket and prefix on every node

[engine]
ownership = "storage"
```

## How accounts are spread

- Coordination uses the leases and liveness of Baton, the coordination library Skein uses, with its compare-and-swap arbiter over the storage's control records.
- Each node writes one heartbeat record per interval (in the reserved group `_nodes`, which no tenant id can name, so it cannot be registered, purged or exported); a node is alive for three heartbeat intervals after another node last saw a new heartbeat from it.
- Object storage bills these requests. Per node and interval: one write (its heartbeat), one listing and one read per node (who is alive, asked once per interval however many accounts it holds), plus one read per account it owns or checks. Ten nodes at the default 10 s interval make about 2.6 million writes, 2.6 million listings and 26 million reads a month, roughly $36 a month on AWS S3 before accounts; a longer `heartbeat_secs` lowers this proportionally but makes failover slower (three intervals). A single node (`engine.ownership = "single"`) writes no heartbeats.
- Every node sharing a store must use the same `engine.heartbeat_secs`: a node judges the others with its own interval. The agreed value is kept in shared storage; a node configured with another value refuses to start while any node with the agreed one is running, and becomes the new agreed value once none is (it watches heartbeats for three of the longer interval before deciding). To change the interval, stop every node, then start them with the new value.
- Accounts go first to nodes with `always_on = true`, then by weighted rendezvous hashing, so every node computes the same owner and only a leaving node's accounts move. Keep `always_on` the same on nodes that should share accounts.
- `weight = 0` makes a node take no accounts; it can still receive push.
- Taking an account over writes a new fencing token with compare-and-swap; the old owner's next write is refused. A node whose heartbeats fail stops working on its accounts before another node may take them, and a node that stops releases its accounts at once.
- Stop every node of a release before Skein on Baton before starting nodes of the new one: their coordination records differ (see the migration notes).

Failover has been load-tested with crashed and heartbeat-less nodes, checking whole journals and refused stale tokens, and 1,000+ accounts per node.

## Behind a load balancer

Any node can take any push request: the receivers only read the shared push registry. With in-process signals, though, the hint wakes a worker only on the node that received it; an account owned by another node waits for its next interval. Route push to the nodes with a shared signal backend once Baton has one, or keep `engine.interval_secs` short. The push rate limit counts per node. Management subcommands write to the shared storage and work from any machine with the config and master key file.

## Push

Gmail and Graph notifications can reach any node: the push routes only look up the account and publish a hint. With in-process signals, a hint reaches the owner only when the notification lands on the owner; otherwise the account syncs on its interval.
