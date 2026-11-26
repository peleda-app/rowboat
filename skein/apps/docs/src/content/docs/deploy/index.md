---
title: Deploy and store
description: Running the skein binary, choosing storage, and operating it.
---

The `skein` binary is the only place that picks implementations. It reads a TOML config, builds storage (memory, files or S3), the local keyring, leases and liveness (single node, or coordination through the storage), in-process signals, every mail, calendar and contacts provider and every sender, then runs a node and its inbound listener (provider push and a health check) until `SIGTERM` or Ctrl-C, giving running work 30 seconds to stop.

| Page | |
| --- | --- |
| [The binary](/rowboat/deploy/run/binary/) | running, managing tenants, accounts, commands and webhooks, the image, export and import |
| [Configuration](/rowboat/deploy/run/configuration/) | every section of `skein.toml` |
| [Stateless deployment](/rowboat/deploy/run/stateless/) | what is durable and where |
| [Multiple nodes](/rowboat/deploy/run/multiple-nodes/) | leases through storage, weights, failover |
| [Metrics and OpenTelemetry](/rowboat/deploy/run/observability/) | Prometheus counters, OTLP, logs, account health |
| [Releases and verification](/rowboat/deploy/run/releases/) | images, binaries, signatures and attestations |
| [Storage requirements](/rowboat/deploy/storage/) | what object storage must do |
| [S3](/rowboat/deploy/storage/s3/), [files](/rowboat/deploy/storage/fs/), [memory](/rowboat/deploy/storage/memory/) | the backends |
