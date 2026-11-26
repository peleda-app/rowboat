---
title: Memory
description: Objects in memory, for tests and library mode.
sidebar:
  order: 4
---

`skein-storage-memory` keeps every object in memory. Nothing survives the process. It passes the full storage conformance suite and is meant for tests, load tests and library mode, where the journal feeds a consumer in the same process.

```toml
[storage]
kind = "memory"
```

The binary refuses `engine.ownership = "storage"` with memory storage, since other nodes cannot see it.
