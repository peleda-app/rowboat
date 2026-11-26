---
title: Previews and hints
description: Durable events, previews before they are durable, and hints that say where the head is.
sidebar:
  order: 8
---

Skein delivers a change in three ways, from slow and certain to fast and lossy.

| Kind | Carries | Guarantee | Use |
| --- | --- | --- | --- |
| **Durable** | events in the log with their `seq` | ordered, gap-free, at least once to readers | the only thing that moves a consumer's checkpoint and becomes a fact in its database |
| **Preview** | the change as soon as it is seen, without a number: mailbox, item and blob | none | show a new message at once, or push to a phone, then wait for the durable event before recording it |
| **Hint** | "account A is at N" | none | wake up and read the log |

A node that crashes before flushing loses only previews; the change comes back from the provider because the cursor had not moved.

## Where they arrive

- Previews are published as signals on the topic `preview/{account}`, head hints on `heads/{account}`.
- A consumer in the node's process subscribes to them on the Baton `Signal`; [`skein-view`](/rowboat/consumers/skein-view/) does.
- Signed [webhooks](/rowboat/consumers/webhooks/) carry durable events themselves.
- Without any of them, a consumer polls the tenant's heads (`Log::heads`) every few seconds. A missed hint only delays a consumer.
