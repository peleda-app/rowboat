---
title: Quick start
description: Run one node, register a tenant, connect a mailbox and read its journal from the command line.
sidebar:
  order: 3
---

This walk-through runs one node on one machine with file storage, connects an IMAP mailbox and reads its journal with the binary's subcommands. There is no management API: the subcommands open the node's storage and master key file and write through the same stores the node reads. All names and addresses are examples.

## 1. Configure

Write `skein.toml`:

```toml
[node]
id = "node-1"

[storage]
kind = "fs"
path = "/data/skein"

[keyring]
master_key_file = "/data/master.key"   # created with mode 0600 when missing; back it up

[server]
listen = "127.0.0.1:8080"              # only push receivers and GET /v1/health

[engine]
enabled = true
ownership = "single"
```

```bash
skein check-config -c skein.toml
skein serve -c skein.toml
```

The full set of settings is in the [configuration reference](/rowboat/deploy/run/configuration/). The commands below take `-c skein.toml` too, or read `SKEIN_CONFIG`.

## 2. Register a tenant

Every account belongs to a tenant, an id from your side:

```bash
skein tenant add acme
```

## 3. Connect a mailbox

```bash
cat > box.json <<'JSON'
{"provider": "imap", "settings": {"host": "imap.example.com", "username": "ada@example.com"}, "auth": {"type": "password"}}
JSON
skein account put --tenant acme box --file box.json
skein account password --tenant acme box < app-password.txt
```

The password is read from stdin (a file or a pipe; a terminal is refused, since it would show what you type), sealed with the account's key and never shown again. For Google and Microsoft accounts, hand in tokens with `skein account grant` and configure an [OAuth client](/rowboat/providers/auth/oauth-clients/) so the node can refresh them.

## 4. Read the journal

```bash
skein account show --tenant acme box                  # the record and its health
skein journal events --tenant acme box --from 1
skein journal get-blob --tenant acme <hash> --out message.eml
```

Events point at blobs; a blob is the original RFC 5322 message. [Reading the journal](/rowboat/consumers/) explains checkpoints, snapshots and compaction for programs that follow it.
