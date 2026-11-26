---
title: The binary
description: skein serve, the management subcommands, check-config, export, import, copy, and the container image.
sidebar:
  order: 1
---

There is no management API. The subcommands open the node's storage and master key file from the same config and write through the same stores the node reads, with the same checks; they work while the node runs, with `fs` or `s3` storage. Every command takes `-c skein.toml` or reads `SKEIN_CONFIG`. Secrets come from stdin (a pipe or a file, never a terminal that would show them), never from arguments.

## Running

| Command | |
| --- | --- |
| `skein serve` | runs a node and its inbound listener (push, health) |
| `skein check-config` | checks the file and the secrets it names |
| `skein push-token` | prints a new random secret for the Gmail Pub/Sub push address |

## Managing

| Command | |
| --- | --- |
| `skein tenant add <t>` / `list` / `remove <t>` | registers (idempotent), lists, unregisters (data stays) |
| `skein tenant remove <t> --purge --confirm <t>` | deletes every account, credential, journal, blob and command of the tenant and destroys its key; irreversible, and the id cannot come back |
| `skein account put --tenant t <a> --file a.json` | stores a record (`provider`, `settings`, `auth`, optional `include`, `exclude`, `paused`, `send`, `pim`); never secrets |
| `skein account list --tenant t` / `show --tenant t <a>` | records with their health |
| `skein account remove --tenant t <a>` | deletes the record and its credentials; the journal stays |
| `skein account password --tenant t <a> [--pim]` | seals a password from stdin |
| `skein account send-key --tenant t <a> --access-key-id ID` | seals an SES secret (and optional session token) from stdin |
| `skein account grant --tenant t <a> [--expires-at ms]` | stores OAuth tokens from stdin: access token, optional refresh token |
| `skein journal put-blob --tenant t --file m.eml` | stores a blob and prints its hash |
| `skein journal get-blob --tenant t <hash> --out m.eml` | writes a blob to a new owner-only file, checked against its hash |
| `skein journal submit --tenant t <a> --file c.json` | queues `{"id"?, "body"}`; prints `{"id", "duplicate"}` |
| `skein journal cancel --tenant t <a> <id>` | cancels a queued command that has not started |
| `skein journal events --tenant t <a> [--from 1] [--limit 100]` | prints events, one JSON object per line |
| `skein webhook add --tenant t --url U [--events ...] [--accounts ...]` | adds an endpoint, printing its secret once |
| `skein webhook list` / `pause` / `resume` / `rotate` / `remove` | manages endpoints |

A command queued from the command line reaches the owner on its next round, at most `engine.interval_secs` later (sooner when the provider pushes a change).

## Moving data

| Command | |
| --- | --- |
| `skein export --tenant t --out t.ndjson.zst` | writes every object of a tenant to a file; sealed records stay sealed |
| `skein import --tenant t --in t.ndjson.zst` | reads an export into the configured storage; never overwrites, refuses objects of another tenant |
| `skein copy --from a.toml --to b.toml --tenant t` | copies a tenant between storages directly; never overwrites |

Export, import and copy run while no node writes the tenant; the target keeps working with the same master key file.

## Image

```bash
docker build -t rowboat -f skein/Dockerfile .
docker run -v /srv/skein/skein.toml:/etc/skein/skein.toml:ro -v skein-data:/data \
  -e SKEIN_S3_ACCESS_KEY_ID -e SKEIN_S3_SECRET_ACCESS_KEY -p 8080:8080 rowboat
docker exec -i <container> skein tenant add acme
```

The image is Debian slim, runs as uid 10001, has `/data` as a volume and `/etc/skein/skein.toml` as the config path. Mount the config read-only and pass secrets as environment variables. Published images are described in [Releases and verification](/rowboat/deploy/run/releases/).

:::note
Build from the root of the rowboat repository: the build context must hold both `skein/` and `baton/`, since Skein depends on Baton by path.
:::

## Features

The `otel` cargo feature adds the OTLP exporter for traces and metrics. Asking for an OTLP endpoint in a build without it is an error, not a silent no-op.
