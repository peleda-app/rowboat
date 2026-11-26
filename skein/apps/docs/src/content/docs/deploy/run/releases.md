---
title: Releases and verification
description: What a release will publish, how to check images and binaries against their signatures and attestations, and how to report a vulnerability.
sidebar:
  order: 7
---

:::note
No release has been published yet. This page describes how releases will work once they start; until then, build the binary or the image from a checkout.
:::

The container image and the binaries share one version. Nothing is published to crates.io or npm. A release is the tag `vX.Y.Z` and a GitHub release of the same name, with the changelog section as its notes.

## What a release publishes

| Artifact | Where |
| --- | --- |
| `skein` image | `ghcr.io/peleda-app/rowboat:X.Y.Z`, `:X.Y`, `:latest` |
| archives holding `skein` | the GitHub release, as `rowboat-vX.Y.Z-<target>.tar.gz` (`.zip` on Windows) |

Images are built for `linux/amd64` and `linux/arm64`. Archives cover `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `x86_64-apple-darwin`, `aarch64-apple-darwin` and `x86_64-pc-windows-msvc`.

## Signatures and attestations

- Every image carries SBOM and provenance attestations, a keyless [cosign](https://docs.sigstore.dev/) signature made by the release workflow, and a GitHub build provenance attestation.
- Every archive has a `.sha256` file next to it; the release also carries `SHA256SUMS` and a build provenance attestation for the archives.

Nothing is signed with a long-lived key: the signatures and attestations name the workflow in `peleda-app/rowboat` that built the artifact, which is what you check.

## Verifying

Check an archive's checksum, then its provenance with the [GitHub CLI](https://cli.github.com/):

```sh
sha256sum -c rowboat-v0.1.0-x86_64-unknown-linux-musl.tar.gz.sha256
gh attestation verify rowboat-v0.1.0-x86_64-unknown-linux-musl.tar.gz --repo peleda-app/rowboat
```

On macOS, `shasum -a 256 -c` does what `sha256sum -c` does.

Check an image's provenance, and its cosign signature:

```sh
gh attestation verify oci://ghcr.io/peleda-app/rowboat:0.1.0 --repo peleda-app/rowboat

cosign verify ghcr.io/peleda-app/rowboat:0.1.0 \
  --certificate-identity-regexp '^https://github.com/peleda-app/rowboat/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

A failed check means the artifact was not built by this repository's release workflow: do not run it. Pin images by digest once verified, so a moved tag cannot change what you run.

## Supported versions and reporting

Only the latest release gets security fixes; upgrade before reporting a problem.

Report vulnerabilities privately through [GitHub security advisories](https://github.com/peleda-app/rowboat/security/advisories/new) (the repository's **Security** tab, **Report a vulnerability**), never in a public issue, pull request or discussion. Include the affected version or commit, the component (for example `skein-server` or `skein-view`), how to reproduce it with invented data, and the impact you see. A fix and its advisory are published together once a release carries the fix.

See [Tenants and security](/rowboat/concepts/security/) for how Skein is hardened and what has been reviewed.
