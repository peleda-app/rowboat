# Releasing

rowboat publishes no crates and no npm packages: every crate is `publish = false` under the PolyForm Noncommercial License. A release is the tag `vX.Y.Z` with container images and binary archives built from it. The version is `version` in `[workspace.package]` of the root `Cargo.toml`.

The pipeline is built but switched off. Nothing in it runs until the repository variable `RELEASES_ENABLED` is `true`.

## How a release happens

1. Set `version` in `[workspace.package]` of the root `Cargo.toml` and add a section to `CHANGELOG.md` in a commit on `main`.
2. Push the tag `vX.Y.Z` on that commit. `.github/workflows/publish.yml` (at the repository root) starts on the tag; `workflow_dispatch` reruns it for an existing tag. Before building it checks that the tag matches the workspace version.
3. It builds and publishes, with the repository root as the build context:
   - the image `ghcr.io/peleda-app/rowboat:X.Y.Z`, `:X.Y` and `:latest` from `skein/Dockerfile`, for `linux/amd64` and `linux/arm64`, built on native runners, with SBOM and provenance attestations, a keyless cosign signature and a GitHub build provenance attestation;
   - archives `rowboat-vX.Y.Z-<target>.tar.gz` (`.zip` on Windows) holding `skein` for `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `x86_64-apple-darwin`, `aarch64-apple-darwin` and `x86_64-pc-windows-msvc`, each with `LICENSE.md`, a `.sha256` file and a Sigstore bundle (`.sigstore.json`, keyless cosign signature), plus `SHA256SUMS` with its own bundle and a build provenance attestation, uploaded to the GitHub release.

Binaries and images can be checked against their attestations:

```sh
gh attestation verify rowboat-v0.1.0-x86_64-unknown-linux-musl.tar.gz --repo peleda-app/rowboat
gh attestation verify oci://ghcr.io/peleda-app/rowboat:0.1.0 --repo peleda-app/rowboat
cosign verify ghcr.io/peleda-app/rowboat:0.1.0 \
  --certificate-identity-regexp '^https://github.com/peleda-app/rowboat/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Archives and `SHA256SUMS` verify with their bundles:

```sh
cosign verify-blob rowboat-v0.1.0-x86_64-unknown-linux-musl.tar.gz \
  --bundle rowboat-v0.1.0-x86_64-unknown-linux-musl.tar.gz.sigstore.json \
  --certificate-identity-regexp '^https://github.com/peleda-app/rowboat/\.github/workflows/publish\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Turning it on

1. **Rename the GitHub repository** `peleda-app/skein` to `peleda-app/rowboat` (the workflow runs only in `peleda-app/rowboat`), update `origin` and remove the local `pre-push` hook that blocks pushes until then.
2. **Set the repository variable** `RELEASES_ENABLED` to `true` (Settings → Secrets and variables → Actions → Variables).
3. **After the first image push**, open the package `rowboat` under the organization's Packages, set its visibility to public and link it to this repository so later runs can push with `GITHUB_TOKEN`. The organization has to allow public packages.

To pause releases, set `RELEASES_ENABLED` to anything else.
