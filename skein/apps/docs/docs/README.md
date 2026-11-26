# skein-docs

The documentation site, published at <https://peleda-app.github.io/rowboat/>. Astro Starlight with `starlight-sidebar-topics` (one sidebar per topic), `astro-mermaid` (diagrams in fenced `mermaid` blocks), the Geist font and `starlight-links-validator` (the build fails on a broken internal link or anchor).

It is a standalone bun project with its own `package.json` and `bun.lock`; the repository has no other JavaScript. Dependencies are pinned to exact versions.

## Running

```bash
cd skein/apps/docs
mise x -- bun install --frozen-lockfile
mise x -- bun run dev      # http://localhost:4321/rowboat/
mise x -- bun run build    # static site in dist/, then link validation
mise x -- bun run preview  # serves dist/
```

## Layout

- `astro.config.ts`: site and base (`https://peleda-app.github.io`, `/rowboat`), topics, Mermaid theme, link checker setup, edit links to GitHub.
- `src/content/docs/<topic>/`: one folder per topic (`start`, `concepts`, `providers`, `deploy`, `consumers`, `extending`). There is no API reference: the HTTP management API was removed.
- `src/styles/theme.css`: fonts and colors.

## Writing

- Internal links include the base: `/rowboat/concepts/journal/`, with a trailing slash.
- Facts come from the crate READMEs under `crates/*/docs/README.md` and `docs/*.md`; link to the README on GitHub for details instead of copying them. A change to a crate's behavior that the site describes updates the page in the same change.
- Invented data only: addresses on `example.com` and `example.org`, made-up names.
- Page order inside a topic comes from `sidebar.order` in the frontmatter.

## Deployment

`.github/workflows/docs.yml` at the repository root builds the site on pull requests and pushes that touch `skein/apps/docs/**`, and deploys `dist/` to GitHub Pages from `main` with `actions/deploy-pages`. The repository's Pages source must be set to **GitHub Actions**.
