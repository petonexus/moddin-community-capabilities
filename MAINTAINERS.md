# Maintainers

This repo is curated by the **Moddin Desktop maintainer team**. PRs
require at least one approval before they can merge.

## Active maintainers

| GitHub handle | Role | Public key fingerprint |
|---|---|---|
| @marcoasjunior | Lead maintainer, signing-key holder | TBD on first release |
| _(add your handle here)_ | Co-maintainer | TBD on first release |

Add yourself via a PR that updates this file and the matching
`public-keys.json` entry. Two existing maintainers must approve.

## Maintainer responsibilities

- **PR review** — usually within 48h, ideally same-day.
- **CI hygiene** — keep `validate.yml` updated when the schema evolves.
- **Signing key custody** — at least two maintainers must hold copies
  of the catalog signing key (offline). Rotate when a maintainer
  leaves.
- **Releases** — the `build-catalog.yml` workflow publishes a
  `catalog-vN` GitHub release after every merge to `main`. Validate
  the regenerated `catalog.json` and `public-keys.json` before
  approving the workflow run.

## What you cannot merge

- A PR that adds a new step kind. New kinds belong in the
  [app repo](https://github.com/petonexus/moddin-desktop).
- A PR that changes the schema. Schema lives in the app.
- A PR that disables a CI gate.
- A PR that revokes a previously merged capability **without**
  including a public `revoked-ids.json` entry in the same PR.

## Off-boarding

When a maintainer leaves:

1. Open a PR rotating the signing key (validates + re-signs the
   catalog).
2. Ship a new Moddin Desktop release that pins the new key.
3. Remove the maintainer's GitHub access on this repo.
4. Update `MAINTAINERS.md` and `public-keys.json`.