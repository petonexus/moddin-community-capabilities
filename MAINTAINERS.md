# Maintainers

This repo is curated by the **Moddin Desktop maintainer team**. PRs
require at least one approval before they can merge.

## Active maintainers

| GitHub handle | Role | Public key fingerprint | Added |
|---|---|---|---|
| @moddin-bot | Lead maintainer, signing-key holder | `d489a3a0be894b19` | 2026-09-24 |
| _(add your handle here)_ | Co-maintainer | _(pending)_ | — |

The `d489a3a0be894b19` fingerprint is `SHA-256(R2oSrMGh0d6pHIWFHZwvU+sA+wK1Uo/vaBq/L1WJ6GU=)[:8]`,
matching the value embedded in Moddin Desktop's `BOOTSTRAP_PUBLIC_KEY_B64`
constant. Apps verify this matches the public key in `public-keys.json`
before trusting any signed catalog.

### Past signing keys

| Fingerprint | Public key | Status |
|---|---|---|
| `d489a3a0be894b19` | `R2oSrMGh0d6pHIWFHZwvU+sA+wK1Uo/vaBq/L1WJ6GU=` | active |
| `e247ca4981f22245` | `Mh/WGQ0kCviGtiX/8wLB5fqBCLgtVR/4smlVai13xs8=` | rotated 2026-09-24 |

The 2026-09-24 rotation was triggered by a catalog signature mismatch:
the previous `.sig` no longer matched the catalog bytes (BOM / CRLF drift
in the working tree). Apps older than the v0.1.0-beta.2 release that
carries the new key will keep rejecting the new catalog until they update.

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
