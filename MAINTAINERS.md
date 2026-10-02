# Maintainers

This repo is curated by the **Moddin Desktop maintainer team**. PRs
require at least one approval before they can merge.

## Active maintainers

| GitHub handle | Role | Public key fingerprint | Added |
|---|---|---|---|
| @moddin-bot | Lead maintainer, signing-key holder | `bbe4bcb7ebd11a6f` | 2026-10-02 |
| _(add your handle here)_ | Co-maintainer | _(pending)_ | — |

The `bbe4bcb7ebd11a6f` fingerprint is the first 16 hex characters of
SHA-256 over the raw 32 public-key bytes (base64:
`JURnO8HhZDsJdoTFEeF4mq1pDgFnfXN0/OZgPuzJKfc=`). It matches the
Moddin Desktop beta.6 bootstrap anchor and the active `public-keys.json` entry.
The previous active key was retired after its private copy could not be recovered;
the repository secret still held the older e247ca4981f22245 key. The maintainer
authorized a replacement on 2026-10-02. The new private key is kept outside Git
and supplied only through the `MODDIN_CATALOG_SIGNING_KEY` Actions secret.

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

## Revoking a capability

`revoked-ids.json` is the file maintainers edit. It is **not** what the
app reads: `scripts/regenerate_catalog.py` inlines it into `catalog.json`
and the maintainer signs the result, so one signature covers the
capability list and the kill switch together. See SECURITY.md, "Layer 6
— kill switch", for why.

1. Add the entry to `revoked-ids.json`:

   ```json
   { "revoked": [{ "id": "compromised-mod", "reason": "why, in one line" }] }
   ```

2. Check the shape:

   ```bash
   python scripts/validate_capability.py revoked-ids.json
   ```

3. Regenerate **and re-sign** the catalog. Both steps are required — a
   `revoked-ids.json` edit that was never regenerated is a revocation
   that is not in force, and the app only ever reads the signed copy:

   ```bash
   MODDIN_SIGNING_KEY="$(cat ~/.moddin/signing-key)" \
       python scripts/regenerate_catalog.py
   ```

   Without `MODDIN_SIGNING_KEY` the script deliberately writes
   `catalog.json` and skips the signature. That is fine for a dry run
   and a disaster to commit: the stale `catalog.json.sig` no longer
   matches, and every install in the field is refused until a real key
   is used.

4. Confirm the copy in the catalog matches the source, then commit
   `revoked-ids.json`, `catalog.json` **and** `catalog.json.sig`
   together:

   ```bash
   python scripts/validate_capability.py catalog.json
   ```

   That check fails if the embedded `revoked` array has drifted from
   `revoked-ids.json`, which is the failure mode this arrangement
   invites.

5. The revoke is live within one catalog TTL, and immediately on a user
   hitting Refresh.

A revocation is not a removal. A user who installed a capability before
it was revoked can still restore a snapshot taken while it was
installed — restores work from the transaction's own backups and never
read the catalog. A user who uninstalls and tries to reinstall is
blocked.

## What you cannot merge

- A PR that adds a new step kind. New kinds belong in the
  [app repo](https://github.com/petonexus/moddin-desktop).
- A PR that changes the schema. Schema lives in the app.
- A PR that disables a CI gate.
- A PR that revokes a previously merged capability **without**
  including a public `revoked-ids.json` entry in the same PR.
- A PR that edits `revoked-ids.json` **without** the regenerated
  `catalog.json` and its matching `catalog.json.sig`. The app reads the
  signed copy only, so the revocation is not in force until all three
  land together.

## Off-boarding

When a maintainer leaves:

1. Open a PR rotating the signing key (validates + re-signs the
   catalog).
2. Ship a new Moddin Desktop release that pins the new key.
3. Remove the maintainer's GitHub access on this repo.
4. Update `MAINTAINERS.md` and `public-keys.json`.
