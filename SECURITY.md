# Security

This document covers the threat model for the Moddin Community
Capabilities catalog and the defenses each layer provides.

## Threat model

| Adversary | Goal | Example |
|---|---|---|
| Network attacker | Tamper with `catalog.json` or a capability YAML in transit | MITM, DNS poisoning, malicious mirror |
| Compromised contributor | Ship a malicious capability | Maintainer trust violation |
| Compromised maintainer | Ship a malicious catalog update | Key compromise |
| Compromised user account | Bypass review by merging a PR without review | Stolen GitHub credentials |

A capability YAML **cannot** execute arbitrary code. The capability
runtime in Moddin Desktop only knows the ten built-in step kinds
listed in `CAPABILITY-CONTRACT.md`. New kinds require a PR in the app
core. So the worst a malicious capability can do is:

- Spawn a process (any user-spawnable Windows process)
- Write to the game directory or `%LOCALAPPDATA%`
- Write / delete HKCU registry keys
- Download from the GitHub allow-list

A capability **cannot** read arbitrary files, exfiltrate data over the
network, or escalate privileges. The HKCU-only registry restriction
keeps anti-cheat unaffected.

## Defense layers

### Layer 1 — kind allow-list

The app's `builtin_steps::known_kinds()` is the source of truth. A
capability that references any other `kind` fails to load.

```
known_kinds() == [
  "extract-zip", "verify-hash", "file-delete", "write-text-file",
  "write-binary-file", "move-file", "spawn-process", "kill-process",
  "registry-write", "registry-delete"
]
```

Adding a kind requires a Rust code review in the app repo.

### Layer 2 — CI gate (this repo)

`validate.yml` runs on every PR:

- Parses every `capability.yaml` against the schema.
- Rejects unknown kinds, categories, statuses, severities.
- Verifies declared `sha256` checksums (downloads the archive and
  hashes it; rejects mismatches).
- Rejects `http://` URLs (HTTPS-only).
- Rejects relative `path` fields.
- Rejects duplicate `id`s.
- Rejects filesystem-escaping values.

A capability that passes CI is **syntactically and cryptographically
valid**, not necessarily safe.

### Layer 3 — maintainer review

`MAINTAINERS.md` lists who can merge. Every PR requires at least one
approval from a maintainer.

Maintainers should:

- Read the `safetyNotes` and check they match what the recipe actually
  does.
- Skim the `install` steps and check the kind combinations.
- Verify the maintainer / contributor has a clean track record
  (first-time contributors get a deeper review).
- Confirm the optional signature, when present, points to a public key
  the contributor controls.

### Layer 4 — signing

#### Per-capability signing (optional)

A contributor can sign their `capability.yaml` with an Ed25519 keypair:

```
SIGNED-BY:
  algorithm: ed25519
  publicKey: <base64>
  signature: <base64 of yaml_body || sha256(publicKey)>
```

The app verifies both the public key on file and the signature before
trusting the YAML. Keys can rotate independently per capability.

#### Catalog signing (mandatory for the public catalog)

`catalog.json` is signed by the maintainer team:

```
catalog.json
  + catalog.json.sig  ← detached Ed25519 signature of catalog.json bytes
  + public-keys.json  ← map of maintainer handle → Ed25519 public key
```

Apps verify the catalog signature against the pinned public key
embedded in the app binary. Key rotation requires a new app release —
intentional friction for the highest-trust asset.

Apps can pin multiple keys during a rotation window.

### Current maintainer key

The active maintainer signing key carries the following fingerprint:

| Field | Value |
|---|---|
| Public key (base64, raw 32 bytes) | `Mh/WGQ0kCviGtiX/8wLB5fqBCLgtVR/4smlVai13xs8=` |
| SHA-256 fingerprint (first 16 hex chars) | `e247ca4981f22245` |
| Generated | 2026-09-22 |
| Embedded in Moddin Desktop as | `BOOTSTRAP_PUBLIC_KEY_B64` in `src-tauri/src/community_catalog.rs` |

To verify the catalog on disk against this key locally:

```bash
cd src-tauri
MODDIN_BOOTSTRAP_KEY=Mh/WGQ0kCviGtiX/8wLB5fqBCLgtVR/4smlVai13xs8= \
    cargo run --example verify_signed_catalog -- \
    ../moddin-community-capabilities/catalog.json \
    ../moddin-community-capabilities/catalog.json.sig
```

Expected output: `[OK] ... (1021 bytes) signed by 64 bytes signature`.

### Layer 5 — origin-aware UX

The app shows different UI for capabilities of different origins:

| Origin | UI badge | Activity log | Install prompt |
|---|---|---|---|
| Built-in | "Verified" | normal | none |
| Local file | "Local" | verbose | none |
| Community + signed | "Verified" | normal | none |
| Community + unsigned | "Unverified" | verbose | confirmation required |

The user can disable Community catalog fetching entirely (config
toggle in `Settings → Privacy`).

### Layer 6 — kill switch

A capability is revoked by adding its `id` to `revoked-ids.json` in this
repo. That file is the **human-maintained input**. It is *not* what the
app reads: `scripts/regenerate_catalog.py` inlines it into the top-level
`revoked` array of `catalog.json`, and the maintainer signs the result.
One Ed25519 signature therefore covers the capability list and the
revocation list together, and the two cannot disagree.

```json
// revoked-ids.json — the input maintainers edit
{
  "revoked": [
    { "id": "compromised-mod", "reason": "..." },
    { "id": "another-mod", "reason": "..." }
  ]
}
```

```json
// catalog.json — the signed artefact the app actually reads
{
  "version": 1,
  "capabilities": [ ... ],
  "revoked": [
    { "id": "compromised-mod", "reason": "..." }
  ]
}
```

Revocation propagates within one catalog TTL.

#### Why it is not a separate file any more

While `revoked-ids.json` was fetched over its own GET, the kill switch
was the one unsigned thing in the trust chain, and the cache
re-verification could not cover it: the list is trusted *precisely when
it is stale*, so an attacker who could intercept that one request could
suppress a revocation until the TTL expired, and the app had no way to
tell. Inlining it removes the second channel rather than trying to
verify it.

The same change moves the check. The app used to consult the kill
switch **before** the signature, deliberately: an unsigned list can only
add refusals and never remove one, so checking it first could not weaken
anything. That ordering is gone, and deliberately so — there is nothing
left to read before the signature. What replaces it is stronger. An
attacker who edits the `revoked` array now edits `catalog.json`, which
breaks the signature and refuses **every** community install outright,
rather than quietly restoring one. A tampered list can no longer remove
a refusal, because there is no untampered-of list to remove it from.

#### How the app reads `revoked`

| Signed catalogue contains | The app does |
|---|---|
| `revoked` with a well-formed array | revokes those ids |
| **no `revoked` key at all** (or `revoked: null`) | **treats it as "nothing is revoked" and installs normally** |
| `revoked` of the wrong type, or an entry with no usable `id` | **refuses every community install** |
| a signature that does not verify | **refuses every community install, revoked or not** |

The absent-key row is a decision, and it is the safe direction. An
absent key cannot be treated as a failure without two bad outcomes: it
adds no protection (an attacker able to strip the key could rewrite the
whole catalog, and the signature check refuses everything anyway) while
bricking community installs against any catalog generated before the
field existed. Reading it as "nothing is revoked" cannot be exploited,
because a stripped key still has to survive the signature.

The malformed row is the opposite case and does fail closed. A broken
`revoked` value is not a statement by the maintainer, it is an app that
cannot tell a revoked capability from a live one. Guessing is exactly
the bounded-but-wrong reading the app avoids everywhere else, so the
whole catalog is refused. `scripts/validate_capability.py` checks the
same shape, and `regenerate_catalog.py` refuses to write a catalog at
all if `revoked-ids.json` is malformed — the mistake surfaces at review
time, not at install time.

A `revoked` entry with no `reason` still revokes; the app substitutes
"no reason published" rather than reading the missing field as "not
really revoked".

#### Revocation and rollback

Revocation governs **installs**, not restores. A snapshot restore copies
files back from the transaction's own backups and never reads the
catalog, so a user who installed a capability before it was revoked can
still undo or restore it. That asymmetry is intentional: revocation
stops new installs of a mod that should no longer be downloaded, and
refusing to restore would strand a user with files they cannot get back
out of their game folder. A user who uninstalls a revoked capability
and tries to install it again is blocked — that is the point.

## Reporting a vulnerability

Open a GitHub issue prefixed `[SECURITY]` or email
`security@petonexus.example` (replace with the real address). For
critical issues, do not disclose publicly until the maintainer team
has had a chance to ship a revoke.

## Out of scope

The following are intentionally **not** part of the threat model and
are the user's responsibility:

- Mods that violate game EULAs (Moddin does not bypass EAC / BattlEye).
- Side effects of any third-party mod once installed.
- Damage from running unsigned, "Unverified" capabilities without
  reading the safety notes.