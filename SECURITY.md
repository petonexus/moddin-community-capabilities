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

A capability can be revoked by adding its `id` to
`revoked-ids.json` in this repo. The app consults this list before
loading any capability. Revocation propagates within one catalog TTL.

```
{
  "revoked": [
    { "id": "compromised-mod", "reason": "..." },
    { "id": "another-mod", "reason": "..." }
  ]
}
```

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