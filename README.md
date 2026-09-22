# Moddin Community Capabilities

Community-maintained install recipes for **[Moddin Desktop](https://github.com/petonexus/moddin-desktop)** — the Windows-first game mod manager.

A **capability** is a data-driven YAML recipe that declares checks, install / uninstall / verify steps, and safety notes. The Moddin Desktop app consumes both built-in capabilities (shipped with the app) and the ones listed here, so any contributor can ship a new mod without touching the Rust core.

---

## How it works

```
┌────────────────────────┐  1. open PR   ┌──────────────────────────┐
│ Moddin Community Repo   │ ───────────► │ petonexus/moddin-desktop  │
│ (this repo)             │   4. app     │ (Rust + Vue app)         │
│                        │   fetches    │                          │
│ capabilities/*/        │   catalog    │                          │
│   capability.yaml      │              │                          │
│                        │              │                          │
└────────────────────────┘              └──────────────────────────┘
            ▲                                       │
            │                                       │
            │      2. CI validates YAML              │
            │      3. maintainer reviews             │
            │      5. catalog.json regenerates ──────┘
```

1. **Anyone** opens a PR adding `capabilities/<id>/capability.yaml`.
2. **CI validates** schema, kinds, SHA-256 (when declared), and signs.
3. **Maintainer** reviews the PR and merges if it looks safe.
4. **App fetches** the regenerated `catalog.json` on startup (TTL configurable, default 24h).
5. **User installs** the new capability from inside Moddin Desktop.

See [`SUBMITTING.md`](SUBMITTING.md) for the contributor flow and [`SECURITY.md`](SECURITY.md) for the threat model.

---

## Catalog format

`catalog.json` is the auto-regenerated index the app downloads:

```json
{
  "version": 1,
  "generatedAt": "2026-09-21T18:30:00Z",
  "generator": "scripts/regenerate-catalog.py",
  "signature": {
    "algorithm": "ed25519",
    "publicKey": "...",
    "value": "..."
  },
  "capabilities": [
    {
      "id": "community-fps-unlocker",
      "version": "1.0.0",
      "sha256": "abc...",
      "downloadUrl": "https://raw.githubusercontent.com/petonexus/moddin-community-capabilities/main/capabilities/community-fps-unlocker/capability.yaml",
      "configSchema": { "...": "..." },
      "homepage": "https://github.com/petonexus/moddin-community-capabilities/tree/main/capabilities/community-fps-unlocker",
      "maintainer": "github-user"
    }
  ]
}
```

The app uses the `signature` to detect tampering. The maintainer key
is rotated when the maintainer team changes.

---

## Repository layout

```
moddin-community-capabilities/
├── README.md                       ← you are here
├── SUBMITTING.md                   ← how to add a capability
├── SECURITY.md                     ← threat model + signing
├── MAINTAINERS.md                  ← who can merge PRs
├── LICENSE                         ← GPL-3.0 (matches the app)
├── catalog.json                    ← auto-generated index (do not edit)
├── capabilities/                   ← one folder per capability
│   └── <id>/
│       ├── capability.yaml         ← required
│       ├── CHANGELOG.md            ← recommended (one entry per release)
│       └── SIGNED-BY               ← optional Ed25519 public key
├── scripts/
│   ├── regenerate-catalog.py       ← rebuilds catalog.json + signs
│   ├── validate-capability.py     ← local pre-commit check
│   └── sign.py                     ← Ed25519 keypair helper
└── .github/workflows/
    ├── validate.yml                ← runs on PR: schema + kind + sha256
    └── build-catalog.yml           ← runs on main: regen + sign catalog
```

---

## Adding a new capability

```bash
# 1. Fork this repo
# 2. Create a folder under capabilities/
mkdir capabilities/community-my-mod
# 3. Write capability.yaml (see SUBMITTING.md for the schema)
cp scripts/template.yaml capabilities/community-my-mod/capability.yaml
# 4. Validate locally
python scripts/validate-capability.py capabilities/community-my-mod/capability.yaml
# 5. (Optional) Sign with your Ed25519 key
python scripts/sign.py capabilities/community-my-mod/capability.yaml
# 6. Open PR — CI will validate, maintainer will review
gh pr create --fill
```

See [`SUBMITTING.md`](SUBMITTING.md) for the full guide, or
[`docs/CAPABILITY-CONTRACT.md`](https://github.com/petonexus/moddin-desktop/blob/main/docs/CAPABILITY-CONTRACT.md)
in the app repo for the full schema reference.

---

## Trust levels

| Origin | Verification | UI badge | Activity log |
|---|---|---|---|
| **BuiltIn** (shipped with the app) | code-signed binary | "Verified" | normal |
| **Local** (`%LOCALAPPDATA%\Moddin\capabilities\*.yaml`) | none — user dropped it | "Local" | verbose |
| **Community + signed** | Ed25519 + maintainer signature | "Verified" | normal |
| **Community + unsigned** | none | "Unverified" | **confirmation prompt before install** |

Apps that don't want to participate in the community catalog can simply
disable catalog fetching (config flag) and use only built-in + local
capabilities.

---

## Maintainers

See [`MAINTAINERS.md`](MAINTAINERS.md) for the current list.

---

## License

[GPL-3.0](LICENSE) — same as Moddin Desktop, so the catalog stays a
single source of truth without licensing concerns.