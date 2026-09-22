# Submitting a capability

Welcome! This guide walks through adding a new community capability to
Moddin Desktop.

## Quick check first

Before opening a PR, make sure your capability **belongs here** and
not in the app's core:

| Want to ... | Submit here? |
|---|---|
| Add a new mod / preset / override for a specific game | ✅ yes |
| Add a new step **kind** (`json-merge`, `com-create-shortcut`, ...) | ❌ open a PR on [petonexus/moddin-desktop](https://github.com/petonexus/moddin-desktop) — the vocabulary is fixed in Rust |
| Change the `CapabilitySpec` schema | ❌ same — schema lives in the app |
| Improve the catalog infrastructure (CI, signing, validator) | ✅ yes |

When in doubt, open an issue and ask.

---

## Step 1 — create the folder

```bash
mkdir capabilities/community-my-mod
```

The folder name must match the `id` of your capability (kebab-case).
The capability id is how the app, the UI, and the catalog refer to it.

## Step 2 — write `capability.yaml`

Use [`scripts/template.yaml`](scripts/template.yaml) (or copy one of the
existing capabilities) and edit. The full schema is documented in
[`docs/CAPABILITY-CONTRACT.md`](https://github.com/petonexus/moddin-desktop/blob/main/docs/CAPABILITY-CONTRACT.md)
in the app repo.

Minimum required fields:

```yaml
id: community-my-mod
displayName: My Mod
category: graphics                # vr | graphics | qol | system
status: available                 # available | planned
configSchema:
  - name: version
    type: string
    required: true
install:
  - kind: extract-zip
    params:
      archivePathField: downloadUrl
safetyNotes:
  - Always close the game before applying.
```

Conventions:

- **`id`** is kebab-case, stable, unique. Once merged, never change it
  (users reference it in their save data).
- **`displayName`** is the user-facing label.
- **`category`** drives the engine preset layer; pick the category
  whose modules this capability most resembles.
- **`status: available`** means the recipe is fully tested on at least
  one PC. Use `planned` while iterating.
- **`configSchema`** declares the typed inputs the UI form should
  render. The app fills `ResolvedConfig.values` from the user's input.
- **`install`** runs every step in order; failures abort and rollback
  via the transaction store.
- **`safetyNotes`** are surfaced in the UI card header banner.

## Step 3 — validate locally

```bash
python scripts/validate-capability.py capabilities/community-my-mod/capability.yaml
```

This catches the most common PR-blocking mistakes before you push:

- Missing required fields
- Unknown `kind` values (only the 10 built-in step kinds are
  accepted; adding new kinds requires a PR in the app repo)
- Invalid `category` / `status` / `severity` values
- `sha256` fields that don't look like hex
- `url` fields that aren't HTTPS
- `path` fields that aren't absolute
- Duplicate `id` across the catalog
- `id` that doesn't match the folder name

## Step 4 — sign (optional but recommended)

Signing tells users "this capability comes from a known contributor who
isn't just anybody with a GitHub account". Generate a key once:

```bash
python scripts/sign.py --generate-key-pair
# → creates ~/.config/moddin-signing/maintainer.pub
# → private key stays on your machine
```

Then sign your capability:

```bash
python scripts/sign.py capabilities/community-my-mod/capability.yaml
# → creates capabilities/community-my-mod/SIGNED-BY (public key + signature)
```

`git commit` the resulting `SIGNED-BY` file. The `private.key` MUST NOT
be committed.

If you don't sign, your capability is still accepted — but users will
get an "Unverified" badge and a confirmation prompt before install.

## Step 5 — open a PR

```bash
git add capabilities/community-my-mod/
git commit -m "feat(community): add community-my-mod"
gh pr create --fill
```

The CI will run [`validate.yml`](.github/workflows/validate.yml) which
re-runs the local validator. Maintainers review the change in the PR
thread.

## Step 6 — wait for merge

Once merged, the [`build-catalog.yml`](.github/workflows/build-catalog.yml)
workflow regenerates `catalog.json`, signs it with the maintainer key,
and creates a GitHub release for it. Moddin Desktop apps detect the
new catalog entry within the configured TTL (default 24h) and surface
the new capability in **Settings → Community**.

---

## Updating an existing capability

1. Bump `version` in the capability YAML.
2. Update `CHANGELOG.md` with a one-line entry describing the change.
3. (Optional) Bump `sha256` if the archive changed.
4. Re-run the validator + (re)sign.
5. Open a PR.

The CI detects that the `id` already exists in the catalog and treats
the change as an update rather than a new entry.

## Removing a capability

Open a PR that deletes the folder and add a `DEPRECATED.md` note. The
next catalog regeneration will drop it. Apps already running with that
capability installed keep working until the user uninstalls it.

---

## Coding style

- 2-space indent in YAML.
- Quotes around string values that contain special characters
  (`:` `#` `?` etc).
- Order fields by their place in the schema:
  1. `id`, `displayName`, `category`, `status`
  2. `supportedEngines`, `configSchema`
  3. `checks`, `install`, `uninstall`, `verify`
  4. `safetyNotes`
- One `safetyNotes` item per line.

## When in doubt

Open a draft PR. Maintainers review in the order received; drafts
don't merge until you mark them ready, so you can iterate safely.