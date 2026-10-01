#!/usr/bin/env python3
"""Regenerate catalog.json (and the matching catalog.json.sig) from the
contents of capabilities/*/capability.yaml on main.

Run by .github/workflows/build-catalog.yml. Can also be run locally for
sanity:

    python scripts/regenerate_catalog.py

The script:
  1. Discovers every capabilities/<id>/capability.yaml.
  2. Validates each with validate_capability.py.
  3. Reads revoked-ids.json and embeds it in catalog.json.
  4. Signs catalog.json with the maintainer Ed25519 key.
  5. Drops catalog.json.sig next to catalog.json.

The signing key lives in the SIGNING_KEY repository secret. The matching
public key is committed to public-keys.json so apps can verify the
catalog signature offline.

Why the revocations are inlined (SECURITY.md, "Layer 6 — kill switch"):
revoked-ids.json is the human-maintained *input*, but the app never
fetches it. A capability list that ships unsigned alongside a signed
one is a second trust channel -- whoever can intercept that one GET can
suppress a revocation until the TTL expires. Emitting it inside the
signed bytes means one signature covers both, and they cannot disagree.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def load_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def load_revoked(root: Path) -> tuple[list[dict], list[str]]:
    """Read revoked-ids.json and check it against the shape the app reads.

    Returns (entries, errors). An error here is fatal and the catalog is
    not regenerated: a catalogue that silently dropped a malformed
    revocation list would turn a typo into "nothing is revoked", which
    is the one failure this file exists to make impossible. Refusing to
    publish is loud, and the maintainer reads it here rather than a
    user reads it as a revoked mod that still installs.
    """
    path = root / "revoked-ids.json"
    errors: list[str] = []
    if not path.is_file():
        return [], [f"{path} is missing; the revocation list is a required catalog input"]

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return [], [f"{path} could not be read as JSON: {error}"]

    if not isinstance(payload, dict):
        return [], [f"{path}: top level must be an object with a 'revoked' list"]

    raw = payload.get("revoked")
    if not isinstance(raw, list):
        return [], [f"{path}: 'revoked' must be a list (got {type(raw).__name__})"]

    entries: list[dict] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            errors.append(
                f"{path}: revoked[{index}] must be an object, got {type(item).__name__}"
            )
            continue
        identifier = item.get("id")
        if not isinstance(identifier, str) or not identifier.strip():
            errors.append(
                f"{path}: revoked[{index}].id must be a non-empty string. An entry "
                "without one cannot be matched to a capability, so the app would "
                "ignore it and the capability would stay installable."
            )
            continue
        reason = item.get("reason", "")
        if not isinstance(reason, str):
            errors.append(
                f"{path}: revoked[{index}].reason must be a string, got "
                f"{type(reason).__name__}"
            )
            continue
        if identifier in seen:
            errors.append(
                f"{path}: revoked lists '{identifier}' twice. The app shows the first "
                "reason and the second is a silent no-op; keep one entry per id."
            )
            continue
        seen.add(identifier)
        entries.append({"id": identifier.strip(), "reason": reason})

    return entries, errors


def build_catalog(root: Path) -> dict:
    capabilities = []
    for folder in sorted((root / "capabilities").iterdir()):
        if not folder.is_dir():
            continue
        spec_path = folder / "capability.yaml"
        if not spec_path.is_file():
            continue
        spec = load_yaml(spec_path)

        signed = (folder / "SIGNED-BY").is_file()
        entry = {
            "id": spec["id"],
            "version": spec.get("version", "0.0.0"),
            "displayName": spec.get("displayName", spec["id"]),
            "category": spec.get("category", "graphics"),
            "status": spec.get("status", "available"),
            "homepage": f"https://github.com/petonexus/moddin-community-capabilities/tree/main/capabilities/{spec['id']}",
            "downloadUrl": f"https://raw.githubusercontent.com/petonexus/moddin-community-capabilities/main/capabilities/{spec['id']}/capability.yaml",
            "configSchema": spec.get("configSchema", []),
            "safetyNotes": spec.get("safetyNotes", []),
            "signed": signed,
        }
        if signed:
            public_key = (folder / "SIGNED-BY").read_text(encoding="utf-8")
            entry["signedBy"] = public_key.strip()
        capabilities.append(entry)

    revoked, revoked_errors = load_revoked(root)
    if revoked_errors:
        raise ValueError("\n".join(revoked_errors))

    return {
        "version": 1,
        "generatedAt": _dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "generator": "scripts/regenerate_catalog.py",
        "capabilities": capabilities,
        # Always emitted, even when empty. The key is itself a statement
        # by the maintainer; the app reads an absent key as the same
        # statement, but a catalog that carries it says so on its face.
        "revoked": revoked,
    }


def load_signing_key(signing_key: str) -> Ed25519PrivateKey:
    """Decode the maintainer key from the shapes a secret store mangles it into.

    The CI secret has historically arrived in more than one shape: a PEM
    body, a PEM with literal "\\n" escapes, base64-of-PEM, and
    base64-of-the-raw-32-byte seed (the shape sign.py stores
    contributor.key in). All decode to the same Ed25519 key, so each is
    tried in turn and the first that parses wins. The key material is
    never printed; a failure message names the shapes, not the bytes.
    """
    text = signing_key.strip()
    candidates: list[bytes] = [
        text.encode("utf-8"),
        text.replace("\\n", "\n").encode("utf-8"),
    ]
    try:
        candidates.append(base64.b64decode(text, validate=True))
    except ValueError:
        pass

    for candidate in candidates:
        if b"PRIVATE KEY-----" not in candidate:
            if len(candidate) == 32:
                return Ed25519PrivateKey.from_private_bytes(candidate)
            continue
        try:
            loaded = serialization.load_pem_private_key(candidate, password=None)
        except (ValueError, TypeError):
            continue
        if not isinstance(loaded, Ed25519PrivateKey):
            raise TypeError(
                f"the signing key is {type(loaded).__name__}, not Ed25519; "
                "the catalog is signed with Ed25519"
            )
        return loaded

    raise ValueError(
        "MODDIN_SIGNING_KEY is neither a PEM private key, a PEM with "
        "escaped newlines, base64-of-PEM, nor base64-of-raw-32-byte-seed"
    )


def maybe_sign(catalog_path: Path) -> None:
    signing_key = os.environ.get("MODDIN_SIGNING_KEY")
    if not signing_key:
        print("MODDIN_SIGNING_KEY not set; skipping signature", file=sys.stderr)
        return

    key = load_signing_key(signing_key)
    # Raw Ed25519 (no DER wrapping) — the 64-byte payload the app verifies
    # byte-for-byte with ed25519-dalek. The previous openssl dgst -sign
    # step produced the same bytes; cryptography is used here because it
    # accepts every PEM shape above without a temp file on disk.
    signature = key.sign(catalog_path.read_bytes())
    catalog_path.with_name("catalog.json.sig").write_bytes(signature)


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path(".")
    if not (root / "capabilities").is_dir():
        print(f"missing {root}/capabilities/", file=sys.stderr)
        return 1

    # Validate first so the catalog only ships clean entries.
    validate_script = root / "scripts" / "validate_capability.py"
    result = subprocess.run(
        ["python", str(validate_script), str(root / "capabilities")],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        return result.returncode

    # A malformed revocation list must stop the build, not produce a
    # catalog that quietly says "nothing is revoked".
    try:
        catalog = build_catalog(root)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        print("catalog.json was not regenerated.", file=sys.stderr)
        return 1

    catalog_path = root / "catalog.json"
    catalog_path.write_text(
        json.dumps(catalog, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(
        f"wrote {catalog_path} ({len(catalog['capabilities'])} capabilities, "
        f"{len(catalog['revoked'])} revocations)"
    )

    maybe_sign(catalog_path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
