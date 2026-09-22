#!/usr/bin/env python3
"""Regenerate catalog.json (and the matching catalog.json.sig) from the
contents of capabilities/*/capability.yaml on main.

Run by .github/workflows/build-catalog.yml. Can also be run locally for
sanity:

    python scripts/regenerate_catalog.py

The script:
  1. Discovers every capabilities/<id>/capability.yaml.
  2. Validates each with validate_capability.py.
  3. Builds catalog.json with one entry per capability.
  4. Signs catalog.json with the maintainer Ed25519 key.
  5. Drops catalog.json.sig next to catalog.json.

The signing key lives in the SIGNING_KEY repository secret. The matching
public key is committed to public-keys.json so apps can verify the
catalog signature offline.
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


def load_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file)


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
    return {
        "version": 1,
        "generatedAt": _dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "generator": "scripts/regenerate_catalog.py",
        "capabilities": capabilities,
    }


def maybe_sign(catalog_path: Path) -> None:
    signing_key = os.environ.get("MODDIN_SIGNING_KEY")
    if not signing_key:
        print("MODDIN_SIGNING_KEY not set; skipping signature", file=sys.stderr)
        return

    pem_path = Path("secrets") / "maintainer.pem"
    pem_path.parent.mkdir(exist_ok=True)
    pem_path.write_text(signing_key, encoding="utf-8")
    pem_path.chmod(0o600)

    try:
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(pem_path),
                "-in",
                str(catalog_path),
                "-out",
                "catalog.json.sig",
            ],
            check=True,
        )
    finally:
        pem_path.unlink()


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

    catalog = build_catalog(root)
    catalog_path = root / "catalog.json"
    catalog_path.write_text(
        json.dumps(catalog, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {catalog_path} ({len(catalog['capabilities'])} capabilities)")

    maybe_sign(catalog_path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
