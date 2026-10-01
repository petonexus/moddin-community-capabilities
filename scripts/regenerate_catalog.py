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
import binascii
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


def load_signing_key(signing_key: str) -> tuple[Ed25519PrivateKey, str]:
    """Decode the maintainer key from the shape a secret store mangled it into.

    The CI secret cannot be read back, so this loader is the only place
    that can meet whatever shape it holds. Candidates, in order: plain
    text, escaped-newline text, UTF-16 text (PowerShell 5.1 writes
    Unicode), then base64 / base64url / hex decodings of the whole
    secret, and finally the common JSON envelopes (a JWK field ``d``,
    or a ``privateKey``/``priv``/``seed`` string). A decoded 32-byte
    value is an Ed25519 seed; a decoded PEM body loads directly. On
    success the caller learns which shape matched; on failure the error
    names decodability only — never key bytes.
    """
    text = signing_key.strip().strip('"').strip("'")
    candidates: list[tuple[str, bytes]] = [
        ("plain text", text.encode("utf-8")),
        ("escaped-newline text", text.replace("\\n", "\n").encode("utf-8")),
    ]
    notes: list[str] = [f"secret is {len(text)} chars"]

    try:
        utf16 = text.encode("utf-8").decode("utf-16-le")
        candidates.append(("UTF-16 text", utf16.encode("utf-8")))
        notes.append("utf16-decodes")
    except UnicodeDecodeError:
        notes.append("utf16 no")

    def try_decode(label: str, decode) -> None:
        try:
            decoded = decode(text)
        except (ValueError, TypeError, binascii.Error):
            notes.append(f"{label} no")
            return
        notes.append(f"{label}->{len(decoded)}B")
        candidates.append((label, decoded))
        try:
            inner = decoded.decode("utf-8")
        except UnicodeDecodeError:
            return
        candidates.append((f"{label} as text", inner.encode("utf-8")))
        candidates.append(
            (f"{label} as escaped text", inner.replace("\\n", "\n").encode("utf-8"))
        )

    try_decode(
        "base64", lambda s: base64.b64decode(s, validate=True)
    )
    try_decode("base64url", lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
    try_decode("hex", lambda s: bytes.fromhex(s))

    try:
        doc = json.loads(text)
    except ValueError:
        doc = None
    if isinstance(doc, dict):
        for field in ("d", "privateKey", "priv", "seed"):
            value = doc.get(field)
            if not isinstance(value, str):
                continue
            for label, decode in (
                ("base64url", lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))),
                ("base64", lambda s: base64.b64decode(s, validate=True)),
                ("hex", lambda s: bytes.fromhex(s)),
            ):
                try:
                    candidates.append((f"JSON {field} as {label}", decode(value.strip())))
                    notes.append(f"json.{field}/{label} ok")
                    break
                except (ValueError, TypeError, binascii.Error):
                    continue

    for label, candidate in candidates:
        if b"PRIVATE KEY-----" in candidate:
            try:
                loaded = serialization.load_pem_private_key(candidate, password=None)
            except TypeError as error:
                raise ValueError(
                    f"the signing key (via {label}) is passphrase-encrypted: "
                    f"{error}; store it unencrypted — the catalog signature "
                    "is only as strong as the secret it lives in"
                ) from error
            except ValueError:
                continue
            if not isinstance(loaded, Ed25519PrivateKey):
                raise TypeError(
                    f"the signing key is {type(loaded).__name__}, not Ed25519; "
                    "the catalog is signed with Ed25519"
                )
            return loaded, label
        if len(candidate) == 32:
            return Ed25519PrivateKey.from_private_bytes(candidate), label

    raise ValueError(f"unrecognised secret shape ({'; '.join(notes)})")


def maybe_sign(catalog_path: Path) -> None:
    signing_key = os.environ.get("MODDIN_SIGNING_KEY")
    if not signing_key:
        print("MODDIN_SIGNING_KEY not set; skipping signature", file=sys.stderr)
        return

    key, shape = load_signing_key(signing_key)
    # The fingerprint is public data (public-keys.json, MAINTAINERS.md)
    # and is the only way to tell from a CI log whether the secret holds
    # the key the app pins, whatever shape it arrived in.
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    fingerprint = hashlib.sha256(base64.b64encode(public)).hexdigest()[:16]
    print(f"signing with key {fingerprint} (secret shape: {shape})")
    # Raw Ed25519 (no DER wrapping) — the 64-byte payload the app verifies
    # byte-for-byte with ed25519-dalek. The previous openssl dgst -sign
    # step produced the same bytes; cryptography is used here because it
    # accepts every shape above without a temp file on disk.
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
