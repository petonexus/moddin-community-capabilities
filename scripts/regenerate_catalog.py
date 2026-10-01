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
import re
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


# RFC 8410: an Ed25519 PKCS#8 body is the AlgorithmIdentifier (OID
# 1.3.101.112, no parameters) followed directly by the privateKey OCTET
# STRING, which wraps the 32-byte seed in a second one: 04 22 04 20 <seed>.
_ED25519_OID = bytes.fromhex("2b6570")
_SEED_PREFIX = bytes.fromhex("04220420")
_PEM_BODY = re.compile(
    rb"-----BEGIN PRIVATE KEY-----(.+?)-----END PRIVATE KEY-----", re.DOTALL
)


def _encrypted_key_error(label: str, error: Exception) -> ValueError:
    return ValueError(
        f"the signing key (via {label}) is passphrase-encrypted: "
        f"{error}; store it unencrypted — the catalog signature "
        "is only as strong as the secret it lives in"
    )


def _ed25519_from_der(der: bytes, label: str) -> Ed25519PrivateKey | None:
    """Read an Ed25519 key from PKCS#8 DER; None when the bytes are not one.

    ``cryptography`` reads PKCS#8 v1 only. RFC 8410 OneAsymmetricKey v2
    (version 1 plus a ``[1]`` publicKey) it rejects outright, and v2 is
    exactly what the Rust pkcs8 crate writes -- the tool that generated
    this repo's maintainer keys. The seed still sits at a fixed offset
    behind the algorithm OID, so a blob the library refuses is read for
    it directly.
    """
    try:
        loaded = serialization.load_der_private_key(der, password=None)
    except TypeError as error:
        raise _encrypted_key_error(label, error) from error
    except ValueError:
        marker = der.find(_ED25519_OID)
        if der[:1] != b"\x30" or marker == -1:
            return None
        start = marker + len(_ED25519_OID)
        if der[start : start + len(_SEED_PREFIX)] != _SEED_PREFIX:
            return None
        seed = der[start + len(_SEED_PREFIX) : start + len(_SEED_PREFIX) + 32]
        if len(seed) != 32:
            return None
        return Ed25519PrivateKey.from_private_bytes(seed)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise TypeError(
            f"the signing key is {type(loaded).__name__}, not Ed25519; "
            "the catalog is signed with Ed25519"
        )
    return loaded


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

    def try_decode(label: str, decode, nested: bool = True) -> None:
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
        if not nested:
            return
        for inner_label, inner_decode in (
            ("base64", lambda s: base64.b64decode(s, validate=True)),
            (
                "base64url",
                lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)),
            ),
        ):
            try:
                candidates.append(
                    (f"{label} as {inner_label}", inner_decode(inner.strip()))
                )
                notes.append(f"{label}/{inner_label}->{len(candidates[-1][1])}B")
            except (ValueError, TypeError, binascii.Error):
                pass

    try_decode(
        "base64", lambda s: base64.b64decode(s, validate=True)
    )
    # `openssl base64` and many hand-copied secrets wrap at 64 columns;
    # the strict decoder above rejects the embedded newlines.
    try_decode(
        "base64-wrapped",
        lambda s: base64.b64decode("".join(s.split()), validate=True),
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
                raise _encrypted_key_error(label, error) from error
            except ValueError:
                # The library refuses PKCS#8 v2, which is what a key
                # generated by the Rust pkcs8 crate is. Falling through
                # to the next candidate here is how a well-formed PEM
                # secret ended up reported as an unrecognised shape: the
                # body has to be unwrapped and read as DER.
                body = _PEM_BODY.search(candidate)
                der = None
                if body:
                    try:
                        der = base64.b64decode(b"".join(body.group(1).split()), validate=True)
                    except (ValueError, binascii.Error):
                        pass
                from_der = _ed25519_from_der(der, label) if der else None
                if from_der is None:
                    notes.append(f"{label}: PEM-reject")
                    continue
                return from_der, f"{label} (PEM body as DER)"
            if not isinstance(loaded, Ed25519PrivateKey):
                raise TypeError(
                    f"the signing key is {type(loaded).__name__}, not Ed25519; "
                    "the catalog is signed with Ed25519"
                )
            return loaded, label
        if len(candidate) == 32:
            return Ed25519PrivateKey.from_private_bytes(candidate), label
        # A decoded binary blob that is not a seed is often DER — PKCS#8
        # with the public key embedded is ~119 bytes, which is the shape
        # the CI secret arrived in. DER is attempted for every binary
        # candidate; a rejection is recorded so a failure can tell
        # "not DER" apart from "DER the loader cannot read".
        loaded = _ed25519_from_der(candidate, label)
        if loaded is None:
            notes.append(f"{label}: DER-reject({candidate[:2].hex()})")
            continue
        return loaded, f"{label} (DER)"

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
    fingerprint = key_fingerprint(public)
    print(f"signing with key {fingerprint} (secret shape: {shape})")

    # A signature from a key the app does not pin is rejected by every
    # client, and the workflow commits whatever this writes. The secret
    # cannot be read back, so this is the only place that can tell it
    # still holds the maintainer key and not a retired or stray one.
    active = active_public_keys(catalog_path.parent)
    if public not in active.values():
        raise ValueError(
            f"the signing key {fingerprint} is not an active key in "
            f"public-keys.json (active: {', '.join(sorted(active)) or 'none'}); "
            "refusing to write a signature the app would reject"
        )

    payload = catalog_path.read_bytes()
    signature = key.sign(payload)
    sig_path = catalog_path.with_name("catalog.json.sig")
    # The app base64-decodes catalog.json.sig (verify_signature in
    # community_catalog.rs) and rejects a raw 64-byte file. `openssl dgst
    # -sign -out`, which this step used to shell out to, writes raw bytes,
    # so a CI-produced signature never verified. cryptography is used
    # here because it accepts every key shape above without a temp file.
    sig_path.write_bytes(base64.b64encode(signature))

    # Read the file back the way the app does, so an encoding mistake
    # fails here and not on a user's machine.
    on_disk = base64.b64decode(sig_path.read_text(encoding="ascii").strip())
    if len(on_disk) != 64:
        raise ValueError(f"catalog.json.sig decodes to {len(on_disk)} bytes, not 64")
    key.public_key().verify(on_disk, payload)


def key_fingerprint(public: bytes) -> str:
    """First 16 hex of SHA-256 over the 32 raw public-key bytes.

    The same definition as `fingerprint()` in community_catalog.rs and the
    one public-keys.json and MAINTAINERS.md quote. Hashing the base64 text
    instead gives a value that never matches any of them, which reads in
    a CI log as "the secret holds the wrong key".
    """
    return hashlib.sha256(public).hexdigest()[:16]


def active_public_keys(root: Path) -> dict[str, bytes]:
    """Return {fingerprint: raw public key} for every active entry in
    public-keys.json -- the same keyring SECURITY.md tells apps to trust."""
    doc = json.loads((root / "public-keys.json").read_text(encoding="utf-8"))
    keys: dict[str, bytes] = {}
    for entry in doc.get("keys", []):
        if not entry.get("active"):
            continue
        raw = base64.b64decode(entry["publicKey"], validate=True)
        keys[key_fingerprint(raw)] = raw
    return keys


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

    try:
        maybe_sign(catalog_path)
    except (ValueError, TypeError) as error:
        # The workflow's `set -e` stops before the commit step, so neither
        # a rejected key nor a failed read-back of the signature reaches
        # main. A rejected key is caught before anything is written, so
        # the .sig on disk is still the previous catalog's.
        print(f"catalog.json was regenerated but NOT signed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
