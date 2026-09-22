#!/usr/bin/env python3
"""Sign a single capability's capability.yaml with the contributor's
Ed25519 keypair.

Usage:
  python scripts/sign.py --generate-key-pair
      Generates ~/.config/moddin-signing/contributor.{key,pub}. Stores
      the public key on disk; the private key never leaves your
      machine.

  python scripts/sign.py path/to/capability.yaml
      Reads ~/.config/moddin-signing/contributor.{key,pub}, signs the
      yaml body, and writes (or overwrites) SIGNED-BY next to the yaml.

The SIGNED-BY file embeds the public key so a reviewer can verify the
signature against the same key the maintainer-side tooling uses.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

CONFIG_DIR = Path(os.environ.get("MODDIN_SIGNING_DIR", str(Path.home() / ".config" / "moddin-signing")))
PRIVATE_KEY_PATH = CONFIG_DIR / "contributor.key"
PUBLIC_KEY_PATH = CONFIG_DIR / "contributor.pub"


def generate_keypair() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    PRIVATE_KEY_PATH.write_bytes(
        private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    PRIVATE_KEY_PATH.chmod(0o600)
    PUBLIC_KEY_PATH.write_bytes(
        public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    print(f"wrote {PRIVATE_KEY_PATH} (PRIVATE — never commit)")
    print(f"wrote {PUBLIC_KEY_PATH} (share this when signing)")


def load_keys() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    private_bytes = PRIVATE_KEY_PATH.read_bytes()
    public_bytes = PUBLIC_KEY_PATH.read_bytes()
    private = Ed25519PrivateKey.from_private_bytes(private_bytes)
    public = Ed25519PublicKey.from_public_bytes(public_bytes)
    return private, public


def sign_file(yaml_path: Path) -> Path:
    if not yaml_path.is_file():
        raise FileNotFoundError(yaml_path)
    private, public = load_keys()
    body = yaml_path.read_bytes()
    signature = private.sign(body)
    signed_by = yaml_path.parent / "SIGNED-BY"
    public_b64 = base64.b64encode(
        public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    signature_b64 = base64.b64encode(signature).decode("ascii")
    signed_by.write_text(
        f"""# Ed25519 signature for {yaml_path.name}.
# Public key (base64 raw 32 bytes):
#   {public_b64}
# To verify (after committing): run scripts/sign.py --verify <yaml>
signed-by:
  algorithm: ed25519
  publicKey: "{public_b64}"
  signature: "{signature_b64}"
  bodyDigest:
    algorithm: sha256
    value: "{hashlib.sha256(body).hexdigest()}"
""",
        encoding="utf-8",
    )
    print(f"wrote {signed_by}")
    return signed_by


def verify_file(yaml_path: Path) -> bool:
    signed_by = yaml_path.parent / "SIGNED-BY"
    if not signed_by.is_file():
        print(f"no SIGNED-BY next to {yaml_path}", file=sys.stderr)
        return False
    payload = yaml.safe_load(signed_by.read_text(encoding="utf-8"))
    signature = payload.get("signed-by") or payload
    try:
        public = Ed25519PublicKey.from_public_bytes(base64.b64decode(signature["publicKey"]))
        signature_bytes = base64.b64decode(signature["signature"])
        body = yaml_path.read_bytes()
        public.verify(signature_bytes, body)
    except (KeyError, ValueError) as error:
        print(f"signature malformed: {error}", file=sys.stderr)
        return False
    print(f"✓ signature valid for {yaml_path}")
    return True


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generate-key-pair", action="store_true", help="generate a fresh Ed25519 keypair under the signing config dir")
    parser.add_argument("--verify", action="store_true", help="verify the signature next to the file instead of signing")
    parser.add_argument("path", nargs="?", help="capability.yaml to sign or verify")
    args = parser.parse_args(argv[1:])

    if args.generate_key_pair:
        generate_keypair()
        return 0
    if not args.path:
        parser.print_help(sys.stderr)
        return 2
    target = Path(args.path)
    if args.verify:
        return 0 if verify_file(target) else 1
    sign_file(target)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
