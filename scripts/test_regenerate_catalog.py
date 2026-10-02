#!/usr/bin/env python3
"""Tests for the signing half of regenerate_catalog.py.

The CI secret cannot be read back, so every way the maintainer key can
arrive has to be proved to load, and the signature that comes out has to
be proved to be what the app accepts. Three things broke at once before
this suite existed:

  * a PEM whose body is PKCS#8 v2 (what the Rust pkcs8 crate writes) was
    reported as an unrecognised shape, because ``cryptography`` rejects v2
    and the PEM branch gave up instead of reading the body as DER;
  * ``catalog.json.sig`` was written as 64 raw bytes, while the app
    base64-decodes it (``verify_signature`` in community_catalog.rs);
  * nothing checked that the key which signed is one the app pins.

Every key here is generated in memory for the test and never leaves it.

Run it with:

    python scripts/test_regenerate_catalog.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent))

import regenerate_catalog  # noqa: E402  (path has to be set first)

REPO_ROOT = Path(__file__).resolve().parent.parent


def raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def raw_seed(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def pem_wrap(der: bytes, label: str = "PRIVATE KEY") -> str:
    body = "\n".join(textwrap.wrap(base64.b64encode(der).decode(), 64))
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----"


def pkcs8_v2_der(key: Ed25519PrivateKey) -> bytes:
    """RFC 8410 OneAsymmetricKey v2: version 1 and the public key embedded."""
    der = (
        bytes.fromhex("3051020101300506032b657004220420")
        + raw_seed(key)
        + bytes.fromhex("812100")
        + raw_public(key)
    )
    assert len(der) == 83
    return der


class Fingerprint(unittest.TestCase):
    def test_matches_the_values_the_app_and_the_keyring_publish(self) -> None:
        # Hashed over the 32 raw bytes, as community_catalog.rs does. These
        # are the real public keys from public-keys.json, not secrets.
        for public_b64, expected in (
            ("R2oSrMGh0d6pHIWFHZwvU+sA+wK1Uo/vaBq/L1WJ6GU=", "d489a3a0be894b19"),
            ("Mh/WGQ0kCviGtiX/8wLB5fqBCLgtVR/4smlVai13xs8=", "e247ca4981f22245"),
        ):
            self.assertEqual(
                regenerate_catalog.key_fingerprint(base64.b64decode(public_b64)), expected
            )

    def test_the_committed_keyring_agrees_with_its_own_fingerprints(self) -> None:
        doc = json.loads((REPO_ROOT / "public-keys.json").read_text(encoding="utf-8"))
        for entry in doc["keys"]:
            raw = base64.b64decode(entry["publicKey"], validate=True)
            self.assertEqual(regenerate_catalog.key_fingerprint(raw), entry["fingerprint"])


def fingerprint(public: bytes) -> str:
    return regenerate_catalog.key_fingerprint(public)


class LoadSigningKey(unittest.TestCase):
    def setUp(self) -> None:
        self.key = Ed25519PrivateKey.generate()

    def assertLoads(self, secret: str) -> str:
        loaded, shape = regenerate_catalog.load_signing_key(secret)
        self.assertEqual(raw_public(loaded), raw_public(self.key))
        return shape

    def test_pkcs8_v2_pem_is_read(self) -> None:
        # The shape the CI secret has: 167 characters, wrapped at 64.
        secret = pem_wrap(pkcs8_v2_der(self.key))
        self.assertEqual(len(secret), 167)
        self.assertLoads(secret)

    def test_pkcs8_v2_pem_survives_a_trailing_newline_and_quotes(self) -> None:
        self.assertLoads(pem_wrap(pkcs8_v2_der(self.key)) + "\n")
        self.assertLoads('"' + pem_wrap(pkcs8_v2_der(self.key)) + '"')

    def test_pkcs8_v2_pem_with_escaped_newlines_is_read(self) -> None:
        self.assertLoads(pem_wrap(pkcs8_v2_der(self.key)).replace("\n", "\\n"))

    def test_pkcs8_v1_pem_is_read(self) -> None:
        der = self.key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self.assertLoads(pem_wrap(der))

    def test_base64_of_pkcs8_v2_der_is_read(self) -> None:
        self.assertLoads(base64.b64encode(pkcs8_v2_der(self.key)).decode())

    def test_base64_of_a_whole_pem_is_read(self) -> None:
        pem = pem_wrap(pkcs8_v2_der(self.key))
        self.assertLoads(base64.b64encode(pem.encode()).decode())

    def test_bare_seed_is_read(self) -> None:
        self.assertLoads(base64.b64encode(raw_seed(self.key)).decode())
        self.assertLoads(raw_seed(self.key).hex())

    def test_garbage_is_refused_without_echoing_it(self) -> None:
        secret = "-----BEGIN PRIVATE KEY-----\nnot-a-key-at-all\n-----END PRIVATE KEY-----"
        with self.assertRaises(ValueError) as caught:
            regenerate_catalog.load_signing_key(secret)
        self.assertIn("unrecognised secret shape", str(caught.exception))
        self.assertNotIn("not-a-key-at-all", str(caught.exception))

    def test_a_v2_pem_with_a_foreign_oid_is_refused(self) -> None:
        # Not Ed25519: the seed extractor must not read it as one.
        der = bytearray(pkcs8_v2_der(self.key))
        der[9:12] = bytes.fromhex("2b6571")
        with self.assertRaises(ValueError):
            regenerate_catalog.load_signing_key(pem_wrap(bytes(der)))

    def test_a_passphrase_encrypted_key_is_named_as_such(self) -> None:
        encrypted = self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"hunter2"),
        ).decode()
        with self.assertRaises(ValueError) as caught:
            regenerate_catalog.load_signing_key(encrypted)
        self.assertIn("passphrase-encrypted", str(caught.exception))


class MaybeSign(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.catalog = self.root / "catalog.json"
        self.catalog.write_text('{"version": 1}\n', encoding="utf-8")
        self.sig = self.root / "catalog.json.sig"
        self.key = Ed25519PrivateKey.generate()

    def keyring(self, *entries: tuple[Ed25519PrivateKey, bool]) -> None:
        (self.root / "public-keys.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "keys": [
                        {
                            "handle": f"@test{i}",
                            "active": active,
                            "publicKey": base64.b64encode(raw_public(key)).decode(),
                        }
                        for i, (key, active) in enumerate(entries)
                    ],
                }
            ),
            encoding="utf-8",
        )

    def sign_with(self, secret: str) -> None:
        with mock.patch.dict(os.environ, {"MODDIN_SIGNING_KEY": secret}):
            regenerate_catalog.maybe_sign(self.catalog)

    def test_signature_is_base64_and_verifies_the_way_the_app_reads_it(self) -> None:
        self.keyring((self.key, True))
        self.sign_with(pem_wrap(pkcs8_v2_der(self.key)))
        # community_catalog.rs: BASE64.decode(signature_b64.trim()), 64 bytes.
        decoded = base64.b64decode(self.sig.read_text(encoding="ascii").strip(), validate=True)
        self.assertEqual(len(decoded), 64)
        self.key.public_key().verify(decoded, self.catalog.read_bytes())

    def test_a_key_that_is_not_in_the_keyring_is_refused(self) -> None:
        self.keyring((Ed25519PrivateKey.generate(), True))
        self.sig.write_text("previous-signature", encoding="ascii")
        with self.assertRaises(ValueError) as caught:
            self.sign_with(pem_wrap(pkcs8_v2_der(self.key)))
        self.assertIn("not an active key", str(caught.exception))
        self.assertEqual(self.sig.read_text(encoding="ascii"), "previous-signature")

    def test_a_retired_key_is_refused(self) -> None:
        # Rotated out, still pinned by older apps, but never to sign with.
        self.keyring((self.key, False), (Ed25519PrivateKey.generate(), True))
        with self.assertRaises(ValueError) as caught:
            self.sign_with(pem_wrap(pkcs8_v2_der(self.key)))
        # Pinned to the guard's own message: a loader that failed first
        # would also raise ValueError and let this pass for nothing.
        self.assertIn("not an active key", str(caught.exception))
        self.assertFalse(self.sig.exists())

    def test_the_error_names_the_active_fingerprints_and_never_the_key(self) -> None:
        other = Ed25519PrivateKey.generate()
        self.keyring((other, True))
        with self.assertRaises(ValueError) as caught:
            self.sign_with(pem_wrap(pkcs8_v2_der(self.key)))
        message = str(caught.exception)
        self.assertIn(fingerprint(raw_public(other)), message)
        self.assertNotIn(base64.b64encode(raw_seed(self.key)).decode(), message)

    def test_no_secret_means_no_signature(self) -> None:
        self.keyring((self.key, True))
        with mock.patch.dict(os.environ, {}, clear=True):
            regenerate_catalog.maybe_sign(self.catalog)
        self.assertFalse(self.sig.exists())


class YamlDigest(unittest.TestCase):
    def test_digest_covers_original_bytes_including_crlf(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / "capabilities" / "test"
            folder.mkdir(parents=True)
            payload = b"id: test\r\nversion: 1.0.0\r\n"
            (folder / "capability.yaml").write_bytes(payload)
            (root / "revoked-ids.json").write_text('{"revoked": []}', encoding="utf-8")
            entry = regenerate_catalog.build_catalog(root)["capabilities"][0]
            self.assertEqual(entry["yamlSha256"], hashlib.sha256(payload).hexdigest())
            self.assertNotEqual(entry["yamlSha256"], hashlib.sha256(payload.replace(b"\r\n", b"\n")).hexdigest())

if __name__ == "__main__":
    unittest.main()
