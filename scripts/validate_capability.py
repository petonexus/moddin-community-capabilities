#!/usr/bin/env python3
"""Validate every capabilities/*/capability.yaml against the
Moddin Desktop capability contract.

Exit codes:
  0 = all files pass
  1 = at least one file failed
  2 = internal error

Run locally before opening a PR:
    python scripts/validate_capability.py path/to/capability.yaml
    python scripts/validate_capability.py capabilities/             # whole tree
"""

from __future__ import annotations

import glob
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

KNOWN_STEP_KINDS = {
    "extract-zip",
    "verify-hash",
    "file-delete",
    "write-text-file",
    "write-binary-file",
    "move-file",
    "spawn-process",
    "kill-process",
    "registry-write",
    "registry-delete",
}
KNOWN_CHECK_KINDS = {
    "process-running",
    "file-exists",
    "file-absent",
    "archive-reachable",
    "archive-sha256",
}
KNOWN_CATEGORIES = {"vr", "graphics", "qol", "system"}
KNOWN_STATUSES = {"available", "planned"}
KNOWN_SEVERITIES = {"info", "warning", "blocker"}
KNOWN_STEP_CHECK_CATEGORIES = {"global", "category", "modulespecific"}

HEX_256 = re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE)
HTTPS_URL = re.compile(r"^https://", re.IGNORECASE)


def _fail(errors: list[str], message: str) -> None:
    errors.append(message)


def _check_field_string(errors: list[str], spec: dict, path: str, key: str) -> None:
    value = spec.get(key)
    if not isinstance(value, str) or not value.strip():
        _fail(errors, f"{path}.{key} must be a non-empty string")


def _check_field_enum(
    errors: list[str], spec: dict, path: str, key: str, allowed: set, label: str
) -> None:
    value = spec.get(key)
    if value not in allowed:
        _fail(errors, f"{path}.{key} must be one of {sorted(allowed)} (got {value!r})")


def _check_kinds(errors: list[str], steps: list, parent: str) -> None:
    for index, step in enumerate(steps):
        kind = step.get("kind") if isinstance(step, dict) else None
        if kind not in KNOWN_STEP_KINDS:
            _fail(
                errors,
                f"{parent}[{index}].kind must be one of {sorted(KNOWN_STEP_KINDS)} (got {kind!r})",
            )


def _check_check_kinds(errors: list[str], checks: list, parent: str) -> None:
    for index, check in enumerate(checks):
        if not isinstance(check, dict):
            _fail(errors, f"{parent}[{index}] must be an object")
            continue
        kind = check.get("kind")
        if kind not in KNOWN_CHECK_KINDS:
            _fail(
                errors,
                f"{parent}[{index}].kind must be one of {sorted(KNOWN_CHECK_KINDS)} (got {kind!r})",
            )
        severity = check.get("severity", "info")
        if severity not in KNOWN_SEVERITIES:
            _fail(
                errors,
                f"{parent}[{index}].severity must be one of {sorted(KNOWN_SEVERITIES)} (got {severity!r})",
            )
        category = check.get("category", "modulespecific")
        if category not in KNOWN_STEP_CHECK_CATEGORIES:
            _fail(
                errors,
                f"{parent}[{index}].category must be one of {sorted(KNOWN_STEP_CHECK_CATEGORIES)} (got {category!r})",
            )


def _check_schema_fields(errors: list[str], schema: list, parent: str) -> None:
    if not isinstance(schema, list):
        _fail(errors, f"{parent} must be a list")
        return
    seen = set()
    for index, field in enumerate(schema):
        if not isinstance(field, dict):
            _fail(errors, f"{parent}[{index}] must be an object")
            continue
        name = field.get("name")
        if not isinstance(name, str) or not name:
            _fail(errors, f"{parent}[{index}].name must be a non-empty string")
        elif name in seen:
            _fail(errors, f"{parent} has duplicate name '{name}'")
        else:
            seen.add(name)
        type_ = field.get("type")
        if type_ not in {"string", "number", "boolean", "url", "sha256", "path", "enum"}:
            _fail(
                errors,
                f"{parent}[{index}].type must be string|number|boolean|url|sha256|path|enum (got {type_!r})",
            )
        if type_ == "enum" and not isinstance(field.get("enumValues"), list):
            _fail(errors, f"{parent}[{index}].enumValues must be a list when type=enum")


def _check_url(errors: list[str], value: str, parent: str) -> None:
    if not HTTPS_URL.match(value):
        _fail(errors, f"{parent} must start with https:// (got {value!r})")


def _check_sha256(errors: list[str], value: str, parent: str) -> None:
    if not HEX_256.match(value):
        _fail(errors, f"{parent} must be 64 hex chars (got {value!r})")


def _check_absolute_path(errors: list[str], value: str, parent: str) -> None:
    if not Path(value).is_absolute():
        _fail(errors, f"{parent} must be an absolute path (got {value!r})")


def validate_capability_file(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        return [f"could not read {path}: {error}"]

    try:
        spec = yaml.safe_load(text)
    except yaml.YAMLError as error:
        return [f"invalid YAML in {path}: {error}"]

    if not isinstance(spec, dict):
        return [f"{path}: top-level must be a mapping"]

    folder = path.parent.name
    capability_id = spec.get("id")
    if capability_id != folder:
        errors.append(
            f"{path}: id {capability_id!r} does not match folder name {folder!r}"
        )

    _check_field_string(errors, spec, "", "id")
    _check_field_string(errors, spec, "", "displayName")
    _check_field_enum(errors, spec, "", "category", KNOWN_CATEGORIES, "category")
    _check_field_enum(errors, spec, "", "status", KNOWN_STATUSES, "status")

    if isinstance(spec.get("configSchema"), list):
        _check_schema_fields(errors, spec["configSchema"], "configSchema")
        for index, field in enumerate(spec["configSchema"]):
            if not isinstance(field, dict):
                continue
            type_ = field.get("type")
            if type_ == "url" and isinstance(field.get("default"), str):
                _check_url(errors, field["default"], f"configSchema[{index}].default")
            if type_ == "sha256" and isinstance(field.get("default"), str):
                _check_sha256(errors, field["default"], f"configSchema[{index}].default")
            if type_ == "path" and isinstance(field.get("default"), str):
                _check_absolute_path(
                    errors, field["default"], f"configSchema[{index}].default"
                )

    if isinstance(spec.get("checks"), list):
        _check_check_kinds(errors, spec["checks"], "checks")
    if isinstance(spec.get("verify"), list):
        _check_check_kinds(errors, spec["verify"], "verify")
    if isinstance(spec.get("install"), list):
        _check_kinds(errors, spec["install"], "install")
    if isinstance(spec.get("uninstall"), list):
        _check_kinds(errors, spec["uninstall"], "uninstall")

    if isinstance(spec.get("safetyNotes"), list) and not all(
        isinstance(note, str) for note in spec["safetyNotes"]
    ):
        errors.append("safetyNotes must be a list of strings")

    return errors


def validate_tree(root: Path) -> int:
    base = root if root.name == "capabilities" else root / "capabilities"
    paths = sorted(Path(p) for p in glob.glob(str(base / "*" / "capability.yaml")))
    if not paths:
        print(f"no capabilities found under {base}/", file=sys.stderr)
        return 1

    failed = False
    for path in paths:
        errors = validate_capability_file(path)
        if errors:
            failed = True
            print(f"\n[FAIL] {path}", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)
        else:
            print(f"[OK]   {path}")
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    targets = [Path(arg) for arg in argv[1:]]
    if len(targets) == 1 and targets[0].is_dir():
        return validate_tree(targets[0])
    failed = False
    for path in targets:
        errors = validate_capability_file(path)
        if errors:
            failed = True
            print(f"\n[FAIL] {path}", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)
        else:
            print(f"[OK]   {path}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
