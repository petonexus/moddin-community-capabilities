#!/usr/bin/env python3
"""Validate every capabilities/*/capability.yaml against the
Moddin Desktop capability contract.

Exit codes:
  0 = all files pass
  1 = at least one file failed
  2 = internal error

Run locally before opening a PR:
    python scripts/validate_capability.py path/to/capability.yaml
    python scripts/validate_capability.py capabilities/           # whole tree
    python scripts/validate_capability.py revoked-ids.json        # the kill switch
    python scripts/validate_capability.py catalog.json           # the signed copy

The last one also checks that the revocations embedded in a generated
catalog still match revoked-ids.json. The app reads the signed copy
only, so a source edit that was never regenerated is a revocation that
is not in force.
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

# The kind sets below are checked against the Rust runner and the
# TypeScript union by scripts/check-capability-kind-parity.mjs in the
# Moddin Desktop repo. They drifted once already: `download-file` and
# `exe-version` shipped in the backend while this validator still
# rejected them, which meant a community author could not express the
# recipe that CONTRIBUTING.md teaches as the minimum, nor a capability
# whose checks run an exe-version gate. Do not edit one list alone.
KNOWN_STEP_KINDS = {
    "download-file",
    "extract-zip",
    "git-checkout",
    "build-project",
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
    "exe-version",
}
KNOWN_CATEGORIES = {"vr", "graphics", "qol", "system"}
KNOWN_STATUSES = {"available", "planned"}
KNOWN_SEVERITIES = {"info", "warning", "blocker"}
KNOWN_STEP_CHECK_CATEGORIES = {"global", "category", "modulespecific"}

# The engine vocabulary, mirrored from the desktop runner's
# `KNOWN_ENGINES` in `src-tauri/src/capability.rs`. This is a duplicate
# list, which is exactly the shape of thing that drifts: the first
# parity guard in this project missed a fifth list of step kinds and it
# had already gone stale on its own. `scripts/check-capability-kind-parity.mjs`
# in the desktop repo now compares engine ids across the runner, the
# TypeScript union and this file, so a change to one is a red build in
# the other.
#
# An engine id that is not in this set does not mean "every engine" — it
# means the runner has no opinion about that engine, and a recipe
# listing it can never match a game. An *empty* list is what means every
# engine, and that is the repository's own template default.
KNOWN_ENGINES = {
    "idtech",
    "re-engine",
    "redengine",
    "unity",
    "unreal5",
}

HEX_256 = re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE)
HTTPS_URL = re.compile(r"^https://", re.IGNORECASE)
PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
FULL_COMMIT = re.compile(r"^[a-f0-9]{40}$", re.IGNORECASE)
# Git refuses these inside a ref name, and `git-checkout` refuses them
# too; the validator exists so the author finds out here rather than
# halfway through an install.
REF_FORBIDDEN = re.compile(r"(\.\.|@\{|[\s~^:?*\[\\])")


def _fail(errors: list[str], message: str) -> None:
    errors.append(message)


def _check_supported_engines(errors: list[str], spec: dict) -> None:
    """Reject an engine id the runner has never heard of.

    The desktop runner gates a recipe out of a game's list when the
    recipe names engines and not the game's. An id outside its
    vocabulary therefore does not mean "unrestricted" — it means a
    match that can never happen, and the recipe is silently invisible
    on every game. Failing here tells the author, instead.

    An empty list is fine and means every engine, which is the
    repository's own template default.
    """
    value = spec.get("supportedEngines")
    if value is None:
        return
    if not isinstance(value, list):
        _fail(errors, f"supportedEngines must be a list, got {type(value).__name__}")
        return
    for engine in value:
        if not isinstance(engine, str) or engine not in KNOWN_ENGINES:
            _fail(
                errors,
                f"supportedEngines: {engine!r} is not an engine the runner "
                f"knows. Known engines: {', '.join(sorted(KNOWN_ENGINES))}. "
                f"Use an empty list to mean every engine.",
            )


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


def _check_pinned_ref(errors: list[str], value: str, parent: str) -> None:
    """A `git-checkout` ref must name one immutable object.

    The runner refuses a branch, `HEAD`, an abbreviated commit and a
    name git would not accept as a ref. Everything a recipe can be
    checked against statically is checked here, so the author reads the
    error before an install does.

    The one thing this cannot check is the *value* a `refField` resolves
    to at install time -- the runner re-checks it then.
    """
    reference = value.strip()
    if not reference:
        _fail(errors, f"{parent} must not be empty")
        return
    if FULL_COMMIT.match(reference):
        return
    if 4 <= len(reference) < 40 and re.fullmatch(r"[a-fA-F0-9]+", reference):
        _fail(
            errors,
            f"{parent} is '{reference}', an abbreviated commit. Two commits can share a "
            f"short prefix, so pin the full 40-character SHA and the install reproduces.",
        )
        return
    if reference.lower() in {"head", "main", "master", "latest"} or reference.startswith(
        ("refs/heads/", "heads/")
    ):
        _fail(
            errors,
            f"{parent} is '{reference}', a branch or a floating ref. git-checkout pins an "
            f"exact tag (refs/tags/<tag>) or the full 40-character commit SHA, because a "
            f"branch can move after the install.",
        )
        return
    if reference.count("/") and not reference.startswith("refs/tags/"):
        _fail(
            errors,
            f"{parent} is '{reference}', an unqualified name with a '/' in it. That could be "
            f"a branch path; write the tag in full (refs/tags/<tag>) or pin the commit SHA.",
        )
        return
    name = reference.removeprefix("refs/tags/")
    if REF_FORBIDDEN.search(name) or name.endswith("/") or name.endswith(".lock"):
        _fail(
            errors,
            f"{parent} is '{reference}', which is not a ref name git accepts.",
        )


def _check_staging_subdir(errors: list[str], spec: dict, parent: str, field_types: dict) -> None:
    """`extract-zip`'s staging directory has to stay where it says it is.

    The step writes every archive member below this directory, so a
    value that walks out of it is a recipe that scatters a download
    across the disk instead of extracting it.
    """
    literal = spec.get("targetSubdir")
    if literal is not None:
        if not isinstance(literal, str) or not literal.strip():
            _fail(errors, f"{parent}.targetSubdir must be a non-empty relative path")
            return
        if Path(literal).is_absolute():
            _fail(
                errors,
                f"{parent}.targetSubdir is '{literal}', an absolute path. extract-zip writes "
                f"below the executable directory; use a `path`-typed config field and "
                f"targetSubdirField when the staging area is genuinely elsewhere.",
            )
        if ".." in Path(literal).parts:
            _fail(
                errors,
                f"{parent}.targetSubdir is '{literal}', which walks out of the directory the "
                f"archive extracts into. Use a plain subdirectory name.",
            )
        return
    field = spec.get("targetSubdirField")
    if isinstance(field, str) and field not in field_types:
        _fail(
            errors,
            f"{parent}.targetSubdirField names '{field}', which the capability declares no "
            f"config field for; the step would extract into the game directory instead of "
            f"the staging area (declared: {sorted(field_types)}).",
        )


def _check_templates(errors: list[str], spec: dict) -> None:
    """Every `{placeholder}` in a step param must name a config field.

    `render_template` in builtin_steps.rs substitutes `{name}` from the
    resolved config and leaves anything it cannot resolve verbatim.
    A `{{name}}` placeholder in a plain string param has no engine at
    all -- the parameter is used as a literal.

    The shipped `community-fps-unlocker` capability was exactly this:
    `processName: '{{gameExecutableBaseName}}'`, copied from the
    template, naming a field no schema declared. Nothing caught it, and
    `kill-process` would simply never match a process.
    """
    declared = {
        field.get("name")
        for field in spec.get("configSchema") or []
        if isinstance(field, dict)
    }
    for section in ("install", "uninstall"):
        steps = spec.get(section)
        if not isinstance(steps, list):
            continue
        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            params = step.get("params")
            if not isinstance(params, dict):
                continue
            for key, value in params.items():
                if not isinstance(value, str):
                    continue
                for name in PLACEHOLDER.findall(value):
                    if name not in declared:
                        _fail(
                            errors,
                            f"{section}[{index}].params.{key} references "
                            f"{{{name}}} but the capability declares no config field "
                            f"with that name; the runner has no engine for it and would "
                            f"use the literal text "
                            f"(declared: {sorted(n for n in declared if n)})",
                        )


def _check_install_chain(errors: list[str], spec: dict) -> None:
    """Structural checks that catch recipes which cannot install.

    Each of these shipped at least once in this project's own specs or
    in the community catalogue, and none of them produced an error the
    recipe author would recognise as "this recipe is wrong".
    """
    field_types = {
        field.get("name"): field.get("type")
        for field in spec.get("configSchema") or []
        if isinstance(field, dict)
    }

    for section in ("install", "uninstall"):
        steps = spec.get(section)
        if not isinstance(steps, list):
            continue
        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            kind = step.get("kind")
            params = step.get("params") or {}
            if not isinstance(params, dict):
                continue

            # `extract-zip` reads a local path. A field of type `url`
            # is never one: `resolve_download_path` only special-cases a
            # bare filename and otherwise joins the URL onto the game
            # directory, which fails at install time with a
            # file-not-found the user cannot act on.
            if kind == "extract-zip":
                archive_field = params.get("archivePathField")
                if isinstance(archive_field, str) and field_types.get(archive_field) == "url":
                    _fail(
                        errors,
                        f"{section}[{index}] extract-zip reads archivePathField "
                        f"'{archive_field}', which is declared type 'url'. extract-zip "
                        f"needs a local file: add a download-file step that fetches "
                        f"'{archive_field}' into Moddin's cache first, and point "
                        f"archivePath at the bare filename it saves.",
                    )
                archive_literal = params.get("archivePath")
                if isinstance(archive_literal, str) and "://" in archive_literal:
                    _fail(
                        errors,
                        f"{section}[{index}] extract-zip points archivePath at a URL "
                        f"({archive_literal}); it needs a local file path.",
                    )
                _check_staging_subdir(
                    errors, params, f"{section}[{index}].params", field_types
                )

            # A `git-checkout` that names a branch builds whatever the
            # branch happens to point at today, so two installs of the
            # same recipe can produce different binaries. The runner
            # refuses it; this is the same rule one step earlier.
            if kind == "git-checkout":
                literal = params.get("ref")
                if literal is not None and not isinstance(literal, str):
                    # `ref: 1.8` is a YAML float and `ref: 2024` an
                    # integer, not a tag. Without this the ref vanishes
                    # into a number and the step fails at install time.
                    _fail(
                        errors,
                        f"{section}[{index}].params.ref is {literal!r}, not a string. Quote the "
                        f"tag or SHA (ref: '1.8').",
                    )
                elif isinstance(literal, str):
                    _check_pinned_ref(
                        errors, literal, f"{section}[{index}].params.ref"
                    )
                field = params.get("refField")
                if isinstance(field, str) and field not in field_types:
                    _fail(
                        errors,
                        f"{section}[{index}] git-checkout pins refField '{field}', which "
                        f"the capability declares no config field for (declared: "
                        f"{sorted(field_types)}).",
                    )
                repository = params.get("repo")
                if isinstance(repository, str) and not HTTPS_URL.match(repository):
                    _fail(
                        errors,
                        f"{section}[{index}] git-checkout repo must start with https:// "
                        f"(got {repository!r}).",
                    )

            # A move whose source and destination resolve to the same
            # path is a no-op that Windows reports as an error.
            if kind == "move-file":
                source = params.get("fromField", params.get("from"))
                destination = params.get("toField", params.get("to"))
                if source is not None and source == destination:
                    _fail(
                        errors,
                        f"{section}[{index}] move-file has the same source and "
                        f"destination ('{source}'); it cannot do anything.",
                    )


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
    _check_supported_engines(errors, spec)

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

    _check_templates(errors, spec)
    _check_install_chain(errors, spec)

    return errors


def validate_revocations_file(path: Path) -> list[str]:
    """Check `revoked-ids.json` against the shape the app reads.

    This is the human-maintained *input*. `regenerate_catalog.py`
    inlines it into `catalog.json` and the maintainer signs the result,
    so this file alone decides nothing — but a malformed value here
    would be a malformed `revoked` field in every signed catalog after
    it, and the app refuses those outright. Catching it here says so at
    review time instead of at install time.
    """
    errors: list[str] = []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return [f"{path}: could not be read as JSON: {error}"]

    if not isinstance(payload, dict):
        return [f"{path}: top level must be an object with a 'revoked' list"]

    errors.extend(_check_revocation_list(payload.get("revoked"), f"{path}"))
    return errors


def _check_revocation_list(raw: Any, label: str) -> list[str]:
    """The exact shape `parse_revocations` enforces on the app side.

    Kept deliberately in step with `moddin-desktop`'s
    `src-tauri/src/community_catalog.rs`: a valid signature does not
    make a broken value trustworthy, and the app's answer to a broken
    value is to refuse every community install.
    """
    errors: list[str] = []
    if not isinstance(raw, list):
        kind = type(raw).__name__
        return [f"{label}: 'revoked' must be a list, got {kind}"]

    seen: set[str] = set()
    for index, entry in enumerate(raw):
        where = f"{label}: revoked[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{where} must be an object, got {type(entry).__name__}")
            continue
        identifier = entry.get("id")
        if not isinstance(identifier, str) or not identifier.strip():
            errors.append(
                f"{where}.id must be a non-empty string — an entry without one "
                "cannot be matched to a capability, so the app would ignore it"
            )
            continue
        reason = entry.get("reason", "")
        if not isinstance(reason, str):
            errors.append(
                f"{where}.reason must be a string, got {type(reason).__name__}"
            )
            continue
        if identifier in seen:
            errors.append(
                f"{where} lists '{identifier}', which is already revoked earlier "
                "in the list. The app shows the first reason; keep one entry per id."
            )
            continue
        seen.add(identifier.strip())
    return errors


def validate_catalog_file(path: Path) -> list[str]:
    """Check the `revoked` list embedded in a generated `catalog.json`.

    Two things matter here, and only the first is about shape:

    1. the embedded list is well-formed, because the app refuses the
       whole catalogue when it is not;
    2. it matches `revoked-ids.json`, because the signed catalogue is
       the *only* copy of the kill switch the app ever reads. A
       revocation edited into the source file and never regenerated
       does not ship, and nothing else in the pipeline notices.

    Run it after regenerating:
        python scripts/validate_capability.py catalog.json
    """
    errors: list[str] = []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return [f"{path}: could not be read as JSON: {error}"]

    if not isinstance(payload, dict):
        return [f"{path}: top level must be an object"]

    capabilities = payload.get("capabilities")
    if not isinstance(capabilities, list):
        errors.append(f"{path}: 'capabilities' must be a list")

    if "revoked" not in payload:
        # Read as "nothing is revoked" by the app, so it is legal — but
        # `regenerate_catalog.py` always emits the key, so its absence
        # means this catalog predates the inlined revocations and needs
        # re-generating before it is signed again.
        errors.append(
            f"{path}: no 'revoked' key. The app reads that as 'nothing is "
            "revoked'. Re-run scripts/regenerate_catalog.py and re-sign."
        )
    else:
        errors.extend(_check_revocation_list(payload.get("revoked"), str(path)))

    source = path.parent / "revoked-ids.json"
    if errors or not source.is_file():
        return errors

    source_ids = {
        entry["id"]
        for entry in json.loads(source.read_text(encoding="utf-8"))["revoked"]
    }
    catalog_ids = {
        entry["id"]
        for entry in payload["revoked"]
    }
    if source_ids != catalog_ids:
        only_source = ", ".join(sorted(source_ids - catalog_ids)) or "(none)"
        only_catalog = ", ".join(sorted(catalog_ids - source_ids)) or "(none)"
        errors.append(
            f"{path}: the embedded revocations do not match {source.name}. "
            f"Only in {source.name}: {only_source}. Only in {path.name}: "
            f"{only_catalog}. Re-run scripts/regenerate_catalog.py and re-sign — "
            "the app reads the signed copy, so a mismatch here means a "
            "revocation is not actually in force."
        )
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

    # The revocation list is a repo-level input to the catalog, so it is
    # checked whenever the repo is, not only when someone remembers to
    # name it. The generated catalog's copy of it is a separate check —
    # run `python scripts/validate_capability.py catalog.json` for that.
    revocations = base.parent / "revoked-ids.json"
    if revocations.is_file():
        errors = validate_revocations_file(revocations)
        if errors:
            failed = True
            print(f"\n[FAIL] {revocations}", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)
        else:
            print(f"[OK]   {revocations}")

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
        if path.name == "revoked-ids.json":
            errors = validate_revocations_file(path)
        elif path.name == "catalog.json":
            errors = validate_catalog_file(path)
        else:
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
