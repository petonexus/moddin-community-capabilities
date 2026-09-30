#!/usr/bin/env python3
"""Fixture suite for validate_capability.py's own rules.

Every rule the validator enforces needs a capability that fails it and a
near-identical one that does not. A rule with no failing fixture is an
assumption that the rule works, and a rule whose fixture is broken in some
other way passes the suite without proving anything -- so each case here
asserts three things:

  * the bad fixture is rejected,
  * it is rejected *for this rule*: the errors are the ones named below,
    and there are no others,
  * the good fixture, which differs only in the thing the rule is about,
    is accepted.

Run it with:

    python scripts/test_validator.py

The fixtures live under scripts/fixtures/, not capabilities/, because
validate_tree() globs capabilities/*/capability.yaml and a deliberately
broken recipe in there would fail the build for everyone.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import validate_capability  # noqa: E402  (path has to be set first)

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "scripts" / "fixtures"

# (case, bad fixture, good fixture, expected errors -- each a tuple of
# substrings that must all appear in that one error)
CASES = [
    (
        "no template placeholder in a check param",
        "check-param-template-bad",
        "check-param-template-good",
        [
            ("checks[0].params.processNameField", "builtin_checks.rs", "never renders"),
        ],
    ),
    (
        "no absolute path handed to a file check",
        "check-path-field-bad",
        "check-path-field-good",
        [
            ("checks[0].params.pathField", "safe_join_relative"),
            ("checks[1].params.path", "Path escapes the allowed root"),
        ],
    ),
]


def errors_for(fixture: str) -> list[str]:
    path = FIXTURES / fixture / "capability.yaml"
    if not path.is_file():
        raise AssertionError(f"missing fixture: {path}")
    return validate_capability.validate_capability_file(path)


class ValidatorRules(unittest.TestCase):
    def test_each_rule_has_a_failing_and_a_passing_fixture(self) -> None:
        for name, bad, good, expected_errors in CASES:
            with self.subTest(rule=name):
                errors = errors_for(bad)
                self.assertTrue(
                    errors,
                    f"{bad} is supposed to fail the '{name}' rule and passed; "
                    f"the rule is not being enforced",
                )
                unmatched = list(errors)
                for expected in expected_errors:
                    hits = [
                        error
                        for error in unmatched
                        if all(marker in error for marker in expected)
                    ]
                    self.assertEqual(
                        len(hits),
                        1,
                        f"{bad}: expected exactly one error naming all of "
                        f"{expected}, found {len(hits)} in {errors}",
                    )
                    unmatched.remove(hits[0])
                self.assertEqual(
                    unmatched,
                    [],
                    f"{bad} is meant to break one rule and nothing else, but "
                    f"also reported: {unmatched}",
                )
                self.assertEqual(
                    errors_for(good),
                    [],
                    f"{good} is the fix for '{name}' and must be accepted",
                )

    def test_shipped_capabilities_still_validate(self) -> None:
        paths = sorted((REPO_ROOT / "capabilities").glob("*/capability.yaml"))
        self.assertTrue(paths, "no capabilities found; the glob moved")
        for path in paths:
            with self.subTest(capability=path.parent.name):
                self.assertEqual(validate_capability.validate_capability_file(path), [])

    def test_fixtures_are_outside_the_validated_tree(self) -> None:
        # If this ever fails, a deliberately broken fixture is being shipped
        # inside capabilities/ and validate_tree() would fail the build.
        self.assertFalse(
            list((REPO_ROOT / "capabilities").glob("*/scripts/*")),
            "fixture-shaped paths found under capabilities/",
        )
        self.assertTrue(FIXTURES.is_dir(), f"no fixture directory at {FIXTURES}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
