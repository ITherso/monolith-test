"""Checks for the reviewed management surface; never import operational modules.

This is an explicit, limited CI contract, not validation of the offensive framework.
Adding a file requires reviewing its import and execution behavior, then updating
these tuples and the dedicated pytest configuration together.
"""

from __future__ import annotations

import argparse
import ast
import json
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]

ISOLATED_TESTS = (
    "tests/test_audit_security.py",
    "tests/test_host_safety.py",
    "tests/test_installation_regressions.py",
    "tests/test_management_security.py",
    "tests/test_simulation_contract.py",
    "tests/test_vulnerable.py",
    "tests/test_coverage_badge.py",
    "tests/test_ci_contract.py",
)

SAFE_LINT_TARGETS = (
    "cyberapp/security.py",
    "cyberapp/host_safety.py",
    "cyberapp/migrations.py",
    "cyberapp/settings.py",
    "cyberapp/__init__.py",
    "scripts/update_coverage_badge.py",
    "scripts/check_management_safety.py",
    *ISOLATED_TESTS,
)

KNOWN_LEGACY_SYNTAX_FAILURES = (
    "cybermodules/event_driven_c2.py:524 (invalid Unicode escape in source)",
    "cybermodules/kernel_callbacks_bypass.py:407 (invalid hexadecimal literal)",
)

SCOPE_NOTICE = (
    "Management safety checks only. Legacy operational tests are not executed; "
    "a passing result does not validate the offensive framework."
)


def validated_targets(
    paths: Sequence[str], root: Path | None = None
) -> tuple[str, ...]:
    """Reject globs, absolute paths, traversal, duplicates, and escaping symlinks."""
    repository_root = ROOT if root is None else root
    validated = []
    for value in paths:
        path = PurePosixPath(value)
        if (
            not value
            or any(
                not character.isascii()
                or not (character.isalnum() or character in "/_.-")
                for character in value
            )
            or "\\" in value
            or ":" in value
            or any(character in value for character in "*?[]\n\r")
            or path.is_absolute()
            or ".." in path.parts
            or any(part.startswith("-") for part in path.parts)
            or path.suffix != ".py"
            or path.as_posix() != value
        ):
            raise ValueError(f"Unsafe CI target: {value!r}")
        if value in validated:
            raise ValueError(f"Duplicate CI target: {value}")
        resolved = (repository_root / value).resolve()
        if not resolved.is_relative_to(repository_root.resolve()):
            raise ValueError(f"CI target escapes repository: {value}")
        validated.append(value)
    return tuple(validated)


def manifest() -> dict[str, object]:
    return {
        "scope": "management_safety_only",
        "notice": SCOPE_NOTICE,
        "tests": list(validated_targets(ISOLATED_TESTS)),
        "lint_targets": list(validated_targets(SAFE_LINT_TARGETS)),
        "known_legacy_syntax_failures": list(KNOWN_LEGACY_SYNTAX_FAILURES),
    }


def syntax_check() -> int:
    """Parse the reviewed source files as data, without executing or importing them."""
    errors = []
    targets = validated_targets(SAFE_LINT_TARGETS)
    for relative in targets:
        try:
            ast.parse((ROOT / relative).read_bytes(), filename=relative)
        except (OSError, SyntaxError) as exc:
            errors.append(f"{relative}: {exc}")
    print(SCOPE_NOTICE)
    print("Known legacy source failures (outside this check):")
    for failure in KNOWN_LEGACY_SYNTAX_FAILURES:
        print(f"  {failure}")
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f"Syntax check passed for {len(targets)} reviewed management/test files.")
    return 0


def run_ruff(action: str) -> int:
    """Run only the fixed static targets; callers cannot supply paths or options."""
    actions = {"lint": ["check"], "format-check": ["format", "--check"]}
    if action not in actions:
        raise ValueError("Unsupported static check")
    targets = validated_targets(SAFE_LINT_TARGETS)
    command = [sys.executable, "-m", "ruff", *actions[action], *targets]
    return subprocess.run(command, cwd=ROOT, check=False).returncode


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    choices = parser.add_mutually_exclusive_group()
    choices.add_argument("--syntax-check", action="store_true")
    choices.add_argument("--list-tests", action="store_true")
    choices.add_argument("--list-lint-targets", action="store_true")
    choices.add_argument("--manifest", action="store_true")
    choices.add_argument("--lint", action="store_true")
    choices.add_argument("--format-check", action="store_true")
    args = parser.parse_args(argv)
    if args.list_tests:
        print("\n".join(validated_targets(ISOLATED_TESTS)))
        return 0
    if args.list_lint_targets:
        print("\n".join(validated_targets(SAFE_LINT_TARGETS)))
        return 0
    if args.manifest:
        print(json.dumps(manifest(), indent=2))
        return 0
    if args.lint:
        return run_ruff("lint")
    if args.format_check:
        return run_ruff("format-check")
    return syntax_check()


if __name__ == "__main__":
    raise SystemExit(main())
