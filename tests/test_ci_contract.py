"""The supported CI surface stays explicit and cannot launch operational code."""

import ast
import configparser
import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "scripts/check_management_safety.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("isolated_ci_manifest", TOOL_PATH)
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    return tool


class ManagementCIContractTests(unittest.TestCase):
    def setUp(self):
        self.tool = load_tool()

    def test_tool_imports_only_standard_library_and_never_discovers_files(self):
        tree = ast.parse(TOOL_PATH.read_text(encoding="utf-8"))
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module.split(".")[0])
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(
                    node.func.attr,
                    {"glob", "rglob", "iterdir", "walk", "import_module"},
                )
        self.assertTrue(set(imports).issubset(sys.stdlib_module_names | {"__future__"}))

    def test_reviewed_tests_are_explicit_and_operational_tests_remain_outside_scope(
        self,
    ):
        expected = {
            "tests/test_audit_security.py",
            "tests/test_host_safety.py",
            "tests/test_installation_regressions.py",
            "tests/test_management_security.py",
            "tests/test_simulation_contract.py",
            "tests/test_vulnerable.py",
            "tests/test_coverage_badge.py",
            "tests/test_ci_contract.py",
        }
        self.assertEqual(set(self.tool.ISOLATED_TESTS), expected)
        self.assertNotIn("tests/test_c2.py", self.tool.ISOLATED_TESTS)
        self.assertNotIn("tests/test_db_flows.py", self.tool.ISOLATED_TESTS)
        self.assertTrue(expected.issubset(self.tool.SAFE_LINT_TARGETS))
        with tempfile.TemporaryDirectory() as directory:
            tests = Path(directory) / "tests"
            tests.mkdir()
            (tests / "test_unreviewed.py").write_text(
                "raise AssertionError", encoding="utf-8"
            )
            with patch.object(self.tool, "ROOT", Path(directory)):
                self.assertEqual(set(self.tool.manifest()["tests"]), expected)

    def test_target_validation_rejects_globs_commands_and_path_escape(self):
        for value in (
            "tests/*.py",
            "tests/../cyber.py",
            "/tmp/test.py",
            "C:/temp/test.py",
            "tests\\test_c2.py",
            "python cyber.py",
            "tests/test_x.py\ncyber.py",
            "./tests/test_x.py",
            "tests//test_x.py",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.tool.validated_targets([value])
        with self.assertRaises(ValueError):
            self.tool.validated_targets(["tests/test_x.py", "tests/test_x.py"])

    def test_cli_lists_only_manifest_paths_and_explains_limited_scope(self):
        for flag, expected in (
            ("--list-tests", self.tool.ISOLATED_TESTS),
            ("--list-lint-targets", self.tool.SAFE_LINT_TARGETS),
        ):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(self.tool.main([flag]), 0)
            self.assertEqual(tuple(output.getvalue().splitlines()), expected)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(self.tool.main(["--manifest"]), 0)
        manifest = json.loads(output.getvalue())
        self.assertEqual(manifest["scope"], "management_safety_only")
        self.assertIn("not executed", manifest["notice"])
        self.assertTrue(manifest["known_legacy_syntax_failures"])

    def test_ruff_commands_are_fixed_and_propagate_failures(self):
        for flag, expected in (
            ("--lint", ["check"]),
            ("--format-check", ["format", "--check"]),
        ):
            with (
                self.subTest(flag=flag),
                patch.object(
                    self.tool.subprocess,
                    "run",
                    return_value=SimpleNamespace(returncode=7),
                ) as run,
            ):
                self.assertEqual(self.tool.main([flag]), 7)
            run.assert_called_once_with(
                [sys.executable, "-m", "ruff", *expected, *self.tool.SAFE_LINT_TARGETS],
                cwd=ROOT,
                check=False,
            )
        with self.assertRaises(ValueError):
            self.tool.run_ruff("run-application")

    def test_cli_does_not_accept_arbitrary_source_paths_or_commands(self):
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as error,
        ):
            self.tool.main(["--lint", "cyber.py"])
        self.assertEqual(error.exception.code, 2)

    def test_syntax_check_parses_without_executing_and_reports_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in self.tool.SAFE_LINT_TARGETS:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(
                    "raise AssertionError('source must not execute')\n",
                    encoding="utf-8",
                )
            with (
                patch.object(self.tool, "ROOT", root),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(self.tool.syntax_check(), 0)
                (root / self.tool.SAFE_LINT_TARGETS[0]).write_text(
                    "def invalid(:\n", encoding="utf-8"
                )
                errors = io.StringIO()
                with contextlib.redirect_stderr(errors):
                    self.assertEqual(self.tool.syntax_check(), 1)
                self.assertIn(self.tool.SAFE_LINT_TARGETS[0], errors.getvalue())

    def test_dedicated_pytest_configuration_matches_reviewed_manifest(self):
        config = configparser.ConfigParser()
        config.read(ROOT / "pytest-management.ini", encoding="utf-8")
        self.assertEqual(
            tuple(config["pytest"]["testpaths"].split()), self.tool.ISOLATED_TESTS
        )
        self.assertNotIn("--ignore", config["pytest"].get("addopts", ""))

    def test_workflow_only_runs_curated_checks_and_never_starts_the_app(self):
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/python.yml").read_text(encoding="utf-8")
        )
        self.assertEqual(workflow["name"], "Management Safety CI")
        job = workflow["jobs"]["management-safety"]
        self.assertEqual(job["env"]["PYTEST_DISABLE_PLUGIN_AUTOLOAD"], "1")
        self.assertEqual(
            set(job["strategy"]["matrix"]["os"]), {"ubuntu-latest", "windows-latest"}
        )
        required_checks = {
            "python scripts/check_management_safety.py --syntax-check",
            "python -m pytest -c pytest-management.ini --junitxml=reports/management-safety.xml",
            "python scripts/check_management_safety.py --lint",
            "python scripts/check_management_safety.py --format-check",
            "python -m mypy --follow-imports=skip cyberapp/host_safety.py cyberapp/security.py",
        }
        allowed_commands = required_checks | {
            "python -m pip install -r requirements_ci.txt"
        }
        commands = {
            step["run"].strip()
            for entry in workflow["jobs"].values()
            for step in entry.get("steps", [])
            if "run" in step
        }
        self.assertTrue(required_checks.issubset(commands))
        self.assertTrue(commands.issubset(allowed_commands))
        for command in commands:
            self.assertNotIn("cyber.py", command)
            self.assertNotIn("docker run", command)
        self.assertFalse(
            any(step.get("continue-on-error", False) for step in job["steps"])
        )


if __name__ == "__main__":
    unittest.main()
