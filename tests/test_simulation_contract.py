"""Offline contract checks; compile isolated definitions without importing the app."""

import ast
import contextlib
import csv
import io
import json
import logging
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]


def isolated_function(path, name, namespace=None, class_name=None):
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
    nodes = tree.body
    if class_name:
        nodes = next(
            node
            for node in reversed(nodes)
            if isinstance(node, ast.ClassDef) and node.name == class_name
        ).body
    function = next(
        node
        for node in nodes
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    function.decorator_list = []
    module = ast.Module(
        body=[
            ast.ImportFrom(
                module="__future__", names=[ast.alias(name="annotations")], level=0
            ),
            function,
        ],
        type_ignores=[],
    )
    scope = {} if namespace is None else dict(namespace)
    exec(compile(ast.fix_missing_locations(module), str(ROOT / path), "exec"), scope)
    return scope[name]


class SimulationContractTests(unittest.TestCase):
    def write_sample(self, directory, report_format, target="https://example.test"):
        writer = isolated_function("cyberapp/cli.py", "_write_web_scan_sample_report")
        args = SimpleNamespace(
            web_app_scan=target, output=directory, output_format=report_format
        )
        console = io.StringIO()
        with contextlib.redirect_stdout(console):
            output = writer(args)
        self.assertIn("SIMULATION", console.getvalue())
        self.assertIn("Verified vulnerabilities: 0", console.getvalue())
        self.assertIn("No requests were sent", console.getvalue())
        return output

    def test_json_has_no_verified_findings_and_labels_every_example(self):
        with tempfile.TemporaryDirectory() as directory:
            report = json.loads(
                self.write_sample(directory, "json").read_text(encoding="utf-8")
            )
        self.assertEqual(report["status"], "simulation")
        self.assertTrue(report["simulated"])
        self.assertFalse(report["performed_scan"])
        self.assertEqual(report["vulnerabilities"], [])
        self.assertEqual(report["summary"]["verified_vulnerabilities"], 0)
        for key in ("critical", "high", "medium", "low", "total"):
            self.assertEqual(report["summary"][key], 0)
        self.assertEqual(report["summary"]["example_count"], len(report["examples"]))
        self.assertTrue(all(example["simulated"] for example in report["examples"]))

    def test_html_labels_examples_and_escapes_untrusted_target(self):
        target = "https://example.test/?q=<script>alert(1)</script>"
        with tempfile.TemporaryDirectory() as directory:
            report = self.write_sample(directory, "html", target).read_text(
                encoding="utf-8"
            )
        self.assertIn("SIMULATION", report)
        self.assertIn("EXAMPLE ONLY", report)
        self.assertIn("Verified vulnerabilities: 0", report)
        self.assertNotIn("<script>", report)
        self.assertIn("&lt;script&gt;", report)

    def test_non_http_sample_url_is_rejected_without_output(self):
        writer = isolated_function("cyberapp/cli.py", "_write_web_scan_sample_report")
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(
                web_app_scan="file:///private", output=directory, output_format="json"
            )
            with self.assertRaises(ValueError):
                writer(args)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_csv_keeps_simulation_metadata_on_every_row(self):
        with tempfile.TemporaryDirectory() as directory:
            output = self.write_sample(directory, "csv")
            with output.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(row["status"], "simulation")
            self.assertEqual(row["simulated"], "True")
            self.assertEqual(row["performed_scan"], "False")
            self.assertIn("SIMULATION", row["warning"])

    def test_demo_mode_does_not_initialize_the_app_or_run_scans(self):
        tree = ast.parse((ROOT / "cyberapp/cli.py").read_text(encoding="utf-8"))
        branch = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.Attribute)
            and node.test.attr == "web_app_scan"
        )
        calls = [
            node.func.id
            for node in ast.walk(branch)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        ]
        self.assertIn("_write_web_scan_sample_report", calls)
        self.assertFalse(
            {"create_app", "run_migrations", "run_worker", "enqueue_job"}.intersection(
                calls
            )
        )

    def test_toy_verifier_rejects_all_inputs(self):
        verifier = isolated_function(
            "cybermodules/quantum_crypto.py",
            "verify",
            {"logger": logging.getLogger("simulation-contract")},
            class_name="DilithiumSignature",
        )
        for signature in (b"", b"arbitrary signature", b"\x00" * 4096):
            with (
                self.subTest(length=len(signature)),
                self.assertLogs("simulation-contract", level="WARNING"),
            ):
                self.assertFalse(verifier(None, b"message", signature, object()))

    def test_verify_api_fails_closed_without_using_crypto(self):
        verify_api = isolated_function(
            "cyberapp/routes/quantum.py",
            "quantum_verify",
            {"jsonify": lambda data: data},
        )
        payload, status = verify_api()
        self.assertEqual(status, 501)
        self.assertFalse(payload["valid"])
        self.assertFalse(payload["verification_supported"])
        self.assertFalse(payload["quantum_safe"])

    def test_quantum_payload_cannot_claim_security(self):
        label = isolated_function(
            "cyberapp/routes/quantum.py", "_label_quantum_demo_payload"
        )
        original = {
            "quantum_safe": True,
            "verification_supported": True,
            "value": "example",
        }
        labelled = label(original)
        self.assertFalse(labelled["quantum_safe"])
        self.assertFalse(labelled["verification_supported"])
        self.assertEqual(labelled["implementation"], "educational_simulation")
        self.assertIn("not audited", labelled["warning"])
        self.assertEqual(labelled["value"], "example")
        self.assertTrue(original["quantum_safe"])


if __name__ == "__main__":
    unittest.main()
