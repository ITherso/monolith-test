"""Offline contract checks; compile isolated definitions without importing the app."""

import ast
import contextlib
import csv
import importlib.util
import io
import json
import logging
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from flask import Flask, jsonify

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


class ListenerFailureContractTests(unittest.TestCase):
    """Exercise isolated failure paths, never an operational server or listener."""

    WEB_ROUTES = (
        ("web_c2_sessions", ()),
        ("web_c2_command", ()),
        ("web_c2_register", ()),
        ("web_c2_beacon", ()),
        ("web_c2_terminate", ("inert-session",)),
        ("web_c2_beacon_templates", ()),
        ("web_c2_generate_beacon", ()),
        ("web_c2_config", ()),
    )

    def web_unavailable(self):
        return isolated_function(
            "cyberapp/routes/c2.py", "_web_c2_unavailable", {"jsonify": jsonify}
        )

    def assert_unavailable(self, response, error="web_c2_backend_incomplete"):
        self.assertEqual(response.status_code, 501)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        payload = response.get_json()
        self.assertIs(payload["success"], False)
        self.assertIs(payload["available"], False)
        self.assertIs(payload["running"], False)
        self.assertEqual(payload["error"], error)
        self.assertTrue(payload["message"])

    def test_framework_start_clears_stale_running_flag_without_starting_runtime(self):
        start = isolated_function(
            "cybermodules/c2_framework.py", "start_listener", class_name="C2Server"
        )
        listener = SimpleNamespace(status="running")
        database = SimpleNamespace(
            get_listener=Mock(return_value=listener),
            update_listener_status=Mock(
                side_effect=lambda _identifier, status: setattr(
                    listener, "status", status
                )
            ),
        )
        server = SimpleNamespace(db=database)
        self.assertIs(start(server, "inert-listener"), False)
        self.assertEqual(listener.status, "stopped")
        database.get_listener.assert_called_once_with("inert-listener")
        database.update_listener_status.assert_called_once_with(
            "inert-listener", "stopped"
        )

    def test_framework_start_missing_listener_does_not_create_or_update_record(self):
        start = isolated_function(
            "cybermodules/c2_framework.py", "start_listener", class_name="C2Server"
        )
        database = SimpleNamespace(
            get_listener=Mock(return_value=None), update_listener_status=Mock()
        )
        self.assertIs(start(SimpleNamespace(db=database), "missing"), False)
        database.get_listener.assert_called_once_with("missing")
        database.update_listener_status.assert_not_called()

    def test_web_start_returns_failure_and_replaces_stale_running_flag(self):
        start = isolated_function(
            "c2/web_c2_listener.py",
            "start",
            {"logger": logging.getLogger("listener-failure-contract")},
            class_name="WebC2Listener",
        )
        for initial in (False, True):
            listener = SimpleNamespace(running=initial)
            with (
                self.subTest(initial_running=initial),
                self.assertLogs("listener-failure-contract", level="WARNING"),
            ):
                self.assertIs(start(listener), False)
            self.assertIs(listener.running, False)

    def test_unavailable_response_is_an_explicit_uncacheable_failure(self):
        app = Flask("listener-unavailable-response-contract")
        with app.app_context():
            self.assert_unavailable(self.web_unavailable()())

    def test_all_missing_method_routes_fail_without_reading_requests_or_backend(self):
        app = Flask("listener-unavailable-route-contract")
        getter = Mock(side_effect=AssertionError("backend must not be constructed"))
        request_trap = Mock()
        request_trap.get_json.side_effect = AssertionError("body must not be parsed")
        helper = self.web_unavailable()
        namespace = {
            "_web_c2_unavailable": helper,
            "_get_web_c2_listener": getter,
            "request": request_trap,
        }
        for name, arguments in self.WEB_ROUTES:
            handler = isolated_function("cyberapp/routes/c2.py", name, namespace)
            with self.subTest(route=name), app.app_context():
                self.assert_unavailable(handler(*arguments))
        getter.assert_not_called()
        self.assertEqual(request_trap.mock_calls, [])

    def test_advanced_start_requires_login_then_reports_unavailable_without_server(
        self,
    ):
        app = Flask("advanced-listener-failure-contract")
        getter = Mock(side_effect=AssertionError("server must not be constructed"))
        for authenticated in (False, True):
            start = isolated_function(
                "cyberapp/routes/c2_advanced.py",
                "start_listener",
                {
                    "jsonify": jsonify,
                    "session": {"logged_in": authenticated},
                    "get_c2_server": getter,
                },
            )
            with self.subTest(authenticated=authenticated), app.app_context():
                response = app.make_response(start("inert-listener"))
                if authenticated:
                    self.assert_unavailable(response, "listener_runtime_unavailable")
                else:
                    self.assertEqual(response.status_code, 401)
                    self.assertEqual(response.get_json(), {"error": "login_required"})
        getter.assert_not_called()

    def protected_web_app(self):
        spec = importlib.util.spec_from_file_location(
            "isolated_listener_authorization", ROOT / "cyberapp/authorization.py"
        )
        authorization = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(authorization)
        app = Flask("listener-admin-failure-contract")
        app.config.update(TESTING=True, SECRET_KEY="isolated-listener-contract-only")
        authorization.install_admin_access_control(app)
        entered = []
        helper = self.web_unavailable()
        getter = Mock(side_effect=AssertionError("backend must not be constructed"))

        def tracked_handler(name, handler, arguments):
            def tracked():
                entered.append(name)
                return handler(*arguments)

            return tracked

        for name, arguments in self.WEB_ROUTES:
            handler = isolated_function(
                "cyberapp/routes/c2.py",
                name,
                {"_web_c2_unavailable": helper, "_get_web_c2_listener": getter},
            )
            app.add_url_rule(
                f"/api/listener-contract/{name}",
                f"c2_implant.{name}",
                tracked_handler(name, handler, arguments),
                methods=["GET", "POST"],
            )
        return app.test_client(), entered, getter

    def test_admin_guard_denies_all_incomplete_routes_before_handler_entry(self):
        client, entered, getter = self.protected_web_app()
        for role, expected_status in ((None, 401), ("analyst", 403)):
            with client.session_transaction() as current:
                current.clear()
                if role:
                    current.update(logged_in=True, user="inert-user", role=role)
            for name, _arguments in self.WEB_ROUTES:
                with self.subTest(role=role, route=name):
                    response = client.post(f"/api/listener-contract/{name}")
                    self.assertEqual(response.status_code, expected_status)
                    self.assertEqual(response.headers["Cache-Control"], "no-store")
                    self.assertEqual(entered, [])
        getter.assert_not_called()

    def test_admin_requests_get_failure_without_constructing_a_listener(self):
        client, entered, getter = self.protected_web_app()
        with client.session_transaction() as current:
            current.update(logged_in=True, user="inert-admin", role="admin")
        for name, _arguments in self.WEB_ROUTES:
            with self.subTest(route=name):
                response = client.post(f"/api/listener-contract/{name}")
                self.assert_unavailable(response)
        self.assertEqual(entered, [name for name, _arguments in self.WEB_ROUTES])
        getter.assert_not_called()


if __name__ == "__main__":
    unittest.main()
