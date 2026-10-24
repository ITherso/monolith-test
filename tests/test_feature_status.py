"""Read-only status contracts in an isolated Flask harness, without app imports."""

import ast
import importlib.util
import sys
import unittest
from html.parser import HTMLParser
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

from flask import Flask

ROOT = Path(__file__).resolve().parents[1]


def load_file(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {name: module}):
        spec.loader.exec_module(module)
    return module


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.controls = []
        self.feature_rows = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag in {"form", "button", "input", "iframe", "img"}:
            self.controls.append(tag)
        if tag == "tr" and attributes.get("id", "").startswith("feature-"):
            self.feature_rows.append(attributes["data-status"])


class FeatureStatusTest(unittest.TestCase):
    def setUp(self):
        self.model = load_file("isolated_feature_status", "cyberapp/feature_status.py")
        # Only the inert model is available to the directly loaded route module.
        # A DB stub makes any accidental DB use fail instead of reading host data.
        db = ModuleType("cyberapp.models.db")

        def forbidden_db(*args, **kwargs):
            raise AssertionError("Feature status must not access a database")

        db.db_conn = forbidden_db
        with patch.dict(
            sys.modules,
            {"cyberapp.feature_status": self.model, "cyberapp.models.db": db},
        ):
            self.route = load_file(
                "isolated_feature_status_routes", "cyberapp/routes/feature_status.py"
            )
        self.app = Flask("feature-status-test", template_folder=str(ROOT / "templates"))
        self.app.config.update(TESTING=True, SECRET_KEY="feature-status-tests-only")
        self.app.register_blueprint(self.route.feature_status_bp)
        self.client = self.app.test_client()

    def _login(self, role="analyst"):
        with self.client.session_transaction() as session:
            session.update(logged_in=True, user="test-user", role=role)

    def test_page_and_api_require_login(self):
        page = self.client.get("/feature-status")
        self.assertEqual(page.status_code, 302)
        self.assertEqual(page.headers["Location"], "/login")
        api = self.client.get("/api/feature-status")
        self.assertEqual(api.status_code, 401)
        self.assertEqual(api.json, {"error": "login_required"})

    def test_analyst_can_read_identical_page_and_api_inventory(self):
        self._login()
        page = self.client.get("/feature-status")
        api = self.client.get("/api/feature-status")
        self.assertEqual(page.status_code, 200)
        self.assertEqual(api.status_code, 200)
        self.assertEqual(api.json, self.model.feature_status_snapshot())
        self.assertEqual(api.headers["Cache-Control"], "no-store")
        self.assertEqual(page.headers["Cache-Control"], "no-store")
        parser = _PageParser()
        parser.feed(page.get_data(as_text=True))
        self.assertEqual(parser.controls, [])
        self.assertEqual(
            parser.feature_rows, [item["status"] for item in api.json["features"]]
        )
        self.assertIn("Canlı kurulum denetimi", page.get_data(as_text=True))

    def test_statuses_are_distinct_and_never_claim_full_readiness(self):
        snapshot = self.model.feature_status_snapshot()
        self.assertEqual(
            set(snapshot["statuses"]),
            {
                "verified_management",
                "simulation",
                "blocked_by_host_safety",
                "incomplete_offline",
                "external_config_required",
                "unverified",
            },
        )
        self.assertTrue(snapshot["read_only"])
        self.assertFalse(snapshot["live_probe_performed"])
        self.assertFalse(snapshot["production_certified"])
        self.assertFalse(snapshot["inventory_complete"])
        self.assertEqual(sum(snapshot["counts"].values()), len(snapshot["features"]))
        self.assertEqual(
            len({item["id"] for item in snapshot["features"]}),
            len(snapshot["features"]),
        )
        for item in snapshot["features"]:
            self.assertTrue(item["verification_scope"])
            self.assertTrue(item["evidence"])
            self.assertIn(item["status"], snapshot["statuses"])
        statuses = {item["id"]: item["status"] for item in snapshot["features"]}
        self.assertEqual(statuses["host_startup"], "blocked_by_host_safety")
        self.assertEqual(statuses["oauth_demo"], "simulation")
        self.assertEqual(statuses["operational_runtime"], "unverified")

    def test_snapshot_is_fresh_and_exposes_no_configuration(self):
        first = self.model.feature_status_snapshot()
        first["features"][0]["title"] = "changed"
        first["counts"].clear()
        first["documentation"][0]["url"] = "changed"
        second = self.model.feature_status_snapshot()
        self.assertNotEqual(second["features"][0]["title"], "changed")
        self.assertTrue(second["counts"])
        self.assertNotEqual(second["documentation"][0]["url"], "changed")
        with patch.dict("os.environ", {"PRIVATE_TEST_VALUE": "never-return-this"}):
            self._login()
            response = self.client.get("/api/feature-status")
        self.assertNotIn("never-return-this", response.get_data(as_text=True))

    def test_routes_only_support_read_methods(self):
        self._login("admin")
        rules = [
            rule
            for rule in self.app.url_map.iter_rules()
            if rule.endpoint.startswith("feature_status.")
        ]
        self.assertEqual(
            {rule.rule for rule in rules}, {"/feature-status", "/api/feature-status"}
        )
        for rule in rules:
            self.assertEqual(rule.methods, {"GET", "HEAD", "OPTIONS"})
            for method in ("POST", "PUT", "PATCH", "DELETE"):
                self.assertEqual(
                    self.client.open(rule.rule, method=method).status_code, 405
                )

    def test_rendering_escapes_inventory_text(self):
        snapshot = self.model.feature_status_snapshot()
        snapshot["features"][0]["title"] = '<img src=x onerror="alert(1)">'
        self._login()
        with patch.object(self.route, "feature_status_snapshot", return_value=snapshot):
            response = self.client.get("/feature-status")
        self.assertIn("&lt;img", response.get_data(as_text=True))
        parser = _PageParser()
        parser.feed(response.get_data(as_text=True))
        self.assertEqual(parser.controls, [])

    def test_import_boundary_never_loads_operational_modules_or_probes(self):
        model = ast.parse(
            (ROOT / "cyberapp/feature_status.py").read_text(encoding="utf-8")
        )
        route = ast.parse(
            (ROOT / "cyberapp/routes/feature_status.py").read_text(encoding="utf-8")
        )
        imports = [
            node.module
            for tree in (model, route)
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        ]
        self.assertEqual(imports, ["dataclasses", "flask", "cyberapp.feature_status"])
        self.assertFalse(
            any(
                isinstance(node, ast.Import)
                for tree in (model, route)
                for node in ast.walk(tree)
            )
        )
        template = (ROOT / "templates/feature_status.html").read_text(encoding="utf-8")
        for operation in (
            "fetch(",
            "XMLHttpRequest",
            "<form",
            "<button",
            "onclick=",
            "<script",
        ):
            self.assertNotIn(operation, template)


if __name__ == "__main__":
    unittest.main()
