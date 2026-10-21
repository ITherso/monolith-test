"""Audit HTML security checks without importing the application or attack modules."""

import importlib.util
import sqlite3
import sys
import unittest
from contextlib import contextmanager
from html.parser import HTMLParser
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

from flask import Flask


class _TableParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.cells = []
        self.cell_tags = []
        self._in_cell = False

    def handle_starttag(self, tag, attrs):
        if self._in_cell:
            self.cell_tags.append(tag)
        if tag == "td":
            self._in_cell = True
            self.cells.append("")

    def handle_endtag(self, tag):
        if tag == "td":
            self._in_cell = False

    def handle_data(self, data):
        if self._in_cell:
            self.cells[-1] += data


class AuditSecurityTest(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.execute(
            "CREATE TABLE audit_logs (id INTEGER PRIMARY KEY, user_id TEXT, "
            "role TEXT, action TEXT, detail TEXT, ip TEXT, timestamp TEXT)"
        )

        @contextmanager
        def db_conn():
            yield self.db

        db_stub = ModuleType("cyberapp.models.db")
        db_stub.db_conn = db_conn
        path = Path(__file__).resolve().parents[1] / "cyberapp/routes/monitoring.py"
        spec = importlib.util.spec_from_file_location("audit_security_monitoring", path)
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {"cyberapp.models.db": db_stub}):
            spec.loader.exec_module(module)

        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY="audit-tests-only")
        app.register_blueprint(module.monitoring_bp)
        self.client = app.test_client()

    def _login(self, role="admin"):
        with self.client.session_transaction() as sess:
            sess["logged_in"] = True
            sess["role"] = role

    def _insert(self, values):
        self.db.execute(
            "INSERT INTO audit_logs (user_id, role, action, detail, ip, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            values,
        )
        self.db.commit()

    def test_every_database_column_is_rendered_as_text(self):
        values = (
            '<img src=x onerror="alert(1)">',
            "<script>alert(2)</script>",
            "</td><svg onload=alert(3)>",
            "<iframe srcdoc='<script>alert(4)</script>'></iframe>",
            "<a href='javascript:alert(5)'>address</a>",
            "<b>2026 & 'quoted' \"timestamp\"</b>",
        )
        self._insert(values)
        self._login()

        response = self.client.get("/audit")

        self.assertEqual(response.status_code, 200)
        parser = _TableParser()
        parser.feed(response.get_data(as_text=True))
        self.assertEqual(parser.cell_tags, [])
        self.assertEqual(parser.cells, [values[5], *values[:5]])
        for value in values:
            self.assertNotIn(value, response.get_data(as_text=True))

    def test_plain_text_order_and_empty_state_are_preserved(self):
        self._login()
        response = self.client.get("/audit")
        self.assertIn(b"No audit logs", response.data)

        first = ("first", "admin", "login", "A & B", "127.0.0.1", "earlier")
        second = ("second", "analyst", "logout", None, "::1", "later")
        self._insert(first)
        self._insert(second)

        response = self.client.get("/audit")

        parser = _TableParser()
        parser.feed(response.get_data(as_text=True))
        self.assertEqual(
            parser.cells,
            [
                "later",
                "second",
                "analyst",
                "logout",
                "None",
                "::1",
                "earlier",
                "first",
                "admin",
                "login",
                "A & B",
                "127.0.0.1",
            ],
        )

    def test_unauthenticated_request_still_requires_login(self):
        response = self.client.get("/audit")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")

    def test_analyst_still_cannot_view_audit_logs(self):
        self._login("analyst")
        response = self.client.get("/audit")
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
