import sqlite3
import unittest

from cyberapp.app import create_app
from cyberapp.migrations import run_migrations
from cyberapp.models.db import db_conn
from cyberapp import settings


class RoutesExtraTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        run_migrations()
        cls.app = create_app(run_migrations_on_start=False)
        cls.app.testing = True

    def setUp(self):
        self.client = self.app.test_client()

    def _login_admin(self):
        with self.client.session_transaction() as sess:
            sess["logged_in"] = True
            sess["user"] = settings.ADMIN_USER
            sess["role"] = "admin"

    def _login_analyst(self):
        with self.client.session_transaction() as sess:
            sess["logged_in"] = True
            sess["user"] = settings.ANALYST_USER
            sess["role"] = "analyst"

    def _insert_scan(self):
        with db_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO scans (target, status, user_id) VALUES (?, ?, ?)",
                ("http://example.com", "RUNNING", "tester"),
            )
            scan_id = cursor.lastrowid
            conn.execute(
                "INSERT INTO scan_progress (scan_id, progress, eta_seconds) VALUES (?, ?, ?)",
                (scan_id, 10, 100),
            )
            conn.commit()
        return scan_id

    def test_login_success(self):
        res = self.client.post(
            "/login",
            data={"user": settings.ADMIN_USER, "pass": settings.ADMIN_PASS},
            follow_redirects=False,
        )
        self.assertEqual(res.status_code, 302)

    def test_logout(self):
        self._login_admin()
        res = self.client.get("/logout")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/login", res.headers.get("Location", ""))

    def test_metrics_with_login(self):
        self._login_admin()
        res = self.client.get("/metrics")
        self.assertEqual(res.status_code, 200)

    def test_scan_status_with_login(self):
        self._login_admin()
        scan_id = self._insert_scan()
        res = self.client.get(f"/scan_status/{scan_id}")
        self.assertEqual(res.status_code, 200)

    def test_audit_requires_admin(self):
        self._login_analyst()
        res = self.client.get("/audit")
        self.assertEqual(res.status_code, 403)

    def test_opsec_dashboard(self):
        self._login_admin()
        res = self.client.get("/opsec")
        self.assertEqual(res.status_code, 200)

    def test_phishing_stats(self):
        self._login_admin()
        res = self.client.get("/phishing/stats/camp_demo")
        self.assertEqual(res.status_code, 200)
        self.assertIn("application/json", res.content_type)

    def test_exploit_search_api(self):
        self._login_admin()
        res = self.client.post("/api/exploit", json={"query": "test"})
        self.assertIn(res.status_code, (200, 503))


if __name__ == "__main__":
    unittest.main()
