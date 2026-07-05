import datetime
import unittest

from cyberapp.app import create_app
from cyberapp.migrations import run_migrations
from cyberapp.models.db import db_conn


class DBFlowsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        run_migrations()
        cls.app = create_app(run_migrations_on_start=False)
        cls.app.testing = True

    def setUp(self):
        self.client = self.app.test_client()
        with self.client.session_transaction() as sess:
            sess["logged_in"] = True
            sess["user"] = "test-user"
            sess["role"] = "admin"

    def _create_scan(self, status="COMPLETED"):
        with db_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO scans (target, date, status, user_id)
                VALUES (?, ?, ?, ?)
                """,
                ("http://example.com", datetime.datetime.now().isoformat(), status, "test-user"),
            )
            scan_id = cursor.lastrowid
            conn.execute(
                "INSERT INTO scan_progress (scan_id, progress, eta_seconds) VALUES (?, ?, ?)",
                (scan_id, 100, 0),
            )
            conn.execute(
                "INSERT INTO vulns (scan_id, type, url, fix, severity) VALUES (?, ?, ?, ?, ?)",
                (scan_id, "RCE", "http://example.com", "Patch", "HIGH"),
            )
            conn.execute(
                "INSERT INTO techno (scan_id, name, detected_via) VALUES (?, ?, ?)",
                (scan_id, "nginx", "headers"),
            )
            conn.execute(
                "INSERT INTO intel (scan_id, type, data) VALUES (?, ?, ?)",
                (scan_id, "TEST", "intel"),
            )
            conn.commit()
        return scan_id

    def test_details_page(self):
        scan_id = self._create_scan()
        res = self.client.get(f"/details/{scan_id}")
        self.assertEqual(res.status_code, 200)

    def test_autoexploit_endpoint(self):
        scan_id = self._create_scan(status="TAMAMLANDI ✅")
        res = self.client.get(f"/autoexploit/{scan_id}")
        self.assertEqual(res.status_code, 200)
        self.assertIn("application/json", res.content_type)


if __name__ == "__main__":
    unittest.main()
