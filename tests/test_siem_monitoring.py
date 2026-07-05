import unittest

from cyberapp.app import create_app
from cyberapp.migrations import run_migrations


class SIEMMonitoringRoutesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            run_migrations()
        except Exception:
            # Some workspaces may have multiple alembic heads; route tests don't
            # require migrations.
            pass
        cls.app = create_app(run_migrations_on_start=False)
        cls.app.testing = True

    def setUp(self):
        self.client = self.app.test_client()

    def test_siem_status_get_ok(self):
        res = self.client.get("/api/elite/siem-monitor/status")
        self.assertEqual(res.status_code, 200)
        body = res.get_json() or {}
        self.assertEqual(body.get("status"), "ok")
        self.assertIn("report", body)
        self.assertIn("platform", body["report"])

    def test_siem_status_post_with_destinations_ok(self):
        res = self.client.post(
            "/api/elite/siem-monitor/status",
            json={
                "destinations": [
                    {"host": "127.0.0.1", "port": 1, "proto": "tcp"},
                ],
                "recent_change_window_sec": 60,
            },
        )
        self.assertEqual(res.status_code, 200)
        body = res.get_json() or {}
        self.assertEqual(body.get("status"), "ok")
        report = body.get("report") or {}
        self.assertIsInstance(report.get("destinations"), list)

    def test_emit_test_signal(self):
        res = self.client.post("/api/elite/siem-monitor/emit-test", json={"marker": "unit-test"})
        self.assertEqual(res.status_code, 200)
        body = res.get_json() or {}
        self.assertEqual(body.get("status"), "emitted")


if __name__ == "__main__":
    unittest.main()
