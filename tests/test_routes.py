import unittest

from cyberapp.app import create_app
from cyberapp.migrations import run_migrations


class RoutesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        run_migrations()
        cls.app = create_app(run_migrations_on_start=False)
        cls.app.testing = True

    def setUp(self):
        self.client = self.app.test_client()

    def _login(self):
        with self.client.session_transaction() as sess:
            sess["logged_in"] = True
            sess["user"] = "test-user"
            sess["role"] = "admin"

    def test_login_page(self):
        res = self.client.get("/login")
        self.assertEqual(res.status_code, 200)

    def test_dashboard_requires_login(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/login", res.headers.get("Location", ""))

    def test_dashboard_ok(self):
        self._login()
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)

    def test_scan_status_requires_login(self):
        res = self.client.get("/scan_status/1")
        self.assertEqual(res.status_code, 401)

    def test_metrics_requires_login(self):
        res = self.client.get("/metrics")
        self.assertEqual(res.status_code, 401)

    def test_phishing_advanced_ok(self):
        self._login()
        res = self.client.get("/phishing/advanced")
        self.assertEqual(res.status_code, 200)

    def test_payloads_ok(self):
        self._login()
        res = self.client.get("/payloads")
        self.assertEqual(res.status_code, 200)


if __name__ == "__main__":
    unittest.main()
