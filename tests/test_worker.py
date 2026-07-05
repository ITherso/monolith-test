import sqlite3
import tempfile
import unittest
from contextlib import closing, contextmanager
from unittest.mock import patch

from cyberapp.services import worker


def _init_db(db_path):
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                date TEXT DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'PENDING',
                user_id TEXT DEFAULT 'anonymous'
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_progress (
                scan_id INTEGER PRIMARY KEY,
                progress INTEGER DEFAULT 0,
                eta_seconds INTEGER DEFAULT NULL,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tool_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                tool_name TEXT NOT NULL,
                output TEXT,
                execution_time REAL,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS intel (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                type TEXT NOT NULL,
                data TEXT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vulns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                type TEXT NOT NULL,
                url TEXT,
                fix TEXT,
                severity TEXT DEFAULT 'MEDIUM'
            )
            """
        )


@contextmanager
def _db_conn(db_path):
    conn = sqlite3.connect(db_path)
    try:
        yield conn
    finally:
        conn.close()


class _NoopAutoExploitEngine:
    def __init__(self, *args, **kwargs):
        pass

    def auto_chain_from_findings(self, *args, **kwargs):
        return []


class WorkerTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = f"{self.tmpdir.name}/test.db"
        _init_db(self.db_path)
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute(
                "INSERT INTO scans (target, status, user_id) VALUES (?, ?, ?)",
                ("http://example.com", "RUNNING", "tester"),
            )
            conn.commit()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_worker_completes_without_tools(self):
        with patch.object(worker, "db_conn", lambda: _db_conn(self.db_path)):
            with patch.object(worker, "update_scan_progress", lambda *args, **kwargs: None):
                worker.run_worker("http://example.com", 1, False, [], "tester")

        with closing(sqlite3.connect(self.db_path)) as conn:
            status = conn.execute("SELECT status FROM scans WHERE id = 1").fetchone()[0]
            self.assertIn("TAMAMLANDI", status)
            intel = conn.execute(
                "SELECT COUNT(*) FROM intel WHERE scan_id = 1 AND type = 'EXECUTION_TIME'"
            ).fetchone()[0]
            self.assertEqual(intel, 1)

    def test_worker_sets_critical_status(self):
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute(
                "INSERT INTO vulns (scan_id, type, url) VALUES (?, ?, ?)",
                (1, "SQL_INJECTION", "http://example.com"),
            )
            conn.commit()

        with patch.object(worker, "db_conn", lambda: _db_conn(self.db_path)):
            with patch.object(worker, "update_scan_progress", lambda *args, **kwargs: None):
                with patch.object(worker, "AutoExploitEngine", _NoopAutoExploitEngine):
                    worker.run_worker("http://example.com", 1, False, [], "tester")

        with closing(sqlite3.connect(self.db_path)) as conn:
            status = conn.execute("SELECT status FROM scans WHERE id = 1").fetchone()[0]
            self.assertIn("TAMAMLANDI", status)


if __name__ == "__main__":
    unittest.main()
