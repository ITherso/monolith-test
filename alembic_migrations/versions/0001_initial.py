"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2025-12-29
"""

from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
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

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS vulns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            url TEXT,
            fix TEXT,
            severity TEXT DEFAULT 'MEDIUM',
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        )
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            data TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        )
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS techno (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            detected_via TEXT,
            confidence INTEGER DEFAULT 80,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        )
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS tool_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            tool_name TEXT NOT NULL,
            output TEXT,
            execution_time REAL,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        )
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS gamification (
            scan_id INTEGER PRIMARY KEY,
            user_id TEXT NOT NULL,
            score INTEGER DEFAULT 0,
            xp INTEGER DEFAULT 0,
            level INTEGER DEFAULT 1,
            achievements TEXT,
            badges TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        )
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS blockchain_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            tx_hash TEXT UNIQUE,
            evidence_hash TEXT,
            merkle_root TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            verified BOOLEAN DEFAULT FALSE,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        )
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS cloud_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            service TEXT,
            finding TEXT,
            severity TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        )
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS api_endpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            url TEXT,
            method TEXT,
            status INTEGER,
            parameters TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        )
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS phishing_campaigns (
            id TEXT PRIMARY KEY,
            name TEXT,
            targets TEXT,
            link TEXT,
            clicks INTEGER DEFAULT 0,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_progress (
            scan_id INTEGER PRIMARY KEY,
            progress INTEGER DEFAULT 0,
            eta_seconds INTEGER DEFAULT NULL,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        )
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            role TEXT,
            action TEXT,
            detail TEXT,
            ip TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    op.execute("CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_vulns_scan_id ON vulns(scan_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulns(severity)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_tool_logs_scan_id ON tool_logs(scan_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_blockchain_scan_id ON blockchain_evidence(scan_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_cloud_scan ON cloud_findings(scan_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_api_scan ON api_endpoints(scan_id)")


def downgrade():
    op.execute("DROP INDEX IF EXISTS idx_api_scan")
    op.execute("DROP INDEX IF EXISTS idx_cloud_scan")
    op.execute("DROP INDEX IF EXISTS idx_blockchain_scan_id")
    op.execute("DROP INDEX IF EXISTS idx_tool_logs_scan_id")
    op.execute("DROP INDEX IF EXISTS idx_vulns_severity")
    op.execute("DROP INDEX IF EXISTS idx_vulns_scan_id")
    op.execute("DROP INDEX IF EXISTS idx_scans_status")

    op.execute("DROP TABLE IF EXISTS audit_logs")
    op.execute("DROP TABLE IF EXISTS scan_progress")
    op.execute("DROP TABLE IF EXISTS phishing_campaigns")
    op.execute("DROP TABLE IF EXISTS api_endpoints")
    op.execute("DROP TABLE IF EXISTS cloud_findings")
    op.execute("DROP TABLE IF EXISTS blockchain_evidence")
    op.execute("DROP TABLE IF EXISTS gamification")
    op.execute("DROP TABLE IF EXISTS tool_logs")
    op.execute("DROP TABLE IF EXISTS techno")
    op.execute("DROP TABLE IF EXISTS intel")
    op.execute("DROP TABLE IF EXISTS vulns")
    op.execute("DROP TABLE IF EXISTS scans")
