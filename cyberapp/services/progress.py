import datetime

from cyberapp.models.db import db_conn
from cyberapp.services.logger import get_logger

logger = get_logger("monolith.progress")


def update_scan_progress(scan_id, progress, eta_seconds):
    try:
        with db_conn() as conn:
            conn.execute(
                """
                INSERT INTO scan_progress (scan_id, progress, eta_seconds, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    progress=excluded.progress,
                    eta_seconds=excluded.eta_seconds,
                    updated_at=excluded.updated_at
                """,
                (scan_id, progress, eta_seconds, datetime.datetime.now().isoformat()),
            )
            conn.commit()
    except Exception:
        logger.exception("Failed to update scan progress")
