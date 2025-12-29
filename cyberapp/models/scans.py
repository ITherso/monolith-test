from cyberapp.models.db import db_conn


def list_recent_scans(limit=20):
    with db_conn() as conn:
        return conn.execute(
            """
            SELECT scans.id, scans.target, scans.date, scans.status, scans.user_id,
                   scan_progress.progress, scan_progress.eta_seconds
            FROM scans
            LEFT JOIN scan_progress ON scans.id = scan_progress.scan_id
            ORDER BY scans.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
