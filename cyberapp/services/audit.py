from cyberapp.models.db import db_conn
from cyberapp.services.logger import get_logger

logger = get_logger("monolith.audit")


def log_audit(user_id, role, action, detail, ip):
    try:
        with db_conn() as conn:
            conn.execute(
                """
                INSERT INTO audit_logs (user_id, role, action, detail, ip)
                VALUES (?, ?, ?, ?, ?)
                """,
                (user_id, role, action, detail, ip),
            )
            conn.commit()
    except Exception:
        logger.exception("Failed to write audit log")
