from cyberapp.models.db import db_conn
from cyberapp.services.logger import get_logger

logger = get_logger("monolith.audit")


def _bounded_text(value, limit):
    if value is None:
        return ""
    return str(value)[:limit]


def log_audit(user_id, role, action, detail, ip):
    try:
        with db_conn() as conn:
            conn.execute(
                """
                INSERT INTO audit_logs (user_id, role, action, detail, ip)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    _bounded_text(user_id, 128),
                    _bounded_text(role, 64),
                    _bounded_text(action, 128),
                    _bounded_text(detail, 2048),
                    _bounded_text(ip, 128),
                ),
            )
            conn.commit()
    except Exception:
        logger.exception("Failed to write audit log")
