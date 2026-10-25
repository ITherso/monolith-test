"""Bounded read-only views of records already stored by Monolith."""

import math

from cyberapp.models.db import db_conn

MAX_RECENT_SCANS = 50
MAX_DETAIL_ROWS = 100
MAX_AUDIT_ROWS = 200


def _bounded_text(value, limit, default=""):
    if value is None:
        return default
    return str(value)[:limit]


def _finite_number(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _positive_limit(value, maximum):
    if type(value) is not int or not 0 < value <= maximum:
        raise ValueError("invalid limit")
    return value


def _scan_id(value):
    if type(value) is not int or not 0 < value <= 2**63 - 1:
        raise ValueError("invalid scan id")
    return value


def load_management_summary(limit=20):
    """Return aggregate and recent-record data without contacting any target."""
    limit = _positive_limit(limit, MAX_RECENT_SCANS)
    with db_conn() as conn:
        scan_total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        vuln_total = conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0]
        running = conn.execute(
            """
            SELECT COUNT(*)
            FROM scans
            WHERE UPPER(TRIM(COALESCE(status, ''))) LIKE 'RUNNING%'
               OR UPPER(TRIM(COALESCE(status, ''))) LIKE 'HAZIRLANIYOR%'
               OR UPPER(TRIM(COALESCE(status, ''))) LIKE 'DEVAM%'
            """
        ).fetchone()[0]
        rows = conn.execute(
            """
            SELECT scans.id,
                   CASE WHEN typeof(scans.target) = 'text'
                        THEN substr(scans.target, 1, 2048) ELSE '' END,
                   CASE WHEN typeof(scans.date) = 'text'
                        THEN substr(scans.date, 1, 128) ELSE '' END,
                   CASE WHEN typeof(scans.status) = 'text' AND TRIM(scans.status) <> ''
                        THEN substr(scans.status, 1, 256) ELSE 'UNKNOWN' END,
                   CASE WHEN typeof(scans.user_id) = 'text'
                        THEN substr(scans.user_id, 1, 128) ELSE '' END,
                   CASE WHEN typeof(scan_progress.progress) IN ('integer', 'real')
                        THEN scan_progress.progress END,
                   CASE WHEN typeof(scan_progress.eta_seconds) IN ('integer', 'real')
                        THEN scan_progress.eta_seconds END,
                   (SELECT COUNT(*) FROM vulns WHERE vulns.scan_id = scans.id)
            FROM scans
            LEFT JOIN scan_progress ON scan_progress.scan_id = scans.id
            ORDER BY scans.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    scans = []
    for row in rows:
        progress = row[5] if _finite_number(row[5]) else None
        eta = row[6] if _finite_number(row[6]) and row[6] >= 0 else None
        scans.append(
            {
                "id": int(row[0]),
                "target": _bounded_text(row[1], 2048),
                "date": _bounded_text(row[2], 128),
                "status": _bounded_text(row[3], 256, "UNKNOWN") or "UNKNOWN",
                "user": _bounded_text(row[4], 128),
                "progress": min(100, max(0, progress))
                if progress is not None
                else None,
                "eta_seconds": eta,
                "vulnerability_count": max(0, int(row[7])),
            }
        )
    return {
        "read_only": True,
        "target_contacted": False,
        "totals": {
            "scans": int(scan_total),
            "vulnerabilities": int(vuln_total),
            "running": int(running),
        },
        "scans": scans,
    }


def load_scan_status(scan_id):
    """Return the small status contract used by the dashboard poller."""
    scan_id = _scan_id(scan_id)
    with db_conn() as conn:
        scan = conn.execute(
            """
            SELECT CASE WHEN typeof(status) = 'text' AND TRIM(status) <> ''
                        THEN substr(status, 1, 256) ELSE 'UNKNOWN' END,
                   CASE WHEN typeof(target) = 'text'
                        THEN substr(target, 1, 2048) ELSE '' END
            FROM scans WHERE id = ?
            """,
            (scan_id,),
        ).fetchone()
        if scan is None:
            return None
        progress = conn.execute(
            """
            SELECT CASE WHEN typeof(progress) IN ('integer', 'real') THEN progress END,
                   CASE WHEN typeof(eta_seconds) IN ('integer', 'real') THEN eta_seconds END
            FROM scan_progress WHERE scan_id = ?
            """,
            (scan_id,),
        ).fetchone()
        vulnerability_count = conn.execute(
            "SELECT COUNT(*) FROM vulns WHERE scan_id = ?", (scan_id,)
        ).fetchone()[0]
    percent = progress[0] if progress and _finite_number(progress[0]) else None
    eta = (
        progress[1]
        if progress and _finite_number(progress[1]) and progress[1] >= 0
        else None
    )
    return {
        "scan_id": scan_id,
        "status": _bounded_text(scan[0], 256, "UNKNOWN") or "UNKNOWN",
        "target": _bounded_text(scan[1], 2048),
        "progress": min(100, max(0, percent)) if percent is not None else 0,
        "progress_available": percent is not None,
        "eta_seconds": eta,
        "eta_available": eta is not None,
        "vuln_count": max(0, int(vulnerability_count)),
    }


def load_audit_page(limit=100, before_id=None):
    """Return one bounded newest-first audit page with an opaque numeric cursor."""
    limit = _positive_limit(limit, MAX_AUDIT_ROWS)
    if before_id is not None:
        before_id = _scan_id(before_id)
    where = "WHERE id < ?" if before_id is not None else ""
    parameters = (before_id, limit + 1) if before_id is not None else (limit + 1,)
    with db_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT id,
                   CASE WHEN typeof(user_id) = 'text'
                        THEN substr(user_id, 1, 128) ELSE '' END,
                   CASE WHEN typeof(role) = 'text'
                        THEN substr(role, 1, 64) ELSE '' END,
                   CASE WHEN typeof(action) = 'text'
                        THEN substr(action, 1, 128) ELSE '' END,
                   CASE WHEN typeof(detail) = 'text'
                        THEN substr(detail, 1, 2048) ELSE '' END,
                   CASE WHEN typeof(ip) = 'text'
                        THEN substr(ip, 1, 128) ELSE '' END,
                   CASE WHEN typeof(timestamp) = 'text'
                        THEN substr(timestamp, 1, 128) ELSE '' END
            FROM audit_logs {where} ORDER BY id DESC LIMIT ?
            """,
            parameters,
        ).fetchall()
    has_more = len(rows) > limit
    rows = rows[:limit]
    records = [
        {
            "id": int(row[0]),
            "user": _bounded_text(row[1], 128),
            "role": _bounded_text(row[2], 64),
            "action": _bounded_text(row[3], 128),
            "detail": _bounded_text(row[4], 2048),
            "ip": _bounded_text(row[5], 128),
            "timestamp": _bounded_text(row[6], 128),
        }
        for row in rows
    ]
    return {
        "records": records,
        "limit": limit,
        "has_more": has_more,
        "next_before_id": records[-1]["id"] if has_more and records else None,
    }


def load_audit_records(limit=MAX_AUDIT_ROWS):
    """Compatibility helper returning the first bounded audit page."""
    return load_audit_page(limit=limit)["records"]


def load_scan_record(scan_id, limit=MAX_DETAIL_ROWS):
    """Return one bounded stored record, or ``None`` when it does not exist."""
    scan_id = _scan_id(scan_id)
    limit = _positive_limit(limit, MAX_DETAIL_ROWS)
    with db_conn() as conn:
        scan = conn.execute(
            """
            SELECT id,
                   CASE WHEN typeof(target) = 'text'
                        THEN substr(target, 1, 2048) ELSE '' END,
                   CASE WHEN typeof(date) = 'text'
                        THEN substr(date, 1, 128) ELSE '' END,
                   CASE WHEN typeof(status) = 'text' AND TRIM(status) <> ''
                        THEN substr(status, 1, 256) ELSE 'UNKNOWN' END,
                   CASE WHEN typeof(user_id) = 'text'
                        THEN substr(user_id, 1, 128) ELSE '' END
            FROM scans WHERE id = ?
            """,
            (scan_id,),
        ).fetchone()
        if scan is None:
            return None
        progress = conn.execute(
            """
            SELECT CASE WHEN typeof(progress) IN ('integer', 'real') THEN progress END,
                   CASE WHEN typeof(eta_seconds) IN ('integer', 'real') THEN eta_seconds END
            FROM scan_progress WHERE scan_id = ?
            """,
            (scan_id,),
        ).fetchone()
        totals = conn.execute(
            """
            SELECT (SELECT COUNT(*) FROM vulns WHERE scan_id = ?),
                   (SELECT COUNT(*) FROM techno WHERE scan_id = ?),
                   (SELECT COUNT(*) FROM intel WHERE scan_id = ?),
                   (SELECT COUNT(*) FROM tool_logs WHERE scan_id = ?)
            """,
            (scan_id, scan_id, scan_id, scan_id),
        ).fetchone()
        vulnerabilities = conn.execute(
            """
            SELECT CASE WHEN typeof(type) = 'text'
                        THEN substr(type, 1, 256) ELSE 'UNKNOWN' END,
                   CASE WHEN typeof(url) = 'text'
                        THEN substr(url, 1, 2048) ELSE '' END,
                   CASE WHEN typeof(fix) = 'text'
                        THEN substr(fix, 1, 4096) ELSE '' END,
                   CASE WHEN typeof(severity) = 'text'
                        THEN substr(severity, 1, 32) ELSE 'MEDIUM' END
            FROM vulns WHERE scan_id = ? ORDER BY id DESC LIMIT ?
            """,
            (scan_id, limit),
        ).fetchall()
        technologies = conn.execute(
            """
            SELECT CASE WHEN typeof(name) = 'text'
                        THEN substr(name, 1, 256) ELSE 'UNKNOWN' END,
                   CASE WHEN typeof(detected_via) = 'text'
                        THEN substr(detected_via, 1, 512) ELSE '' END,
                   CASE WHEN typeof(confidence) IN ('integer', 'real')
                        THEN confidence END
            FROM techno WHERE scan_id = ? ORDER BY id DESC LIMIT ?
            """,
            (scan_id, limit),
        ).fetchall()
        intel = conn.execute(
            """
            SELECT CASE WHEN typeof(type) = 'text'
                        THEN substr(type, 1, 128) ELSE 'INFO' END,
                   CASE WHEN typeof(data) = 'text'
                        THEN substr(data, 1, 4096) ELSE '' END,
                   CASE WHEN typeof(timestamp) = 'text'
                        THEN substr(timestamp, 1, 128) ELSE '' END
            FROM intel WHERE scan_id = ? ORDER BY id DESC LIMIT ?
            """,
            (scan_id, limit),
        ).fetchall()
        logs = conn.execute(
            """
            SELECT CASE WHEN typeof(tool_name) = 'text'
                        THEN substr(tool_name, 1, 128) ELSE 'LOG' END,
                   CASE WHEN typeof(output) = 'text'
                        THEN substr(output, 1, 4096) ELSE '' END,
                   CASE WHEN typeof(timestamp) = 'text'
                        THEN substr(timestamp, 1, 128) ELSE '' END
            FROM tool_logs WHERE scan_id = ? ORDER BY id DESC LIMIT ?
            """,
            (scan_id, limit),
        ).fetchall()

    progress_value = progress[0] if progress and _finite_number(progress[0]) else None
    eta_value = (
        progress[1]
        if progress and _finite_number(progress[1]) and progress[1] >= 0
        else None
    )
    vulnerability_records = [
        {
            "type": _bounded_text(row[0], 256, "UNKNOWN"),
            "url": _bounded_text(row[1], 2048),
            "fix": _bounded_text(row[2], 4096),
            "severity": _bounded_text(row[3], 32, "MEDIUM"),
        }
        for row in vulnerabilities
    ]
    technology_records = [
        {
            "name": _bounded_text(row[0], 256, "UNKNOWN"),
            "detected_via": _bounded_text(row[1], 512),
            "confidence": row[2] if _finite_number(row[2]) else None,
        }
        for row in technologies
    ]
    intel_records = [
        {
            "type": _bounded_text(row[0], 128, "INFO"),
            "data": _bounded_text(row[1], 4096),
            "timestamp": _bounded_text(row[2], 128),
        }
        for row in intel
    ]
    log_records = [
        {
            "tool": _bounded_text(row[0], 128, "LOG"),
            "output": _bounded_text(row[1], 4096),
            "timestamp": _bounded_text(row[2], 128),
        }
        for row in logs
    ]
    collections = {
        "vulnerabilities": vulnerability_records,
        "technologies": technology_records,
        "intel": intel_records,
        "logs": log_records,
    }
    collection_meta = {}
    for (name, records), total in zip(collections.items(), totals, strict=True):
        total = max(0, int(total))
        collection_meta[name] = {
            "returned": len(records),
            "total": total,
            "truncated": total > len(records),
        }
    return {
        "read_only": True,
        "target_contacted": False,
        "scan": {
            "id": int(scan[0]),
            "target": _bounded_text(scan[1], 2048),
            "date": _bounded_text(scan[2], 128),
            "status": _bounded_text(scan[3], 256, "UNKNOWN") or "UNKNOWN",
            "user": _bounded_text(scan[4], 128),
            "progress": min(100, max(0, progress_value))
            if progress_value is not None
            else None,
            "eta_seconds": eta_value,
        },
        **collections,
        "collection_meta": collection_meta,
    }
