import math

from flask import Blueprint, jsonify, redirect, session
from markupsafe import escape

from cyberapp.models.db import db_conn

monitoring_bp = Blueprint("monitoring", __name__)


def _status_response(payload, status=200):
    response = jsonify(payload)
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"
    return response


def _finite_number(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


@monitoring_bp.route("/scan_status/<int:scan_id>")
@monitoring_bp.route("/api/management/scans/<int:scan_id>/status")
def scan_status(scan_id):
    """Read one recorded scan; never start a scan or contact its target."""
    if session.get("logged_in") is not True:
        return _status_response({"error": "login_required"}, 401)
    if (
        isinstance(scan_id, bool)
        or not isinstance(scan_id, int)
        or not 0 < scan_id <= 2**63 - 1
    ):
        return _status_response({"error": "invalid_scan_id"}, 400)

    try:
        with db_conn() as conn:
            scan = conn.execute(
                "SELECT status, target FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
            if not scan:
                return _status_response({"error": "not_found"}, 404)
            progress = conn.execute(
                "SELECT progress, eta_seconds FROM scan_progress WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
            vuln_count = conn.execute(
                "SELECT COUNT(*) FROM vulns WHERE scan_id = ?", (scan_id,)
            ).fetchone()[0]
    except Exception:
        return _status_response({"error": "scan_status_unavailable"}, 503)

    percent = progress[0] if progress else None
    eta = progress[1] if progress else None
    progress_available = _finite_number(percent)
    eta_available = _finite_number(eta) and eta >= 0
    status = scan[0] if isinstance(scan[0], str) and scan[0].strip() else "UNKNOWN"
    target = scan[1] if isinstance(scan[1], str) else ""
    return _status_response(
        {
            "scan_id": scan_id,
            "status": status[:256],
            "target": target[:2048],
            "progress": min(100, max(0, percent)) if progress_available else 0,
            "progress_available": progress_available,
            "eta_seconds": eta if eta_available else None,
            "eta_available": eta_available,
            "vuln_count": vuln_count,
        }
    )


@monitoring_bp.route("/audit")
def audit_dashboard():
    if not session.get("logged_in"):
        return redirect("/login")
    if session.get("role") != "admin":
        return "Forbidden", 403

    with db_conn() as conn:
        logs = conn.execute(
            "SELECT user_id, role, action, detail, ip, timestamp FROM audit_logs ORDER BY id DESC LIMIT 200"
        ).fetchall()

    rows = ""
    for row in logs:
        cells = [escape(value) for value in row]
        rows += (
            "<tr>"
            f"<td>{cells[5]}</td>"
            f"<td>{cells[0]}</td>"
            f"<td>{cells[1]}</td>"
            f"<td>{cells[2]}</td>"
            f"<td>{cells[3]}</td>"
            f"<td>{cells[4]}</td>"
            "</tr>"
        )

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Audit Log</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {{ background: #0f0f23; color: #fff; }}
            .card {{ background: rgba(30, 30, 46, 0.9); border: 1px solid #00ff00; }}
            table {{ color: #fff; }}
        </style>
    </head>
    <body>
        <div class="container mt-4">
            <h2 class="text-success mb-3">Audit Log</h2>
            <div class="card p-3">
                <div class="table-responsive">
                    <table class="table table-dark table-hover">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>User</th>
                                <th>Role</th>
                                <th>Action</th>
                                <th>Detail</th>
                                <th>IP</th>
                            </tr>
                        </thead>
                        <tbody>
                            {rows if rows else '<tr><td colspan="6" class="text-center text-muted">No audit logs</td></tr>'}
                        </tbody>
                    </table>
                </div>
            </div>
            <a href="/" class="btn btn-outline-light mt-3">Back to Dashboard</a>
        </div>
    </body>
    </html>
    """


@monitoring_bp.route("/metrics")
def metrics():
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401

    with db_conn() as conn:
        scan_total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        vuln_total = conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0]
        running = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE status LIKE '%RUNNING%' OR status LIKE '%HAZIRLANIYOR%'"
        ).fetchone()[0]

    return jsonify(
        {
            "scans_total": scan_total,
            "vulns_total": vuln_total,
            "running_scans": running,
        }
    )
