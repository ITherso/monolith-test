from flask import Blueprint, jsonify, redirect, session

from cyberapp.models.db import db_conn

monitoring_bp = Blueprint("monitoring", __name__)


@monitoring_bp.route("/scan_status/<int:scan_id>")
def scan_status(scan_id):
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401

    with db_conn() as conn:
        scan = conn.execute(
            "SELECT status FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()
        progress = conn.execute(
            "SELECT progress, eta_seconds FROM scan_progress WHERE scan_id = ?",
            (scan_id,),
        ).fetchone()

    if not scan:
        return jsonify({"error": "not_found"}), 404

    progress_value = progress[0] if progress else 0
    eta_value = progress[1] if progress else None

    return jsonify(
        {
            "scan_id": scan_id,
            "status": scan[0],
            "progress": progress_value,
            "eta_seconds": eta_value,
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
        rows += (
            "<tr>"
            f"<td>{row[5]}</td>"
            f"<td>{row[0]}</td>"
            f"<td>{row[1]}</td>"
            f"<td>{row[2]}</td>"
            f"<td>{row[3]}</td>"
            f"<td>{row[4]}</td>"
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
