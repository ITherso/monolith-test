"""Safe management-only Flask factory.

This factory loads authenticated record review and offline analysis features. It
does not import the operational application factory or any attack module.
"""

from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify

from cyberapp.authorization import install_admin_access_control
from cyberapp.migrations import run_migrations
from cyberapp.models.db import db_conn
from cyberapp.settings import DB_NAME, SECRET_KEY

SCHEMA_HEAD = "0007_ai_vulnerability_reports"
REQUIRED_SCHEMA = {
    "scans": frozenset({"id", "target", "date", "status", "user_id"}),
    "vulns": frozenset({"id", "scan_id", "type", "url", "fix", "severity"}),
    "scan_progress": frozenset({"scan_id", "progress", "eta_seconds"}),
    "audit_logs": frozenset(
        {"id", "user_id", "role", "action", "detail", "ip", "timestamp"}
    ),
    "techno": frozenset({"id", "scan_id", "name", "detected_via", "confidence"}),
    "intel": frozenset({"id", "scan_id", "type", "data", "timestamp"}),
    "tool_logs": frozenset({"id", "scan_id", "tool_name", "output", "timestamp"}),
    "ai_vulnerability_reports": frozenset({"scan_id", "report_json", "updated_at"}),
}


def _database_file(value):
    if not isinstance(value, (str, Path)):
        raise TypeError("DATABASE must be a filesystem path")
    if str(value) == ":memory:":
        raise ValueError("management mode requires a persistent SQLite file")
    return str(Path(value).expanduser().resolve())


def create_management_app(run_migrations_on_start=True, config=None):
    root = Path(__file__).resolve().parents[1]
    app = Flask(__name__, template_folder=str(root / "templates"))
    app.config.update(
        SECRET_KEY=SECRET_KEY,
        DATABASE=DB_NAME,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=False,
        MAX_CONTENT_LENGTH=1_572_864,
        MANAGEMENT_MODE=True,
        PRODUCTION_READY=False,
    )
    if config:
        app.config.update(config)
    app.config["DATABASE"] = _database_file(app.config["DATABASE"])

    install_admin_access_control(app)

    from cyberapp.management_routes import (
        ai_vulnerability_bp,
        auth_bp,
        feature_status_bp,
        management_bp,
        monitoring_bp,
    )

    for blueprint in (
        auth_bp,
        management_bp,
        monitoring_bp,
        feature_status_bp,
        ai_vulnerability_bp,
    ):
        app.register_blueprint(blueprint)

    from cyberapp.services.errors import register_error_handlers

    register_error_handlers(app)

    @app.after_request
    def management_headers(response):
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; connect-src 'self'; "
            "img-src 'self' data:; object-src 'none'; base-uri 'self'; "
            "frame-ancestors 'none'; form-action 'self'"
        )
        return response

    @app.route("/health", methods=["GET"])
    @app.route("/api/management/health", methods=["GET"])
    def management_health():
        database_ready = True
        try:
            with db_conn() as conn:
                tables = {
                    row[0]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    ).fetchall()
                }
                revision = conn.execute(
                    "SELECT version_num FROM alembic_version"
                ).fetchone()
                schema_ready = set(REQUIRED_SCHEMA) <= tables and all(
                    required
                    <= {
                        row[1]
                        for row in conn.execute(
                            f"PRAGMA table_info({table})"
                        ).fetchall()
                    }
                    for table, required in REQUIRED_SCHEMA.items()
                )
                database_ready = schema_ready and revision == (SCHEMA_HEAD,)
        except Exception:
            database_ready = False
        status = "OPERATIONAL" if database_ready else "DEGRADED"
        return (
            jsonify(
                {
                    "status": status,
                    "mode": "management",
                    "database_ready": database_ready,
                    "operational_modules_loaded_by_management_factory": False,
                    "production_ready": False,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            200 if database_ready else 503,
        )

    if run_migrations_on_start:
        run_migrations(app.config["DATABASE"])

    app.extensions["management_mode"] = {
        "operational_modules_loaded_by_management_factory": False,
        "registered_blueprints": tuple(app.blueprints),
    }
    return app
