"""Authenticated routes for the management-only application.

The module deliberately lives outside ``cyberapp.routes``. That package remains
blocked on Windows because it contains the operational route collection.
"""

import datetime
import json
import secrets

from flask import (
    Blueprint,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from cyberapp.feature_status import feature_status_snapshot
from cyberapp.management_data import (
    load_audit_records,
    load_management_summary,
    load_scan_record,
    load_scan_status,
)
from cyberapp.services.audit import log_audit as audit_log
from cyberapp.settings import ADMIN_PASS, ADMIN_USER, ANALYST_PASS, ANALYST_USER
from cyberapp.vulnerability_analysis import analyze_vulnerability_observations
from cyberapp.vulnerability_service import review_saved_scan
from cyberapp.vulnerability_store import (
    get_vulnerability_report,
    save_vulnerability_report,
)

auth_bp = Blueprint("auth", __name__)
management_bp = Blueprint("management", __name__)
monitoring_bp = Blueprint("monitoring", __name__)
feature_status_bp = Blueprint("feature_status", __name__)
ai_vulnerability_bp = Blueprint("ai_vulnerability", __name__)
MAX_REQUEST_BYTES = 1_572_864


def _json(payload, status=200):
    response = jsonify(payload)
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"
    return response


def _logged_in():
    return session.get("logged_in") is True and bool(session.get("user"))


def _admin():
    return _logged_in() and session.get("role") == "admin"


def _no_cache(response):
    response.headers["Cache-Control"] = "no-store"
    return response


for blueprint in (
    auth_bp,
    management_bp,
    monitoring_bp,
    feature_status_bp,
    ai_vulnerability_bp,
):
    blueprint.after_request(_no_cache)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("user", "")
        password = request.form.get("pass", "")
        role = None
        if username == ADMIN_USER and secrets.compare_digest(
            password.encode(), ADMIN_PASS.encode()
        ):
            role = "admin"
        elif username == ANALYST_USER and secrets.compare_digest(
            password.encode(), ANALYST_PASS.encode()
        ):
            role = "analyst"
        session.clear()
        if role:
            session.update(
                logged_in=True,
                user=username,
                role=role,
                start_time=datetime.datetime.now().isoformat(),
            )
            audit_log(
                username,
                role,
                "login_success",
                f"user={username}",
                request.remote_addr,
            )
            return redirect(url_for("management.dashboard"))
        audit_log(
            username,
            "unknown",
            "login_failed",
            f"user={username}",
            request.remote_addr,
        )
    return render_template("login.html", base_template="management_base.html")


@auth_bp.route("/logout", methods=["GET"])
def logout():
    audit_log(
        session.get("user"),
        session.get("role"),
        "logout",
        "user_logout",
        request.remote_addr,
    )
    session.clear()
    return redirect(url_for("auth.login"))


@management_bp.route("/", methods=["GET"])
@management_bp.route("/dashboard", methods=["GET"])
def dashboard():
    if not _logged_in():
        return redirect(url_for("auth.login"))
    available = True
    try:
        summary = load_management_summary()
    except Exception:
        available = False
        summary = {
            "read_only": True,
            "target_contacted": False,
            "totals": {"scans": 0, "vulnerabilities": 0, "running": 0},
            "scans": [],
        }
    page = render_template(
        "management_dashboard.html",
        title="MONOLITH yönetim modu",
        summary=summary,
        records_available=available,
        role=session.get("role"),
        user=session.get("user"),
    )
    return page if available else (page, 503)


@management_bp.route("/management/scans/<int:scan_id>", methods=["GET"])
def scan_record(scan_id):
    if not _logged_in():
        return redirect(url_for("auth.login"))
    try:
        record = load_scan_record(scan_id)
    except (TypeError, ValueError):
        return "Geçersiz tarama kimliği", 400
    except Exception:
        return "Tarama kaydı şu anda okunamıyor", 503
    if record is None:
        return "Tarama kaydı bulunamadı", 404
    return render_template(
        "management_scan_detail.html",
        title=f"Tarama kaydı #{scan_id}",
        record=record,
    )


@management_bp.route("/api/management/summary", methods=["GET"])
def summary_api():
    if not _logged_in():
        return _json({"error": "login_required"}, 401)
    try:
        return _json(load_management_summary())
    except Exception:
        return _json({"error": "management_records_unavailable"}, 503)


@management_bp.route("/api/management/scans/<int:scan_id>/record", methods=["GET"])
def scan_record_api(scan_id):
    if not _logged_in():
        return _json({"error": "login_required"}, 401)
    try:
        record = load_scan_record(scan_id)
    except (TypeError, ValueError):
        return _json({"error": "invalid_scan_id"}, 400)
    except Exception:
        return _json({"error": "scan_record_unavailable"}, 503)
    if record is None:
        return _json({"error": "not_found"}, 404)
    return _json(record)


@monitoring_bp.route("/api/management/scans/<int:scan_id>/status", methods=["GET"])
def scan_status(scan_id):
    if not _logged_in():
        return _json({"error": "login_required"}, 401)
    try:
        status = load_scan_status(scan_id)
    except (TypeError, ValueError):
        return _json({"error": "invalid_scan_id"}, 400)
    except Exception:
        return _json({"error": "scan_status_unavailable"}, 503)
    if status is None:
        return _json({"error": "not_found"}, 404)
    return _json(status)


@monitoring_bp.route("/metrics", methods=["GET"])
def metrics():
    if not _logged_in():
        return _json({"error": "login_required"}, 401)
    try:
        totals = load_management_summary(limit=1)["totals"]
    except Exception:
        return _json({"error": "metrics_unavailable"}, 503)
    return _json(
        {
            "scans_total": totals["scans"],
            "vulns_total": totals["vulnerabilities"],
            "running_scans": totals["running"],
        }
    )


@monitoring_bp.route("/audit", methods=["GET"])
def audit_dashboard():
    if not _admin():
        return _json({"error": "admin_required"}, 403)
    try:
        records = load_audit_records()
    except Exception:
        return "Audit kayıtları şu anda okunamıyor", 503
    return render_template("management_audit.html", records=records)


@feature_status_bp.route("/feature-status", methods=["GET"])
def feature_status_page():
    if not _logged_in():
        return redirect(url_for("auth.login"))
    return render_template(
        "feature_status.html",
        title="Özellik durumu — MONOLITH",
        snapshot=feature_status_snapshot(),
        base_template="management_base.html",
    )


@feature_status_bp.route("/api/feature-status", methods=["GET"])
def feature_status_api():
    if not _logged_in():
        return _json({"error": "login_required"}, 401)
    return _json(feature_status_snapshot())


@ai_vulnerability_bp.route("/ai-vulnerability", methods=["GET"])
def analysis_page():
    if not _admin():
        return _json({"error": "admin_required"}, 403)
    return render_template(
        "ai_vulnerability.html",
        title="Kural tabanlı açık tahmini",
        base_template="management_base.html",
    )


@ai_vulnerability_bp.route("/api/ai-vulnerability/analyze", methods=["POST"])
def analyze_supplied_data():
    if not _admin():
        return _json({"error": "admin_required"}, 403)
    if not request.is_json:
        return _json({"error": "json_required"}, 415)
    if (
        request.content_length is not None
        and request.content_length > MAX_REQUEST_BYTES
    ):
        return _json({"error": "request_too_large"}, 413)
    raw = request.stream.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        return _json({"error": "request_too_large"}, 413)
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        return _json({"error": "invalid_json"}, 400)
    allowed = {
        "scan_id",
        "headers",
        "html",
        "cookies",
        "existing_vulns",
        "technologies",
        "response_scheme",
        "persist",
    }
    if not isinstance(payload, dict) or set(payload) - allowed:
        return _json({"error": "invalid_observation_fields"}, 400)
    persist = payload.pop("persist", False)
    scan_id = payload.get("scan_id", 0)
    if type(persist) is not bool or (
        persist and (type(scan_id) is not int or not 0 < scan_id <= 2**63 - 1)
    ):
        return _json({"error": "invalid_persistence_options"}, 400)
    try:
        report = analyze_vulnerability_observations(**payload)
    except (TypeError, ValueError):
        return _json({"error": "invalid_observations"}, 400)
    report["persistence"] = {"requested": persist, "saved": persist}
    if persist:
        try:
            save_vulnerability_report(scan_id, report)
        except Exception:
            return _json({"error": "report_storage_unavailable", "saved": False}, 503)
    return _json(report)


@ai_vulnerability_bp.route(
    "/api/ai-vulnerability/reports/<int:scan_id>", methods=["GET"]
)
def saved_analysis(scan_id):
    if not _admin():
        return _json({"error": "admin_required"}, 403)
    if not 0 < scan_id <= 2**63 - 1:
        return _json({"error": "invalid_scan_id"}, 400)
    try:
        report = get_vulnerability_report(scan_id)
    except Exception:
        return _json({"error": "report_storage_unavailable"}, 503)
    if report is None:
        return _json({"error": "report_not_found"}, 404)
    return _json(report)


@ai_vulnerability_bp.route(
    "/api/ai-vulnerability/scans/<int:scan_id>/review", methods=["POST"]
)
def review_saved_records(scan_id):
    if not _admin():
        return _json({"error": "admin_required"}, 403)
    if not 0 < scan_id <= 2**63 - 1:
        return _json({"error": "invalid_scan_id"}, 400)
    try:
        return _json(review_saved_scan(scan_id))
    except LookupError:
        return _json({"error": "scan_not_found"}, 404)
    except Exception:
        return _json({"error": "stored_observations_unavailable", "saved": False}, 503)
