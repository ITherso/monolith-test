"""Authenticated routes for the management-only application.

The module deliberately lives outside ``cyberapp.routes``. That package remains
blocked on Windows because it contains the operational route collection.
"""

import datetime
import json
import secrets
from pathlib import Path
from tempfile import TemporaryDirectory

from flask import (
    Blueprint,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from cyberapp.feature_status import feature_status_snapshot
from cyberapp.management_data import (
    load_audit_page,
    load_management_summary,
    load_scan_record,
    load_scan_status,
)
from cyberapp.passive_monitor import MAX_REVIEW_BYTES, review_jsonl_bytes
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
PDF_RECORD_ROWS = 20


def _json(payload, status=200):
    response = jsonify(payload)
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"
    return response


def _logged_in():
    return session.get("logged_in") is True and bool(session.get("user"))


def _admin():
    return _logged_in() and session.get("role") == "admin"


def _query_id(name):
    raw = request.args.get(name)
    if raw in (None, ""):
        return None
    if len(raw) > 19 or not raw.isascii() or not raw.isdigit():
        raise ValueError("invalid cursor")
    value = int(raw)
    if not 0 < value <= 2**63 - 1:
        raise ValueError("invalid cursor")
    return value


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
    login_error = None
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
        login_error = "Kullanıcı adı veya parola geçersiz."
    return render_template(
        "login.html",
        base_template="management_base.html",
        login_error=login_error,
    )


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
        role=session.get("role"),
    )


@management_bp.route("/management/scans/<int:scan_id>/report.pdf", methods=["GET"])
def scan_record_pdf(scan_id):
    if not _admin():
        return _json({"error": "admin_required"}, 403)
    try:
        record = load_scan_record(scan_id, limit=PDF_RECORD_ROWS)
    except (TypeError, ValueError):
        return _json({"error": "invalid_scan_id"}, 400)
    except Exception:
        return _json({"error": "scan_record_unavailable"}, 503)
    if record is None:
        return _json({"error": "not_found"}, 404)

    try:
        from cyberapp.pdf_renderer import render_html_pdf

        report_html = render_template("management_scan_report.html", record=record)
        with TemporaryDirectory(prefix="monolith-report-") as directory:
            output = Path(directory) / "report.pdf"
            render_html_pdf(report_html, output)
            pdf_bytes = output.read_bytes()
    except Exception:
        return _json({"error": "pdf_render_unavailable"}, 503)

    response = make_response(pdf_bytes)
    response.mimetype = "application/pdf"
    response.headers["Content-Disposition"] = (
        f'attachment; filename="monolith-scan-{scan_id}.pdf"'
    )
    return response


@management_bp.route(
    "/management/scans/<int:scan_id>/protected-report.pdf", methods=["POST"]
)
def protected_scan_record_pdf(scan_id):
    if not _admin():
        return _json({"error": "admin_required"}, 403)
    password = request.form.get("pdf_password", "")
    if not isinstance(password, str) or not 8 <= len(password) <= 128:
        return _json({"error": "invalid_pdf_password"}, 400)
    try:
        record = load_scan_record(scan_id, limit=PDF_RECORD_ROWS)
    except (TypeError, ValueError):
        return _json({"error": "invalid_scan_id"}, 400)
    except Exception:
        return _json({"error": "scan_record_unavailable"}, 503)
    if record is None:
        return _json({"error": "not_found"}, 404)

    try:
        from cyberapp.pdf_renderer import render_html_pdf
        from cyberapp.report_security import encrypt_pdf_atomic

        report_html = render_template("management_scan_report.html", record=record)
        with TemporaryDirectory(prefix="monolith-protected-report-") as directory:
            output = Path(directory) / "report.pdf"
            render_html_pdf(report_html, output)
            encrypt_pdf_atomic(output, password)
            pdf_bytes = output.read_bytes()
    except Exception:
        return _json({"error": "pdf_render_unavailable"}, 503)

    response = make_response(pdf_bytes)
    response.mimetype = "application/pdf"
    response.headers["Content-Disposition"] = (
        f'attachment; filename="monolith-scan-{scan_id}-protected.pdf"'
    )
    return response


@management_bp.route("/passive-review", methods=["GET"])
def passive_review_page():
    if not _admin():
        return _json({"error": "admin_required"}, 403)
    return render_template(
        "management_passive_review.html",
        title="Pasif JSONL olay incelemesi",
        max_review_bytes=MAX_REVIEW_BYTES,
        base_template="management_base.html",
    )


@management_bp.route("/api/management/passive-events/review", methods=["POST"])
def passive_review_api():
    if not _admin():
        return _json({"error": "admin_required"}, 403)
    if request.mimetype not in {
        "application/x-ndjson",
        "application/jsonl",
        "text/plain",
    }:
        return _json({"error": "jsonl_required"}, 415)
    if request.content_length is not None and request.content_length > MAX_REVIEW_BYTES:
        return _json({"error": "request_too_large"}, 413)
    raw = request.stream.read(MAX_REVIEW_BYTES + 1)
    if len(raw) > MAX_REVIEW_BYTES:
        return _json({"error": "request_too_large"}, 413)
    if not raw:
        return _json({"error": "empty_jsonl"}, 400)
    try:
        return _json(review_jsonl_bytes(raw))
    except ValueError:
        return _json({"error": "invalid_jsonl"}, 400)


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
        page = load_audit_page(before_id=_query_id("before_id"))
    except ValueError:
        return "Geçersiz audit sayfası", 400
    except Exception:
        return "Audit kayıtları şu anda okunamıyor", 503
    return render_template("management_audit.html", **page)


@monitoring_bp.route("/api/management/audit", methods=["GET"])
def audit_api():
    if not _admin():
        return _json({"error": "admin_required"}, 403)
    try:
        return _json(load_audit_page(before_id=_query_id("before_id")))
    except ValueError:
        return _json({"error": "invalid_before_id"}, 400)
    except Exception:
        return _json({"error": "audit_unavailable"}, 503)


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
    try:
        selected_scan_id = _query_id("scan_id")
    except ValueError:
        selected_scan_id = None
    return render_template(
        "ai_vulnerability.html",
        title="Kural tabanlı açık tahmini",
        base_template="management_base.html",
        selected_scan_id=str(selected_scan_id or ""),
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
