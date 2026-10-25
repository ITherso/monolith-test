"""Server-side access restrictions; never initialize or enable feature modules."""

from functools import wraps

from flask import (
    has_request_context,
    jsonify,
    make_response,
    redirect,
    request,
    session,
    url_for,
)

PUBLIC_ENDPOINTS = frozenset(
    {
        "auth.login",
        "auth.logout",
        "static",
        "orchestration_health_check",
        "management_health",
    }
)
READER_ENDPOINTS = frozenset(
    {
        "dashboard.index",
        "management.dashboard",
        "management.scan_record",
        "management.summary_api",
        "management.scan_record_api",
        "feature_status.feature_status_page",
        "feature_status.feature_status_api",
        "ops.start_threathunter",
        "monitoring.scan_status",
        "monitoring.metrics",
        "scans.scans_list",
        "scans.scan_status",
        "scans.details",
        "scans.api_get_vulnerabilities",
        "scans.api_get_scan_stats",
    }
)
READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def is_authenticated_session() -> bool:
    """Require the identity stored by the login handler in the signed session."""
    if not has_request_context():
        return False
    user = session.get("user")
    return session.get("logged_in") is True and isinstance(user, str) and bool(user)


def admin_session_authorized() -> bool:
    return is_authenticated_session() and session.get("role") == "admin"


def _deny_access(authenticated: bool):
    wants_json = (
        request.path.startswith("/api/")
        or request.is_json
        or request.method not in {"GET", "HEAD"}
        or request.accept_mimetypes["application/json"]
        > request.accept_mimetypes["text/html"]
    )
    if wants_json:
        response = jsonify(
            {"error": "admin_required" if authenticated else "login_required"}
        )
        response.status_code = 403 if authenticated else 401
    elif authenticated:
        response = make_response("Admin yetkisi gerekli", 403)
    else:
        login_url = url_for("auth.login")
        if not login_url.startswith("/") or login_url.startswith("//"):
            login_url = "/login"
        response = redirect(login_url)
    response.headers["Cache-Control"] = "no-store"
    return response


def install_admin_access_control(app) -> None:
    """Default every matched feature route to admin, with explicit read exceptions.

    Install before registering blueprints so denial runs before their request
    callbacks. This authorizes requests only; host stops remain independent.
    """

    @app.before_request
    def enforce_admin_access():
        if request.url_rule is None or request.endpoint in PUBLIC_ENDPOINTS:
            return None
        authenticated = is_authenticated_session()
        if (
            request.endpoint in READER_ENDPOINTS
            and request.method in READ_METHODS
            and authenticated
        ):
            return None
        if admin_session_authorized():
            return None
        return _deny_access(authenticated)


def socket_admin_required(handler):
    """Recheck the signed session for every existing socket event; enable nothing."""

    @wraps(handler)
    def guarded(*args, **kwargs):
        if not admin_session_authorized():
            return False
        return handler(*args, **kwargs)

    return guarded
