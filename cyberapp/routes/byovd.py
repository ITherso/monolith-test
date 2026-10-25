"""BYOVD status only; never import or dispatch an operational driver backend."""

from flask import Blueprint, jsonify, render_template

byovd_bp = Blueprint("byovd", __name__, url_prefix="/byovd")


def _status_payload():
    return {
        "module": "byovd",
        "status": "unavailable",
        "success": False,
        "available": False,
        "executed": False,
        "host_probe_performed": False,
        "driver_loaded": False,
        "kernel_access": False,
        "edr_terminated": False,
        "reason": "byovd_backend_unavailable",
    }


def _unavailable():
    payload = _status_payload()
    payload["error"] = "byovd_backend_unavailable"
    payload["message"] = (
        "The operational driver backend is unavailable; no action was performed."
    )
    return jsonify(payload), 501


@byovd_bp.after_request
def no_caching(response):
    response.headers["Cache-Control"] = "no-store"
    return response


@byovd_bp.route("/")
def index():
    return render_template("byovd.html")


@byovd_bp.route("/api/status")
def module_status():
    """Static descriptor; no process, driver, credential or host inspection."""
    return jsonify(_status_payload())


@byovd_bp.route("/api/drivers")
def get_drivers():
    return _unavailable()


@byovd_bp.route("/api/edr-products")
def get_edr_products():
    return _unavailable()


@byovd_bp.route("/api/detect-edr", methods=["POST"])
def detect_edr():
    return _unavailable()


@byovd_bp.route("/api/generate-payload", methods=["POST"])
def generate_payload():
    return _unavailable()


@byovd_bp.route("/api/deploy", methods=["POST"])
def deploy_byovd():
    return _unavailable()


@byovd_bp.route("/api/kill-edr", methods=["POST"])
def kill_edr():
    return _unavailable()


@byovd_bp.route("/api/job/<job_id>")
def get_job_status(job_id):
    return _unavailable()


@byovd_bp.route("/api/capabilities")
def get_capabilities():
    """Legacy labels only; they are not available runtime capabilities."""
    payload = _status_payload()
    payload["catalog_only"] = True
    payload["capabilities"] = [
        {"id": identifier, "name": name, "available": False}
        for identifier, name in (
            ("read_memory", "Kernel Memory Read"),
            ("write_memory", "Kernel Memory Write"),
            ("kill_process", "Kill Protected Process"),
            ("unload_driver", "Unload Kernel Driver"),
            ("registry_access", "Registry Access"),
            ("file_access", "Protected File Access"),
        )
    ]
    return jsonify(payload)
