"""Authenticated read-only inventory; never load or run a feature to inspect it."""

from flask import Blueprint, jsonify, redirect, render_template, session

from cyberapp.feature_status import feature_status_snapshot

feature_status_bp = Blueprint("feature_status", __name__)


@feature_status_bp.after_request
def prevent_inventory_caching(response):
    response.headers["Cache-Control"] = "no-store"
    return response


@feature_status_bp.route("/feature-status", methods=["GET"])
def feature_status_page():
    if not session.get("logged_in"):
        return redirect("/login")
    return render_template(
        "feature_status.html",
        title="Özellik durumu — MONOLITH",
        snapshot=feature_status_snapshot(),
    )


@feature_status_bp.route("/api/feature-status", methods=["GET"])
def feature_status_api():
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    return jsonify(feature_status_snapshot())
