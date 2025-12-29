import os

from flask import Blueprint, jsonify, redirect, render_template, request, session

from cyberapp.models.db import db_conn
from cybermodules.opsec import OpSecEngine, has_aws, has_digitalocean

infra_bp = Blueprint("infra", __name__)


@infra_bp.route("/decentralized")
def decentralized_dashboard():
    if not session.get("logged_in"):
        return redirect("/login")
    return render_template("decentralized.html")


@infra_bp.route("/opsec")
def opsec_dashboard():
    if not session.get("logged_in"):
        return redirect("/login")

    with db_conn() as conn:
        opsec_logs = conn.execute(
            "SELECT scan_id, type, data FROM intel WHERE type LIKE 'OPSEC%' ORDER BY rowid DESC LIMIT 50"
        ).fetchall()

    log_rows = []
    for scan_id, log_type, data in opsec_logs:
        log_rows.append(
            {
                "scan_id": scan_id,
                "data": data or "",
            }
        )

    return render_template(
        "opsec.html",
        logs=log_rows,
        aws_enabled=bool(os.getenv("AWS_ACCESS_KEY_ID")),
        do_enabled=bool(os.getenv("DIGITALOCEAN_TOKEN")),
        has_aws=has_aws,
        has_digitalocean=has_digitalocean,
    )


@infra_bp.route("/opsec/activate", methods=["POST"])
def opsec_activate():
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    if session.get("role") != "admin":
        return jsonify({"error": "forbidden"}), 403

    target = None
    try:
        data = request.get_json() or {}
        target = data.get("target")
    except Exception:
        target = request.form.get("target") if request.form else None

    oe = OpSecEngine(0)
    result = {}
    if os.getenv("AWS_ACCESS_KEY_ID") and has_aws:
        proxy_url = oe.create_aws_api_gateway(target or "http://example.com")
        result["aws_proxy"] = proxy_url
        oe.log_opsec(f"Activated AWS API Gateway for target: {target}")
    elif os.getenv("DIGITALOCEAN_TOKEN") and has_digitalocean:
        ip = oe.create_digitalocean_droplet()
        result["do_droplet_ip"] = ip
        oe.log_opsec(f"Created DO droplet: {ip}")
    else:
        return jsonify({"error": "no_cloud_credentials"}), 400

    return jsonify({"status": "ok", "result": result})
