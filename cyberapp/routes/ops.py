import os
import threading

from flask import Blueprint, jsonify, redirect, request, session

from cyberapp.models.db import db_conn
from cybermodules.threat_hunter import ThreatHunter

ops_bp = Blueprint("ops", __name__)


@ops_bp.route("/threathunter/start")
def start_threathunter():
    if not session.get("logged_in"):
        return redirect("/login")

    interface = request.args.get("interface", "eth0")
    hunter = ThreatHunter(interface)
    threading.Thread(target=hunter.start, daemon=True).start()

    return jsonify(
        {
            "status": "started",
            "dashboard": "http://127.0.0.1:5001/threathunter",
            "interface": interface,
            "message": "Threat Hunter started in background",
        }
    )


@ops_bp.route("/blockchain/publish/<int:scan_id>", methods=["POST", "GET"])
def blockchain_publish(scan_id):
    try:
        import monolith.blockchain as mchain
    except Exception:
        return jsonify(
            {"status": "error", "message": "blockchain module not available (install web3)"}
        ), 500

    try:
        with db_conn() as conn:
            rows = conn.execute(
                "SELECT id, evidence_hash FROM blockchain_evidence WHERE scan_id = ?",
                (scan_id,),
            ).fetchall()
    except Exception as e:
        return jsonify({"status": "error", "message": f"db error: {str(e)}"}), 500

    if not rows:
        return jsonify({"status": "error", "message": "no evidence found for scan"}), 404

    leaves = [(str(r[0]) + ":" + (r[1] or "")).encode("utf-8") for r in rows]

    try:
        private_key = os.getenv("WEB3_PRIVATE_KEY")
        if not private_key:
            return jsonify({"status": "error", "message": "WEB3_PRIVATE_KEY env var not set"}), 400

        tx_hash = mchain.publish_merkle_root(leaves, private_key)
        return jsonify({"status": "ok", "tx_hash": tx_hash})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
