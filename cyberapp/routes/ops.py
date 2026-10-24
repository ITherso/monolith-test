import os

from flask import Blueprint, jsonify, redirect, session

from cyberapp.models.db import db_conn
from cyberapp.passive_monitor import PassiveEventMonitor

ops_bp = Blueprint("ops", __name__)


@ops_bp.route("/threathunter/start")
@ops_bp.route("/threathunter/events")
def start_threathunter():
    if not session.get("logged_in"):
        return redirect("/login")

    source = os.getenv("MONOLITH_EVENT_LOG")
    if not source:
        return jsonify(
            {
                "status": "source_required",
                "message": "Configure MONOLITH_EVENT_LOG with a regular JSONL event file.",
            }
        ), 503
    try:
        monitor = PassiveEventMonitor(source)
        findings = monitor.poll_once()
    except ValueError:
        return jsonify(
            {
                "status": "invalid_source",
                "message": "The configured event source must be a regular JSONL file.",
            }
        ), 400
    except OSError:
        return jsonify(
            {
                "status": "source_unavailable",
                "message": "The configured event file could not be read.",
            }
        ), 503

    response = jsonify(
        {
            "status": "analyzed",
            "mode": "bounded_preview",
            "packet_capture": False,
            "background_monitor_started": False,
            "events_processed": monitor.events_processed,
            "invalid_records": monitor.invalid_records,
            "partial": monitor.has_more,
            "findings": findings,
            "message": "Read-only preview of the configured log; each request starts at its beginning.",
        }
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@ops_bp.route("/blockchain/publish/<int:scan_id>", methods=["POST", "GET"])
def blockchain_publish(scan_id):
    try:
        import monolith.blockchain as mchain
    except Exception:
        return jsonify(
            {
                "status": "error",
                "message": "blockchain module not available (install web3)",
            }
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
        return jsonify(
            {"status": "error", "message": "no evidence found for scan"}
        ), 404

    leaves = [(str(r[0]) + ":" + (r[1] or "")).encode("utf-8") for r in rows]

    try:
        private_key = os.getenv("WEB3_PRIVATE_KEY")
        if not private_key:
            return jsonify(
                {"status": "error", "message": "WEB3_PRIVATE_KEY env var not set"}
            ), 400

        tx_hash = mchain.publish_merkle_root(leaves, private_key)
        return jsonify({"status": "ok", "tx_hash": tx_hash})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
