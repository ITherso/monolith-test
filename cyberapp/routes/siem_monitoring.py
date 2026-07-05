"""SIEM ingestion monitoring routes (defensive).

Exposes endpoints to validate host-side log forwarding health and identify
potential ingestion blind spots (service down, unreachable forwarders, config
recently changed). This does not stop services or suppress logging.
"""

from __future__ import annotations

import time
from typing import Any, Dict

from flask import Blueprint, jsonify, request

from cyberapp.services.logger import get_logger
from cybermodules.siem_ingestion_monitor import SIEMIngestionMonitor, parse_destinations


logger = get_logger("siem_monitor")

siem_monitoring_bp = Blueprint(
    "siem_monitoring",
    __name__,
    url_prefix="/api/elite/siem-monitor",
)


@siem_monitoring_bp.route("/status", methods=["GET", "POST"])
def siem_status():
    """Return log pipeline health signals.

    POST body (optional):
    {
      "destinations": [{"host": "siem.local", "port": 514, "proto": "tcp"}],
      "recent_change_window_sec": 3600,
      "extra_linux_services": ["rsyslog"]
    }
    """
    payload: Dict[str, Any] = request.get_json(silent=True) or {}

    destinations = parse_destinations(payload.get("destinations"))
    recent_change_window_sec = int(payload.get("recent_change_window_sec") or 3600)
    extra_linux_services = payload.get("extra_linux_services")

    monitor = SIEMIngestionMonitor(extra_linux_services=extra_linux_services)
    report = monitor.collect(
        destinations=destinations,
        recent_change_window_sec=recent_change_window_sec,
    )

    return jsonify({"status": "ok", "report": report}), 200


@siem_monitoring_bp.route("/emit-test", methods=["POST"])
def emit_test_signal():
    """Emit an application-level test signal.

    This is meant to help correlate expected log/metric appearance in downstream
    tooling. It only logs through the app logger.
    """
    payload: Dict[str, Any] = request.get_json(silent=True) or {}
    marker = str(payload.get("marker") or "siem-monitor-test")

    ts = int(time.time())
    logger.warning("SIEM_MONITOR_TEST marker=%s ts=%s", marker, ts)

    return jsonify({"status": "emitted", "marker": marker, "timestamp": ts}), 200
