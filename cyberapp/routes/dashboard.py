import os
import json
from datetime import datetime

from flask import Blueprint, redirect, render_template, session

from cyberapp.models.scans import list_recent_scans
from cybermodules.arsenal import TOOLS
from cybermodules.ad_enum import has_ldap

# Evasion stats file path
EVASION_STATS_FILE = "/tmp/evasion_stats.json"

dashboard_bp = Blueprint("dashboard", __name__)


def _get_evasion_stats():
    """Get evasion layer statistics from persistent storage."""
    stats = {
        "timestomp_count": 0,
        "logs_cleared_count": 0,
        "artifacts_removed_count": 0,
        "payloads_obfuscated_count": 0,
        "last_evasion_action": None,
        "evasion_enabled": True,
    }

    if os.path.exists(EVASION_STATS_FILE):
        try:
            with open(EVASION_STATS_FILE, "r") as f:
                saved_stats = json.load(f)
                stats.update(saved_stats)
        except Exception:
            pass

    return stats


def _save_evasion_stats(stats):
    """Save evasion statistics to persistent storage."""
    try:
        with open(EVASION_STATS_FILE, "w") as f:
            json.dump(stats, f, indent=2)
    except Exception:
        pass


@dashboard_bp.route("/")
def index():
    if not session.get("logged_in"):
        return redirect("/login")

    scans = list_recent_scans(limit=20)

    leaderboard = []
    leaderboard_file = "/tmp/monolith_leaderboard.json"
    if os.path.exists(leaderboard_file):
        with open(leaderboard_file, "r") as f:
            leaderboard = json.load(f)[:10]

    available_tools = sum(
        1 for tool in TOOLS.values() if tool and os.path.exists(tool.split()[0] if " " in tool else tool)
    )
    total_tools = len(TOOLS)
    tools_ok = available_tools >= 10

    blockchain_ready = False
    try:
        import web3  # noqa: F401

        blockchain_ready = True
    except Exception:
        pass

    # Get evasion layer statistics
    evasion_stats = _get_evasion_stats()

    return render_template(
        "dashboard.html",
        scans=scans,
        leaderboard=leaderboard,
        user=session.get("user", "guest"),
        available_tools=available_tools,
        total_tools=total_tools,
        tools_ok=tools_ok,
        has_openai=_has_openai(),
        has_ldap=has_ldap,
        blockchain_ready=blockchain_ready,
        evasion_stats=evasion_stats,
    )


def _has_openai():
    try:
        import openai  # type: ignore

        return True
    except Exception:
        return False
