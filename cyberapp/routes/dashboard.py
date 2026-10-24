import json

from flask import Blueprint, redirect, render_template, session

from cyberapp.dashboard_data import (
    executable_available,
    load_evasion_stats,
    load_leaderboard,
)
from cyberapp.models.scans import list_recent_scans
from cybermodules.ad_enum import has_ldap
from cybermodules.arsenal import TOOLS

# Evasion stats file path
EVASION_STATS_FILE = "/tmp/evasion_stats.json"
LEADERBOARD_FILE = "/tmp/monolith_leaderboard.json"

dashboard_bp = Blueprint("dashboard", __name__)


def _get_evasion_stats():
    """Get evasion layer statistics from persistent storage."""
    return load_evasion_stats(EVASION_STATS_FILE)


def _save_evasion_stats(stats):
    """Save evasion statistics to persistent storage."""
    try:
        with open(EVASION_STATS_FILE, "w") as f:
            json.dump(stats, f, indent=2)
    except Exception:
        pass


@dashboard_bp.route("/")
@dashboard_bp.route("/dashboard")
def index():
    if not session.get("logged_in"):
        return redirect("/login")

    scans = list_recent_scans(limit=20)

    leaderboard = load_leaderboard(LEADERBOARD_FILE)

    available_tools = sum(1 for tool in TOOLS.values() if executable_available(tool))
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


@dashboard_bp.route("/attack-playground")
def attack_playground():
    """Attack Playground - Vulnerable by Design training lab."""
    if not session.get("logged_in"):
        return redirect("/login")
    return render_template("attack_playground.html")


def _has_openai():
    try:
        import openai  # noqa: F401

        return True
    except Exception:
        return False
