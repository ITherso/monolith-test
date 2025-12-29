import os
import json

from flask import Blueprint, redirect, render_template, session

from cyberapp.models.scans import list_recent_scans
from cybermodules.arsenal import TOOLS
from cybermodules.ad_enum import has_ldap

dashboard_bp = Blueprint("dashboard", __name__)


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
    )


def _has_openai():
    try:
        import openai  # type: ignore

        return True
    except Exception:
        return False
