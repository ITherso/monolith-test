import csv
import io

from flask import Blueprint, jsonify, make_response, redirect, render_template, request, session

from cyberapp.models.db import db_conn
from cybermodules.phishing import LivePhishingDashboard
from cybermodules.social_engineering import SocialEngineeringAI

phishing_bp = Blueprint("phishing", __name__)


@phishing_bp.route("/phishing")
def phishing_home():
    if not session.get("logged_in"):
        return redirect("/login")
    return redirect("/phishing/advanced")


@phishing_bp.route("/phishing/advanced", methods=["GET", "POST"])
def advanced_phishing():
    if not session.get("logged_in"):
        return redirect("/login")

    if request.method == "POST":
        target_info = {
            "name": request.form.get("name"),
            "email": request.form.get("email"),
            "company": request.form.get("company"),
            "linkedin": request.form.get("linkedin"),
            "position": request.form.get("position"),
            "company_domain": request.form.get("company_domain"),
        }

        se_ai = SocialEngineeringAI(target_info)
        campaign = se_ai.start_campaign(target_info)
        return render_template("phishing_created.html", campaign=campaign)

    return render_template("phishing_advanced.html")


@phishing_bp.route("/phishing/live/<campaign_id>")
def live_phishing_dashboard(campaign_id):
    if not session.get("logged_in"):
        return redirect("/login")

    dashboard = LivePhishingDashboard()
    return dashboard.create_live_dashboard_html(campaign_id)


@phishing_bp.route("/phishing/stats/<campaign_id>")
def phishing_stats(campaign_id):
    if not session.get("logged_in"):
        return redirect("/login")

    dashboard = LivePhishingDashboard()
    stats = dashboard.get_dashboard_stats(campaign_id)
    return jsonify(stats)


@phishing_bp.route("/phishing/export/<campaign_id>")
def export_phishing_credentials(campaign_id):
    if not session.get("logged_in"):
        return redirect("/login")

    dashboard = LivePhishingDashboard()
    creds = dashboard.get_all_credentials(campaign_id)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        ["ID", "Campaign", "Username", "Password", "IP", "User Agent", "Timestamp", "Status"]
    )

    for c in creds:
        writer.writerow(c)

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = (
        f"attachment; filename=phishing_creds_{campaign_id}.csv"
    )
    response.headers["Content-type"] = "text/csv"

    return response


@phishing_bp.route("/phishing/clear/<campaign_id>", methods=["POST"])
def clear_phishing_credentials(campaign_id):
    if not session.get("logged_in"):
        return redirect("/login")

    try:
        with db_conn("/tmp/phishing_credentials.db") as conn:
            conn.execute("DELETE FROM credentials WHERE campaign_id = ?", (campaign_id,))
            conn.execute("DELETE FROM clicks WHERE campaign_id = ?", (campaign_id,))

        return jsonify({"status": "success", "message": "Credentials cleared"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})
