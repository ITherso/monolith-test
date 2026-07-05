"""
CI/CD Pipeline Jacker - Flask Routes
Supply chain attack via CI/CD pipeline poisoning
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
    from cicd_pipeline_jacker import get_cicd_jacker, CICDPlatform, BackdoorType
except ImportError:
    get_cicd_jacker = None

cicd_bp = Blueprint('cicd_jacker', __name__, url_prefix='/cicd')


@cicd_bp.route('/')
@login_required
def index():
    """CI/CD Pipeline Jacker main page"""
    return render_template('cicd_jacker.html')


@cicd_bp.route('/api/scan', methods=['POST'])
@login_required
def scan_cicd():
    """Scan target for CI/CD systems"""
    if not get_cicd_jacker:
        return jsonify({"error": "CI/CD module not available"}), 500
    
    data = request.get_json()
    target = data.get('target')
    
    if not target:
        return jsonify({"error": "Target URL required"}), 400
    
    jacker = get_cicd_jacker()
    results = jacker.detect_cicd_platform(target)
    
    return jsonify(results)


@cicd_bp.route('/api/enumerate', methods=['POST'])
@login_required
def enumerate_pipelines():
    """Enumerate CI/CD pipelines"""
    if not get_cicd_jacker:
        return jsonify({"error": "CI/CD module not available"}), 500
    
    data = request.get_json()
    target = data.get('target')
    platform = data.get('platform')
    credentials = data.get('credentials', {})
    
    if not target or not platform:
        return jsonify({"error": "Target and platform required"}), 400
    
    jacker = get_cicd_jacker()
    
    try:
        platform_enum = CICDPlatform(platform)
    except ValueError:
        return jsonify({"error": f"Unknown platform: {platform}"}), 400
    
    results = jacker.enumerate_pipelines(target, platform_enum, credentials)
    return jsonify(results)


@cicd_bp.route('/api/generate-backdoor', methods=['POST'])
@login_required
def generate_backdoor():
    """Generate CI/CD backdoor payload"""
    if not get_cicd_jacker:
        return jsonify({"error": "CI/CD module not available"}), 500
    
    data = request.get_json()
    platform = data.get('platform')
    backdoor_type = data.get('backdoor_type')
    callback_url = data.get('callback_url')
    
    if not platform or not backdoor_type:
        return jsonify({"error": "Platform and backdoor type required"}), 400
    
    jacker = get_cicd_jacker()
    
    try:
        platform_enum = CICDPlatform(platform)
        backdoor_enum = BackdoorType(backdoor_type)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    
    payload = jacker.generate_backdoor(platform_enum, backdoor_enum, callback_url)
    return jsonify({"payload": payload})


@cicd_bp.route('/api/inject', methods=['POST'])
@login_required
def inject_backdoor():
    """Inject backdoor into CI/CD pipeline"""
    if not get_cicd_jacker:
        return jsonify({"error": "CI/CD module not available"}), 500
    
    data = request.get_json()
    target = data.get('target')
    platform = data.get('platform')
    backdoor_type = data.get('backdoor_type')
    credentials = data.get('credentials', {})
    callback_url = data.get('callback_url')
    
    if not all([target, platform, backdoor_type]):
        return jsonify({"error": "Missing required parameters"}), 400
    
    jacker = get_cicd_jacker()
    
    try:
        platform_enum = CICDPlatform(platform)
        backdoor_enum = BackdoorType(backdoor_type)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    
    result = jacker.inject_backdoor(target, platform_enum, backdoor_enum, credentials, callback_url)
    return jsonify(result)


@cicd_bp.route('/api/test-creds', methods=['POST'])
@login_required
def test_credentials():
    """Test CI/CD credentials"""
    if not get_cicd_jacker:
        return jsonify({"error": "CI/CD module not available"}), 500
    
    data = request.get_json()
    target = data.get('target')
    platform = data.get('platform')
    credentials = data.get('credentials', {})
    
    if not target or not platform:
        return jsonify({"error": "Target and platform required"}), 400
    
    jacker = get_cicd_jacker()
    
    try:
        platform_enum = CICDPlatform(platform)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    
    is_valid = jacker.test_credentials(target, platform_enum, credentials)
    return jsonify({"valid": is_valid, "target": target, "platform": platform})


@cicd_bp.route('/api/platforms')
@login_required
def get_platforms():
    """Get supported CI/CD platforms"""
    platforms = [
        {"id": "jenkins", "name": "Jenkins", "icon": "🔧"},
        {"id": "gitlab_ci", "name": "GitLab CI", "icon": "🦊"},
        {"id": "github_actions", "name": "GitHub Actions", "icon": "🐙"},
        {"id": "azure_devops", "name": "Azure DevOps", "icon": "☁️"},
        {"id": "circleci", "name": "CircleCI", "icon": "⭕"},
        {"id": "travis_ci", "name": "Travis CI", "icon": "🔨"},
        {"id": "bamboo", "name": "Bamboo", "icon": "🎋"},
        {"id": "teamcity", "name": "TeamCity", "icon": "🏙️"},
    ]
    return jsonify({"platforms": platforms})


@cicd_bp.route('/api/backdoor-types')
@login_required
def get_backdoor_types():
    """Get available backdoor types"""
    types = [
        {"id": "reverse_shell", "name": "Reverse Shell", "description": "Inject reverse shell into build"},
        {"id": "credential_stealer", "name": "Credential Stealer", "description": "Exfiltrate secrets and tokens"},
        {"id": "persistence", "name": "Persistence", "description": "Add persistent backdoor access"},
        {"id": "supply_chain", "name": "Supply Chain", "description": "Poison built artifacts"},
        {"id": "dependency_confusion", "name": "Dependency Confusion", "description": "Inject malicious packages"},
    ]
    return jsonify({"types": types})
