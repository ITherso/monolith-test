"""
Smart Password Spraying - Flask Routes
AI-powered intelligent password spraying
"""

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

try:
    from smart_spray import get_smart_sprayer, AuthProtocol
except ImportError:
    get_smart_sprayer = None

spray_bp = Blueprint('smart_spray', __name__, url_prefix='/spray')


@spray_bp.route('/')
@login_required
def index():
    """Smart Password Spraying main page"""
    return render_template('smart_spray.html')


@spray_bp.route('/api/analyze', methods=['POST'])
@login_required
def analyze_policy():
    """Analyze password policy"""
    if not get_smart_sprayer:
        return jsonify({"error": "Smart Spray module not available"}), 500
    
    data = request.get_json()
    company = data.get('company')
    sample_passwords = data.get('sample_passwords', [])
    domain = data.get('domain')
    
    if not company:
        return jsonify({"error": "Company name required"}), 400
    
    sprayer = get_smart_sprayer()
    policy = sprayer.analyze_password_policy(company, sample_passwords, domain)
    
    return jsonify({
        "company": company,
        "policy": {
            "min_length": policy.min_length,
            "max_length": policy.max_length,
            "require_uppercase": policy.require_uppercase,
            "require_lowercase": policy.require_lowercase,
            "require_number": policy.require_number,
            "require_special": policy.require_special,
            "lockout_threshold": policy.lockout_threshold,
            "lockout_duration_minutes": policy.lockout_duration_minutes,
            "common_patterns": policy.common_patterns,
            "confidence": policy.confidence
        }
    })


@spray_bp.route('/api/preview', methods=['POST'])
@login_required
def preview_candidates():
    """Preview password candidates"""
    if not get_smart_sprayer:
        return jsonify({"error": "Smart Spray module not available"}), 500
    
    data = request.get_json()
    company = data.get('company')
    sample_passwords = data.get('sample_passwords', [])
    
    if not company:
        return jsonify({"error": "Company name required"}), 400
    
    sprayer = get_smart_sprayer()
    preview = sprayer.preview_candidates(company, sample_passwords)
    
    return jsonify(preview)


@spray_bp.route('/api/start', methods=['POST'])
@login_required
def start_spray():
    """Start password spraying"""
    if not get_smart_sprayer:
        return jsonify({"error": "Smart Spray module not available"}), 500
    
    data = request.get_json()
    company = data.get('company')
    domain = data.get('domain')
    usernames = data.get('usernames', [])
    protocol = data.get('protocol', 'ldap')
    sample_passwords = data.get('sample_passwords', [])
    target_url = data.get('target_url')
    
    if not all([company, domain, usernames]):
        return jsonify({"error": "Company, domain, and usernames required"}), 400
    
    sprayer = get_smart_sprayer()
    
    try:
        protocol_enum = AuthProtocol(protocol)
    except ValueError:
        protocol_enum = AuthProtocol.LDAP
    
    job_id = sprayer.start_spray(company, domain, usernames, protocol_enum, 
                                 sample_passwords, target_url)
    
    return jsonify({"job_id": job_id, "message": "Spray started"})


@spray_bp.route('/api/job/<job_id>')
@login_required
def get_job_status(job_id):
    """Get spray job status"""
    if not get_smart_sprayer:
        return jsonify({"error": "Smart Spray module not available"}), 500
    
    sprayer = get_smart_sprayer()
    status = sprayer.get_job_status(job_id)
    
    if not status:
        return jsonify({"error": "Job not found"}), 404
    
    return jsonify(status)


@spray_bp.route('/api/job/<job_id>/results')
@login_required
def get_job_results(job_id):
    """Get spray job results"""
    if not get_smart_sprayer:
        return jsonify({"error": "Smart Spray module not available"}), 500
    
    sprayer = get_smart_sprayer()
    results = sprayer.get_job_results(job_id)
    
    if not results:
        return jsonify({"error": "Job not found"}), 404
    
    return jsonify(results)


@spray_bp.route('/api/protocols')
@login_required
def get_protocols():
    """Get supported authentication protocols"""
    protocols = [
        {"id": "ldap", "name": "LDAP", "icon": "📁", "description": "Active Directory LDAP"},
        {"id": "smb", "name": "SMB", "icon": "🗂️", "description": "SMB/CIFS authentication"},
        {"id": "rdp", "name": "RDP", "icon": "🖥️", "description": "Remote Desktop Protocol"},
        {"id": "office365", "name": "Office 365", "icon": "☁️", "description": "Microsoft 365 login"},
        {"id": "owa", "name": "OWA", "icon": "📧", "description": "Outlook Web Access"},
        {"id": "vpn_cisco", "name": "Cisco VPN", "icon": "🔒", "description": "Cisco AnyConnect VPN"},
        {"id": "vpn_fortinet", "name": "Fortinet VPN", "icon": "🔐", "description": "FortiGate VPN"},
        {"id": "ssh", "name": "SSH", "icon": "💻", "description": "Secure Shell"},
        {"id": "kerberos", "name": "Kerberos", "icon": "🎫", "description": "Kerberos authentication"},
    ]
    return jsonify({"protocols": protocols})


@spray_bp.route('/api/patterns')
@login_required
def get_patterns():
    """Get common password patterns"""
    patterns = [
        {"id": "season_year", "name": "Season + Year", "example": "Summer2024!"},
        {"id": "company_year", "name": "Company + Year", "example": "Acme2024!"},
        {"id": "month_year", "name": "Month + Year", "example": "January2024!"},
        {"id": "welcome", "name": "Welcome Pattern", "example": "Welcome2024!"},
        {"id": "password", "name": "Password Pattern", "example": "Password2024!"},
        {"id": "changeme", "name": "Change Me", "example": "Changeme2024!"},
    ]
    return jsonify({"patterns": patterns})


@spray_bp.route('/api/jobs')
@login_required
def list_jobs():
    """List all spray jobs"""
    if not get_smart_sprayer:
        return jsonify({"error": "Smart Spray module not available"}), 500
    
    sprayer = get_smart_sprayer()
    jobs = [sprayer.get_job_status(job_id) for job_id in sprayer.jobs.keys()]
    
    return jsonify({"jobs": jobs})


@spray_bp.route('/api/stats')
@login_required
def get_stats():
    """Get spray statistics"""
    if not get_smart_sprayer:
        return jsonify({"error": "Smart Spray module not available"}), 500
    
    sprayer = get_smart_sprayer()
    
    total_jobs = len(sprayer.jobs)
    completed_jobs = sum(1 for j in sprayer.jobs.values() if j.status == "completed")
    total_found = sum(len(j.found_credentials) for j in sprayer.jobs.values())
    
    return jsonify({
        "total_jobs": total_jobs,
        "completed_jobs": completed_jobs,
        "running_jobs": total_jobs - completed_jobs,
        "total_credentials_found": total_found
    })
