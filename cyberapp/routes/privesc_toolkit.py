"""
Privilege Escalation Toolkit Flask Routes
"""

from flask import Blueprint, request, jsonify, render_template
import sys
import os

# Add tools directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

try:
    from privesc_toolkit import get_privesc_toolkit
except ImportError:
    get_privesc_toolkit = None

privesc_bp = Blueprint('privesc', __name__, url_prefix='/api/privesc')


@privesc_bp.route('/scan', methods=['POST'])
def start_scan():
    """Start privilege escalation scan"""
    if not get_privesc_toolkit:
        return jsonify({"error": "Privesc toolkit not available"}), 500
    
    data = request.get_json() or {}
    target_os = data.get('target_os', 'auto')
    scan_type = data.get('scan_type', 'full')
    
    toolkit = get_privesc_toolkit()
    job_id = toolkit.start_scan(target_os=target_os, scan_type=scan_type)
    
    return jsonify({
        "status": "started",
        "job_id": job_id,
        "message": f"Privilege escalation scan started ({scan_type})"
    })


@privesc_bp.route('/status/<job_id>', methods=['GET'])
def get_status(job_id):
    """Get scan job status"""
    if not get_privesc_toolkit:
        return jsonify({"error": "Privesc toolkit not available"}), 500
    
    toolkit = get_privesc_toolkit()
    status = toolkit.get_job_status(job_id)
    
    if not status:
        return jsonify({"error": "Job not found"}), 404
    
    return jsonify(status)


@privesc_bp.route('/results/<job_id>', methods=['GET'])
def get_results(job_id):
    """Get scan results"""
    if not get_privesc_toolkit:
        return jsonify({"error": "Privesc toolkit not available"}), 500
    
    toolkit = get_privesc_toolkit()
    results = toolkit.get_job_results(job_id)
    
    if not results:
        return jsonify({"error": "Job not found"}), 404
    
    return jsonify(results)


@privesc_bp.route('/gtfobins', methods=['GET'])
def get_gtfobins():
    """Get GTFOBins database"""
    if not get_privesc_toolkit:
        return jsonify({"error": "Privesc toolkit not available"}), 500
    
    toolkit = get_privesc_toolkit()
    return jsonify(toolkit.suid_gtfobins)


@privesc_bp.route('/kernel-exploits', methods=['GET'])
def get_kernel_exploits():
    """Get kernel exploit database"""
    if not get_privesc_toolkit:
        return jsonify({"error": "Privesc toolkit not available"}), 500
    
    toolkit = get_privesc_toolkit()
    
    # Convert to serializable format
    exploits = {}
    for os_type, exploit_list in toolkit.kernel_exploits.items():
        exploits[os_type] = []
        for exp in exploit_list:
            exploits[os_type].append({
                "name": exp.name,
                "cve_id": exp.cve_id,
                "affected_versions": exp.affected_versions,
                "exploit_url": exp.exploit_url,
                "description": exp.description,
                "success_rate": exp.success_rate
            })
    
    return jsonify(exploits)


@privesc_bp.route('/windows-techniques', methods=['GET'])
def get_windows_techniques():
    """Get Windows privilege escalation techniques"""
    if not get_privesc_toolkit:
        return jsonify({"error": "Privesc toolkit not available"}), 500
    
    toolkit = get_privesc_toolkit()
    return jsonify(toolkit.windows_exploits)


# UI Route
privesc_ui_bp = Blueprint('privesc_ui', __name__)


@privesc_ui_bp.route('/privesc')
def privesc_page():
    """Render privilege escalation toolkit page"""
    return render_template('privesc_toolkit.html')
