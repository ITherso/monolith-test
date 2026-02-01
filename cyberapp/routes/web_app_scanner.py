"""Web Application Scanner routes"""
from flask import Blueprint, render_template, request, jsonify
import sys
from pathlib import Path

# Add tools to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "tools"))

try:
    from web_app_scanner import get_web_app_scanner, VulnerabilityType, SeverityLevel
    scanner_available = True
except ImportError:
    scanner_available = False

web_app_scanner_bp = Blueprint('web_app_scanner', __name__, url_prefix='/tools')


@web_app_scanner_bp.route('/web-app-scanner')
def web_app_scanner_page():
    """Web Application Scanner page"""
    return render_template('web_app_scanner.html', scanner_available=scanner_available)


@web_app_scanner_bp.route('/api/web-app-scanner/scan', methods=['POST'])
def start_scan():
    """Start web application scan"""
    if not scanner_available:
        return jsonify({"error": "Web Application Scanner not available"}), 500
    
    try:
        data = request.get_json()
        target_url = data.get('target_url')
        scan_mode = data.get('scan_mode', 'black_box')
        scan_depth = int(data.get('scan_depth', 2))
        max_requests = int(data.get('max_requests', 1000))
        
        if not target_url:
            return jsonify({"error": "Target URL is required"}), 400
        
        scanner = get_web_app_scanner()
        job_id = scanner.start_scan(target_url, scan_mode=scan_mode, 
                                     scan_depth=scan_depth, max_requests=max_requests)
        
        return jsonify({
            "success": True,
            "job_id": job_id,
            "target_url": target_url,
            "scan_mode": scan_mode
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@web_app_scanner_bp.route('/api/web-app-scanner/status/<job_id>')
def scan_status(job_id):
    """Get scan status"""
    if not scanner_available:
        return jsonify({"error": "Web Application Scanner not available"}), 500
    
    try:
        scanner = get_web_app_scanner()
        status = scanner.get_job_status(job_id)
        
        if not status:
            return jsonify({"error": "Job not found"}), 404
        
        return jsonify(status)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@web_app_scanner_bp.route('/api/web-app-scanner/results/<job_id>')
def scan_results(job_id):
    """Get scan results"""
    if not scanner_available:
        return jsonify({"error": "Web Application Scanner not available"}), 500
    
    try:
        scanner = get_web_app_scanner()
        results = scanner.get_job_results(job_id)
        
        if not results:
            return jsonify({"error": "Job not found"}), 404
        
        return jsonify(results)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
