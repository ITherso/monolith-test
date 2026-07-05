"""Service Fingerprinting Pro routes"""
from flask import Blueprint, render_template, request, jsonify
import sys
from pathlib import Path

# Add tools to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "tools"))

try:
    from service_fingerprinter_pro import get_service_fingerprinter, ServiceProtocol, VulnerabilityRisk
    fingerprinter_available = True
except ImportError:
    fingerprinter_available = False

service_fingerprinter_bp = Blueprint('service_fingerprinter', __name__, url_prefix='/tools')


@service_fingerprinter_bp.route('/service-fingerprinter')
def service_fingerprinter_page():
    """Service Fingerprinting Pro page"""
    return render_template('service_fingerprinter.html', fingerprinter_available=fingerprinter_available)


@service_fingerprinter_bp.route('/api/service-fingerprinter/scan', methods=['POST'])
def start_scan():
    """Start service fingerprinting scan"""
    if not fingerprinter_available:
        return jsonify({"error": "Service Fingerprinting Pro not available"}), 500
    
    try:
        data = request.get_json()
        target = data.get('target')
        scan_type = data.get('scan_type', 'full')
        ports_str = data.get('ports', '')
        
        if not target:
            return jsonify({"error": "Target is required"}), 400
        
        # Parse ports
        ports = None
        if ports_str:
            try:
                ports = [int(p.strip()) for p in ports_str.split(',')]
            except ValueError:
                return jsonify({"error": "Invalid port format"}), 400
        
        fp = get_service_fingerprinter()
        job_id = fp.start_fingerprint(target, ports=ports, scan_type=scan_type)
        
        return jsonify({
            "success": True,
            "job_id": job_id,
            "target": target,
            "scan_type": scan_type
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@service_fingerprinter_bp.route('/api/service-fingerprinter/status/<job_id>')
def scan_status(job_id):
    """Get scan status"""
    if not fingerprinter_available:
        return jsonify({"error": "Service Fingerprinting Pro not available"}), 500
    
    try:
        fp = get_service_fingerprinter()
        status = fp.get_job_status(job_id)
        
        if not status:
            return jsonify({"error": "Job not found"}), 404
        
        return jsonify(status)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@service_fingerprinter_bp.route('/api/service-fingerprinter/results/<job_id>')
def scan_results(job_id):
    """Get scan results"""
    if not fingerprinter_available:
        return jsonify({"error": "Service Fingerprinting Pro not available"}), 500
    
    try:
        fp = get_service_fingerprinter()
        results = fp.get_job_results(job_id)
        
        if not results:
            return jsonify({"error": "Job not found"}), 404
        
        return jsonify(results)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@service_fingerprinter_bp.route('/api/service-fingerprinter/fingerprints/<job_id>')
def get_fingerprints(job_id):
    """Get service fingerprints"""
    if not fingerprinter_available:
        return jsonify({"error": "Service Fingerprinting Pro not available"}), 500
    
    try:
        fp = get_service_fingerprinter()
        results = fp.get_job_results(job_id)
        
        if not results:
            return jsonify({"error": "Job not found"}), 404
        
        return jsonify({"fingerprints": results['fingerprints']})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@service_fingerprinter_bp.route('/api/service-fingerprinter/cves/<job_id>')
def get_cves(job_id):
    """Get CVE matches"""
    if not fingerprinter_available:
        return jsonify({"error": "Service Fingerprinting Pro not available"}), 500
    
    try:
        fp = get_service_fingerprinter()
        results = fp.get_job_results(job_id)
        
        if not results:
            return jsonify({"error": "Job not found"}), 404
        
        return jsonify({"cve_matches": results['cve_matches']})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@service_fingerprinter_bp.route('/api/service-fingerprinter/exploits/<job_id>')
def get_exploits(job_id):
    """Get exploit recommendations"""
    if not fingerprinter_available:
        return jsonify({"error": "Service Fingerprinting Pro not available"}), 500
    
    try:
        fp = get_service_fingerprinter()
        results = fp.get_job_results(job_id)
        
        if not results:
            return jsonify({"error": "Job not found"}), 404
        
        return jsonify({"exploits": results['exploits']})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
