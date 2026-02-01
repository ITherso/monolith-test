"""Cloud Assets Discovery routes"""
from flask import Blueprint, render_template, request, jsonify
import sys
from pathlib import Path

# Add tools to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "tools"))

try:
    from cloud_assets_discovery import get_cloud_assets_discovery
    discovery_available = True
except ImportError:
    discovery_available = False

cloud_assets_bp = Blueprint('cloud_assets', __name__, url_prefix='/tools')


@cloud_assets_bp.route('/cloud-assets')
def cloud_assets_page():
    """Cloud Assets Discovery page"""
    return render_template('cloud_assets.html', discovery_available=discovery_available)


@cloud_assets_bp.route('/api/cloud-assets/scan', methods=['POST'])
def start_scan():
    """Start cloud assets scan"""
    if not discovery_available:
        return jsonify({"error": "Cloud Assets Discovery not available"}), 500
    
    try:
        data = request.get_json()
        providers = data.get('providers', [])
        scan_type = data.get('scan_type', 'quick')
        
        if not providers:
            return jsonify({"error": "At least one provider is required"}), 400
        
        scanner = get_cloud_assets_discovery()
        job_id = scanner.start_scan(providers, scan_type=scan_type)
        
        return jsonify({
            "success": True,
            "job_id": job_id,
            "providers": providers,
            "scan_type": scan_type
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@cloud_assets_bp.route('/api/cloud-assets/status/<job_id>')
def scan_status(job_id):
    """Get scan status"""
    if not discovery_available:
        return jsonify({"error": "Cloud Assets Discovery not available"}), 500
    
    try:
        scanner = get_cloud_assets_discovery()
        status = scanner.get_job_status(job_id)
        
        if not status:
            return jsonify({"error": "Job not found"}), 404
        
        return jsonify(status)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@cloud_assets_bp.route('/api/cloud-assets/results/<job_id>')
def scan_results(job_id):
    """Get scan results"""
    if not discovery_available:
        return jsonify({"error": "Cloud Assets Discovery not available"}), 500
    
    try:
        scanner = get_cloud_assets_discovery()
        results = scanner.get_job_results(job_id)
        
        if not results:
            return jsonify({"error": "Job not found"}), 404
        
        return jsonify(results)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
