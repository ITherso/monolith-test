"""
WiFi Grabber Flask Routes
=========================
WiFi şifre çıkarma ve analiz API endpoint'leri.
"""

from flask import Blueprint, render_template, request, jsonify, Response
import json
import sys
import os

# Add tools to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

bp = Blueprint('wifi_grabber', __name__, url_prefix='/wifi-grabber')


@bp.route('/')
def index():
    """WiFi Grabber dashboard"""
    return render_template('wifi_grabber.html')


@bp.route('/api/profiles', methods=['GET'])
def get_profiles():
    """Get list of saved WiFi profiles"""
    try:
        from wifi_grabber import get_grabber
        
        grabber = get_grabber()
        profiles = grabber.get_saved_profiles()
        
        return jsonify({
            "status": "success",
            "count": len(profiles),
            "profiles": profiles
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/profile/<profile_name>', methods=['GET'])
def get_profile(profile_name: str):
    """Get details for a specific WiFi profile"""
    try:
        from wifi_grabber import get_grabber
        
        grabber = get_grabber()
        network = grabber.get_profile_details(profile_name)
        
        if network:
            return jsonify({
                "status": "success",
                "network": network.to_dict()
            })
        else:
            return jsonify({
                "status": "error",
                "message": f"Profile not found: {profile_name}"
            }), 404
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/extract/all', methods=['POST'])
def extract_all():
    """Extract all WiFi networks with passwords"""
    try:
        from wifi_grabber import get_grabber
        
        grabber = get_grabber()
        networks = grabber.extract_all()
        
        return jsonify({
            "status": "success",
            "count": len(networks),
            "networks": [n.to_dict() for n in networks]
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/analyze/patterns', methods=['POST'])
def analyze_patterns():
    """Analyze password patterns"""
    try:
        from wifi_grabber import get_grabber
        
        grabber = get_grabber()
        
        # Make sure we have networks
        if not grabber.networks:
            grabber.extract_all()
        
        patterns = grabber.analyze_patterns()
        
        return jsonify({
            "status": "success",
            "count": len(patterns),
            "patterns": [p.to_dict() for p in patterns]
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/analyze/branches', methods=['POST'])
def analyze_branches():
    """Analyze WiFi across corporate branches"""
    try:
        from wifi_grabber import get_grabber
        
        grabber = get_grabber()
        
        # Make sure we have networks
        if not grabber.networks:
            grabber.extract_all()
        
        branches = grabber.analyze_branches()
        
        return jsonify({
            "status": "success",
            "count": len(branches),
            "branches": [b.to_dict() for b in branches]
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/search', methods=['POST'])
def search_networks():
    """Search networks by domain keywords"""
    try:
        from wifi_grabber import get_grabber
        
        data = request.get_json() or {}
        keywords = data.get('keywords', [])
        
        if not keywords:
            return jsonify({
                "status": "error",
                "message": "No keywords provided"
            }), 400
        
        grabber = get_grabber()
        
        # Make sure we have networks
        if not grabber.networks:
            grabber.extract_all()
        
        matching = grabber.get_networks_for_domain(keywords)
        
        return jsonify({
            "status": "success",
            "count": len(matching),
            "networks": [n.to_dict() for n in matching]
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/export/json', methods=['GET'])
def export_json():
    """Export networks to JSON"""
    try:
        from wifi_grabber import get_grabber
        
        grabber = get_grabber()
        json_data = grabber.export_json()
        
        return Response(
            json_data,
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment; filename=wifi_networks.json'}
        )
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/export/csv', methods=['GET'])
def export_csv():
    """Export networks to CSV"""
    try:
        from wifi_grabber import get_grabber
        
        grabber = get_grabber()
        csv_data = grabber.export_csv()
        
        return Response(
            csv_data,
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=wifi_networks.csv'}
        )
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/export/wpa-supplicant', methods=['GET'])
def export_wpa_supplicant():
    """Export to wpa_supplicant.conf format"""
    try:
        from wifi_grabber import get_grabber
        
        grabber = get_grabber()
        wpa_data = grabber.export_wpa_supplicant()
        
        return Response(
            wpa_data,
            mimetype='text/plain',
            headers={'Content-Disposition': 'attachment; filename=wpa_supplicant.conf'}
        )
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/generate/powershell', methods=['GET'])
def generate_powershell():
    """Generate PowerShell grabber script"""
    try:
        from wifi_grabber import get_grabber
        
        grabber = get_grabber()
        ps_script = grabber.generate_powershell_grabber()
        
        return Response(
            ps_script,
            mimetype='text/plain',
            headers={'Content-Disposition': 'attachment; filename=wifi_grabber.ps1'}
        )
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/generate/batch', methods=['GET'])
def generate_batch():
    """Generate batch file grabber"""
    try:
        from wifi_grabber import get_grabber
        
        grabber = get_grabber()
        batch_script = grabber.generate_batch_grabber()
        
        return Response(
            batch_script,
            mimetype='text/plain',
            headers={'Content-Disposition': 'attachment; filename=wifi_grabber.bat'}
        )
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/statistics', methods=['GET'])
def get_statistics():
    """Get WiFi extraction statistics"""
    try:
        from wifi_grabber import get_grabber
        
        grabber = get_grabber()
        stats = grabber.get_statistics()
        
        return jsonify({
            "status": "success",
            "statistics": stats
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
