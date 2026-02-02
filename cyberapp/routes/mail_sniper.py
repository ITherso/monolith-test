"""
Mail Sniper Flask Routes
========================
Email keyword arama ve export API endpoint'leri.
"""

from flask import Blueprint, render_template, request, jsonify, Response, send_file
import json
import sys
import os

# Add tools to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

bp = Blueprint('mail_sniper', __name__, url_prefix='/mail-sniper')


@bp.route('/')
def index():
    """Mail Sniper dashboard"""
    return render_template('mail_sniper.html')


@bp.route('/api/keywords', methods=['GET'])
def get_keywords():
    """Get default keywords"""
    try:
        from mail_sniper import get_sniper
        
        sniper = get_sniper()
        
        return jsonify({
            "status": "success",
            "keywords": sniper.keywords
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/keywords', methods=['POST'])
def set_keywords():
    """Add keywords to search list"""
    try:
        from mail_sniper import get_sniper
        
        data = request.get_json() or {}
        keywords = data.get('keywords', [])
        
        sniper = get_sniper()
        sniper.add_keywords(keywords)
        
        return jsonify({
            "status": "success",
            "keywords": sniper.keywords
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/sources', methods=['GET'])
def get_sources():
    """Get supported email sources"""
    try:
        from mail_sniper import EmailSource
        
        sources = [{"name": s.value, "key": s.name} for s in EmailSource]
        
        return jsonify({
            "status": "success",
            "sources": sources
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/search/directory', methods=['POST'])
def search_directory():
    """Search EML files in directory"""
    try:
        from mail_sniper import get_sniper, SearchQuery
        
        data = request.get_json() or {}
        directory = data.get('directory')
        keywords = data.get('keywords', [])
        folders = data.get('folders', ['Inbox', 'Sent Items'])
        max_results = data.get('max_results', 1000)
        
        if not directory:
            return jsonify({
                "status": "error",
                "message": "Directory path required"
            }), 400
        
        sniper = get_sniper()
        
        if keywords:
            sniper.add_keywords(keywords)
        
        query = SearchQuery(
            keywords=sniper.keywords,
            folders=folders,
            max_results=max_results
        )
        
        results = sniper.search_directory(directory, query)
        
        return jsonify({
            "status": "success",
            "count": len(results),
            "results": [m.to_dict() for m in results]
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/search/pst', methods=['POST'])
def search_pst():
    """Search Outlook PST file"""
    try:
        from mail_sniper import get_sniper, SearchQuery
        
        data = request.get_json() or {}
        pst_path = data.get('pst_path')
        keywords = data.get('keywords', [])
        folders = data.get('folders', ['Inbox', 'Sent Items'])
        max_results = data.get('max_results', 1000)
        
        if not pst_path:
            return jsonify({
                "status": "error",
                "message": "PST file path required"
            }), 400
        
        sniper = get_sniper()
        
        if keywords:
            sniper.add_keywords(keywords)
        
        query = SearchQuery(
            keywords=sniper.keywords,
            folders=folders,
            max_results=max_results
        )
        
        results = sniper.search_pst_file(pst_path, query)
        
        return jsonify({
            "status": "success",
            "count": len(results),
            "results": [m.to_dict() for m in results]
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/connect/exchange', methods=['POST'])
def connect_exchange():
    """Connect to Exchange server"""
    try:
        from mail_sniper import get_sniper
        
        data = request.get_json() or {}
        server = data.get('server')
        username = data.get('username')
        password = data.get('password')
        domain = data.get('domain')
        
        if not all([server, username, password]):
            return jsonify({
                "status": "error",
                "message": "Server, username and password required"
            }), 400
        
        sniper = get_sniper()
        success = sniper.connect_exchange(server, username, password, domain)
        
        if success:
            return jsonify({
                "status": "success",
                "message": "Connected to Exchange"
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Failed to connect to Exchange"
            }), 401
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/search/exchange', methods=['POST'])
def search_exchange():
    """Search Exchange mailbox"""
    try:
        from mail_sniper import get_sniper, SearchQuery
        from datetime import datetime
        
        data = request.get_json() or {}
        keywords = data.get('keywords', [])
        folders = data.get('folders', ['Inbox', 'Sent Items'])
        date_from = data.get('date_from')
        date_to = data.get('date_to')
        max_results = data.get('max_results', 1000)
        
        sniper = get_sniper()
        
        if keywords:
            sniper.add_keywords(keywords)
        
        # Parse dates
        df = datetime.fromisoformat(date_from) if date_from else None
        dt = datetime.fromisoformat(date_to) if date_to else None
        
        query = SearchQuery(
            keywords=sniper.keywords,
            folders=folders,
            date_from=df,
            date_to=dt,
            max_results=max_results
        )
        
        results = sniper.search_exchange(query)
        
        return jsonify({
            "status": "success",
            "count": len(results),
            "results": [m.to_dict() for m in results]
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/connect/imap', methods=['POST'])
def connect_imap():
    """Connect to IMAP server"""
    try:
        from mail_sniper import get_sniper
        
        data = request.get_json() or {}
        server = data.get('server')
        username = data.get('username')
        password = data.get('password')
        port = data.get('port', 993)
        use_ssl = data.get('use_ssl', True)
        
        if not all([server, username, password]):
            return jsonify({
                "status": "error",
                "message": "Server, username and password required"
            }), 400
        
        sniper = get_sniper()
        success = sniper.connect_imap(server, username, password, port, use_ssl)
        
        if success:
            return jsonify({
                "status": "success",
                "message": "Connected to IMAP"
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Failed to connect to IMAP"
            }), 401
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/search/imap', methods=['POST'])
def search_imap():
    """Search IMAP mailbox"""
    try:
        from mail_sniper import get_sniper, SearchQuery
        
        data = request.get_json() or {}
        keywords = data.get('keywords', [])
        folders = data.get('folders', ['INBOX'])
        max_results = data.get('max_results', 1000)
        
        sniper = get_sniper()
        
        if keywords:
            sniper.add_keywords(keywords)
        
        query = SearchQuery(
            keywords=sniper.keywords,
            folders=folders,
            max_results=max_results
        )
        
        results = sniper.search_imap(query)
        
        return jsonify({
            "status": "success",
            "count": len(results),
            "results": [m.to_dict() for m in results]
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/export/json', methods=['GET'])
def export_json():
    """Export results to JSON"""
    try:
        from mail_sniper import get_sniper
        
        sniper = get_sniper()
        export_dir = sniper.export_results()
        
        # Read the JSON file
        json_path = os.path.join(export_dir, "search_results.json")
        with open(json_path, 'r', encoding='utf-8') as f:
            json_data = f.read()
        
        return Response(
            json_data,
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment; filename=mail_sniper_results.json'}
        )
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/export/zip', methods=['GET'])
def export_zip():
    """Export results as ZIP archive"""
    try:
        from mail_sniper import get_sniper
        
        sniper = get_sniper()
        zip_path = sniper.create_zip_archive()
        
        return send_file(
            zip_path,
            mimetype='application/zip',
            as_attachment=True,
            download_name='mail_sniper_results.zip'
        )
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/generate/powershell', methods=['GET'])
def generate_powershell():
    """Generate PowerShell sniper script"""
    try:
        from mail_sniper import get_sniper
        
        sniper = get_sniper()
        ps_script = sniper.generate_powershell_sniper()
        
        return Response(
            ps_script,
            mimetype='text/plain',
            headers={'Content-Disposition': 'attachment; filename=mail_sniper.ps1'}
        )
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/generate/vba', methods=['GET'])
def generate_vba():
    """Generate VBA macro"""
    try:
        from mail_sniper import get_sniper
        
        sniper = get_sniper()
        vba_code = sniper.generate_vba_macro()
        
        return Response(
            vba_code,
            mimetype='text/plain',
            headers={'Content-Disposition': 'attachment; filename=mail_sniper.vba'}
        )
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/statistics', methods=['GET'])
def get_statistics():
    """Get search statistics"""
    try:
        from mail_sniper import get_sniper
        
        sniper = get_sniper()
        stats = sniper.get_statistics()
        
        return jsonify({
            "status": "success",
            "statistics": stats
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
