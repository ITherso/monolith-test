"""
Tools Routes
============
API endpoints for web security tools

Endpoints:
- Web Vulnerability Scanner
- Web Exfiltration Module
"""

from flask import Blueprint, request, jsonify, render_template
import logging
import json
import os

logger = logging.getLogger("tools_routes")

tools_bp = Blueprint('tools', __name__, url_prefix='/tools')


# ============================================================
# WEB VULNERABILITY SCANNER
# ============================================================

_web_vuln_scanner = None

def _get_web_vuln_scanner():
    """Get or create web vulnerability scanner instance"""
    global _web_vuln_scanner
    if _web_vuln_scanner is None:
        try:
            from tools.web_vuln_scanner import WebVulnScanner
            _web_vuln_scanner = WebVulnScanner()
        except Exception as e:
            logger.warning(f"Web vuln scanner import failed: {e}")
            return None
    return _web_vuln_scanner


@tools_bp.route('/vuln-scanner')
def vuln_scanner_page():
    """Web Vulnerability Scanner page"""
    return render_template('web_vuln_scanner.html')


@tools_bp.route('/api/vuln-scanner/categories')
def vuln_scanner_categories():
    """Get vulnerability categories"""
    scanner = _get_web_vuln_scanner()
    if not scanner:
        return jsonify([])
    return jsonify(scanner.get_vuln_categories())


@tools_bp.route('/api/vuln-scanner/chains')
def vuln_scanner_chains():
    """Get exploit chain templates"""
    scanner = _get_web_vuln_scanner()
    if not scanner:
        return jsonify([])
    return jsonify(scanner.get_exploit_chains())


@tools_bp.route('/api/vuln-scanner/scan', methods=['POST'])
def vuln_scanner_scan():
    """Run vulnerability scan"""
    scanner = _get_web_vuln_scanner()
    if not scanner:
        return jsonify({'error': 'Module not available'}), 503
    
    data = request.get_json() or {}
    target_url = data.get('target_url', '')
    
    if not target_url:
        return jsonify({'error': 'Target URL required'}), 400
    
    try:
        from tools.web_vuln_scanner import ScanConfig, VulnCategory
        
        config = ScanConfig(
            target_url=target_url,
            threads=data.get('threads', 10),
            timeout=data.get('timeout', 10),
            proxy=data.get('proxy', ''),
            headers=data.get('headers', {})
        )
        
        # Set categories if provided
        if data.get('categories'):
            config.scan_categories = [
                VulnCategory(c) for c in data['categories']
                if c in [e.value for e in VulnCategory]
            ]
        
        result = scanner.create_scan(config)
        return jsonify(result)
        
    except Exception as e:
        logger.exception("Vulnerability scan error")
        return jsonify({'error': str(e)}), 500


@tools_bp.route('/api/vuln-scanner/result/<scan_id>')
def vuln_scanner_result(scan_id):
    """Get scan result"""
    scanner = _get_web_vuln_scanner()
    if not scanner:
        return jsonify({'error': 'Module not available'}), 503
    
    result = scanner.get_scan_result(scan_id)
    if not result:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(result)


@tools_bp.route('/api/vuln-scanner/stats')
def vuln_scanner_stats():
    """Get scanner statistics"""
    scanner = _get_web_vuln_scanner()
    if not scanner:
        return jsonify({})
    return jsonify(scanner.get_stats())


# ============================================================
# WEB EXFILTRATION MODULE
# ============================================================

_web_exfil = None

def _get_web_exfil():
    """Get or create web exfil instance"""
    global _web_exfil
    if _web_exfil is None:
        try:
            from tools.web_exfil import get_web_exfil
            _web_exfil = get_web_exfil()
        except Exception as e:
            logger.warning(f"Web exfil import failed: {e}")
            return None
    return _web_exfil


@tools_bp.route('/exfil')
def exfil_page():
    """Web Exfiltration page"""
    return render_template('web_exfil.html')


@tools_bp.route('/api/exfil/methods')
def exfil_methods():
    """Get exfiltration methods"""
    exfil = _get_web_exfil()
    if not exfil:
        return jsonify([])
    return jsonify(exfil.get_exfil_methods())


@tools_bp.route('/api/exfil/encodings')
def exfil_encodings():
    """Get encoding types"""
    exfil = _get_web_exfil()
    if not exfil:
        return jsonify([])
    return jsonify(exfil.get_encoding_types())


@tools_bp.route('/api/exfil/stego-methods')
def exfil_stego_methods():
    """Get steganography methods"""
    exfil = _get_web_exfil()
    if not exfil:
        return jsonify([])
    return jsonify(exfil.get_stego_methods())


@tools_bp.route('/api/exfil/jobs')
def exfil_jobs():
    """List exfiltration jobs"""
    exfil = _get_web_exfil()
    if not exfil:
        return jsonify([])
    return jsonify(exfil.list_jobs())


@tools_bp.route('/api/exfil/job/<job_id>')
def exfil_job(job_id):
    """Get job status"""
    exfil = _get_web_exfil()
    if not exfil:
        return jsonify({'error': 'Module not available'}), 503
    
    job = exfil.get_job(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    
    return jsonify(job)


@tools_bp.route('/api/exfil/start', methods=['POST'])
def exfil_start():
    """Start exfiltration job"""
    exfil = _get_web_exfil()
    if not exfil:
        return jsonify({'error': 'Module not available'}), 503
    
    # Check if file upload
    if 'file' in request.files:
        file = request.files['file']
        config_json = request.form.get('config', '{}')
        config_data = json.loads(config_json)
        
        data = file.read()
        filename = file.filename
        
    else:
        data_json = request.get_json() or {}
        data = data_json.get('data', '').encode()
        filename = data_json.get('filename', 'data.bin')
        config_data = data_json.get('config', {})
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    try:
        config = exfil.create_config(
            method=config_data.get('method', 'http_post'),
            destination=config_data.get('destination', ''),
            encoding=config_data.get('encoding', 'base64'),
            compression=config_data.get('compression', 'gzip'),
            chunk_size=config_data.get('chunk_size', 4096),
            use_stego=config_data.get('use_stego', False),
            stego_method=config_data.get('stego_method', 'lsb_image')
        )
        
        job = exfil.exfiltrate_data(data, filename, config)
        
        return jsonify({
            'success': True,
            'job_id': job.job_id,
            'status': job.status
        })
        
    except Exception as e:
        logger.exception("Exfiltration error")
        return jsonify({'error': str(e)}), 500


@tools_bp.route('/api/exfil/stats')
def exfil_stats():
    """Get exfiltration statistics"""
    exfil = _get_web_exfil()
    if not exfil:
        return jsonify({})
    return jsonify(exfil.get_stats())
