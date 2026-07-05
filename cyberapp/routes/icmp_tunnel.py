"""
ICMP Tunneling Flask Routes
PRO Module - Exotic Exfiltration
"""

from flask import Blueprint, render_template, request, jsonify
import secrets

bp = Blueprint('icmp_tunnel', __name__, url_prefix='/icmp-tunnel')

# Import the ICMP Tunnel module
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

try:
    from icmp_tunnel import ICMPTunnel, TunnelMode, get_icmp_tunnel
except ImportError:
    ICMPTunnel = None
    TunnelMode = None


@bp.route('/')
def index():
    """ICMP Tunnel main page"""
    modes = []
    if TunnelMode:
        modes = [
            {"name": m.name, "value": m.value}
            for m in TunnelMode
        ]
    return render_template('icmp_tunnel.html', modes=modes)


@bp.route('/api/create-session', methods=['POST'])
def create_session():
    """Create new ICMP tunnel session"""
    try:
        data = request.get_json() or {}
        target_ip = data.get('target_ip', '192.168.1.1')
        mode_name = data.get('mode', 'FULL_DUPLEX')
        
        # Get mode
        mode = TunnelMode.FULL_DUPLEX
        if TunnelMode:
            try:
                mode = TunnelMode[mode_name]
            except KeyError:
                pass
        
        tunnel = get_icmp_tunnel(mode)
        
        # Set encryption key
        encryption_key = data.get('encryption_key')
        if encryption_key:
            tunnel.set_encryption_key(encryption_key.encode())
        else:
            tunnel.set_encryption_key(secrets.token_bytes(32))
        
        session = tunnel.create_session(target_ip)
        
        return jsonify({
            "success": True,
            "session": session.to_dict(),
            "tunnel": {
                "mode": tunnel.mode.value,
                "max_payload": tunnel.MAX_PAYLOAD,
                "standard_sizes": tunnel.STANDARD_SIZES
            }
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@bp.route('/api/generate-implant', methods=['POST'])
def generate_implant():
    """Generate ICMP tunnel implant code"""
    try:
        data = request.get_json() or {}
        target_ip = data.get('target_ip', '192.168.1.1')
        language = data.get('language', 'python')
        mode_name = data.get('mode', 'FULL_DUPLEX')
        
        # Get mode
        mode = TunnelMode.FULL_DUPLEX
        if TunnelMode:
            try:
                mode = TunnelMode[mode_name]
            except KeyError:
                pass
        
        tunnel = get_icmp_tunnel(mode)
        tunnel.set_encryption_key(secrets.token_bytes(32))
        session = tunnel.create_session(target_ip)
        
        implant_code = tunnel.generate_implant_code(session, language)
        
        return jsonify({
            "success": True,
            "language": language,
            "code": implant_code,
            "session_id": session.session_id[:16]
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@bp.route('/api/simulate-traffic', methods=['POST'])
def simulate_traffic():
    """Simulate ICMP tunnel traffic for demonstration"""
    try:
        data = request.get_json() or {}
        num_packets = min(data.get('num_packets', 10), 50)
        
        tunnel = get_icmp_tunnel()
        traffic = tunnel.simulate_traffic(num_packets)
        
        return jsonify({
            "success": True,
            "traffic": traffic,
            "analysis": {
                "total_packets": len(traffic),
                "hidden_data_packets": sum(1 for t in traffic if t["contains_data"]),
                "detection_difficulty": "Very Low - Looks like normal ping"
            }
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@bp.route('/api/statistics')
def get_statistics():
    """Get ICMP tunnel statistics"""
    try:
        tunnel = get_icmp_tunnel()
        stats = tunnel.get_statistics()
        return jsonify({"success": True, "statistics": stats})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@bp.route('/api/modes')
def list_modes():
    """List available tunnel modes"""
    modes = []
    if TunnelMode:
        modes = [
            {
                "name": m.name,
                "value": m.value,
                "description": {
                    "HALF_DUPLEX": "Data only in Echo Request",
                    "FULL_DUPLEX": "Data in both Request and Reply",
                    "COVERT_SIZE": "Data encoded in packet sizes",
                    "COVERT_TIMING": "Data encoded in timing"
                }.get(m.name, m.value)
            }
            for m in TunnelMode
        ]
    return jsonify({"success": True, "modes": modes})
