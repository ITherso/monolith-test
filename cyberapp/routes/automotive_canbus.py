"""
Automotive & CAN Bus Hacking Flask Routes
==========================================
API endpoints for vehicle exploitation.

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

# Import the Automotive module
try:
    import sys
    sys.path.insert(0, '/home/kali/Desktop/tools')
    from automotive_canbus import get_automotive_hacker
    AUTOMOTIVE_AVAILABLE = True
except ImportError as e:
    print(f"[IMPORT ERROR] automotive_canbus: {e}")
    AUTOMOTIVE_AVAILABLE = False
    get_automotive_hacker = None

automotive_bp = Blueprint('automotive', __name__, url_prefix='/vehicle-ops')


# Default attack payloads (fallback)
DEFAULT_CAN_ATTACKS = {
    "check_engine_light": {"name": "Check Engine Light", "description": "Turn on MIL", "icon": "🔧"},
    "speedometer_max": {"name": "Speedometer Max", "description": "Spike speedometer", "icon": "🏎️"},
    "door_unlock": {"name": "Unlock Doors", "description": "Unlock all doors", "icon": "🔓"},
    "door_lock": {"name": "Lock Doors", "description": "Lock all doors", "icon": "🔒"},
    "horn_honk": {"name": "Horn", "description": "Honk horn", "icon": "📯"},
    "lights_flash": {"name": "Flash Lights", "description": "Flash all lights", "icon": "💡"},
    "radio_max_volume": {"name": "Radio Max", "description": "Max volume", "icon": "🔊"},
    "panic_alarm": {"name": "Panic Alarm", "description": "Trigger alarm", "icon": "🚨"},
    "kill_engine": {"name": "Kill Engine", "description": "Stop engine", "icon": "💀"},
}

DEFAULT_KEY_TECHNIQUES = {
    "simple_replay": {"name": "Simple Replay", "description": "Record and replay signal", "difficulty": "Easy"},
    "rolljam": {"name": "RollJam", "description": "Jam + capture two codes", "difficulty": "Medium"},
    "relay_attack": {"name": "Relay Attack", "description": "Extend passive entry range", "difficulty": "Medium"},
}


# =============================================================================
# MAIN DASHBOARD
# =============================================================================

@automotive_bp.route('/')
@login_required
def automotive_dashboard():
    """Main Automotive Hacking dashboard"""
    if AUTOMOTIVE_AVAILABLE and get_automotive_hacker:
        try:
            hacker = get_automotive_hacker()
            status = hacker.get_status()
            can_attacks = hacker.can_bus.get_available_attacks()
            key_techniques = hacker.keyless.get_attack_techniques()
            vehicle_profiles = hacker.keyless.get_vehicle_profiles()
            vehicle_makes = hacker.get_vehicle_makes()
        except Exception as e:
            print(f"[ERROR] Automotive Hacker: {e}")
            status = {"module": "Automotive & CAN Bus Hacking", "error": str(e)}
            can_attacks = DEFAULT_CAN_ATTACKS
            key_techniques = DEFAULT_KEY_TECHNIQUES
            vehicle_profiles = {}
            vehicle_makes = []
    else:
        status = {"module": "Automotive & CAN Bus Hacking", "version": "1.0.0", "mode": "demo"}
        can_attacks = DEFAULT_CAN_ATTACKS
        key_techniques = DEFAULT_KEY_TECHNIQUES
        vehicle_profiles = {}
        vehicle_makes = ["toyota", "honda", "ford", "bmw", "tesla", "volkswagen", "jeep"]
    
    return render_template(
        'automotive_canbus.html',
        status=status,
        can_attacks=can_attacks,
        key_techniques=key_techniques,
        vehicle_profiles=vehicle_profiles,
        vehicle_makes=vehicle_makes
    )


# =============================================================================
# CAN BUS OPERATIONS
# =============================================================================

@automotive_bp.route('/api/can/connect', methods=['POST'])
@login_required
def can_connect():
    """Connect to CAN interface"""
    if not AUTOMOTIVE_AVAILABLE:
        return jsonify({"success": False, "error": "Module not available"})
    
    data = request.get_json() or {}
    interface = data.get('interface', 'can0')
    
    try:
        hacker = get_automotive_hacker()
        result = hacker.can_bus.connect_obd(interface)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@automotive_bp.route('/api/can/disconnect', methods=['POST'])
@login_required
def can_disconnect():
    """Disconnect from CAN interface"""
    if not AUTOMOTIVE_AVAILABLE:
        return jsonify({"success": False})
    
    try:
        hacker = get_automotive_hacker()
        result = hacker.can_bus.disconnect()
        return jsonify({"success": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@automotive_bp.route('/api/can/detect-vehicle', methods=['POST'])
@login_required
def detect_vehicle():
    """Auto-detect vehicle"""
    if not AUTOMOTIVE_AVAILABLE:
        return jsonify({"success": False, "error": "Module not available"})
    
    try:
        hacker = get_automotive_hacker()
        profile = hacker.can_bus.detect_vehicle()
        
        if profile:
            return jsonify({
                "success": True,
                "make": profile.make,
                "model": profile.model,
                "year": profile.year,
                "protocol": profile.protocol
            })
        return jsonify({"success": False, "error": "Could not detect vehicle"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@automotive_bp.route('/api/can/sniff/start', methods=['POST'])
@login_required
def start_sniffing():
    """Start CAN sniffing"""
    if not AUTOMOTIVE_AVAILABLE:
        return jsonify({"success": False, "error": "Module not available"})
    
    data = request.get_json() or {}
    filter_ids = data.get('filter_ids')
    
    try:
        hacker = get_automotive_hacker()
        result = hacker.can_bus.start_sniffing(filter_ids)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@automotive_bp.route('/api/can/sniff/stop', methods=['POST'])
@login_required
def stop_sniffing():
    """Stop CAN sniffing"""
    if not AUTOMOTIVE_AVAILABLE:
        return jsonify({"success": False})
    
    try:
        hacker = get_automotive_hacker()
        result = hacker.can_bus.stop_sniffing()
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@automotive_bp.route('/api/can/frames', methods=['GET'])
@login_required
def get_frames():
    """Get captured CAN frames"""
    if not AUTOMOTIVE_AVAILABLE:
        return jsonify([])
    
    limit = request.args.get('limit', 100, type=int)
    
    try:
        hacker = get_automotive_hacker()
        frames = hacker.can_bus.get_captured_frames(limit)
        return jsonify(frames)
    except Exception as e:
        return jsonify([])


@automotive_bp.route('/api/can/send', methods=['POST'])
@login_required
def send_frame():
    """Send CAN frame"""
    if not AUTOMOTIVE_AVAILABLE:
        return jsonify({"success": False, "error": "Module not available"})
    
    data = request.get_json() or {}
    can_id = data.get('can_id')
    payload = data.get('payload')
    
    if not can_id or not payload:
        return jsonify({"success": False, "error": "can_id and payload required"})
    
    try:
        hacker = get_automotive_hacker()
        
        # Parse CAN ID (hex string or int)
        if isinstance(can_id, str):
            can_id = int(can_id, 16) if can_id.startswith('0x') else int(can_id, 16)
        
        # Parse payload (hex string)
        if isinstance(payload, str):
            payload = bytes.fromhex(payload.replace(' ', ''))
        
        result = hacker.can_bus.send_frame(can_id, payload)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@automotive_bp.route('/api/can/attack', methods=['POST'])
@login_required
def execute_attack():
    """Execute CAN attack"""
    if not AUTOMOTIVE_AVAILABLE:
        return jsonify({"success": False, "error": "Module not available"})
    
    data = request.get_json() or {}
    attack_name = data.get('attack')
    
    if not attack_name:
        return jsonify({"success": False, "error": "attack name required"})
    
    try:
        hacker = get_automotive_hacker()
        result = hacker.can_bus.execute_attack(attack_name)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@automotive_bp.route('/api/can/attacks', methods=['GET'])
@login_required
def get_attacks():
    """Get available CAN attacks"""
    if not AUTOMOTIVE_AVAILABLE:
        return jsonify(DEFAULT_CAN_ATTACKS)
    
    try:
        hacker = get_automotive_hacker()
        return jsonify(hacker.can_bus.get_available_attacks())
    except:
        return jsonify(DEFAULT_CAN_ATTACKS)


# =============================================================================
# KEYLESS ENTRY OPERATIONS
# =============================================================================

@automotive_bp.route('/api/keyless/connect', methods=['POST'])
@login_required
def keyless_connect():
    """Connect SDR device"""
    if not AUTOMOTIVE_AVAILABLE:
        return jsonify({"success": False, "error": "Module not available"})
    
    data = request.get_json() or {}
    device = data.get('device', 'hackrf')
    
    try:
        hacker = get_automotive_hacker()
        result = hacker.keyless.connect_sdr(device)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@automotive_bp.route('/api/keyless/frequency', methods=['POST'])
@login_required
def set_frequency():
    """Set target frequency"""
    if not AUTOMOTIVE_AVAILABLE:
        return jsonify({"success": False, "error": "Module not available"})
    
    data = request.get_json() or {}
    frequency = data.get('frequency', 315.0)
    
    try:
        hacker = get_automotive_hacker()
        result = hacker.keyless.set_frequency(frequency)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@automotive_bp.route('/api/keyless/listen/start', methods=['POST'])
@login_required
def start_listening():
    """Start listening for signals"""
    if not AUTOMOTIVE_AVAILABLE:
        return jsonify({"success": False, "error": "Module not available"})
    
    try:
        hacker = get_automotive_hacker()
        result = hacker.keyless.start_listening()
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@automotive_bp.route('/api/keyless/listen/stop', methods=['POST'])
@login_required
def stop_listening():
    """Stop listening"""
    if not AUTOMOTIVE_AVAILABLE:
        return jsonify({"success": False})
    
    try:
        hacker = get_automotive_hacker()
        result = hacker.keyless.stop_listening()
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@automotive_bp.route('/api/keyless/capture', methods=['POST'])
@login_required
def capture_signal():
    """Capture key fob signal"""
    if not AUTOMOTIVE_AVAILABLE:
        return jsonify({"success": False, "error": "Module not available"})
    
    data = request.get_json() or {}
    signal_type = data.get('signal_type', 'unlock')
    
    try:
        hacker = get_automotive_hacker()
        result = hacker.keyless.capture_signal(signal_type)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@automotive_bp.route('/api/keyless/replay', methods=['POST'])
@login_required
def replay_signal():
    """Replay captured signal"""
    if not AUTOMOTIVE_AVAILABLE:
        return jsonify({"success": False, "error": "Module not available"})
    
    data = request.get_json() or {}
    signal_id = data.get('signal_id')
    
    if not signal_id:
        return jsonify({"success": False, "error": "signal_id required"})
    
    try:
        hacker = get_automotive_hacker()
        result = hacker.keyless.replay_signal(signal_id)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@automotive_bp.route('/api/keyless/jammer/start', methods=['POST'])
@login_required
def start_jammer():
    """Start RF jammer"""
    if not AUTOMOTIVE_AVAILABLE:
        return jsonify({"success": False, "error": "Module not available"})
    
    data = request.get_json() or {}
    duration = data.get('duration', 30)
    
    try:
        hacker = get_automotive_hacker()
        result = hacker.keyless.start_jammer(duration)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@automotive_bp.route('/api/keyless/jammer/stop', methods=['POST'])
@login_required
def stop_jammer():
    """Stop RF jammer"""
    if not AUTOMOTIVE_AVAILABLE:
        return jsonify({"success": False})
    
    try:
        hacker = get_automotive_hacker()
        result = hacker.keyless.stop_jammer()
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@automotive_bp.route('/api/keyless/signals', methods=['GET'])
@login_required
def get_signals():
    """Get captured signals"""
    if not AUTOMOTIVE_AVAILABLE:
        return jsonify([])
    
    try:
        hacker = get_automotive_hacker()
        return jsonify(hacker.keyless.get_captured_signals())
    except:
        return jsonify([])


@automotive_bp.route('/api/keyless/techniques', methods=['GET'])
@login_required
def get_techniques():
    """Get attack techniques"""
    if not AUTOMOTIVE_AVAILABLE:
        return jsonify(DEFAULT_KEY_TECHNIQUES)
    
    try:
        hacker = get_automotive_hacker()
        return jsonify(hacker.keyless.get_attack_techniques())
    except:
        return jsonify(DEFAULT_KEY_TECHNIQUES)


@automotive_bp.route('/api/keyless/profiles', methods=['GET'])
@login_required
def get_profiles():
    """Get vehicle key fob profiles"""
    if not AUTOMOTIVE_AVAILABLE:
        return jsonify({})
    
    try:
        hacker = get_automotive_hacker()
        return jsonify(hacker.keyless.get_vehicle_profiles())
    except:
        return jsonify({})


# =============================================================================
# STATUS
# =============================================================================

@automotive_bp.route('/api/status', methods=['GET'])
@login_required
def get_status():
    """Get module status"""
    if not AUTOMOTIVE_AVAILABLE:
        return jsonify({"module": "Automotive Hacking", "mode": "demo"})
    
    try:
        hacker = get_automotive_hacker()
        return jsonify(hacker.get_status())
    except Exception as e:
        return jsonify({"error": str(e)})


# =============================================================================
# ERROR HANDLER
# =============================================================================

@automotive_bp.errorhandler(Exception)
def handle_error(error):
    """Global error handler"""
    return jsonify({
        "success": False,
        "error": str(error),
        "type": type(error).__name__
    }), 500
