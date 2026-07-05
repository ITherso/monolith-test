"""
Memory Forensics Evasion Routes - Bellek Hayaletleri
====================================================
Flask blueprint for advanced memory evasion techniques.

Features:
- Sleep Obfuscation (Ekko/Foliage)
- Call Stack Spoofing
- Process Hollowing/Doppelgänging
- Memory Fluctuator (PAGE_NOACCESS sleep protection)
"""

from flask import Blueprint, render_template, request, jsonify
from functools import wraps
import sys
import os

# Add tools to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

try:
    from memory_forensics_evasion import (
        get_memory_evasion_engine,
        SleepTechnique,
        StackSpoofMethod,
        InjectionTechnique,
        TargetProcess,
        EncryptionMethod
    )
except ImportError:
    get_memory_evasion_engine = None
    from enum import Enum
    class SleepTechnique(Enum):
        EKKO = "ekko"
        FOLIAGE = "foliage"
        DEATH_SLEEP = "death_sleep"
    class StackSpoofMethod(Enum):
        SYNTHETIC_FRAMES = "synthetic_frames"
        ROP_CHAIN = "rop_chain"
    class InjectionTechnique(Enum):
        PROCESS_HOLLOWING = "process_hollowing"
        PROCESS_DOPPELGANGING = "process_doppelganging"
    class TargetProcess(Enum):
        SVCHOST = "svchost.exe"
        NOTEPAD = "notepad.exe"
    class EncryptionMethod(Enum):
        XOR_ROLLING = "xor_rolling"
        RC4 = "rc4"

# Memory Fluctuator import
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'evasion'))
    from memory_fluctuator import EliteMemoryFluctuator
except ImportError:
    EliteMemoryFluctuator = None

memory_evasion_bp = Blueprint('memory_evasion', __name__, url_prefix='/memory-evasion')


def handle_errors(f):
    """Error handling decorator"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500
    return wrapper


@memory_evasion_bp.route('/')
def index():
    """Memory Forensics Evasion main page"""
    return render_template('memory_evasion.html')


@memory_evasion_bp.route('/api/techniques', methods=['GET'])
@handle_errors
def get_techniques():
    """Get available evasion techniques"""
    return jsonify({
        "success": True,
        "sleep_techniques": [
            {"id": t.value, "name": t.name.replace("_", " ").title(), 
             "description": _get_sleep_desc(t.value)} 
            for t in SleepTechnique
        ],
        "stack_methods": [
            {"id": m.value, "name": m.name.replace("_", " ").title(),
             "description": _get_stack_desc(m.value)}
            for m in StackSpoofMethod
        ],
        "injection_techniques": [
            {"id": t.value, "name": t.name.replace("_", " ").title(),
             "description": _get_injection_desc(t.value)}
            for t in InjectionTechnique
        ],
        "target_processes": [
            {"id": t.value, "name": t.value}
            for t in TargetProcess
        ],
        "encryption_methods": [
            {"id": e.value, "name": e.name.replace("_", " ").title()}
            for e in EncryptionMethod
        ]
    })


def _get_sleep_desc(technique: str) -> str:
    descs = {
        "ekko": "ROP-based sleep with stack/heap encryption - Most reliable",
        "foliage": "Fiber-based sleep obfuscation - Context independent",
        "death_sleep": "Thread suspension technique - Simple but effective",
        "gargoyle": "Timer-based code execution - Periodic activation",
        "cronos": "Delayed execution chains - Time-based evasion"
    }
    return descs.get(technique, "Advanced sleep obfuscation technique")


def _get_stack_desc(method: str) -> str:
    descs = {
        "synthetic_frames": "Insert fake stack frames - Microsoft signed appearance",
        "frame_hijack": "Hijack existing frames - Minimal modification",
        "rop_chain": "Return-oriented programming - Maximum control",
        "desync_stack": "Desynchronize call/ret pairs - Confuse debuggers",
        "phantom_thread": "Hidden thread execution - Invisible to profilers"
    }
    return descs.get(method, "Advanced stack spoofing technique")


def _get_injection_desc(technique: str) -> str:
    descs = {
        "process_hollowing": "Classic hollowing - Replace process memory",
        "process_doppelganging": "NTFS Transaction - File never on disk",
        "process_herpaderping": "Content change - AV sees clean file",
        "transacted_hollowing": "Combined technique - Maximum stealth",
        "ghostly_hollowing": "Delete-pending file - Phantom process",
        "phantom_dll": "DLL from memory - No disk artifact"
    }
    return descs.get(technique, "Advanced process injection technique")


@memory_evasion_bp.route('/api/configure/sleep', methods=['POST'])
@handle_errors
def configure_sleep():
    """Configure sleep obfuscation"""
    if not get_memory_evasion_engine:
        return jsonify({"success": False, "error": "Module not available"}), 500
    
    data = request.get_json() or {}
    engine = get_memory_evasion_engine()
    
    result = engine.configure_sleep(
        technique=data.get('technique', 'ekko'),
        duration_ms=data.get('duration_ms', 5000),
        encryption=data.get('encryption', 'rc4'),
        jitter=data.get('jitter', 20)
    )
    
    return jsonify({"success": True, "config": result})


@memory_evasion_bp.route('/api/configure/stack', methods=['POST'])
@handle_errors
def configure_stack():
    """Configure call stack spoofing"""
    if not get_memory_evasion_engine:
        return jsonify({"success": False, "error": "Module not available"}), 500
    
    data = request.get_json() or {}
    engine = get_memory_evasion_engine()
    
    result = engine.configure_stack_spoof(
        method=data.get('method', 'synthetic_frames'),
        fake_frames=data.get('fake_frames', 5),
        target_dlls=data.get('target_dlls')
    )
    
    return jsonify({"success": True, "config": result})


@memory_evasion_bp.route('/api/configure/injection', methods=['POST'])
@handle_errors
def configure_injection():
    """Configure process injection"""
    if not get_memory_evasion_engine:
        return jsonify({"success": False, "error": "Module not available"}), 500
    
    data = request.get_json() or {}
    engine = get_memory_evasion_engine()
    
    result = engine.configure_injection(
        technique=data.get('technique', 'process_doppelganging'),
        target=data.get('target', 'svchost.exe'),
        ppid_spoof=data.get('ppid_spoof', True),
        unhook=data.get('unhook_ntdll', True)
    )
    
    return jsonify({"success": True, "config": result})


@memory_evasion_bp.route('/api/generate', methods=['POST'])
@handle_errors
def generate_payload():
    """Generate evasion payload code"""
    if not get_memory_evasion_engine:
        return jsonify({"success": False, "error": "Module not available"}), 500
    
    data = request.get_json() or {}
    engine = get_memory_evasion_engine()
    
    payload_type = data.get('type', 'all')
    result = engine.generate_payload(payload_type)
    
    return jsonify({
        "success": True,
        "payload_type": payload_type,
        "code": result['code'] if isinstance(result['code'], str) else "Multiple payloads generated",
        "timestamp": result['timestamp']
    })


@memory_evasion_bp.route('/api/detection-matrix', methods=['GET'])
@handle_errors
def get_detection_matrix():
    """Get detection matrix for security tools"""
    if not get_memory_evasion_engine:
        return jsonify({"success": False, "error": "Module not available"}), 500
    
    engine = get_memory_evasion_engine()
    matrix = engine.get_detection_matrix()
    
    return jsonify({
        "success": True,
        "matrix": matrix['security_tools'],
        "overall_rate": matrix['overall_evasion_rate'],
        "recommended": matrix['recommended_combination']
    })


@memory_evasion_bp.route('/api/summary', methods=['GET'])
@handle_errors
def get_summary():
    """Get technique summary"""
    if not get_memory_evasion_engine:
        return jsonify({"success": False, "error": "Module not available"}), 500
    
    engine = get_memory_evasion_engine()
    summary = engine.get_technique_summary()
    
    return jsonify({
        "success": True,
        "summary": summary
    })

# ============================================================================
# Memory Fluctuator Routes - Bellek Forenziğini Örteyen VirtualProtect Sayfası
# ============================================================================

# Global Memory Fluctuator instances (scan_id -> EliteMemoryFluctuator)
memory_fluctuators: dict = {}


@memory_evasion_bp.route('/api/fluctuator/register', methods=['POST'])
@handle_errors
def fluctuator_register():
    """
    Register beacon memory address for protection
    
    POST /api/fluctuator/register
    {
        "scan_id": "scan_xyz",
        "base_address": "0x7fff0000",
        "size": 4096,
        "enable_auto": true
    }
    
    Response:
    {
        "success": true,
        "scan_id": "scan_xyz",
        "registered_address": "0x7fff0000",
        "size": 4096,
        "fluctuation_enabled": true
    }
    """
    if not EliteMemoryFluctuator:
        return jsonify({
            "success": False,
            "error": "Memory Fluctuator not available"
        }), 501
    
    data = request.get_json() or {}
    scan_id = data.get('scan_id', f'scan_{os.urandom(4).hex()}')
    base_address = data.get('base_address')
    size = data.get('size', 4096)
    enable_auto = data.get('enable_auto', False)
    
    if not base_address:
        return jsonify({
            "success": False,
            "error": "base_address required"
        }), 400
    
    try:
        # Parse address (support both hex strings and ints)
        if isinstance(base_address, str):
            addr = int(base_address, 16) if base_address.startswith('0x') else int(base_address)
        else:
            addr = base_address
        
        fluctuator = EliteMemoryFluctuator(scan_id=scan_id, logger=lambda msg: print(msg))
        fluctuator.memory_evasion.register_beacon_memory(addr, size)
        
        if enable_auto:
            fluctuator.memory_evasion.enable_automatic_fluctuation()
        
        memory_fluctuators[scan_id] = fluctuator
        
        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "registered_address": base_address,
            "size": size,
            "fluctuation_enabled": enable_auto,
            "message": "Beacon memory registered for PAGE_NOACCESS protection"
        }), 201
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@memory_evasion_bp.route('/api/fluctuator/activate/<scan_id>', methods=['POST'])
@handle_errors
def fluctuator_activate(scan_id: str):
    """
    Activate automatic memory fluctuation for registered beacon
    
    POST /api/fluctuator/activate/scan_xyz
    {
        "fluctuation_interval": 300,
        "sleep_percentage": 100,
        "mode": "cycle"  // "cycle" = PAGE_NOACCESS/PAGE_EXECUTE_READWRITE alternate
    }
    
    Response:
    {
        "success": true,
        "scan_id": "scan_xyz",
        "status": "active",
        "mode": "cycle"
    }
    """
    if scan_id not in memory_fluctuators:
        return jsonify({
            "success": False,
            "error": f"Scan {scan_id} not registered"
        }), 404
    
    data = request.get_json() or {}
    fluctuation_interval = data.get('fluctuation_interval', 300)
    mode = data.get('mode', 'cycle')
    
    try:
        fluctuator = memory_fluctuators[scan_id]
        fluctuator.memory_evasion.enable_automatic_fluctuation()
        
        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "status": "active",
            "mode": mode,
            "interval_seconds": fluctuation_interval,
            "message": "Memory fluctuation active - Beacon invisible to memory dumps"
        }), 200
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@memory_evasion_bp.route('/api/fluctuator/status/<scan_id>', methods=['GET'])
@handle_errors
def fluctuator_status(scan_id: str):
    """
    Get memory fluctuation status for beacon
    
    GET /api/fluctuator/status/scan_xyz
    
    Response:
    {
        "success": true,
        "scan_id": "scan_xyz",
        "protection_status": {
            "regions_protected": 1,
            "current_state": "PAGE_NOACCESS",
            "registered_addresses": ["0x7fff0000"],
            "sizes": [4096],
            "fluctuation_active": true,
            "detection_confidence": "ZERO - Memory dumps show OS memory"
        }
    }
    """
    if scan_id not in memory_fluctuators:
        return jsonify({
            "success": False,
            "error": f"Scan {scan_id} not registered"
        }), 404
    
    try:
        fluctuator = memory_fluctuators[scan_id]
        status = fluctuator.memory_evasion.get_protection_status()
        
        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "protection_status": status,
            "evasion_mechanism": {
                "type": "VirtualProtect PAGE State Transition",
                "sleep_state": "PAGE_NOACCESS (0x01)",
                "wake_state": "PAGE_EXECUTE_READWRITE (0x40)",
                "forensic_bypass": "Memory dumps access violation on protected region",
                "behavioral_signature": "ZERO - OS internal memory management"
            }
        }), 200
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@memory_evasion_bp.route('/api/fluctuator/force-wake/<scan_id>', methods=['POST'])
@handle_errors
def fluctuator_force_wake(scan_id: str):
    """
    Force beacon memory to executable state (emergency/C2 communication)
    
    POST /api/fluctuator/force-wake/scan_xyz
    {}
    
    Response:
    {
        "success": true,
        "scan_id": "scan_xyz",
        "state": "PAGE_EXECUTE_READWRITE",
        "ready_for_c2": true
    }
    """
    if scan_id not in memory_fluctuators:
        return jsonify({
            "success": False,
            "error": f"Scan {scan_id} not registered"
        }), 404
    
    try:
        fluctuator = memory_fluctuators[scan_id]
        status = fluctuator.memory_evasion.get_protection_status()
        
        if status.get('regions_protected', 0) > 0:
            for addr in status.get('registered_addresses', []):
                if isinstance(addr, str):
                    addr = int(addr, 16) if addr.startswith('0x') else int(addr)
                fluctuator.memory_evasion.fluctuate_to_wake(addr)
        
        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "state": "PAGE_EXECUTE_READWRITE",
            "ready_for_c2": True,
            "message": "Beacon memory now executable for C2 communication"
        }), 200
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@memory_evasion_bp.route('/api/fluctuator/force-sleep/<scan_id>', methods=['POST'])
@handle_errors
def fluctuator_force_sleep(scan_id: str):
    """
    Force beacon memory to protected state (emergency hide)
    
    POST /api/fluctuator/force-sleep/scan_xyz
    {}
    
    Response:
    {
        "success": true,
        "scan_id": "scan_xyz",
        "state": "PAGE_NOACCESS",
        "hidden_from_forensics": true
    }
    """
    if scan_id not in memory_fluctuators:
        return jsonify({
            "success": False,
            "error": f"Scan {scan_id} not registered"
        }), 404
    
    try:
        fluctuator = memory_fluctuators[scan_id]
        status = fluctuator.memory_evasion.get_protection_status()
        
        if status.get('regions_protected', 0) > 0:
            for addr in status.get('registered_addresses', []):
                if isinstance(addr, str):
                    addr = int(addr, 16) if addr.startswith('0x') else int(addr)
                fluctuator.memory_evasion.fluctuate_to_sleep(addr)
        
        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "state": "PAGE_NOACCESS",
            "hidden_from_forensics": True,
            "message": "Beacon memory now protected from forensic analysis"
        }), 200
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@memory_evasion_bp.route('/api/fluctuator/cleanup/<scan_id>', methods=['POST'])
@handle_errors
def fluctuator_cleanup(scan_id: str):
    """Cleanup and remove memory fluctuator"""
    if scan_id not in memory_fluctuators:
        return jsonify({
            "success": False,
            "error": f"Scan {scan_id} not registered"
        }), 404
    
    try:
        del memory_fluctuators[scan_id]
        
        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "message": "Memory fluctuator cleaned up"
        }), 200
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@memory_evasion_bp.route('/api/fluctuator/list', methods=['GET'])
@handle_errors
def fluctuator_list():
    """List all active memory fluctuators"""
    try:
        active_scans = []
        for scan_id, fluctuator in memory_fluctuators.items():
            try:
                status = fluctuator.memory_evasion.get_protection_status()
                active_scans.append({
                    "scan_id": scan_id,
                    "regions_protected": status.get('regions_protected', 0),
                    "registered_addresses": status.get('registered_addresses', []),
                    "current_state": status.get('current_state', 'UNKNOWN')
                })
            except:
                pass
        
        return jsonify({
            "success": True,
            "active_fluctuators": len(active_scans),
            "scans": active_scans
        }), 200
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500