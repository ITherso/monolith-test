"""
Memory Forensics Evasion Routes - Bellek Hayaletleri
====================================================
Flask blueprint for advanced memory evasion techniques.

Features:
- Sleep Obfuscation (Ekko/Foliage)
- Call Stack Spoofing
- Process Hollowing/Doppelgänging
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
