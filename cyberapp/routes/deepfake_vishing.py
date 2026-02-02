#!/usr/bin/env python3
"""
Deepfake Vishing API Routes
Flask Blueprint for CEO Voice Cloning & VoIP Attack Module

Author: CyberPunk Framework
Version: 1.0.0 PRO
"""

from flask import Blueprint, render_template, request, jsonify, current_app
from functools import wraps
import os
import sys

# Add tools directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

from deepfake_vishing import get_deepfake_vishing, VishingScriptTemplate, VoiceEmotion

bp = Blueprint('deepfake_vishing', __name__, url_prefix='/deepfake-vishing')


def handle_errors(f):
    """Error handling decorator"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            current_app.logger.error(f"Deepfake Vishing Error: {str(e)}")
            return jsonify({"success": False, "error": str(e)}), 500
    return wrapper


@bp.route('/')
def index():
    """Deepfake Vishing Dashboard"""
    return render_template('deepfake_vishing.html')


@bp.route('/api/providers', methods=['GET'])
@handle_errors
def get_providers():
    """Get available voice and call providers"""
    vishing = get_deepfake_vishing()
    
    voice_providers = [
        {"id": "elevenlabs", "name": "ElevenLabs", "description": "Best quality voice cloning", "requires_key": True},
        {"id": "azure", "name": "Azure Cognitive Services", "description": "Microsoft TTS with SSML", "requires_key": True},
        {"id": "google", "name": "Google Cloud TTS", "description": "WaveNet voices", "requires_key": True},
        {"id": "openai", "name": "OpenAI TTS", "description": "GPT-powered voice", "requires_key": True},
        {"id": "local_rvc", "name": "Local RVC", "description": "Self-hosted voice cloning", "requires_key": False},
        {"id": "bark", "name": "Bark", "description": "Local generative audio", "requires_key": False}
    ]
    
    call_providers = [
        {"id": "twilio", "name": "Twilio", "description": "Cloud telephony", "requires_key": True},
        {"id": "vonage", "name": "Vonage (Nexmo)", "description": "Enterprise VoIP", "requires_key": True},
        {"id": "plivo", "name": "Plivo", "description": "Budget VoIP", "requires_key": True},
        {"id": "asterisk", "name": "Asterisk PBX", "description": "Self-hosted PBX", "requires_key": False},
        {"id": "freepbx", "name": "FreePBX", "description": "Web-managed Asterisk", "requires_key": False},
        {"id": "sip_direct", "name": "SIP Direct", "description": "Direct SIP trunking", "requires_key": False}
    ]
    
    return jsonify({
        "success": True,
        "voice_providers": voice_providers,
        "call_providers": call_providers
    })


@bp.route('/api/templates', methods=['GET'])
@handle_errors
def get_templates():
    """Get available script templates"""
    templates = [
        {
            "id": "ceo_urgent_transfer",
            "name": "CEO Urgent Wire Transfer",
            "description": "CEO requesting emergency fund transfer",
            "variables": ["ceo_name", "amount", "recipient", "reason", "deadline"],
            "sample": "Hi {target_name}, this is {ceo_name}. I need you to process an urgent wire transfer of {amount} to {recipient}..."
        },
        {
            "id": "it_support_password",
            "name": "IT Support Password Reset",
            "description": "IT helpdesk requesting password verification",
            "variables": ["it_name", "system_name", "ticket_number"],
            "sample": "Hello, this is {it_name} from IT support. We're seeing some unusual activity on your account..."
        },
        {
            "id": "vendor_invoice",
            "name": "Vendor Invoice Update",
            "description": "Vendor requesting payment details update",
            "variables": ["vendor_name", "invoice_number", "new_account"],
            "sample": "Hi, this is {vendor_name} from accounting. We've updated our banking details..."
        },
        {
            "id": "bank_security",
            "name": "Bank Security Alert",
            "description": "Bank security team about suspicious activity",
            "variables": ["bank_name", "last_digits", "transaction_amount"],
            "sample": "This is the fraud prevention team from {bank_name}. We've detected a suspicious transaction..."
        },
        {
            "id": "hr_benefits",
            "name": "HR Benefits Enrollment",
            "description": "HR requesting benefits verification",
            "variables": ["hr_name", "deadline", "portal_url"],
            "sample": "Hi, this is {hr_name} from Human Resources. The benefits enrollment deadline is {deadline}..."
        },
        {
            "id": "custom",
            "name": "Custom Script",
            "description": "Create your own vishing script",
            "variables": [],
            "sample": ""
        }
    ]
    
    return jsonify({
        "success": True,
        "templates": templates
    })


@bp.route('/api/emotions', methods=['GET'])
@handle_errors
def get_emotions():
    """Get available voice emotions"""
    emotions = [
        {"id": "urgent", "name": "Urgent", "description": "Stressed, time-sensitive tone", "settings": {"stability": 0.3, "similarity_boost": 0.8}},
        {"id": "calm", "name": "Calm", "description": "Professional, measured tone", "settings": {"stability": 0.7, "similarity_boost": 0.7}},
        {"id": "friendly", "name": "Friendly", "description": "Warm, approachable tone", "settings": {"stability": 0.6, "similarity_boost": 0.75}},
        {"id": "authoritative", "name": "Authoritative", "description": "Commanding, executive tone", "settings": {"stability": 0.8, "similarity_boost": 0.85}},
        {"id": "worried", "name": "Worried", "description": "Concerned, anxious tone", "settings": {"stability": 0.4, "similarity_boost": 0.75}}
    ]
    
    return jsonify({
        "success": True,
        "emotions": emotions
    })


@bp.route('/api/profiles', methods=['GET'])
@handle_errors
def list_profiles():
    """List all voice profiles"""
    vishing = get_deepfake_vishing()
    
    profiles = []
    for profile_id, profile in vishing.voice_profiles.items():
        profiles.append({
            "id": profile_id,
            "name": profile.name,
            "provider": profile.provider.value,
            "language": profile.language,
            "gender": profile.gender,
            "created_at": profile.created_at
        })
    
    return jsonify({
        "success": True,
        "profiles": profiles
    })


@bp.route('/api/profiles', methods=['POST'])
@handle_errors
def create_profile():
    """Create new voice profile"""
    data = request.json
    vishing = get_deepfake_vishing()
    
    # Get voice sample if provided
    voice_sample = None
    if 'voice_sample_base64' in data:
        import base64
        voice_sample = base64.b64decode(data['voice_sample_base64'])
    
    profile = vishing.create_voice_profile(
        name=data.get('name', 'Unnamed Profile'),
        provider=data.get('provider', 'elevenlabs'),
        voice_sample=voice_sample,
        language=data.get('language', 'en-US'),
        gender=data.get('gender', 'male')
    )
    
    return jsonify({
        "success": True,
        "profile": {
            "id": profile.profile_id,
            "name": profile.name,
            "provider": profile.provider.value,
            "voice_id": profile.voice_id
        }
    })


@bp.route('/api/profiles/<profile_id>', methods=['DELETE'])
@handle_errors
def delete_profile(profile_id):
    """Delete voice profile"""
    vishing = get_deepfake_vishing()
    
    if profile_id in vishing.voice_profiles:
        del vishing.voice_profiles[profile_id]
        return jsonify({"success": True, "message": "Profile deleted"})
    else:
        return jsonify({"success": False, "error": "Profile not found"}), 404


@bp.route('/api/generate-audio', methods=['POST'])
@handle_errors
def generate_audio():
    """Generate deepfake audio from text"""
    data = request.json
    vishing = get_deepfake_vishing()
    
    # Render script if template is used
    if data.get('template'):
        text = vishing.render_script(
            template=data['template'],
            variables=data.get('variables', {}),
            target_name=data.get('target_name', '')
        )
    else:
        text = data.get('text', '')
    
    # Generate audio
    audio = vishing.generate_audio(
        profile_id=data.get('profile_id'),
        text=text,
        emotion=data.get('emotion', 'authoritative')
    )
    
    import base64
    audio_base64 = base64.b64encode(audio.audio_data).decode() if audio.audio_data else None
    
    return jsonify({
        "success": True,
        "audio": {
            "id": audio.audio_id,
            "text": audio.text,
            "duration": audio.duration,
            "format": audio.format,
            "audio_base64": audio_base64,
            "file_path": audio.file_path
        }
    })


@bp.route('/api/render-script', methods=['POST'])
@handle_errors
def render_script():
    """Render a script template with variables"""
    data = request.json
    vishing = get_deepfake_vishing()
    
    rendered = vishing.render_script(
        template=data.get('template', 'custom'),
        variables=data.get('variables', {}),
        target_name=data.get('target_name', '')
    )
    
    return jsonify({
        "success": True,
        "rendered_script": rendered
    })


@bp.route('/api/campaigns', methods=['GET'])
@handle_errors
def list_campaigns():
    """List all vishing campaigns"""
    vishing = get_deepfake_vishing()
    
    campaigns = []
    for campaign_id, campaign in vishing.campaigns.items():
        campaigns.append({
            "id": campaign_id,
            "name": campaign.name,
            "profile_id": campaign.profile_id,
            "template": campaign.template.value,
            "total_targets": len(campaign.targets),
            "completed_calls": len([c for c in campaign.calls if c.status == 'completed']),
            "status": campaign.status,
            "created_at": campaign.created_at
        })
    
    return jsonify({
        "success": True,
        "campaigns": campaigns
    })


@bp.route('/api/campaigns', methods=['POST'])
@handle_errors
def create_campaign():
    """Create new vishing campaign"""
    data = request.json
    vishing = get_deepfake_vishing()
    
    campaign = vishing.create_campaign(
        name=data.get('name', 'Unnamed Campaign'),
        profile_id=data.get('profile_id'),
        template=data.get('template', 'ceo_urgent_transfer'),
        targets=data.get('targets', []),
        caller_id=data.get('caller_id'),
        variables=data.get('variables', {})
    )
    
    return jsonify({
        "success": True,
        "campaign": {
            "id": campaign.campaign_id,
            "name": campaign.name,
            "targets": len(campaign.targets)
        }
    })


@bp.route('/api/campaigns/<campaign_id>/start', methods=['POST'])
@handle_errors
def start_campaign(campaign_id):
    """Start a vishing campaign"""
    vishing = get_deepfake_vishing()
    
    if campaign_id not in vishing.campaigns:
        return jsonify({"success": False, "error": "Campaign not found"}), 404
    
    campaign = vishing.campaigns[campaign_id]
    campaign.status = "running"
    
    # Start calls in background (simplified)
    return jsonify({
        "success": True,
        "message": "Campaign started",
        "campaign_id": campaign_id
    })


@bp.route('/api/campaigns/<campaign_id>/stop', methods=['POST'])
@handle_errors
def stop_campaign(campaign_id):
    """Stop a running campaign"""
    vishing = get_deepfake_vishing()
    
    if campaign_id not in vishing.campaigns:
        return jsonify({"success": False, "error": "Campaign not found"}), 404
    
    campaign = vishing.campaigns[campaign_id]
    campaign.status = "stopped"
    
    return jsonify({
        "success": True,
        "message": "Campaign stopped"
    })


@bp.route('/api/campaigns/<campaign_id>', methods=['DELETE'])
@handle_errors
def delete_campaign(campaign_id):
    """Delete a campaign"""
    vishing = get_deepfake_vishing()
    
    if campaign_id in vishing.campaigns:
        del vishing.campaigns[campaign_id]
        return jsonify({"success": True, "message": "Campaign deleted"})
    else:
        return jsonify({"success": False, "error": "Campaign not found"}), 404


@bp.route('/api/call', methods=['POST'])
@handle_errors
def initiate_call():
    """Initiate a single vishing call"""
    data = request.json
    vishing = get_deepfake_vishing()
    
    call = vishing.initiate_call(
        profile_id=data.get('profile_id'),
        target_phone=data.get('target_phone'),
        text=data.get('text'),
        template=data.get('template'),
        variables=data.get('variables', {}),
        caller_id=data.get('caller_id')
    )
    
    return jsonify({
        "success": True,
        "call": {
            "id": call.call_id,
            "target": call.target_phone,
            "status": call.status,
            "provider_call_id": call.provider_call_id
        }
    })


@bp.route('/api/calls', methods=['GET'])
@handle_errors
def list_calls():
    """List recent calls"""
    vishing = get_deepfake_vishing()
    
    # Collect all calls from all campaigns
    all_calls = []
    for campaign in vishing.campaigns.values():
        for call in campaign.calls:
            all_calls.append({
                "id": call.call_id,
                "campaign_id": campaign.campaign_id,
                "target": call.target_phone,
                "status": call.status,
                "duration": call.duration,
                "answered": call.answered,
                "timestamp": call.timestamp
            })
    
    # Sort by timestamp
    all_calls.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return jsonify({
        "success": True,
        "calls": all_calls[:100]  # Last 100 calls
    })


@bp.route('/api/implants', methods=['GET'])
@handle_errors
def get_implants():
    """Get voice sample collection implants"""
    vishing = get_deepfake_vishing()
    
    implants = vishing.generate_voice_sample_collector()
    
    return jsonify({
        "success": True,
        "implants": implants
    })


@bp.route('/api/statistics', methods=['GET'])
@handle_errors
def get_statistics():
    """Get vishing statistics"""
    vishing = get_deepfake_vishing()
    
    total_campaigns = len(vishing.campaigns)
    total_profiles = len(vishing.voice_profiles)
    total_calls = sum(len(c.calls) for c in vishing.campaigns.values())
    answered_calls = sum(
        len([call for call in c.calls if call.answered])
        for c in vishing.campaigns.values()
    )
    
    return jsonify({
        "success": True,
        "statistics": {
            "total_campaigns": total_campaigns,
            "total_profiles": total_profiles,
            "total_calls": total_calls,
            "answered_calls": answered_calls,
            "answer_rate": (answered_calls / total_calls * 100) if total_calls > 0 else 0
        }
    })


@bp.route('/api/config', methods=['GET'])
@handle_errors
def get_config():
    """Get current configuration"""
    vishing = get_deepfake_vishing()
    
    # Return safe config (no API keys)
    return jsonify({
        "success": True,
        "config": {
            "voice_provider": vishing.config.get('voice_provider', 'elevenlabs'),
            "call_provider": vishing.config.get('call_provider', 'twilio'),
            "output_dir": vishing.config.get('output_dir', '/tmp/vishing'),
            "recording_enabled": vishing.config.get('recording_enabled', True)
        }
    })


@bp.route('/api/config', methods=['POST'])
@handle_errors
def update_config():
    """Update configuration"""
    data = request.json
    vishing = get_deepfake_vishing()
    
    # Update allowed config fields
    allowed_fields = [
        'voice_provider', 'call_provider', 'output_dir', 'recording_enabled',
        'elevenlabs_api_key', 'azure_key', 'openai_api_key',
        'twilio_sid', 'twilio_token', 'twilio_from',
        'asterisk_host', 'sip_server'
    ]
    
    for field in allowed_fields:
        if field in data:
            vishing.config[field] = data[field]
    
    return jsonify({
        "success": True,
        "message": "Configuration updated"
    })
