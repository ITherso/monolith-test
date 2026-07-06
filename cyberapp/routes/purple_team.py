"""
Purple Team & JA4 Validation Routes
====================================
API endpoints for:
- JA4 fingerprint verification
- Steganographic exfiltration pipeline
- Purple Team test execution
- Traffic fingerprint baselining
"""

from flask import Blueprint, request, jsonify, render_template, send_file
from functools import wraps
import sys
import os
import io
import base64
import logging

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

from ja4_validator import JA4Validator, JA4Profile, JA4MatchResult
from stego_exfil import LSBStegoExfil, StegoPayload, ExfilStatus

logger = logging.getLogger("purple_team_routes")

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated

ja4_validator = JA4Validator()
stego_exfil = LSBStegoExfil()

purple_bp = Blueprint('purple_team', __name__, url_prefix='/purple')


@purple_bp.route('/')
@login_required
def index():
    return render_template('purple_team.html')


@purple_bp.route('/api/ja4/validate', methods=['POST'])
@login_required
def validate_ja4():
    data = request.get_json()
    ja4 = data.get('ja4', '')
    ja4h = data.get('ja4h', '')
    user_agent = data.get('user_agent', '')
    profile_name = data.get('profile', 'edge_windows_11')

    result = ja4_validator.combined_check(ja4, ja4h, user_agent)
    return jsonify(result)


@purple_bp.route('/api/ja4/profiles', methods=['GET'])
@login_required
def list_ja4_profiles():
    profiles = []
    for name, profile in ja4_validator.LEGITIMATE_PROFILES.items():
        profiles.append({
            "name": profile.name,
            "ja4": profile.ja4,
            "ja4h": profile.ja4h,
            "user_agent": profile.user_agent,
            "tags": profile.tags,
        })
    return jsonify({"profiles": profiles})


@purple_bp.route('/api/ja4/profiles', methods=['POST'])
@login_required
def add_ja4_profile():
    data = request.get_json()
    profile = JA4Profile(
        name=data.get('name', 'custom'),
        ja4=data.get('ja4', ''),
        ja4h=data.get('ja4h', ''),
        user_agent=data.get('user_agent', ''),
        source=data.get('source', 'manual'),
        tags=data.get('tags', []),
    )
    ja4_validator.add_profile(profile)
    return jsonify({"status": "added", "name": profile.name})


@purple_bp.route('/api/stego/encode', methods=['POST'])
@login_required
def stego_encode():
    data = request.get_json()
    image_b64 = data.get('image')
    message = data.get('message', '')
    filename = data.get('filename', 'exfil.png')

    if not image_b64 or not message:
        return jsonify({"error": "image and message required"}), 400

    try:
        image_bytes = base64.b64decode(image_b64)
        message_bytes = message.encode('utf-8')
        result = stego_exfil.encode_png(image_bytes, message_bytes, filename)

        if result:
            payload = StegoPayload(
                payload_id=__import__('uuid').uuid4().hex,
                data=result,
                filename=filename,
                status=ExfilStatus.ENCODED,
            )
            stego_exfil.register_payload(payload)
            return jsonify({
                "status": "encoded",
                "payload_id": payload.payload_id,
                "size": len(result),
                "image_b64": base64.b64encode(result).decode('utf-8'),
            })
        return jsonify({"error": "encode failed"}), 500
    except Exception as exc:
        logger.error(f"Stego encode error: {exc}")
        return jsonify({"error": str(exc)}), 500


@purple_bp.route('/api/stego/decode', methods=['POST'])
@login_required
def stego_decode():
    data = request.get_json()
    image_b64 = data.get('image')

    if not image_b64:
        return jsonify({"error": "image required"}), 400

    try:
        image_bytes = base64.b64decode(image_b64)
        result = stego_exfil.decode_png(image_bytes)

        if result:
            return jsonify({
                "status": "decoded",
                "message": result.decode('utf-8', errors='replace'),
                "size": len(result),
            })
        return jsonify({"error": "decode failed"}), 500
    except Exception as exc:
        logger.error(f"Stego decode error: {exc}")
        return jsonify({"error": str(exc)}), 500


@purple_bp.route('/api/stego/create', methods=['POST'])
@login_required
def stego_create():
    data = request.get_json()
    message = data.get('message', '')
    width = data.get('width', 256)
    height = data.get('height', 256)

    if not message:
        return jsonify({"error": "message required"}), 400

    try:
        message_bytes = message.encode('utf-8')
        result = stego_exfil.create_exfil_image(message_bytes, width, height)

        if result:
            payload = StegoPayload(
                payload_id=__import__('uuid').uuid4().hex,
                data=result,
                filename="exfil.png",
                status=ExfilStatus.ENCODED,
            )
            stego_exfil.register_payload(payload)
            return jsonify({
                "status": "created",
                "payload_id": payload.payload_id,
                "size": len(result),
                "image_b64": base64.b64encode(result).decode('utf-8'),
            })
        return jsonify({"error": "create failed"}), 500
    except Exception as exc:
        logger.error(f"Stego create error: {exc}")
        return jsonify({"error": str(exc)}), 500


@purple_bp.route('/api/stego/payloads', methods=['GET'])
@login_required
def list_stego_payloads():
    return jsonify({"payloads": stego_exfil.list_payloads()})


@purple_bp.route('/api/stego/spread-spectrum', methods=['POST'])
@login_required
def stego_spread_spectrum():
    data = request.get_json()
    image_b64 = data.get('image')
    message = data.get('message', '')

    if not image_b64 or not message:
        return jsonify({"error": "image and message required"}), 400

    try:
        image_bytes = base64.b64decode(image_b64)
        message_bytes = message.encode('utf-8')
        result = stego_exfil.encode_lsb_spread_spectrum(image_bytes, message_bytes)

        if result:
            payload = StegoPayload(
                payload_id=__import__('uuid').uuid4().hex,
                data=result,
                filename="exfil.png",
                status=ExfilStatus.ENCODED,
            )
            stego_exfil.register_payload(payload)
            return jsonify({
                "status": "encoded",
                "payload_id": payload.payload_id,
                "size": len(result),
                "image_b64": base64.b64encode(result).decode('utf-8'),
            })
        return jsonify({"error": "encode failed - data too large or image too small"}), 500
    except Exception as exc:
        logger.error(f"Stego spread spectrum error: {exc}")
        return jsonify({"error": str(exc)}), 500


@purple_bp.route('/api/stego/chunked', methods=['POST'])
@login_required
def stego_chunked():
    data = request.get_json()
    images_b64 = data.get('images', [])
    message = data.get('message', '')
    chunk_size = data.get('chunk_size', 32768)

    if not images_b64 or not message:
        return jsonify({"error": "images list and message required"}), 400

    try:
        image_bytes_list = [base64.b64decode(img) for img in images_b64]
        message_bytes = message.encode('utf-8')
        results = stego_exfil.chunk_and_encode_spectrum(message_bytes, image_bytes_list, chunk_size)

        payload = StegoPayload(
            payload_id=__import__('uuid').uuid4().hex,
            data=message_bytes,
            filename="chunked_exfil.zip",
            status=ExfilStatus.ENCODED,
        )
        stego_exfil.register_payload(payload)
        return jsonify({
            "status": "encoded",
            "payload_id": payload.payload_id,
            "chunks": len(results),
            "chunk_size": chunk_size,
            "total_size": len(message_bytes),
            "images_b64": [base64.b64encode(img).decode('utf-8') for img in results],
        })
    except ValueError as exc:
        logger.error(f"Stego chunked error: {exc}")
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        logger.error(f"Stego chunked error: {exc}")
        return jsonify({"error": str(exc)}), 500
