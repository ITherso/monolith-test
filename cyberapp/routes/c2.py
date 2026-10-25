from flask import Blueprint, render_template, request, jsonify, redirect, session
import logging

from cybermodules.c2_implant import C2ImplantGenerator, ImplantConfig, generate_c2_from_session

logger = logging.getLogger("c2_routes")

c2_bp = Blueprint("c2_implant", __name__)


# ============================================================
# WEB C2 LISTENER
# ============================================================

_web_c2_listener = None

def _web_c2_unavailable():
    """Return an explicit failure; do not construct a listener or dispatch commands."""
    response = jsonify({
        "success": False,
        "available": False,
        "running": False,
        "error": "web_c2_backend_incomplete",
        "message": "This operation is not implemented by the Web C2 backend.",
    })
    response.status_code = 501
    response.headers["Cache-Control"] = "no-store"
    return response


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
        return _web_c2_unavailable()
    return jsonify(c2.get_stats())


@c2_bp.route("/api/web-c2/sessions")
def web_c2_sessions():
    """Report an unimplemented backend operation without dispatching it."""
    return _web_c2_unavailable()


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
    """Report an unimplemented backend operation without dispatching it."""
    return _web_c2_unavailable()


@c2_bp.route("/api/web-c2/register", methods=["POST"])
def web_c2_register():
    """Report an unimplemented backend operation without dispatching it."""
    return _web_c2_unavailable()


@c2_bp.route("/api/web-c2/beacon", methods=["POST"])
def web_c2_beacon():
    """Report an unimplemented backend operation without dispatching it."""
    return _web_c2_unavailable()


@c2_bp.route("/api/web-c2/session/<session_id>/terminate", methods=["POST"])
def web_c2_terminate(session_id):
    """Report an unimplemented backend operation without dispatching it."""
    return _web_c2_unavailable()


@c2_bp.route("/api/web-c2/beacons")
def web_c2_beacon_templates():
    """Report an unimplemented backend operation without dispatching it."""
    return _web_c2_unavailable()


@c2_bp.route("/api/web-c2/generate-beacon", methods=["POST"])
def web_c2_generate_beacon():
    """Report an unimplemented backend operation without dispatching it."""
    return _web_c2_unavailable()


@c2_bp.route("/api/web-c2/config")
def web_c2_config():
    """Report an unimplemented backend operation without dispatching it."""
    return _web_c2_unavailable()
