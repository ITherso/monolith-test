"""
SCCM/MECM Hunter - Flask Routes
The "Game Over" Button for Enterprise Networks
"""

from flask import Blueprint, render_template, request, jsonify
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

try:
    from sccm_hunter import get_hunter, AttackVector, DeploymentType, SCCMRole
except ImportError:
    get_hunter = None

sccm_hunter_bp = Blueprint('sccm_hunter', __name__, url_prefix='/sccm-hunter')


@sccm_hunter_bp.route('/')
def index():
    """SCCM Hunter main page"""
    return render_template('sccm_hunter.html')


@sccm_hunter_bp.route('/api/create-session', methods=['POST'])
def create_session():
    """Create SCCM hunting session"""
    if not get_hunter:
        return jsonify({"error": "SCCM Hunter module not available"}), 500
        
    data = request.get_json() or {}
    target_domain = data.get('target_domain', 'corp.local')
    
    hunter = get_hunter()
    session = hunter.create_session(target_domain)
    
    return jsonify({
        "success": True,
        "session_id": session.session_id,
        "target_domain": session.target_domain,
        "status": session.status,
        "message": f"Hunting session created for {target_domain}"
    })


@sccm_hunter_bp.route('/api/discover', methods=['POST'])
def discover_sccm():
    """Discover SCCM servers"""
    if not get_hunter:
        return jsonify({"error": "SCCM Hunter module not available"}), 500
        
    data = request.get_json() or {}
    session_id = data.get('session_id')
    method = data.get('method', 'ldap')
    
    if not session_id:
        return jsonify({"error": "session_id required"}), 400
        
    hunter = get_hunter()
    
    try:
        servers = hunter.discover_sccm_servers(session_id, method)
        
        return jsonify({
            "success": True,
            "servers": [{
                "server_id": s.server_id,
                "hostname": s.hostname,
                "ip_address": s.ip_address,
                "site_code": s.site_code,
                "version": s.version,
                "roles": [r.value for r in s.roles],
                "managed_clients": s.managed_clients,
                "admin_service_enabled": s.admin_service_enabled,
                "pxe_enabled": s.pxe_enabled
            } for s in servers],
            "count": len(servers)
        })
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@sccm_hunter_bp.route('/api/extract-naa', methods=['POST'])
def extract_naa():
    """Extract Network Access Account credentials"""
    if not get_hunter:
        return jsonify({"error": "SCCM Hunter module not available"}), 500
        
    data = request.get_json() or {}
    session_id = data.get('session_id')
    target_server = data.get('target_server')
    
    if not session_id or not target_server:
        return jsonify({"error": "session_id and target_server required"}), 400
        
    hunter = get_hunter()
    cred = hunter.extract_naa_credentials(session_id, target_server)
    
    if cred:
        return jsonify({
            "success": True,
            "credential": {
                "cred_id": cred.cred_id,
                "cred_type": cred.cred_type,
                "username": cred.username,
                "domain": cred.domain,
                "secret_type": cred.secret_type,
                "source": cred.source,
                "permissions": cred.permissions
            }
        })
    else:
        return jsonify({"error": "Failed to extract credentials"}), 400


@sccm_hunter_bp.route('/api/attack-admin-service', methods=['POST'])
def attack_admin_service():
    """Attack SCCM AdminService API"""
    if not get_hunter:
        return jsonify({"error": "SCCM Hunter module not available"}), 500
        
    data = request.get_json() or {}
    session_id = data.get('session_id')
    target_server = data.get('target_server')
    
    if not session_id or not target_server:
        return jsonify({"error": "session_id and target_server required"}), 400
        
    hunter = get_hunter()
    result = hunter.attack_admin_service(session_id, target_server, {})
    
    return jsonify({
        "success": True,
        "attack_info": result
    })


@sccm_hunter_bp.route('/api/create-package', methods=['POST'])
def create_malicious_package():
    """Create malicious SCCM application package"""
    if not get_hunter:
        return jsonify({"error": "SCCM Hunter module not available"}), 500
        
    data = request.get_json() or {}
    session_id = data.get('session_id')
    app_name = data.get('app_name', 'Microsoft Security Update KB5034441')
    target_collection = data.get('target_collection', 'SMS00001')
    
    if not session_id:
        return jsonify({"error": "session_id required"}), 400
        
    hunter = get_hunter()
    
    try:
        package = hunter.create_malicious_application(
            session_id, 
            app_name, 
            b"PAYLOAD_PLACEHOLDER",
            target_collection
        )
        
        # Generate XML
        app_xml = hunter.generate_application_xml(package, "\\\\SCCM\\Content\\payload.exe")
        
        return jsonify({
            "success": True,
            "package": {
                "package_id": package.package_id,
                "name": package.name,
                "target_collection": package.target_collection,
                "execution_context": package.execution_context,
                "schedule": package.schedule
            },
            "application_xml": app_xml
        })
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@sccm_hunter_bp.route('/api/task-sequence', methods=['POST'])
def create_task_sequence():
    """Create malicious task sequence"""
    if not get_hunter:
        return jsonify({"error": "SCCM Hunter module not available"}), 500
        
    data = request.get_json() or {}
    session_id = data.get('session_id')
    ts_name = data.get('name', 'Windows Security Hardening')
    
    if not session_id:
        return jsonify({"error": "session_id required"}), 400
        
    hunter = get_hunter()
    result = hunter.create_task_sequence_attack(session_id, ts_name, b"PAYLOAD")
    
    return jsonify({
        "success": True,
        "task_sequence": result
    })


@sccm_hunter_bp.route('/api/pxe-attack', methods=['POST'])
def pxe_attack():
    """PXE Boot injection attack"""
    if not get_hunter:
        return jsonify({"error": "SCCM Hunter module not available"}), 500
        
    data = request.get_json() or {}
    session_id = data.get('session_id')
    target_server = data.get('target_server')
    
    if not session_id or not target_server:
        return jsonify({"error": "session_id and target_server required"}), 400
        
    hunter = get_hunter()
    result = hunter.exploit_pxe_boot(session_id, target_server)
    
    return jsonify({
        "success": True,
        "pxe_attack": result
    })


@sccm_hunter_bp.route('/api/generate-implant', methods=['POST'])
def generate_implant():
    """Generate SCCM-aware implant"""
    if not get_hunter:
        return jsonify({"error": "SCCM Hunter module not available"}), 500
        
    data = request.get_json() or {}
    implant_type = data.get('type', 'powershell')
    
    hunter = get_hunter()
    implant_code = hunter.generate_implant_script(implant_type)
    
    return jsonify({
        "success": True,
        "implant_type": implant_type,
        "code": implant_code
    })


@sccm_hunter_bp.route('/api/playbook', methods=['GET'])
def get_playbook():
    """Get SCCM attack playbook"""
    if not get_hunter:
        return jsonify({"error": "SCCM Hunter module not available"}), 500
        
    hunter = get_hunter()
    playbook = hunter.get_attack_playbook()
    
    return jsonify({
        "success": True,
        "playbook": playbook
    })


@sccm_hunter_bp.route('/api/statistics', methods=['GET'])
def get_statistics():
    """Get hunter statistics"""
    if not get_hunter:
        return jsonify({"error": "SCCM Hunter module not available"}), 500
        
    session_id = request.args.get('session_id')
    
    hunter = get_hunter()
    
    if session_id:
        stats = hunter.get_session_stats(session_id)
    else:
        stats = {
            "total_sessions": len(hunter.sessions),
            "sessions": [hunter.get_session_stats(sid) for sid in hunter.sessions]
        }
    
    return jsonify({
        "success": True,
        "statistics": stats
    })


@sccm_hunter_bp.route('/api/roles', methods=['GET'])
def get_roles():
    """Get SCCM role types"""
    return jsonify({
        "success": True,
        "roles": [{"value": r.value, "name": r.name} for r in SCCMRole]
    })


@sccm_hunter_bp.route('/api/attack-vectors', methods=['GET'])
def get_attack_vectors():
    """Get available attack vectors"""
    return jsonify({
        "success": True,
        "vectors": [{"value": v.value, "name": v.name} for v in AttackVector]
    })
