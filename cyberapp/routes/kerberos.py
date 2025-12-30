from flask import Blueprint, render_template, request, jsonify
from cybermodules.kerberos_tickets import KerberosTicketEngine, GoldenTicketForger, SilverTicketForger
from cyberapp.services.db import get_db_connection

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