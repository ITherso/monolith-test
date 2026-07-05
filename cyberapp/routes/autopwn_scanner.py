#!/usr/bin/env python3
"""
Auto-Pwn Scanner API Routes
Flask Blueprint for Automated Vulnerability Scanner & N-Day Exploiter

Author: CyberPunk Framework
Version: 1.0.0 PRO
"""

from flask import Blueprint, render_template, request, jsonify, current_app
from functools import wraps
import os
import sys

# Add tools directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

from autopwn_scanner import get_autopwn_scanner, Severity, ExploitStatus

bp = Blueprint('autopwn_scanner', __name__, url_prefix='/autopwn')


def handle_errors(f):
    """Error handling decorator"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            current_app.logger.error(f"AutoPwn Scanner Error: {str(e)}")
            return jsonify({"success": False, "error": str(e)}), 500
    return wrapper


@bp.route('/')
def index():
    """Auto-Pwn Scanner Dashboard"""
    return render_template('autopwn_scanner.html')


@bp.route('/api/vulnerabilities', methods=['GET'])
@handle_errors
def get_vulnerabilities():
    """Get list of supported vulnerabilities"""
    scanner = get_autopwn_scanner()
    vulns = scanner.get_vulnerability_list()
    
    # Group by severity
    critical = [v for v in vulns if v['severity'] == 'critical']
    high = [v for v in vulns if v['severity'] == 'high']
    medium = [v for v in vulns if v['severity'] == 'medium']
    low = [v for v in vulns if v['severity'] in ['low', 'info']]
    
    return jsonify({
        "success": True,
        "total": len(vulns),
        "by_severity": {
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "low": len(low)
        },
        "vulnerabilities": vulns
    })


@bp.route('/api/sessions', methods=['GET'])
@handle_errors
def list_sessions():
    """List all scan sessions"""
    scanner = get_autopwn_scanner()
    
    sessions = []
    for session_id, session in scanner.sessions.items():
        sessions.append({
            "id": session_id,
            "targets": session.targets,
            "status": session.status,
            "auto_exploit": session.auto_exploit,
            "discovered": len(session.discovered_targets),
            "pwned": session.pwned_count,
            "created_at": session.created_at
        })
    
    # Sort by creation time
    sessions.sort(key=lambda x: x['created_at'], reverse=True)
    
    return jsonify({
        "success": True,
        "sessions": sessions
    })


@bp.route('/api/sessions', methods=['POST'])
@handle_errors
def create_session():
    """Create new scan session"""
    data = request.json
    scanner = get_autopwn_scanner()
    
    targets = data.get('targets', [])
    if isinstance(targets, str):
        # Split by comma, newline, or space
        import re
        targets = re.split(r'[,\n\s]+', targets)
        targets = [t.strip() for t in targets if t.strip()]
    
    auto_exploit = data.get('auto_exploit', True)
    
    session = scanner.create_session(
        targets=targets,
        auto_exploit=auto_exploit
    )
    
    return jsonify({
        "success": True,
        "session": {
            "id": session.session_id,
            "targets": session.targets,
            "auto_exploit": session.auto_exploit,
            "status": session.status
        }
    })


@bp.route('/api/sessions/<session_id>/start', methods=['POST'])
@handle_errors
def start_scan(session_id):
    """Start scanning session"""
    data = request.json or {}
    scanner = get_autopwn_scanner()
    
    max_threads = data.get('max_threads', 50)
    
    # Start scan (this may take a while)
    session = scanner.start_scan(session_id, max_threads=max_threads)
    
    return jsonify({
        "success": True,
        "session": {
            "id": session.session_id,
            "status": session.status,
            "discovered": len(session.discovered_targets),
            "pwned": session.pwned_count,
            "results": len(session.results)
        }
    })


@bp.route('/api/sessions/<session_id>', methods=['GET'])
@handle_errors
def get_session(session_id):
    """Get session details"""
    scanner = get_autopwn_scanner()
    
    if session_id not in scanner.sessions:
        return jsonify({"success": False, "error": "Session not found"}), 404
    
    session = scanner.sessions[session_id]
    
    # Build detailed target list
    targets = []
    for target_id, target in session.discovered_targets.items():
        targets.append({
            "id": target_id,
            "ip": target.ip,
            "hostname": target.hostname,
            "ports": target.ports,
            "os": target.os_fingerprint,
            "vulnerabilities": target.vulnerabilities,
            "exploited": target.exploited,
            "shells": len(target.shells)
        })
    
    # Build results list
    results = []
    for result in session.results:
        results.append({
            "id": result.result_id,
            "target_id": result.target_id,
            "vuln_id": result.vuln_id,
            "status": result.status.value,
            "shell_type": result.shell_type,
            "output": result.output[:500] if result.output else "",
            "timestamp": result.timestamp
        })
    
    return jsonify({
        "success": True,
        "session": {
            "id": session.session_id,
            "targets_input": session.targets,
            "status": session.status,
            "auto_exploit": session.auto_exploit,
            "pwned_count": session.pwned_count,
            "created_at": session.created_at
        },
        "discovered_targets": targets,
        "results": results
    })


@bp.route('/api/sessions/<session_id>', methods=['DELETE'])
@handle_errors
def delete_session(session_id):
    """Delete scan session"""
    scanner = get_autopwn_scanner()
    
    if session_id in scanner.sessions:
        del scanner.sessions[session_id]
        return jsonify({"success": True, "message": "Session deleted"})
    else:
        return jsonify({"success": False, "error": "Session not found"}), 404


@bp.route('/api/sessions/<session_id>/report', methods=['GET'])
@handle_errors
def get_report(session_id):
    """Generate scan report"""
    scanner = get_autopwn_scanner()
    
    report = scanner.generate_report(session_id)
    
    if "error" in report:
        return jsonify({"success": False, "error": report["error"]}), 404
    
    return jsonify({
        "success": True,
        "report": report
    })


@bp.route('/api/sessions/<session_id>/export', methods=['GET'])
@handle_errors
def export_report(session_id):
    """Export report as JSON/HTML"""
    scanner = get_autopwn_scanner()
    format_type = request.args.get('format', 'json')
    
    report = scanner.generate_report(session_id)
    
    if "error" in report:
        return jsonify({"success": False, "error": report["error"]}), 404
    
    if format_type == 'json':
        return jsonify(report)
    elif format_type == 'html':
        # Generate HTML report
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>AutoPwn Scan Report - {session_id}</title>
    <style>
        body {{ font-family: 'Courier New', monospace; background: #0a0a0a; color: #00ff00; padding: 20px; }}
        .header {{ border-bottom: 2px solid #00ff00; padding-bottom: 10px; margin-bottom: 20px; }}
        .critical {{ color: #ff0000; }}
        .high {{ color: #ff6600; }}
        .medium {{ color: #ffff00; }}
        .pwned {{ color: #00ff00; font-weight: bold; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #00ff00; padding: 8px; text-align: left; }}
        th {{ background: #001a00; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🎯 AutoPwn Scan Report</h1>
        <p>Session: {report['session_id']}</p>
        <p>Scan Time: {report['scan_time']}</p>
    </div>
    
    <h2>📊 Summary</h2>
    <ul>
        <li>Targets Scanned: {report['targets_scanned']}</li>
        <li>Targets Discovered: {report['targets_discovered']}</li>
        <li class="pwned">Targets PWNED: {report['targets_pwned']}</li>
    </ul>
    
    <h2>🔥 Vulnerabilities</h2>
    <ul>
        <li class="critical">Critical: {report['vulnerabilities']['critical']}</li>
        <li class="high">High: {report['vulnerabilities']['high']}</li>
        <li>Total: {report['vulnerabilities']['total']}</li>
    </ul>
    
    <h2>📋 Details</h2>
    <table>
        <tr>
            <th>Target</th>
            <th>Vulnerability</th>
            <th>CVE</th>
            <th>Severity</th>
            <th>Exploited</th>
        </tr>
        {"".join(f"<tr><td>{d['target']}</td><td>{d['vuln']}</td><td>{d['cve']}</td><td class='{d['severity']}'>{d['severity'].upper()}</td><td class='{'pwned' if d['exploited'] else ''}'>{('✓ PWNED' if d['exploited'] else '○')}</td></tr>" for d in report['details'])}
    </table>
    
    <h2>🐚 Active Shells</h2>
    <ul>
        {"".join(f"<li class='pwned'>{s['target']}: {len(s['shells'])} shell(s)</li>" for s in report['shells']) if report['shells'] else '<li>No active shells</li>'}
    </ul>
    
    <footer style="margin-top: 40px; border-top: 1px solid #00ff00; padding-top: 10px;">
        <p>Generated by CyberPunk AutoPwn Scanner v1.0.0 PRO</p>
    </footer>
</body>
</html>
"""
        from flask import Response
        return Response(html, mimetype='text/html')
    
    return jsonify(report)


@bp.route('/api/exploit', methods=['POST'])
@handle_errors
def manual_exploit():
    """Manually exploit a specific vulnerability on a target"""
    data = request.json
    scanner = get_autopwn_scanner()
    
    target_ip = data.get('target_ip')
    vuln_id = data.get('vuln_id')
    
    if not target_ip or not vuln_id:
        return jsonify({"success": False, "error": "target_ip and vuln_id required"}), 400
    
    if vuln_id not in scanner.VULNERABILITIES:
        return jsonify({"success": False, "error": f"Unknown vulnerability: {vuln_id}"}), 400
    
    # Create temporary target
    import hashlib
    from datetime import datetime
    from autopwn_scanner import Target
    
    target_id = hashlib.md5(f"{target_ip}{datetime.now().isoformat()}".encode()).hexdigest()[:12]
    target = Target(target_id=target_id, ip=target_ip)
    target.ports = scanner._quick_port_scan(target_ip)
    
    vuln = scanner.VULNERABILITIES[vuln_id]
    result = scanner._exploit_vulnerability(target, vuln)
    
    return jsonify({
        "success": result.status == ExploitStatus.PWNED,
        "result": {
            "id": result.result_id,
            "status": result.status.value,
            "shell_type": result.shell_type,
            "output": result.output,
            "exploit_code": result.shell_data.get('exploit_code', '') if result.shell_data else ''
        }
    })


@bp.route('/api/quick-scan', methods=['POST'])
@handle_errors
def quick_scan():
    """Quick vulnerability scan without exploitation"""
    data = request.json
    scanner = get_autopwn_scanner()
    
    target_ip = data.get('target_ip')
    if not target_ip:
        return jsonify({"success": False, "error": "target_ip required"}), 400
    
    # Quick port scan
    ports = scanner._quick_port_scan(target_ip)
    
    # Check for vulnerabilities
    from autopwn_scanner import Target
    import hashlib
    from datetime import datetime
    
    target_id = hashlib.md5(f"{target_ip}{datetime.now().isoformat()}".encode()).hexdigest()[:12]
    target = Target(target_id=target_id, ip=target_ip, ports=ports)
    
    found_vulns = []
    for vuln_id, vuln in scanner.VULNERABILITIES.items():
        if any(port in ports for port in vuln.ports):
            is_vulnerable = scanner._check_vulnerability(target, vuln)
            if is_vulnerable:
                found_vulns.append({
                    "id": vuln_id,
                    "name": vuln.name,
                    "cve": vuln.cve,
                    "severity": vuln.severity.value
                })
    
    return jsonify({
        "success": True,
        "target": target_ip,
        "open_ports": ports,
        "vulnerabilities": found_vulns,
        "vulnerable": len(found_vulns) > 0
    })


@bp.route('/api/statistics', methods=['GET'])
@handle_errors
def get_statistics():
    """Get scanner statistics"""
    scanner = get_autopwn_scanner()
    stats = scanner.get_statistics()
    
    return jsonify({
        "success": True,
        "statistics": stats
    })


@bp.route('/api/shells', methods=['GET'])
@handle_errors
def list_shells():
    """List all active shells from all sessions"""
    scanner = get_autopwn_scanner()
    
    shells = []
    for session in scanner.sessions.values():
        for target in session.discovered_targets.values():
            for shell in target.shells:
                shells.append({
                    "session_id": session.session_id,
                    "target_ip": target.ip,
                    "type": shell.get('type', 'unknown'),
                    "method": shell.get('method', 'unknown'),
                    "shell_url": shell.get('shell_url'),
                    "timestamp": session.created_at
                })
    
    return jsonify({
        "success": True,
        "shells": shells
    })


@bp.route('/api/config', methods=['GET'])
@handle_errors
def get_config():
    """Get scanner configuration"""
    scanner = get_autopwn_scanner()
    
    return jsonify({
        "success": True,
        "config": {
            "callback_host": scanner.callback_host,
            "callback_port": scanner.callback_port,
            "total_vulnerabilities": len(scanner.VULNERABILITIES)
        }
    })


@bp.route('/api/config', methods=['POST'])
@handle_errors
def update_config():
    """Update scanner configuration"""
    data = request.json
    scanner = get_autopwn_scanner()
    
    if 'callback_host' in data:
        scanner.callback_host = data['callback_host']
    if 'callback_port' in data:
        scanner.callback_port = data['callback_port']
    
    scanner.config.update(data)
    
    return jsonify({
        "success": True,
        "message": "Configuration updated"
    })
