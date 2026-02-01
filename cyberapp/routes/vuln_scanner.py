from flask import Blueprint, render_template, request, jsonify
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from tools.vuln_scanner_integrator import (
    get_vuln_scanner, 
    ScannerType, 
    SeverityLevel,
    VulnerabilityType
)

vuln_scanner_bp = Blueprint("vuln_scanner", __name__, url_prefix="/tools")


@vuln_scanner_bp.route("/vuln-scanner")
def vuln_scanner_page():
    """Vulnerability Scanner main page"""
    scanner = get_vuln_scanner()
    
    # Get available scanners
    available_scanners = []
    for scanner_type, config in scanner.scanners.items():
        if config.enabled:
            available_scanners.append({
                "type": scanner_type.value,
                "name": scanner_type.value.replace("_", " ").title(),
                "binary": config.binary_path
            })
    
    return render_template(
        "vuln_scanner.html",
        available_scanners=available_scanners,
        scanner_types=[s.value for s in ScannerType],
        severity_levels=[s.value for s in SeverityLevel]
    )


@vuln_scanner_bp.route("/api/vuln-scanner/scan", methods=["POST"])
def start_scan():
    """Start a vulnerability scan"""
    try:
        data = request.get_json()
        target = data.get("target")
        scanners = data.get("scanners", [])
        scan_type = data.get("scan_type", "full")
        
        if not target:
            return jsonify({"success": False, "error": "Target URL required"}), 400
        
        # Parse scanner types
        scanner_types = None
        if scanners:
            scanner_map = {
                "nuclei": ScannerType.NUCLEI,
                "owasp_zap": ScannerType.OWASP_ZAP,
                "nikto": ScannerType.NIKTO,
                "sqlmap": ScannerType.SQLMAP,
                "nmap_nse": ScannerType.NMAP_NSE,
                "wpscan": ScannerType.WPSCAN
            }
            scanner_types = [scanner_map[s] for s in scanners if s in scanner_map]
        
        scanner = get_vuln_scanner()
        job_id = scanner.scan_target(target, scanner_types, scan_type)
        
        return jsonify({
            "success": True,
            "job_id": job_id,
            "message": "Scan started successfully"
        })
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@vuln_scanner_bp.route("/api/vuln-scanner/status/<job_id>")
def scan_status(job_id):
    """Get scan status"""
    try:
        scanner = get_vuln_scanner()
        status = scanner.get_scan_status(job_id)
        
        return jsonify(status)
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@vuln_scanner_bp.route("/api/vuln-scanner/results/<job_id>")
def scan_results(job_id):
    """Get scan results"""
    try:
        scanner = get_vuln_scanner()
        
        # Get vulnerabilities
        severity_filter = request.args.get("severity")
        if severity_filter:
            severity = SeverityLevel(severity_filter)
            vulnerabilities = scanner.get_vulnerabilities(job_id, severity)
        else:
            vulnerabilities = scanner.get_vulnerabilities(job_id)
        
        return jsonify({
            "success": True,
            "vulnerabilities": vulnerabilities
        })
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@vuln_scanner_bp.route("/api/vuln-scanner/heatmap/<job_id>")
def scan_heatmap(job_id):
    """Get vulnerability heatmap"""
    try:
        scanner = get_vuln_scanner()
        heatmap = scanner.generate_heatmap(job_id)
        
        return jsonify({
            "success": True,
            "heatmap": heatmap
        })
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@vuln_scanner_bp.route("/api/vuln-scanner/report/<job_id>")
def scan_report(job_id):
    """Export scan report"""
    try:
        scanner = get_vuln_scanner()
        format = request.args.get("format", "json")
        
        report = scanner.export_report(job_id, format)
        
        if format == "html":
            return report, 200, {"Content-Type": "text/html"}
        else:
            return report, 200, {"Content-Type": "application/json"}
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@vuln_scanner_bp.route("/api/vuln-scanner/scanners")
def list_scanners():
    """List available scanners"""
    try:
        scanner = get_vuln_scanner()
        
        scanners = []
        for scanner_type, config in scanner.scanners.items():
            scanners.append({
                "type": scanner_type.value,
                "name": scanner_type.value.replace("_", " ").title(),
                "binary": config.binary_path,
                "enabled": config.enabled
            })
        
        return jsonify({
            "success": True,
            "scanners": scanners
        })
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
