"""
S3 Bucket Marauder Flask Routes
================================
Cloud storage reconnaissance and exfiltration API endpoints.
"""

from flask import Blueprint, render_template, request, jsonify, Response
import io
import json

s3_marauder_bp = Blueprint('s3_marauder', __name__, url_prefix='/s3-marauder')

try:
    from tools.s3_bucket_marauder import (
        get_marauder,
        S3BucketMarauder,
        S3BucketEnumerator,
        BucketStatus,
        DataSensitivity
    )
except ImportError:
    get_marauder = None
    S3BucketMarauder = None


@s3_marauder_bp.route('/')
def index():
    """S3 Marauder main dashboard"""
    return render_template('s3_marauder.html')


@s3_marauder_bp.route('/api/generate-names', methods=['POST'])
def generate_names():
    """Generate bucket name variations for a company"""
    if not S3BucketMarauder:
        return jsonify({"error": "S3 Bucket Marauder not available"}), 500
    
    try:
        data = request.get_json() or {}
        company_name = data.get('company_name', 'acmecorp')
        
        marauder = S3BucketMarauder(threads=20, timeout=5)
        bucket_names = list(marauder.generate_bucket_names(company_name))
        
        return jsonify({
            "success": True,
            "company": company_name,
            "count": len(bucket_names),
            "bucket_names": bucket_names[:100]  # Limit output
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@s3_marauder_bp.route('/api/scan', methods=['POST'])
def scan_buckets():
    """Scan for S3 buckets"""
    if not get_marauder:
        return jsonify({"error": "S3 Bucket Marauder not available"}), 500
    
    try:
        data = request.get_json() or {}
        company_name = data.get('company_name', 'acmecorp')
        max_buckets = min(data.get('max_buckets', 1000), 5000)
        
        marauder = get_marauder()
        marauder._stop_event.clear()
        
        findings = marauder.scan_buckets(company_name, max_buckets=max_buckets)
        
        return jsonify({
            "success": True,
            "company": company_name,
            "findings_count": len(findings),
            "findings": [f.to_dict() for f in findings]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@s3_marauder_bp.route('/api/statistics', methods=['GET'])
def get_statistics():
    """Get marauder statistics"""
    if not get_marauder:
        return jsonify({"error": "S3 Bucket Marauder not available"}), 500
    
    try:
        marauder = get_marauder()
        return jsonify({
            "success": True,
            "statistics": marauder.get_statistics()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@s3_marauder_bp.route('/api/report', methods=['GET'])
def get_report():
    """Generate scan report"""
    if not get_marauder:
        return jsonify({"error": "S3 Bucket Marauder not available"}), 500
    
    try:
        marauder = get_marauder()
        report = marauder.generate_report()
        return jsonify({
            "success": True,
            "report": report
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@s3_marauder_bp.route('/api/stop', methods=['POST'])
def stop_scan():
    """Stop ongoing scan"""
    if not get_marauder:
        return jsonify({"error": "S3 Bucket Marauder not available"}), 500
    
    try:
        marauder = get_marauder()
        marauder.stop()
        return jsonify({
            "success": True,
            "message": "Scan stopped"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@s3_marauder_bp.route('/api/wordlist', methods=['POST'])
def generate_wordlist():
    """Generate wordlist for external tools"""
    if not S3BucketMarauder:
        return jsonify({"error": "S3 Bucket Marauder not available"}), 500
    
    try:
        data = request.get_json() or {}
        company_name = data.get('company_name', 'acmecorp')
        
        marauder = S3BucketMarauder()
        bucket_names = marauder.generate_wordlist(company_name)
        
        return Response(
            '\n'.join(bucket_names),
            mimetype='text/plain',
            headers={'Content-Disposition': 'attachment; filename=s3_wordlist.txt'}
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500