"""
Evasion Testing Routes
======================
API endpoints for payload evasion testing and analysis

Endpoints:
- POST /evasion/test/file - Test a file for detection
- POST /evasion/test/bytes - Test raw bytes
- POST /evasion/test/code - Test code pattern
- POST /evasion/yara - Run YARA scan
- POST /evasion/strings - Check suspicious strings
- POST /evasion/entropy - Analyze entropy
- GET /evasion/report/<id> - Get test report
"""

from flask import Blueprint, request, jsonify, render_template
import logging
import base64
from datetime import datetime
import os
import tempfile

from cybermodules.evasion_testing import (
    EvasionTester,
    YARAScanner,
    StringScanner,
    EntropyAnalyzer,
    BehavioralAnalyzer,
    DetectionLevel,
)

logger = logging.getLogger("evasion_routes")

evasion_bp = Blueprint('evasion', __name__, url_prefix='/evasion')

# Store test reports in memory
_test_reports = {}


@evasion_bp.route('/')
def index():
    """Evasion testing page"""
    return render_template('evasion_test.html')


# ============================================================
# FILE TESTING
# ============================================================

@evasion_bp.route('/test/file', methods=['POST'])
def test_file():
    """
    Test a file for detection indicators
    
    Request (multipart/form-data):
    - file: The file to test
    
    Or JSON:
    {
        "path": "/path/to/file"
    }
    """
    scan_id = int(datetime.now().timestamp())
    tester = EvasionTester(scan_id)
    
    # Handle file upload
    if 'file' in request.files:
        uploaded = request.files['file']
        if uploaded.filename:
            # Save to temp file
            with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uploaded.filename)[1]) as f:
                uploaded.save(f.name)
                try:
                    report = tester.test_file(f.name)
                finally:
                    os.unlink(f.name)
    # Handle path
    elif request.is_json:
        data = request.get_json()
        path = data.get('path')
        if not path or not os.path.exists(path):
            return jsonify({
                'success': False,
                'error': 'Invalid file path'
            }), 400
        report = tester.test_file(path)
    else:
        return jsonify({
            'success': False,
            'error': 'No file provided'
        }), 400
    
    # Store report
    report_id = f"{scan_id}_{report.file_name}"
    _test_reports[report_id] = report
    
    return jsonify({
        'success': True,
        'report_id': report_id,
        'file_name': report.file_name,
        'file_size': report.file_size,
        'overall_risk': report.overall_risk.value,
        'total_score': report.total_score,
        'yara_matches': len(report.yara_matches),
        'suspicious_strings': len(report.suspicious_strings),
        'entropy': report.entropy_analysis.get('overall_entropy', 0) if report.entropy_analysis else 0,
        'behavioral_score': report.behavioral_analysis.get('score', 0) if report.behavioral_analysis else 0,
        'recommendations': report.recommendations[:5]  # First 5 recommendations
    })


@evasion_bp.route('/test/bytes', methods=['POST'])
def test_bytes():
    """
    Test raw bytes for detection indicators
    
    Request:
    {
        "data": "<base64 encoded data>",
        "name": "payload.bin"
    }
    """
    data = request.get_json()
    
    if not data.get('data'):
        return jsonify({
            'success': False,
            'error': 'data field is required (base64 encoded)'
        }), 400
    
    try:
        payload_bytes = base64.b64decode(data['data'])
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Invalid base64 data: {e}'
        }), 400
    
    scan_id = int(datetime.now().timestamp())
    tester = EvasionTester(scan_id)
    
    name = data.get('name', 'payload.bin')
    report = tester.test_bytes(payload_bytes, name=name)
    
    report_id = f"{scan_id}_{name}"
    _test_reports[report_id] = report
    
    return jsonify({
        'success': True,
        'report_id': report_id,
        'file_name': report.file_name,
        'file_size': report.file_size,
        'overall_risk': report.overall_risk.value,
        'total_score': report.total_score,
        'yara_matches': len(report.yara_matches),
        'suspicious_strings': len(report.suspicious_strings),
        'entropy': report.entropy_analysis.get('overall_entropy', 0) if report.entropy_analysis else 0,
        'recommendations': report.recommendations[:5]
    })


@evasion_bp.route('/test/code', methods=['POST'])
def test_code():
    """
    Test code pattern for detection indicators
    
    Request:
    {
        "code": "import ctypes\\nctypes.windll.kernel32...",
        "language": "python"
    }
    """
    data = request.get_json()
    
    code = data.get('code', '')
    language = data.get('language', 'python')
    
    if not code:
        return jsonify({
            'success': False,
            'error': 'code field is required'
        }), 400
    
    scan_id = int(datetime.now().timestamp())
    tester = EvasionTester(scan_id)
    
    report = tester.test_code_pattern(code, language=language)
    
    report_id = f"{scan_id}_code_{language}"
    _test_reports[report_id] = report
    
    return jsonify({
        'success': True,
        'report_id': report_id,
        'language': language,
        'overall_risk': report.overall_risk.value,
        'total_score': report.total_score,
        'suspicious_strings': len(report.suspicious_strings),
        'behavioral_score': report.behavioral_analysis.get('score', 0) if report.behavioral_analysis else 0,
        'recommendations': report.recommendations
    })


# ============================================================
# INDIVIDUAL SCANNERS
# ============================================================

@evasion_bp.route('/yara', methods=['POST'])
def yara_scan():
    """
    Run YARA scan on data
    
    Request:
    {
        "data": "<base64 encoded data>",
        "rules": ["rule1", "rule2"]  // Optional custom rules
    }
    """
    data = request.get_json()
    
    if not data.get('data'):
        return jsonify({
            'success': False,
            'error': 'data field is required'
        }), 400
    
    try:
        payload_bytes = base64.b64decode(data['data'])
    except Exception:
        return jsonify({
            'success': False,
            'error': 'Invalid base64 data'
        }), 400
    
    scan_id = int(datetime.now().timestamp())
    scanner = YARAScanner(scan_id)
    
    # Add custom rules if provided
    custom_rules = data.get('rules', [])
    for rule in custom_rules:
        try:
            scanner.add_rule(rule)
        except Exception as e:
            logger.warning(f"Failed to add custom rule: {e}")
    
    matches = scanner.scan_bytes(payload_bytes)
    
    return jsonify({
        'success': True,
        'matches': [
            {
                'rule': m.rule_name,
                'description': m.description,
                'severity': m.severity,
                'strings': m.matched_strings[:10]  # First 10 matches
            }
            for m in matches
        ],
        'total_matches': len(matches)
    })


@evasion_bp.route('/strings', methods=['POST'])
def string_scan():
    """
    Check for suspicious strings
    
    Request:
    {
        "data": "<base64 encoded data>"
    }
    """
    data = request.get_json()
    
    if not data.get('data'):
        return jsonify({
            'success': False,
            'error': 'data field is required'
        }), 400
    
    try:
        payload_bytes = base64.b64decode(data['data'])
    except Exception:
        return jsonify({
            'success': False,
            'error': 'Invalid base64 data'
        }), 400
    
    scan_id = int(datetime.now().timestamp())
    scanner = StringScanner(scan_id)
    
    strings = scanner.find_suspicious_strings(payload_bytes)
    
    # Group by category
    by_category = {}
    for s in strings:
        cat = s.category
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append({
            'value': s.value[:50] + '...' if len(s.value) > 50 else s.value,
            'offset': s.offset,
            'risk_score': s.risk_score
        })
    
    return jsonify({
        'success': True,
        'total_found': len(strings),
        'by_category': by_category,
        'total_risk': sum(s.risk_score for s in strings)
    })


@evasion_bp.route('/entropy', methods=['POST'])
def entropy_analyze():
    """
    Analyze data entropy
    
    Request:
    {
        "data": "<base64 encoded data>"
    }
    """
    data = request.get_json()
    
    if not data.get('data'):
        return jsonify({
            'success': False,
            'error': 'data field is required'
        }), 400
    
    try:
        payload_bytes = base64.b64decode(data['data'])
    except Exception:
        return jsonify({
            'success': False,
            'error': 'Invalid base64 data'
        }), 400
    
    scan_id = int(datetime.now().timestamp())
    analyzer = EntropyAnalyzer(scan_id)
    
    analysis = analyzer.analyze(payload_bytes)
    
    return jsonify({
        'success': True,
        'overall_entropy': analysis['overall_entropy'],
        'is_packed': analysis['is_packed'],
        'is_encrypted': analysis['is_encrypted'],
        'high_entropy_sections': analysis['high_entropy_sections'],
        'risk_assessment': analysis['risk_assessment']
    })


@evasion_bp.route('/behavioral', methods=['POST'])
def behavioral_analyze():
    """
    Analyze behavioral patterns
    
    Request:
    {
        "code": "python code...",
        "language": "python"
    }
    """
    data = request.get_json()
    
    code = data.get('code', '')
    language = data.get('language', 'python')
    
    if not code:
        return jsonify({
            'success': False,
            'error': 'code field is required'
        }), 400
    
    scan_id = int(datetime.now().timestamp())
    analyzer = BehavioralAnalyzer(scan_id)
    
    analysis = analyzer.analyze_code(code, language)
    
    return jsonify({
        'success': True,
        'score': analysis['score'],
        'patterns_found': analysis['patterns_found'],
        'api_calls': analysis['api_calls'],
        'risk_level': analysis['risk_level']
    })


# ============================================================
# REPORTS
# ============================================================

@evasion_bp.route('/report/<report_id>', methods=['GET'])
def get_report(report_id):
    """Get full test report"""
    if report_id not in _test_reports:
        return jsonify({
            'success': False,
            'error': 'Report not found'
        }), 404
    
    report = _test_reports[report_id]
    
    scan_id = int(datetime.now().timestamp())
    tester = EvasionTester(scan_id)
    
    return jsonify({
        'success': True,
        'report': {
            'file_name': report.file_name,
            'file_size': report.file_size,
            'file_hash': report.file_hash,
            'scan_time': report.scan_time.isoformat() if report.scan_time else None,
            'overall_risk': report.overall_risk.value,
            'total_score': report.total_score,
            'yara_matches': [
                {
                    'rule': m.rule_name,
                    'description': m.description,
                    'severity': m.severity
                }
                for m in report.yara_matches
            ],
            'suspicious_strings': [
                {
                    'value': s.value[:50],
                    'category': s.category,
                    'risk_score': s.risk_score
                }
                for s in report.suspicious_strings[:20]
            ],
            'entropy_analysis': report.entropy_analysis,
            'behavioral_analysis': report.behavioral_analysis,
            'recommendations': report.recommendations
        },
        'markdown': tester.generate_report_markdown(report)
    })


@evasion_bp.route('/report/<report_id>/markdown', methods=['GET'])
def get_report_markdown(report_id):
    """Get report as markdown"""
    if report_id not in _test_reports:
        return jsonify({
            'success': False,
            'error': 'Report not found'
        }), 404
    
    report = _test_reports[report_id]
    
    scan_id = int(datetime.now().timestamp())
    tester = EvasionTester(scan_id)
    
    return tester.generate_report_markdown(report), 200, {'Content-Type': 'text/markdown'}


@evasion_bp.route('/reports', methods=['GET'])
def list_reports():
    """List all test reports"""
    return jsonify({
        'success': True,
        'reports': [
            {
                'id': rid,
                'file_name': r.file_name,
                'risk': r.overall_risk.value,
                'score': r.total_score
            }
            for rid, r in _test_reports.items()
        ]
    })
