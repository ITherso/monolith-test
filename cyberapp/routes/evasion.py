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


# ============================================================
# AI-ADAPTIVE SLEEP OBFUSCATION ROUTES
# ============================================================

# Import sleep obfuscation module
try:
    from evasion.sleep_obfuscation import (
        AIAdaptiveSleepObfuscator,
        JitterPattern,
        EDRProduct,
        EDR_PROFILES,
        create_ghost_mode_obfuscator,
        create_interactive_obfuscator,
        create_aggressive_obfuscator,
    )
    HAS_SLEEP_OBFUSCATION = True
except ImportError:
    HAS_SLEEP_OBFUSCATION = False
    logger.warning("Sleep obfuscation module not available")


# Store active sleep obfuscators for sessions
_sleep_obfuscators = {}


@evasion_bp.route('/sleep/')
def sleep_obfuscation_page():
    """AI-Adaptive Sleep Obfuscation configuration page"""
    return render_template('sleep_obfuscation.html')


@evasion_bp.route('/sleep/status', methods=['GET'])
def sleep_status():
    """Get sleep obfuscation module status and capabilities"""
    return jsonify({
        'success': True,
        'available': HAS_SLEEP_OBFUSCATION,
        'patterns': [p.value for p in JitterPattern] if HAS_SLEEP_OBFUSCATION else [],
        'edr_profiles': [e.value for e in EDRProduct] if HAS_SLEEP_OBFUSCATION else [],
        'active_sessions': len(_sleep_obfuscators),
    })


@evasion_bp.route('/sleep/configure', methods=['POST'])
def configure_sleep():
    """
    Configure sleep obfuscation settings
    
    JSON body:
    {
        "session_id": "beacon_123",
        "base_sleep_ms": 30000,
        "jitter_percent": 50,
        "pattern": "adaptive",
        "opsec_level": 3,
        "edr_override": null,
        "auto_detect_edr": true
    }
    """
    if not HAS_SLEEP_OBFUSCATION:
        return jsonify({
            'success': False,
            'error': 'Sleep obfuscation module not available'
        }), 503
    
    data = request.get_json()
    session_id = data.get('session_id', f"session_{int(datetime.now().timestamp())}")
    
    try:
        # Parse pattern
        pattern_str = data.get('pattern', 'adaptive')
        pattern = JitterPattern(pattern_str)
        
        # Create obfuscator
        obfuscator = AIAdaptiveSleepObfuscator(
            base_sleep_ms=data.get('base_sleep_ms', 30000),
            jitter_percent=data.get('jitter_percent', 50),
            pattern=pattern,
            opsec_level=data.get('opsec_level', 3),
            auto_detect_edr=data.get('auto_detect_edr', True)
        )
        
        # Override EDR if specified
        edr_override = data.get('edr_override')
        if edr_override:
            obfuscator.set_edr_override(EDRProduct(edr_override))
        
        # Store obfuscator
        _sleep_obfuscators[session_id] = obfuscator
        
        return jsonify({
            'success': True,
            'session_id': session_id,
            'config': {
                'base_sleep_ms': obfuscator.base_sleep_ms,
                'jitter_percent': obfuscator.jitter_percent,
                'pattern': obfuscator.pattern.value,
                'opsec_level': obfuscator.opsec_level,
                'detected_edr': obfuscator._detected_edr.value,
            }
        })
    except Exception as e:
        logger.error(f"Failed to configure sleep obfuscation: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


@evasion_bp.route('/sleep/profiles', methods=['GET'])
def get_sleep_profiles():
    """Get available sleep profiles and EDR configurations"""
    if not HAS_SLEEP_OBFUSCATION:
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    profiles = {
        'ghost': {
            'name': 'Ghost Mode',
            'description': 'Maximum stealth for extended undetected operation (hours/days)',
            'base_sleep_ms': 60000,
            'jitter_percent': 70,
            'pattern': 'hybrid',
            'opsec_level': 4
        },
        'interactive': {
            'name': 'Interactive',
            'description': 'Low-latency for interactive sessions with evasion',
            'base_sleep_ms': 5000,
            'jitter_percent': 40,
            'pattern': 'gaussian',
            'opsec_level': 2
        },
        'aggressive': {
            'name': 'Aggressive',
            'description': 'Fast operations with minimal delay and basic evasion',
            'base_sleep_ms': 1000,
            'jitter_percent': 80,
            'pattern': 'gaussian',
            'opsec_level': 1
        }
    }
    
    edr_configs = {}
    for product, profile in EDR_PROFILES.items():
        edr_configs[product.value] = {
            'name': product.value.title(),
            'behavioral_ml': profile.behavioral_ml,
            'memory_scanning': profile.memory_scanning,
            'sleep_pattern_detection': profile.sleep_pattern_detection,
            'syscall_hooking': profile.syscall_hooking,
            'recommended_pattern': profile.recommended_pattern.value,
            'min_sleep_ms': profile.min_sleep_ms,
            'max_jitter_percent': profile.max_jitter_percent
        }
    
    return jsonify({
        'success': True,
        'profiles': profiles,
        'edr_configs': edr_configs,
        'patterns': [
            {
                'value': p.value,
                'name': p.value.replace('_', ' ').title(),
                'description': {
                    'gaussian': 'Natural variance, mimics network traffic',
                    'fibonacci': 'Mathematical pattern, hard to fingerprint',
                    'poisson': 'Event-based timing, realistic network behavior',
                    'ml_entropy': 'GAN-like entropy, defeats ML detection',
                    'adaptive': 'AI-selected based on EDR detection',
                    'hybrid': 'Combines multiple patterns dynamically'
                }.get(p.value, '')
            }
            for p in JitterPattern
        ]
    })


@evasion_bp.route('/sleep/generate-jitter', methods=['POST'])
def generate_jitter_sample():
    """
    Generate sample jitter values for visualization
    
    JSON body:
    {
        "session_id": "beacon_123",  // or use inline config
        "count": 50,
        "pattern": "hybrid",
        "base_sleep_ms": 30000,
        "jitter_percent": 50
    }
    """
    if not HAS_SLEEP_OBFUSCATION:
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    data = request.get_json()
    count = min(data.get('count', 50), 500)  # Max 500 samples
    
    # Get or create obfuscator
    session_id = data.get('session_id')
    if session_id and session_id in _sleep_obfuscators:
        obfuscator = _sleep_obfuscators[session_id]
    else:
        # Create temporary obfuscator
        pattern_str = data.get('pattern', 'hybrid')
        try:
            pattern = JitterPattern(pattern_str)
        except ValueError:
            pattern = JitterPattern.HYBRID
        
        obfuscator = AIAdaptiveSleepObfuscator(
            base_sleep_ms=data.get('base_sleep_ms', 30000),
            jitter_percent=data.get('jitter_percent', 50),
            pattern=pattern,
            auto_detect_edr=False,
            opsec_level=1  # Low OPSEC for simulation
        )
    
    # Generate samples
    samples = []
    for i in range(count):
        jitter_ms = obfuscator.calculate_jitter()
        samples.append({
            'index': i,
            'duration_ms': round(jitter_ms, 2),
            'duration_sec': round(jitter_ms / 1000, 2)
        })
    
    # Calculate statistics
    durations = [s['duration_ms'] for s in samples]
    avg = sum(durations) / len(durations)
    min_d = min(durations)
    max_d = max(durations)
    variance = sum((d - avg) ** 2 for d in durations) / len(durations)
    
    return jsonify({
        'success': True,
        'samples': samples,
        'statistics': {
            'count': count,
            'average_ms': round(avg, 2),
            'min_ms': round(min_d, 2),
            'max_ms': round(max_d, 2),
            'variance': round(variance, 4),
            'std_deviation': round(variance ** 0.5, 2),
            'pattern': obfuscator.pattern.value
        }
    })


@evasion_bp.route('/sleep/simulate', methods=['POST'])
def simulate_sleep():
    """
    Simulate a sleep operation (for testing, doesn't actually sleep)
    
    JSON body:
    {
        "session_id": "beacon_123",
        "duration_ms": null  // null = auto-calculate
    }
    """
    if not HAS_SLEEP_OBFUSCATION:
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    data = request.get_json()
    session_id = data.get('session_id')
    
    if not session_id or session_id not in _sleep_obfuscators:
        return jsonify({
            'success': False,
            'error': 'Session not found. Configure sleep first.'
        }), 404
    
    obfuscator = _sleep_obfuscators[session_id]
    duration_ms = data.get('duration_ms')
    
    # Calculate what would happen
    if duration_ms is None:
        duration_ms = int(obfuscator.calculate_jitter())
    
    # Simulate chunk splitting
    import random
    chunk_count = random.randint(3, 7 + obfuscator.opsec_level)
    
    return jsonify({
        'success': True,
        'simulation': {
            'calculated_duration_ms': duration_ms,
            'chunk_count': chunk_count,
            'syscall_method': 'NtDelayExecution (indirect)' if obfuscator.opsec_level >= 4 else 
                             'WaitForSingleObject' if obfuscator.opsec_level >= 3 else
                             'SleepEx (alertable)' if obfuscator.opsec_level >= 2 else
                             'Sleep (standard)',
            'memory_encryption': obfuscator.opsec_level >= 2,
            'fake_activity': obfuscator.opsec_level >= 2,
            'log_cleanup': obfuscator.opsec_level >= 4,
            'detected_edr': obfuscator.detected_edr,
            'pattern_used': obfuscator.pattern.value
        }
    })


@evasion_bp.route('/sleep/statistics/<session_id>', methods=['GET'])
def get_sleep_statistics(session_id: str):
    """Get statistics for a sleep session"""
    if not HAS_SLEEP_OBFUSCATION:
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    if session_id not in _sleep_obfuscators:
        return jsonify({
            'success': False,
            'error': 'Session not found'
        }), 404
    
    obfuscator = _sleep_obfuscators[session_id]
    stats = obfuscator.get_statistics()
    
    return jsonify({
        'success': True,
        'session_id': session_id,
        'statistics': stats
    })


@evasion_bp.route('/sleep/sessions', methods=['GET'])
def list_sleep_sessions():
    """List all active sleep sessions"""
    if not HAS_SLEEP_OBFUSCATION:
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    sessions = []
    for sid, obf in _sleep_obfuscators.items():
        sessions.append({
            'session_id': sid,
            'base_sleep_ms': obf.base_sleep_ms,
            'pattern': obf.pattern.value,
            'opsec_level': obf.opsec_level,
            'detected_edr': obf.detected_edr,
            'total_sleeps': len(obf._sleep_history)
        })
    
    return jsonify({
        'success': True,
        'sessions': sessions,
        'count': len(sessions)
    })


@evasion_bp.route('/sleep/delete/<session_id>', methods=['DELETE'])
def delete_sleep_session(session_id: str):
    """Delete a sleep session"""
    if session_id in _sleep_obfuscators:
        obf = _sleep_obfuscators.pop(session_id)
        obf.stop_noise_thread()
        return jsonify({
            'success': True,
            'message': f'Session {session_id} deleted'
        })
    
    return jsonify({
        'success': False,
        'error': 'Session not found'
    }), 404


@evasion_bp.route('/sleep/export-config/<session_id>', methods=['GET'])
def export_sleep_config(session_id: str):
    """Export sleep configuration for use in beacon"""
    if not HAS_SLEEP_OBFUSCATION:
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    if session_id not in _sleep_obfuscators:
        return jsonify({
            'success': False,
            'error': 'Session not found'
        }), 404
    
    obf = _sleep_obfuscators[session_id]
    
    # Generate Python code for beacon integration
    config_code = f'''# AI-Adaptive Sleep Obfuscation Configuration
# Generated for session: {session_id}

from evasion.sleep_obfuscation import (
    AIAdaptiveSleepObfuscator,
    JitterPattern,
    EDRProduct
)

# Create obfuscator with exported settings
obfuscator = AIAdaptiveSleepObfuscator(
    base_sleep_ms={obf.base_sleep_ms},
    jitter_percent={obf.jitter_percent},
    pattern=JitterPattern.{obf.pattern.name},
    opsec_level={obf.opsec_level},
    auto_detect_edr=True
)

# Override EDR if detected: {obf.detected_edr}
# obfuscator.set_edr_override(EDRProduct.{obf._detected_edr.name})

# Usage in beacon loop:
# while beacon_active:
#     obfuscator.obfuscated_sleep()  # Auto-calculated duration
#     beacon_callback()

# Or with explicit duration:
# obfuscator.sleep(30000)  # 30 second sleep with obfuscation
'''
    
    return jsonify({
        'success': True,
        'session_id': session_id,
        'config_code': config_code,
        'config_json': {
            'base_sleep_ms': obf.base_sleep_ms,
            'jitter_percent': obf.jitter_percent,
            'pattern': obf.pattern.value,
            'opsec_level': obf.opsec_level,
            'detected_edr': obf.detected_edr
        }
    })


# ============================================================
# AMSI/ETW BYPASS PRO ROUTES
# ============================================================

# Import AMSI/ETW bypass module
try:
    from evasion.amsi_bypass import (
        AMSIETWBypassEngine,
        BypassTechnique,
        EDRProduct as AMSIEDRProduct,
        EDR_PROFILES as AMSI_EDR_PROFILES,
        create_bypass_engine,
        ai_bypass,
        ghost_bypass,
        fast_bypass,
        # Legacy classes
        AMSIBypass,
        ETWBypass,
        DefenderBypass,
    )
    HAS_AMSI_BYPASS = True
except ImportError as e:
    HAS_AMSI_BYPASS = False
    logger.warning(f"AMSI/ETW bypass module not available: {e}")


# Store bypass engine sessions
_bypass_engines = {}


@evasion_bp.route('/amsi/')
def amsi_bypass_page():
    """AMSI/ETW Bypass configuration page"""
    return render_template('amsi_bypass.html')


@evasion_bp.route('/amsi/status', methods=['GET'])
def amsi_status():
    """Get AMSI/ETW bypass module status"""
    return jsonify({
        'success': True,
        'available': HAS_AMSI_BYPASS,
        'techniques': [t.value for t in BypassTechnique] if HAS_AMSI_BYPASS else [],
        'edr_profiles': [e.value for e in AMSIEDRProduct] if HAS_AMSI_BYPASS else [],
        'active_sessions': len(_bypass_engines),
    })


@evasion_bp.route('/amsi/profiles', methods=['GET'])
def get_amsi_profiles():
    """Get available EDR profiles for bypass"""
    if not HAS_AMSI_BYPASS:
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    profiles = {}
    for edr, profile in AMSI_EDR_PROFILES.items():
        profiles[edr.value] = {
            'name': profile.name,
            'hook_types': [h.value for h in profile.hook_types],
            'monitored_apis': profile.monitored_apis,
            'recommended_techniques': [t.value for t in profile.recommended_techniques],
            'syscall_monitoring': profile.syscall_monitoring,
            'detection_capabilities': profile.detection_capabilities
        }
    
    return jsonify({
        'success': True,
        'profiles': profiles,
        'techniques': {t.value: t.name for t in BypassTechnique}
    })


@evasion_bp.route('/amsi/generate', methods=['POST'])
def generate_bypass():
    """
    Generate AMSI/ETW bypass code
    
    JSON body:
    {
        "target": "amsi" | "etw" | "combined" | "unhook",
        "technique": "reflection" | "memory_patch" | etc,
        "edr_override": "falcon" | "defender" | null,
        "opsec_level": 1-4,
        "enable_mutation": true/false
    }
    """
    if not HAS_AMSI_BYPASS:
        return jsonify({
            'success': False,
            'error': 'AMSI/ETW bypass module not available'
        }), 503
    
    data = request.get_json()
    target = data.get('target', 'combined')
    technique_str = data.get('technique')
    edr_override = data.get('edr_override')
    opsec_level = data.get('opsec_level', 3)
    enable_mutation = data.get('enable_mutation', True)
    
    try:
        # Create engine
        engine = create_bypass_engine(
            edr=edr_override,
            opsec_level=opsec_level
        )
        engine.enable_mutation = enable_mutation
        
        # Parse technique if specified
        technique = None
        if technique_str:
            try:
                technique = BypassTechnique(technique_str)
            except ValueError:
                pass
        
        # Generate code based on target
        if target == 'amsi':
            code = engine.get_amsi_bypass(technique)
            bypass_type = 'AMSI Bypass'
        elif target == 'etw':
            code = engine.get_etw_bypass(technique)
            bypass_type = 'ETW Bypass'
        elif target == 'unhook':
            code = engine.get_unhook()
            bypass_type = 'NTDLL Unhook'
        else:  # combined
            code = engine.get_combined_bypass()
            bypass_type = 'Combined AI-Dynamic Bypass'
        
        return jsonify({
            'success': True,
            'bypass_type': bypass_type,
            'target': target,
            'technique': technique.value if technique else 'ai_selected',
            'detected_edr': engine.detected_edr,
            'opsec_level': opsec_level,
            'code': code,
            'code_length': len(code),
            'recommended': engine.get_bypass_status()['recommended_techniques']
        })
    except Exception as e:
        logger.error(f"Failed to generate bypass: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


@evasion_bp.route('/amsi/quick/<preset>', methods=['GET'])
def quick_bypass(preset: str):
    """
    Get quick bypass by preset name
    
    Presets: ai, ghost, fast
    """
    if not HAS_AMSI_BYPASS:
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    presets = {
        'ai': ai_bypass,
        'ghost': ghost_bypass,
        'fast': fast_bypass
    }
    
    if preset not in presets:
        return jsonify({
            'success': False,
            'error': f"Unknown preset. Available: {list(presets.keys())}"
        }), 400
    
    try:
        code = presets[preset]()
        return jsonify({
            'success': True,
            'preset': preset,
            'code': code,
            'code_length': len(code)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@evasion_bp.route('/amsi/session', methods=['POST'])
def create_bypass_session():
    """
    Create persistent bypass session
    
    JSON body:
    {
        "session_id": "beacon_001",
        "edr_override": "falcon",
        "opsec_level": 3
    }
    """
    if not HAS_AMSI_BYPASS:
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    data = request.get_json()
    session_id = data.get('session_id', f"amsi_{int(datetime.now().timestamp())}")
    
    try:
        engine = create_bypass_engine(
            edr=data.get('edr_override'),
            opsec_level=data.get('opsec_level', 3)
        )
        
        _bypass_engines[session_id] = engine
        
        return jsonify({
            'success': True,
            'session_id': session_id,
            'status': engine.get_bypass_status()
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@evasion_bp.route('/amsi/sessions', methods=['GET'])
def list_bypass_sessions():
    """List all bypass sessions"""
    if not HAS_AMSI_BYPASS:
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    sessions = []
    for sid, engine in _bypass_engines.items():
        sessions.append({
            'session_id': sid,
            'detected_edr': engine.detected_edr,
            'opsec_level': engine.opsec_level,
            'status': engine.get_bypass_status()
        })
    
    return jsonify({
        'success': True,
        'sessions': sessions,
        'count': len(sessions)
    })


@evasion_bp.route('/amsi/session/<session_id>', methods=['DELETE'])
def delete_bypass_session(session_id: str):
    """Delete a bypass session"""
    if session_id in _bypass_engines:
        del _bypass_engines[session_id]
        return jsonify({'success': True, 'message': f'Session {session_id} deleted'})
    return jsonify({'success': False, 'error': 'Session not found'}), 404


@evasion_bp.route('/amsi/legacy/<technique>', methods=['GET'])
def legacy_bypass(technique: str):
    """
    Get legacy bypass code (backward compatibility)
    
    Techniques: reflection, memory_patch, context, clr, etw_patch, etw_provider
    """
    if not HAS_AMSI_BYPASS:
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    legacy_map = {
        'reflection': AMSIBypass.get_reflection_bypass,
        'memory_patch': AMSIBypass.get_memory_patch_bypass,
        'context': AMSIBypass.get_context_corruption_bypass,
        'clr': AMSIBypass.get_clr_bypass,
        'etw_patch': ETWBypass.get_etw_patch,
        'etw_provider': ETWBypass.get_etw_provider_bypass,
        'defender_enum': DefenderBypass.get_defender_exclusion_enum,
        'defender_disable': DefenderBypass.get_defender_disable,
    }
    
    if technique not in legacy_map:
        return jsonify({
            'success': False,
            'error': f"Unknown technique. Available: {list(legacy_map.keys())}"
        }), 400
    
    try:
        code = legacy_map[technique]()
        return jsonify({
            'success': True,
            'technique': technique,
            'code': code
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@evasion_bp.route('/amsi/loader', methods=['POST'])
def generate_bypass_loader():
    """
    Generate bypass loader for payload
    
    JSON body:
    {
        "payload": "Write-Host 'Hello'",
        "opsec_level": 3,
        "obfuscate": true
    }
    """
    if not HAS_AMSI_BYPASS:
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    data = request.get_json()
    payload = data.get('payload', "Write-Host '[+] Payload executed successfully'")
    opsec_level = data.get('opsec_level', 3)
    obfuscate = data.get('obfuscate', False)
    
    try:
        from evasion.amsi_bypass import generate_bypass_loader, get_obfuscated_bypass
        
        if obfuscate:
            loader = get_obfuscated_bypass()
            loader += f"\n\n# Payload\n{payload}"
        else:
            loader = generate_bypass_loader(payload)
        
        return jsonify({
            'success': True,
            'loader': loader,
            'loader_length': len(loader),
            'obfuscated': obfuscate
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
