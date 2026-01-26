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
- GET /evasion/adversarial - AI Adversarial training page
- POST /evasion/adversarial/mutate - Mutate payload with GAN
- POST /evasion/adversarial/benchmark - Benchmark against all EDRs
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

# Try to import AI Adversarial module
# Using lazy import to avoid TensorFlow SIGILL on some CPUs
AI_ADVERSARIAL_AVAILABLE = False
AIAdversarialTrainer = None
EDRVendor = None
AttackMethod = None
AdversarialConfig = None

def _lazy_import_adversarial():
    """Lazy import AI Adversarial module to avoid startup issues"""
    global AI_ADVERSARIAL_AVAILABLE, AIAdversarialTrainer, EDRVendor, AttackMethod, AdversarialConfig
    if AIAdversarialTrainer is None:
        try:
            from evasion.ai_adversarial import (
                AIAdversarialTrainer as _AIAdversarialTrainer,
                EDRVendor as _EDRVendor,
                AttackMethod as _AttackMethod,
                AdversarialConfig as _AdversarialConfig,
            )
            AIAdversarialTrainer = _AIAdversarialTrainer
            EDRVendor = _EDRVendor
            AttackMethod = _AttackMethod
            AdversarialConfig = _AdversarialConfig
            AI_ADVERSARIAL_AVAILABLE = True
        except Exception as e:
            logger.warning(f"AI Adversarial import failed: {e}")
            AI_ADVERSARIAL_AVAILABLE = False
    return AI_ADVERSARIAL_AVAILABLE

logger = logging.getLogger("evasion_routes")

evasion_bp = Blueprint('evasion', __name__, url_prefix='/evasion')

# Store test reports in memory
_test_reports = {}

# Global AI Adversarial trainer instance
_ai_trainer = None


def _get_ai_trainer():
    """Get or create AI Adversarial trainer instance"""
    global _ai_trainer
    if not _lazy_import_adversarial():
        return None
    if _ai_trainer is None and AIAdversarialTrainer is not None:
        _ai_trainer = AIAdversarialTrainer()
    return _ai_trainer


@evasion_bp.route('/')
def index():
    """Evasion testing page"""
    return render_template('evasion_test.html')


# ============================================================
# AI ADVERSARIAL TRAINING
# ============================================================

@evasion_bp.route('/adversarial')
def adversarial_page():
    """AI Adversarial training page"""
    # EDR targets with colors and icons
    edrs = [
        {"id": "sentinelone", "name": "SentinelOne", "color": "red", "icon": "fas fa-shield-alt", "evasion_rate": 87},
        {"id": "crowdstrike", "name": "CrowdStrike", "color": "orange", "icon": "fas fa-crow", "evasion_rate": 82},
        {"id": "defender", "name": "Defender ATP", "color": "blue", "icon": "fab fa-windows", "evasion_rate": 79},
        {"id": "carbon_black", "name": "Carbon Black", "color": "gray", "icon": "fas fa-cube", "evasion_rate": 84},
        {"id": "cylance", "name": "Cylance AI", "color": "purple", "icon": "fas fa-brain", "evasion_rate": 91},
        {"id": "sophos", "name": "Sophos", "color": "cyan", "icon": "fas fa-shield-virus", "evasion_rate": 80},
    ]
    
    # Mutation strategies
    strategies = [
        {"id": "nop_insertion", "name": "NOP Insertion", "description": "Insert NOP sleds"},
        {"id": "register_swap", "name": "Register Swap", "description": "Substitute registers"},
        {"id": "instruction_reorder", "name": "Instruction Reorder", "description": "Reorder independent ops"},
        {"id": "dead_code", "name": "Dead Code", "description": "Inject dead code"},
        {"id": "encoding_variation", "name": "Encoding Variation", "description": "Vary instruction encoding"},
        {"id": "api_hashing", "name": "API Hashing", "description": "Hash API names"},
        {"id": "control_flow", "name": "Control Flow", "description": "Obfuscate control flow"},
        {"id": "string_encryption", "name": "String Encryption", "description": "Encrypt strings"},
    ]
    
    # Get stats if available
    stats = None
    has_model = False
    _lazy_import_adversarial()  # Try to import
    if AI_ADVERSARIAL_AVAILABLE:
        trainer = _get_ai_trainer()
        if trainer:
            stats = trainer.get_stats()
            has_model = True
    
    return render_template('adversarial.html',
        available=AI_ADVERSARIAL_AVAILABLE,
        edrs=edrs,
        strategies=strategies,
        stats=stats,
        has_model=has_model,
        now=datetime.now().strftime('%H:%M:%S')
    )


@evasion_bp.route('/adversarial/mutate', methods=['POST'])
def adversarial_mutate():
    """
    Mutate a payload to evade EDR detection
    
    Request (form or JSON):
        payload: Base64 encoded payload
        target_edr: Target EDR vendor
        attack_method: Attack method (gan, fgsm, pgd, etc.)
        confidence_target: Target detection confidence (0-100)
        iterations: Max iterations
    """
    if not AI_ADVERSARIAL_AVAILABLE:
        return jsonify({
            "success": False,
            "error": "AI Adversarial module not available"
        }), 503
    
    # Get parameters from form or JSON
    if request.is_json:
        data = request.get_json()
        payload_b64 = data.get('payload', '')
        target_edr = data.get('target_edr', 'sentinelone')
        attack_method = data.get('attack_method', 'gan')
        confidence_target = float(data.get('confidence_target', 10)) / 100
        iterations = int(data.get('iterations', 100))
    else:
        payload_b64 = request.form.get('payload', '')
        target_edr = request.form.get('target_edr', 'sentinelone')
        attack_method = request.form.get('attack_method', 'gan')
        confidence_target = float(request.form.get('confidence_target', 10)) / 100
        iterations = int(request.form.get('iterations', 100))
        
        # Handle file upload
        if 'payload_file' in request.files:
            file = request.files['payload_file']
            if file.filename:
                payload_b64 = base64.b64encode(file.read()).decode()
    
    if not payload_b64:
        return jsonify({
            "success": False,
            "error": "No payload provided"
        }), 400
    
    try:
        payload = base64.b64decode(payload_b64)
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Invalid base64 payload: {e}"
        }), 400
    
    try:
        trainer = _get_ai_trainer()
        if not trainer:
            return jsonify({
                "success": False,
                "error": "Failed to initialize AI trainer"
            }), 500
        
        # Run adversarial mutation
        result = trainer.evade_edr(
            payload=payload,
            target_edr=target_edr,
            confidence_target=confidence_target,
            max_iterations=iterations
        )
        
        return jsonify({
            "success": result.success,
            "original_detection": result.original_confidence,
            "evaded_detection": result.final_confidence,
            "improvement": result.original_confidence - result.final_confidence,
            "mutations_applied": result.mutations_applied,
            "edr_target": target_edr,
            "attack_method": attack_method,
            "iterations": result.iterations,
            "mutated_payload": base64.b64encode(result.mutated_payload).decode() if result.success else None
        })
        
    except Exception as e:
        logger.exception("Adversarial mutation error")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@evasion_bp.route('/adversarial/benchmark', methods=['POST'])
def adversarial_benchmark():
    """
    Benchmark payload against multiple EDRs
    
    Request (JSON):
        payload: Base64 encoded payload
        target_edrs: List of EDR vendors (optional, defaults to all)
    """
    if not AI_ADVERSARIAL_AVAILABLE:
        return jsonify({
            "success": False,
            "error": "AI Adversarial module not available"
        }), 503
    
    data = request.get_json()
    payload_b64 = data.get('payload', '')
    target_edrs = data.get('target_edrs', ['sentinelone', 'crowdstrike', 'defender', 'carbon_black', 'cylance', 'sophos'])
    
    if not payload_b64:
        return jsonify({
            "success": False,
            "error": "No payload provided"
        }), 400
    
    try:
        payload = base64.b64decode(payload_b64)
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Invalid base64 payload: {e}"
        }), 400
    
    try:
        trainer = _get_ai_trainer()
        if not trainer:
            return jsonify({
                "success": False,
                "error": "Failed to initialize AI trainer"
            }), 500
        
        benchmark_results = {}
        for edr in target_edrs:
            try:
                result = trainer.evade_edr(
                    payload=payload,
                    target_edr=edr,
                    confidence_target=0.1,
                    max_iterations=50
                )
                benchmark_results[edr] = {
                    "original_detection": result.original_confidence,
                    "evaded_detection": result.final_confidence,
                    "success": result.success,
                    "iterations": result.iterations
                }
            except Exception as e:
                benchmark_results[edr] = {
                    "error": str(e),
                    "success": False
                }
        
        avg_improvement = sum(
            r.get("original_detection", 0) - r.get("evaded_detection", 0)
            for r in benchmark_results.values()
            if not r.get("error")
        ) / max(len([r for r in benchmark_results.values() if not r.get("error")]), 1)
        
        return jsonify({
            "success": True,
            "benchmark_results": benchmark_results,
            "avg_improvement": avg_improvement
        })
        
    except Exception as e:
        logger.exception("Benchmark error")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@evasion_bp.route('/adversarial/train', methods=['POST'])
def adversarial_train():
    """
    Train GAN model with benign samples
    
    Request (multipart/form-data):
        training_samples: Uploaded files
        epochs: Number of epochs
    """
    if not AI_ADVERSARIAL_AVAILABLE:
        return jsonify({
            "success": False,
            "error": "AI Adversarial module not available"
        }), 503
    
    epochs = int(request.form.get('epochs', 50))
    
    # Collect training samples
    samples = []
    if 'training_samples' in request.files:
        files = request.files.getlist('training_samples')
        for f in files:
            if f.filename:
                samples.append(f.read())
    
    if not samples:
        return jsonify({
            "success": False,
            "error": "No training samples provided"
        }), 400
    
    try:
        trainer = _get_ai_trainer()
        if not trainer:
            return jsonify({
                "success": False,
                "error": "Failed to initialize AI trainer"
            }), 500
        
        result = trainer.train(
            benign_samples=samples,
            epochs=epochs
        )
        
        return jsonify({
            "success": True,
            "epochs_trained": epochs,
            "training_loss": result.get("final_loss", 0.0),
            "generator_loss": result.get("generator_loss", 0.0),
            "discriminator_loss": result.get("discriminator_loss", 0.0)
        })
        
    except Exception as e:
        logger.exception("Training error")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@evasion_bp.route('/adversarial/analyze', methods=['POST'])
def adversarial_analyze():
    """
    Analyze payload for detection likelihood
    
    Request (JSON):
        payload: Base64 encoded payload
    """
    if not AI_ADVERSARIAL_AVAILABLE:
        return jsonify({
            "success": False,
            "error": "AI Adversarial module not available"
        }), 503
    
    data = request.get_json()
    payload_b64 = data.get('payload', '')
    
    if not payload_b64:
        return jsonify({
            "success": False,
            "error": "No payload provided"
        }), 400
    
    try:
        payload = base64.b64decode(payload_b64)
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Invalid base64 payload: {e}"
        }), 400
    
    try:
        trainer = _get_ai_trainer()
        if not trainer:
            return jsonify({
                "success": False,
                "error": "Failed to initialize AI trainer"
            }), 500
        
        analysis = trainer.analyze_payload(payload)
        
        return jsonify({
            "success": True,
            "feature_analysis": analysis.get("features", {}),
            "detection_likelihood": analysis.get("detection_likelihood", {}),
            "recommended_mutations": analysis.get("recommended_mutations", []),
            "risk_score": analysis.get("risk_score", 0.0)
        })
        
    except Exception as e:
        logger.exception("Analysis error")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@evasion_bp.route('/adversarial/status', methods=['GET'])
def adversarial_status():
    """Get AI Adversarial module status"""
    if not AI_ADVERSARIAL_AVAILABLE:
        return jsonify({
            "available": False,
            "error": "AI Adversarial module not available"
        })
    
    trainer = _get_ai_trainer()
    if trainer:
        stats = trainer.get_stats()
        return jsonify({
            "available": True,
            "stats": stats
        })
    
    return jsonify({
        "available": True,
        "stats": None
    })


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


# ============================================================
# EDR TELEMETRY POISONING
# ============================================================

# Try to import EDR Poison module
EDR_POISON_AVAILABLE = False
_edr_poison_api = None

def _get_edr_poison_api():
    """Get or create EDR Poison API instance"""
    global EDR_POISON_AVAILABLE, _edr_poison_api
    if _edr_poison_api is None:
        try:
            import sys
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'evasion'))
            from edr_poison import get_edr_poison_api
            _edr_poison_api = get_edr_poison_api()
            EDR_POISON_AVAILABLE = True
        except Exception as e:
            logger.warning(f"EDR Poison import failed: {e}")
            EDR_POISON_AVAILABLE = False
    return _edr_poison_api


@evasion_bp.route('/edr-poison')
def edr_poison_page():
    """EDR Telemetry Poisoning page"""
    return render_template('edr_poison.html')


@evasion_bp.route('/api/edr-poison/status')
def edr_poison_status():
    """Get EDR Poison module status"""
    api = _get_edr_poison_api()
    return jsonify({
        'success': True,
        'available': api is not None,
        'module': 'edr_poison',
        'features': {
            'noise_generator': True,
            'campaigns': True,
            'edr_patterns': True,
            'script_generator': True
        }
    })


@evasion_bp.route('/api/edr-poison/generate', methods=['POST'])
def edr_poison_generate():
    """Generate instant noise burst"""
    api = _get_edr_poison_api()
    if not api:
        return jsonify({'success': False, 'error': 'EDR Poison module not available'}), 503
    
    data = request.get_json() or {}
    
    try:
        result = api.generate_instant_noise(
            categories=data.get('categories', ['discovery', 'credential_access']),
            intensity=data.get('intensity', 'medium'),
            target_edr=data.get('target_edr', 'generic')
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@evasion_bp.route('/api/edr-poison/campaign/create', methods=['POST'])
def edr_poison_create_campaign():
    """Create a new poisoning campaign"""
    api = _get_edr_poison_api()
    if not api:
        return jsonify({'success': False, 'error': 'EDR Poison module not available'}), 503
    
    data = request.get_json() or {}
    
    try:
        result = api.create_campaign(
            name=data.get('name', 'Untitled Campaign'),
            target_edr=data.get('target_edr', 'generic'),
            intensity=data.get('intensity', 'medium'),
            categories=data.get('categories'),
            duration_minutes=data.get('duration_minutes', 30)
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@evasion_bp.route('/api/edr-poison/campaign/<campaign_id>/start', methods=['POST'])
def edr_poison_start_campaign(campaign_id):
    """Start a poisoning campaign"""
    api = _get_edr_poison_api()
    if not api:
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    try:
        result = api.start_campaign(campaign_id)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@evasion_bp.route('/api/edr-poison/campaign/<campaign_id>/stop', methods=['POST'])
def edr_poison_stop_campaign(campaign_id):
    """Stop a poisoning campaign"""
    api = _get_edr_poison_api()
    if not api:
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    try:
        result = api.stop_campaign(campaign_id)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@evasion_bp.route('/api/edr-poison/campaigns')
def edr_poison_list_campaigns():
    """List all campaigns"""
    api = _get_edr_poison_api()
    if not api:
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    try:
        result = api.list_campaigns()
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@evasion_bp.route('/api/edr-poison/stats')
def edr_poison_stats():
    """Get poisoning statistics"""
    api = _get_edr_poison_api()
    if not api:
        return jsonify({
            'success': True,
            'total_events': 0,
            'by_category': {},
            'by_severity': {},
            'active_campaigns': 0,
            'total_campaigns': 0
        })
    
    try:
        result = api.get_statistics()
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@evasion_bp.route('/api/edr-poison/patterns/<edr>/<category>')
def edr_poison_patterns(edr, category):
    """Get EDR-specific patterns"""
    api = _get_edr_poison_api()
    if not api:
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    try:
        result = api.get_edr_specific_payload(edr, category)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@evasion_bp.route('/api/edr-poison/export')
def edr_poison_export():
    """Export generated events"""
    api = _get_edr_poison_api()
    if not api:
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    format = request.args.get('format', 'json')
    
    try:
        data = api.export_events(format=format)
        return data, 200, {'Content-Type': 'application/json' if format == 'json' else 'text/csv'}
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@evasion_bp.route('/api/edr-poison/clear', methods=['POST'])
def edr_poison_clear():
    """Clear all generated events"""
    api = _get_edr_poison_api()
    if not api:
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    try:
        result = api.clear_events()
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================
# PURPLE TEAM VALIDATOR
# ============================================================

PURPLE_TEAM_AVAILABLE = False
_purple_team_validator = None

def _get_purple_team_validator():
    """Get or create Purple Team Validator instance"""
    global PURPLE_TEAM_AVAILABLE, _purple_team_validator
    if _purple_team_validator is None:
        try:
            from tools.purple_team_validator import PurpleTeamValidator
            _purple_team_validator = PurpleTeamValidator()
            PURPLE_TEAM_AVAILABLE = True
        except Exception as e:
            logger.warning(f"Purple Team Validator import failed: {e}")
            PURPLE_TEAM_AVAILABLE = False
    return _purple_team_validator


@evasion_bp.route('/purple-team')
def purple_team_page():
    """Purple Team Validator page"""
    return render_template('purple_team.html')


@evasion_bp.route('/api/purple-team/status')
def purple_team_status():
    """Get Purple Team Validator status"""
    validator = _get_purple_team_validator()
    if not validator:
        return jsonify({
            'success': False,
            'available': False,
            'error': 'Purple Team module not available'
        })
    
    try:
        status = validator.get_campaign_status()
        return jsonify({
            'success': True,
            'available': True,
            **status
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@evasion_bp.route('/api/purple-team/tests')
def purple_team_tests():
    """Get available test library"""
    validator = _get_purple_team_validator()
    if not validator:
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    try:
        tests = validator.get_available_tests()
        coverage = validator.get_technique_coverage()
        return jsonify({
            'success': True,
            'tests': tests,
            'coverage': coverage
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@evasion_bp.route('/api/purple-team/campaign/create', methods=['POST'])
def purple_team_create_campaign():
    """Create a new validation campaign"""
    validator = _get_purple_team_validator()
    if not validator:
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    try:
        data = request.get_json() or {}
        
        campaign_id = validator.create_campaign(
            name=data.get('name', 'Purple Team Validation'),
            target_environment=data.get('target_environment', 'Production'),
            edr_vendors=data.get('edr_vendors'),
            tactics=data.get('tactics'),
            techniques=data.get('techniques')
        )
        
        return jsonify({
            'success': True,
            'campaign_id': campaign_id,
            'message': 'Campaign created successfully'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@evasion_bp.route('/api/purple-team/campaign/<campaign_id>/run', methods=['POST'])
def purple_team_run_campaign(campaign_id):
    """Run a validation campaign"""
    validator = _get_purple_team_validator()
    if not validator:
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    try:
        data = request.get_json() or {}
        simulate = data.get('simulate', True)
        
        report = validator.run_campaign(
            campaign_id=campaign_id,
            simulate=simulate
        )
        
        # Convert report to dict for JSON serialization
        report_dict = {
            'report_id': report.report_id,
            'campaign_name': report.campaign_name,
            'start_time': report.start_time.isoformat(),
            'end_time': report.end_time.isoformat() if report.end_time else None,
            'target_environment': report.target_environment,
            'edr_vendors': report.edr_vendors,
            'total_tests': report.total_tests,
            'tests_executed': report.tests_executed,
            'tests_passed': report.tests_passed,
            'tests_failed': report.tests_failed,
            'detection_rate': report.detection_rate,
            'evasion_rate': report.evasion_rate,
            'mitre_coverage': report.mitre_coverage,
            'ai_recommendations': report.ai_recommendations,
            'executive_summary': report.executive_summary,
            'test_results': [
                {
                    'test_id': r.test_id,
                    'test_name': r.test_name,
                    'technique_id': r.technique_id,
                    'technique_name': r.technique_name,
                    'tactic': r.tactic,
                    'detection_result': r.detection_result.value,
                    'duration_ms': r.duration_ms,
                }
                for r in report.test_results
            ],
            'detection_gaps': [
                {
                    'gap_id': g.gap_id,
                    'technique_id': g.technique_id,
                    'technique_name': g.technique_name,
                    'severity': g.severity.value,
                    'description': g.description,
                    'recommendation': g.recommendation,
                    'remediation_steps': g.remediation_steps,
                }
                for g in report.detection_gaps
            ]
        }
        
        return jsonify({
            'success': True,
            'report': report_dict
        })
    except Exception as e:
        logger.error(f"Error running campaign: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@evasion_bp.route('/api/purple-team/quick-assessment', methods=['POST'])
def purple_team_quick_assessment():
    """Run a quick assessment"""
    validator = _get_purple_team_validator()
    if not validator:
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    try:
        data = request.get_json() or {}
        techniques = data.get('techniques')
        
        result = validator.run_quick_assessment(techniques=techniques)
        
        return jsonify({
            'success': True,
            'result': result
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@evasion_bp.route('/api/purple-team/report/generate', methods=['POST'])
def purple_team_generate_report():
    """Generate reports for a campaign"""
    validator = _get_purple_team_validator()
    if not validator:
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    try:
        data = request.get_json() or {}
        campaign_id = data.get('campaign_id')
        formats = data.get('formats', ['html', 'json'])
        
        files = validator.generate_reports(campaign_id=campaign_id, formats=formats)
        
        return jsonify({
            'success': True,
            'files': files
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@evasion_bp.route('/api/purple-team/report/view')
def purple_team_view_report():
    """View a generated HTML report"""
    path = request.args.get('path')
    if not path:
        return "No path specified", 400
    
    # Security check - only allow files from purple reports directory
    if not path.startswith('/tmp/purple_reports/'):
        return "Access denied", 403
    
    try:
        with open(path, 'r') as f:
            content = f.read()
        return content, 200, {'Content-Type': 'text/html'}
    except FileNotFoundError:
        return "Report not found", 404
    except Exception as e:
        return str(e), 500


@evasion_bp.route('/api/purple-team/export')
def purple_team_export():
    """Export campaign data"""
    validator = _get_purple_team_validator()
    if not validator:
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    try:
        campaign_id = request.args.get('campaign_id')
        data = validator.export_campaign_data(campaign_id=campaign_id)
        
        return jsonify({
            'success': True,
            'data': data
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
