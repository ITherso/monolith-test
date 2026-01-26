"""
WAF Bypass Routes
==================
Flask API endpoints for WAF bypass operations.

Endpoints:
- GET /waf - WAF bypass dashboard
- GET /api/waf/status - Module status
- GET /api/waf/vendors - List supported WAF vendors
- POST /api/waf/fingerprint - Fingerprint WAF from response
- POST /api/waf/generate - Generate bypass payloads
- POST /api/waf/smuggle - Generate HTTP smuggling request
- POST /api/waf/test - Test payload against WAF
- GET /api/waf/techniques - List bypass techniques
- GET /api/waf/stats - Get bypass statistics
"""

import os
import sys
import json
from datetime import datetime
from typing import Dict, Any, List, Optional

from flask import Blueprint, render_template, request, jsonify, Response

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Try to import WAF bypass module
try:
    from evasion.waf_bypass import (
        WAFBypassEngine,
        WAFFingerprinter,
        EncodingEngine,
        HTTPSmugglingEngine,
        ParameterPollutionEngine,
        AIPayloadMutator,
        WAFVendor,
        BypassTechnique,
        AttackType,
        WAFProfile,
        BypassPayload,
        WAFFingerprint,
        SmugglingRequest,
        quick_bypass,
        fingerprint_waf
    )
    HAS_WAF_BYPASS = True
except ImportError as e:
    HAS_WAF_BYPASS = False
    IMPORT_ERROR = str(e)

# Create blueprint
waf_bp = Blueprint('waf', __name__)

# Global engine instance
_engine: Optional[WAFBypassEngine] = None


def get_engine() -> WAFBypassEngine:
    """Get or create WAF bypass engine instance."""
    global _engine
    if _engine is None:
        _engine = WAFBypassEngine()
    return _engine


# =============================================================================
# Dashboard Route
# =============================================================================

@waf_bp.route('/waf')
def waf_dashboard():
    """WAF bypass management dashboard."""
    return render_template('waf.html')


# =============================================================================
# API Routes
# =============================================================================

@waf_bp.route('/api/waf/status')
def waf_status():
    """Get WAF bypass module status."""
    if not HAS_WAF_BYPASS:
        return jsonify({
            "available": False,
            "error": f"WAF bypass module not available: {IMPORT_ERROR}"
        })
    
    engine = get_engine()
    
    return jsonify({
        "available": True,
        "features": {
            "fingerprinting": True,
            "http_smuggling": True,
            "encoding_bypass": True,
            "parameter_pollution": True,
            "ai_mutation": True,
            "rate_limit_bypass": True,
            "bot_bypass": True
        },
        "supported_wafs": [v.value for v in WAFVendor if v != WAFVendor.UNKNOWN],
        "supported_attacks": [a.value for a in AttackType],
        "techniques_count": len(BypassTechnique),
        "current_waf": engine.current_waf.value if engine.current_waf else None,
        "stats": engine.get_bypass_stats()
    })


@waf_bp.route('/api/waf/vendors')
def list_vendors():
    """List all supported WAF vendors with their profiles."""
    if not HAS_WAF_BYPASS:
        return jsonify({"success": False, "error": "Module not available"}), 500
    
    engine = get_engine()
    vendors = engine.list_waf_vendors()
    
    return jsonify({
        "success": True,
        "vendors": vendors,
        "count": len(vendors)
    })


@waf_bp.route('/api/waf/techniques')
def list_techniques():
    """List all bypass techniques."""
    if not HAS_WAF_BYPASS:
        return jsonify({"success": False, "error": "Module not available"}), 500
    
    techniques = []
    for tech in BypassTechnique:
        category = "other"
        if "smuggling" in tech.value.lower() or "desync" in tech.value.lower():
            category = "http_smuggling"
        elif "encode" in tech.value.lower() or "utf" in tech.value.lower() or "unicode" in tech.value.lower():
            category = "encoding"
        elif "hpp" in tech.value.lower() or "pollution" in tech.value.lower():
            category = "parameter_pollution"
        elif "mutation" in tech.value.lower() or "ai" in tech.value.lower():
            category = "mutation"
        elif "header" in tech.value.lower() or "host" in tech.value.lower():
            category = "header_manipulation"
        elif "chunk" in tech.value.lower():
            category = "chunked_encoding"
        else:
            category = "payload_mutation"
        
        techniques.append({
            "name": tech.value,
            "category": category
        })
    
    return jsonify({
        "success": True,
        "techniques": techniques,
        "count": len(techniques)
    })


@waf_bp.route('/api/waf/fingerprint', methods=['POST'])
def fingerprint_waf_route():
    """
    Fingerprint WAF from HTTP response.
    
    Expected JSON:
    {
        "headers": {"header-name": "value", ...},
        "body": "response body content",
        "status_code": 403,
        "url": "https://target.com"
    }
    """
    if not HAS_WAF_BYPASS:
        return jsonify({"success": False, "error": "Module not available"}), 500
    
    try:
        data = request.get_json() or {}
        
        headers = data.get('headers', {})
        body = data.get('body', '')
        status_code = data.get('status_code', 403)
        url = data.get('url', '')
        
        engine = get_engine()
        fingerprint = engine.fingerprint_waf(headers, body, status_code, url)
        
        return jsonify({
            "success": True,
            "fingerprint": {
                "vendor": fingerprint.vendor.value,
                "confidence": round(fingerprint.confidence, 2),
                "evidence": fingerprint.evidence,
                "features": fingerprint.features,
                "version": fingerprint.version
            },
            "profile": {
                "name": engine.current_profile.name if engine.current_profile else None,
                "effective_techniques": [t.value for t in engine.current_profile.effective_techniques] if engine.current_profile else [],
                "rate_limit": engine.current_profile.rate_limit if engine.current_profile else None
            } if engine.current_profile else None
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@waf_bp.route('/api/waf/generate', methods=['POST'])
def generate_bypass():
    """
    Generate WAF bypass payloads.
    
    Expected JSON:
    {
        "payload": "' OR 1=1--",
        "attack_type": "sqli",
        "waf": "cloudflare",  // optional
        "techniques": ["unicode_normalization", "double_url_encode"],  // optional
        "max_payloads": 10  // optional
    }
    """
    if not HAS_WAF_BYPASS:
        return jsonify({"success": False, "error": "Module not available"}), 500
    
    try:
        data = request.get_json() or {}
        
        payload = data.get('payload', '')
        if not payload:
            return jsonify({"success": False, "error": "Payload is required"}), 400
        
        attack_type_str = data.get('attack_type', 'sqli').lower()
        waf_str = data.get('waf')
        technique_strs = data.get('techniques', [])
        max_payloads = data.get('max_payloads', 20)
        
        # Map attack type
        attack_map = {
            'sqli': AttackType.SQLI,
            'xss': AttackType.XSS,
            'rce': AttackType.RCE,
            'lfi': AttackType.LFI,
            'rfi': AttackType.RFI,
            'ssrf': AttackType.SSRF,
            'xxe': AttackType.XXE,
            'ssti': AttackType.SSTI,
            'path': AttackType.PATH_TRAVERSAL,
            'cmd': AttackType.COMMAND_INJECTION
        }
        attack_type = attack_map.get(attack_type_str, AttackType.SQLI)
        
        engine = get_engine()
        
        # Set WAF if specified
        if waf_str:
            try:
                vendor = WAFVendor(waf_str.lower())
                engine.set_target_waf(vendor)
            except ValueError:
                pass
        
        # Map techniques
        techniques = None
        if technique_strs:
            techniques = []
            for t in technique_strs:
                try:
                    techniques.append(BypassTechnique(t))
                except ValueError:
                    pass
        
        # Generate payloads
        bypasses = engine.generate_bypass_payloads(
            payload, attack_type, techniques, max_payloads
        )
        
        return jsonify({
            "success": True,
            "original": payload,
            "attack_type": attack_type.value,
            "target_waf": engine.current_waf.value if engine.current_waf else "unknown",
            "bypasses": [
                {
                    "payload": b.mutated,
                    "technique": b.technique.value,
                    "encoding": b.encoding,
                    "success_probability": round(b.success_probability, 2)
                }
                for b in bypasses
            ],
            "count": len(bypasses)
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@waf_bp.route('/api/waf/quick', methods=['POST'])
def quick_generate():
    """
    Quick bypass generation (simplified).
    
    Expected JSON:
    {
        "payload": "' OR 1=1--",
        "type": "sqli",
        "waf": "cloudflare"
    }
    """
    if not HAS_WAF_BYPASS:
        return jsonify({"success": False, "error": "Module not available"}), 500
    
    try:
        data = request.get_json() or {}
        
        payload = data.get('payload', '')
        attack_type = data.get('type', 'sqli')
        waf = data.get('waf')
        
        if not payload:
            return jsonify({"success": False, "error": "Payload is required"}), 400
        
        results = quick_bypass(payload, attack_type, waf, max_results=10)
        
        return jsonify({
            "success": True,
            "original": payload,
            "bypasses": results
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@waf_bp.route('/api/waf/smuggle', methods=['POST'])
def generate_smuggle():
    """
    Generate HTTP smuggling request.
    
    Expected JSON:
    {
        "path": "/admin",
        "host": "target.com",
        "technique": "cl_te_desync"  // optional
    }
    """
    if not HAS_WAF_BYPASS:
        return jsonify({"success": False, "error": "Module not available"}), 500
    
    try:
        data = request.get_json() or {}
        
        path = data.get('path', '/admin')
        host = data.get('host', 'target.com')
        technique_str = data.get('technique', 'cl_te_desync')
        
        # Map technique
        technique_map = {
            'cl_te': BypassTechnique.CL_TE_DESYNC,
            'cl_te_desync': BypassTechnique.CL_TE_DESYNC,
            'te_cl': BypassTechnique.TE_CL_DESYNC,
            'te_cl_desync': BypassTechnique.TE_CL_DESYNC,
            'te_te': BypassTechnique.TE_TE_DESYNC,
            'te_te_desync': BypassTechnique.TE_TE_DESYNC,
            'h2c': BypassTechnique.HTTP2_H2C_SMUGGLING,
            'http2': BypassTechnique.HTTP2_CL_SMUGGLING
        }
        technique = technique_map.get(technique_str.lower(), BypassTechnique.CL_TE_DESYNC)
        
        engine = get_engine()
        smuggle = engine.generate_smuggling_request(path, host, technique)
        
        # Build raw request
        raw_request = f"{smuggle.method} {smuggle.path} HTTP/1.1\r\n"
        for header, value in smuggle.headers.items():
            raw_request += f"{header}: {value}\r\n"
        raw_request += f"\r\n{smuggle.body}"
        
        return jsonify({
            "success": True,
            "technique": smuggle.technique.value,
            "smuggled_path": path,
            "request": {
                "method": smuggle.method,
                "path": smuggle.path,
                "headers": smuggle.headers,
                "body": smuggle.body
            },
            "raw_request": raw_request,
            "smuggled_request": smuggle.smuggled_request
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@waf_bp.route('/api/waf/encode', methods=['POST'])
def encode_payload():
    """
    Apply specific encoding to payload.
    
    Expected JSON:
    {
        "payload": "<script>alert(1)</script>",
        "encoding": "unicode"  // unicode, double_url, mixed, html_entity, utf7, hex, base64
    }
    """
    if not HAS_WAF_BYPASS:
        return jsonify({"success": False, "error": "Module not available"}), 500
    
    try:
        data = request.get_json() or {}
        
        payload = data.get('payload', '')
        encoding = data.get('encoding', 'unicode').lower()
        
        if not payload:
            return jsonify({"success": False, "error": "Payload is required"}), 400
        
        enc = EncodingEngine()
        
        if encoding == 'unicode':
            result = enc.unicode_normalize(payload, aggressive=True)
        elif encoding == 'double_url':
            result = enc.double_url_encode(payload)
        elif encoding == 'triple_url':
            result = enc.triple_url_encode(payload)
        elif encoding == 'mixed':
            result = enc.mixed_encoding(payload)
        elif encoding == 'html_entity':
            result = enc.html_entity_encode(payload)
        elif encoding == 'utf7':
            result = enc.utf7_encode(payload)
        elif encoding == 'utf16':
            result = enc.utf16_encode(payload)
        elif encoding == 'hex':
            result = enc.hex_encode(payload)
        elif encoding == 'octal':
            result = enc.octal_encode(payload)
        elif encoding == 'base64':
            import base64
            result = base64.b64encode(payload.encode()).decode()
        else:
            result = payload
        
        return jsonify({
            "success": True,
            "original": payload,
            "encoded": result,
            "encoding": encoding,
            "original_length": len(payload),
            "encoded_length": len(result)
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@waf_bp.route('/api/waf/rate-limit-bypass')
def rate_limit_bypass():
    """Get rate limit bypass strategies."""
    if not HAS_WAF_BYPASS:
        return jsonify({"success": False, "error": "Module not available"}), 500
    
    try:
        engine = get_engine()
        strategies = engine.generate_rate_limit_bypass()
        
        return jsonify({
            "success": True,
            "strategies": strategies
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@waf_bp.route('/api/waf/bot-bypass-headers')
def bot_bypass_headers():
    """Get headers for bot detection bypass."""
    if not HAS_WAF_BYPASS:
        return jsonify({"success": False, "error": "Module not available"}), 500
    
    try:
        engine = get_engine()
        headers = engine.generate_bot_bypass_headers()
        
        return jsonify({
            "success": True,
            "headers": headers
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@waf_bp.route('/api/waf/stats')
def get_stats():
    """Get bypass statistics."""
    if not HAS_WAF_BYPASS:
        return jsonify({"success": False, "error": "Module not available"}), 500
    
    try:
        engine = get_engine()
        stats = engine.get_bypass_stats()
        
        return jsonify({
            "success": True,
            "stats": stats
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@waf_bp.route('/api/waf/record-attempt', methods=['POST'])
def record_attempt():
    """
    Record bypass attempt result.
    
    Expected JSON:
    {
        "original": "' OR 1=1--",
        "bypass": "' /*!OR*/ 1=1--",
        "technique": "comment_injection",
        "attack_type": "sqli",
        "success": true
    }
    """
    if not HAS_WAF_BYPASS:
        return jsonify({"success": False, "error": "Module not available"}), 500
    
    try:
        data = request.get_json() or {}
        
        original = data.get('original', '')
        bypass = data.get('bypass', '')
        technique_str = data.get('technique', '')
        attack_type_str = data.get('attack_type', 'sqli')
        success = data.get('success', False)
        
        # Map values
        try:
            technique = BypassTechnique(technique_str)
        except ValueError:
            technique = BypassTechnique.AI_MUTATION
        
        attack_map = {
            'sqli': AttackType.SQLI,
            'xss': AttackType.XSS,
            'rce': AttackType.RCE,
        }
        attack_type = attack_map.get(attack_type_str.lower(), AttackType.SQLI)
        
        engine = get_engine()
        
        # Create payload object
        payload = BypassPayload(
            original=original,
            mutated=bypass,
            technique=technique,
            attack_type=attack_type,
            encoding=technique.value,
            waf_target=engine.current_waf
        )
        
        engine.record_bypass_attempt(payload, success)
        
        return jsonify({
            "success": True,
            "recorded": True,
            "stats": engine.get_bypass_stats()
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@waf_bp.route('/api/waf/profile/<vendor>')
def get_waf_profile(vendor: str):
    """Get specific WAF vendor profile."""
    if not HAS_WAF_BYPASS:
        return jsonify({"success": False, "error": "Module not available"}), 500
    
    try:
        waf_vendor = WAFVendor(vendor.lower())
        engine = get_engine()
        profile = engine.get_waf_profile(waf_vendor)
        
        if not profile:
            return jsonify({"success": False, "error": "Profile not found"}), 404
        
        return jsonify({
            "success": True,
            "profile": {
                "vendor": profile.vendor.value,
                "name": profile.name,
                "effective_techniques": [t.value for t in profile.effective_techniques],
                "blocked_patterns": profile.blocked_patterns,
                "rate_limit": profile.rate_limit,
                "features": {
                    "bot_detection": profile.bot_detection,
                    "javascript_challenge": profile.javascript_challenge,
                    "captcha": profile.captcha,
                    "ml_detection": profile.ml_detection
                }
            }
        })
        
    except ValueError:
        return jsonify({"success": False, "error": f"Unknown WAF vendor: {vendor}"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@waf_bp.route('/api/waf/demo')
def demo_bypass():
    """Generate demo bypass for testing."""
    if not HAS_WAF_BYPASS:
        return jsonify({"success": False, "error": "Module not available"}), 500
    
    try:
        # Demo payloads
        demos = [
            {
                "name": "SQLi Bypass (Cloudflare)",
                "original": "' OR 1=1--",
                "attack_type": "sqli",
                "waf": "cloudflare"
            },
            {
                "name": "XSS Bypass (Akamai)",
                "original": "<script>alert(1)</script>",
                "attack_type": "xss",
                "waf": "akamai"
            },
            {
                "name": "RCE Bypass (AWS WAF)",
                "original": "; cat /etc/passwd",
                "attack_type": "rce",
                "waf": "aws_waf"
            },
            {
                "name": "LFI Bypass (Imperva)",
                "original": "../../../etc/passwd",
                "attack_type": "lfi",
                "waf": "imperva"
            }
        ]
        
        results = []
        for demo in demos:
            bypasses = quick_bypass(
                demo["original"],
                demo["attack_type"],
                demo["waf"],
                max_results=3
            )
            results.append({
                "name": demo["name"],
                "original": demo["original"],
                "waf": demo["waf"],
                "bypasses": bypasses
            })
        
        return jsonify({
            "success": True,
            "demos": results
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@waf_bp.route('/api/waf/hpp', methods=['POST'])
def generate_hpp():
    """
    Generate HTTP Parameter Pollution payloads.
    
    Expected JSON:
    {
        "param": "id",
        "value": "1",
        "malicious": "1 OR 1=1"
    }
    """
    if not HAS_WAF_BYPASS:
        return jsonify({"success": False, "error": "Module not available"}), 500
    
    try:
        data = request.get_json() or {}
        
        param = data.get('param', 'id')
        value = data.get('value', '1')
        malicious = data.get('malicious', "' OR 1=1--")
        
        hpp = ParameterPollutionEngine()
        payloads = hpp.hpp_duplicate(param, value, malicious)
        
        return jsonify({
            "success": True,
            "param": param,
            "original_value": value,
            "malicious_value": malicious,
            "payloads": payloads
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
