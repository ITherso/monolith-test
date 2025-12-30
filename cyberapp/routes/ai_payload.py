from flask import Blueprint, render_template, request, jsonify, session, redirect

from cybermodules.llm_engine import llm_engine, generate_ai_payload

ai_payload_bp = Blueprint("ai_payload", __name__)


@ai_payload_bp.route("/ai-payload")
def ai_payload_page():
    """AI Payload Generator sayfası"""
    if not session.get("logged_in"):
        return redirect("/login")
    
    return render_template("ai_payload.html")


@ai_payload_bp.route("/api/ai_payload", methods=["POST"])
def api_generate_payload():
    """AI Payload Generator API"""
    if not session.get("logged_in"):
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    
    try:
        data = request.get_json()
        
        vuln_type = data.get("vuln_type", "SQL_INJECTION")
        evasion_level = data.get("evasion_level", "high")
        context = data.get("context", "")
        
        # AI payload üret
        result = generate_ai_payload(vuln_type, evasion_level, context)
        
        # Test sonuçları
        test_results = llm_engine.test_payload(result)
        
        return jsonify({
            "success": True,
            "id": result["id"],
            "vuln_type": result["vuln_type"],
            "evasion_level": result["evasion_level"],
            "base_payload": result["base_payload"],
            "mutations": result["mutations"],
            "timestamp": result["timestamp"],
            "hash": result["hash"],
            "blockchain_proof": result["blockchain_proof"],
            "evasion_score": test_results["evasion_score"],
            "waf_risk": test_results["waf_detection_risk"],
            "recommendations": test_results["recommendations"]
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@ai_payload_bp.route("/api/payload/evidence")
def api_get_evidence():
    """Blockchain evidence chain'i döndürür"""
    if not session.get("logged_in"):
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    
    try:
        evidence = llm_engine.get_evidence_chain()
        export = llm_engine.export_evidence()
        
        return jsonify({
            "success": True,
            "evidence_chain": evidence,
            "total_payloads": len(llm_engine.payload_history),
            "export": export
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})
