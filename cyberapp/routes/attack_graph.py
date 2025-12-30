from flask import Blueprint, render_template, request, jsonify, redirect, session

from cybermodules.attack_graph import AttackPathGraph

graph_bp = Blueprint("graph", __name__)


@graph_bp.route("/attack-graph")
def attack_graph_dashboard():
    """Attack Path Graph ana sayfası"""
    if not session.get("logged_in"):
        return redirect("/login")
    return render_template("attack_graph.html")


@graph_bp.route("/attack-graph/scan/<int:scan_id>")
def get_graph_from_scan(scan_id: int):
    """Scan ID'den graph oluştur"""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    try:
        graph = AttackPathGraph(scan_id=scan_id)
        graph_data = graph.load_from_db(scan_id)
        
        return jsonify(graph_data)
        
    except Exception as e:
        return jsonify({
            "error": str(e),
            "nodes": [],
            "edges": [],
            "attack_paths": []
        })


@graph_bp.route("/attack-graph/generate", methods=["POST"])
def generate_graph():
    """Manuel veriden graph oluştur"""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    data = request.get_json()
    
    try:
        graph = AttackPathGraph()
        graph_data = graph.generate_from_scan_data(data)
        
        return jsonify(graph_data)
        
    except Exception as e:
        return jsonify({
            "error": str(e),
            "nodes": [],
            "edges": [],
            "attack_paths": []
        })


@graph_bp.route("/attack-graph/llm-analysis", methods=["POST"])
def get_llm_analysis():
    """Graph için LLM analizi al"""
    if not session.get("logged_in"):
        return jsonify({"error": "login_required"}), 401
    
    try:
        graph = AttackPathGraph()
        analysis = graph.get_llm_analysis()
        
        return jsonify({
            "success": True,
            "analysis": analysis
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        })
