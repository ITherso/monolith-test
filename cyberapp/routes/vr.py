"""
VR/AR Red Team Visualization Routes
====================================
API endpoints for VR/AR attack graph visualization and Unity export

Endpoints:
- GET /vr - VR Visualization dashboard
- POST /api/vr/generate - Generate VR scene from chain log
- POST /api/vr/export - Export scene in specified format
- GET /api/vr/scene/<scene_id> - Get scene data
- GET /api/vr/stats - Get scene statistics
- GET /api/vr/demo - Generate demo scene
- GET /api/vr/mitre - Get MITRE ATT&CK mapping
- POST /api/vr/webxr - Generate WebXR viewer
- GET /api/vr/formats - List supported export formats
"""

from flask import Blueprint, request, jsonify, render_template, send_file
import logging
import json
import os
from datetime import datetime
from pathlib import Path
import hashlib

logger = logging.getLogger("vr_routes")

vr_bp = Blueprint('vr', __name__)

# Lazy import VR module
VR_AVAILABLE = False
VRViz = None
ExportFormat = None
_vr_instance = None
_cached_scenes = {}


def _lazy_import_vr():
    """Lazy import VR visualization module"""
    global VR_AVAILABLE, VRViz, ExportFormat
    if VRViz is None:
        try:
            from tools.vr_viz import (
                VRViz as _VRViz,
                ExportFormat as _ExportFormat,
                MITREAttackMapper,
                NodeType,
                EdgeType
            )
            VRViz = _VRViz
            ExportFormat = _ExportFormat
            VR_AVAILABLE = True
        except Exception as e:
            logger.warning(f"VR Viz import failed: {e}")
            VR_AVAILABLE = False
    return VR_AVAILABLE


def _get_vr_instance():
    """Get or create VR Viz instance"""
    global _vr_instance
    if not _lazy_import_vr():
        return None
    if _vr_instance is None and VRViz is not None:
        _vr_instance = VRViz()
    return _vr_instance


# ============== Dashboard Route ==============

@vr_bp.route('/vr')
def vr_dashboard():
    """VR Visualization Dashboard"""
    return render_template('vr_viz.html')


# ============== API Routes ==============

@vr_bp.route('/api/vr/status', methods=['GET'])
def vr_status():
    """Check VR module status"""
    _lazy_import_vr()
    return jsonify({
        "available": VR_AVAILABLE,
        "module": "VR/AR Red Team Visualization",
        "version": "1.0.0",
        "features": {
            "unity_export": True,
            "webxr": True,
            "mitre_mapping": True,
            "attack_replay": True,
            "3d_visualization": True
        },
        "supported_formats": ["unity", "webxr", "threejs", "json", "gltf"]
    })


@vr_bp.route('/api/vr/generate', methods=['POST'])
def generate_vr_scene():
    """Generate VR scene from attack chain log"""
    vr = _get_vr_instance()
    if not vr:
        return jsonify({
            "error": "VR module not available",
            "fallback": True,
            "scene": _generate_fallback_scene(request.json.get("chain_log", []))
        }), 200
    
    try:
        data = request.json or {}
        chain_log = data.get("chain_log", [])
        scene_name = data.get("name", f"Attack Chain - {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        layout = data.get("layout", "hierarchical")
        
        if not chain_log:
            return jsonify({"error": "No chain_log provided"}), 400
        
        # Configure and generate
        vr.config["layout_algorithm"] = layout
        scene = vr.generate_from_chain_log(chain_log)
        scene.name = scene_name
        
        # Cache scene
        scene_id = hashlib.md5(json.dumps(chain_log).encode()).hexdigest()[:12]
        _cached_scenes[scene_id] = {
            "scene": scene.to_dict(),
            "stats": vr.get_scene_stats(),
            "created": datetime.now().isoformat()
        }
        
        return jsonify({
            "success": True,
            "scene_id": scene_id,
            "scene": scene.to_dict(),
            "stats": vr.get_scene_stats()
        })
    
    except Exception as e:
        logger.error(f"VR generation error: {e}")
        return jsonify({"error": str(e)}), 500


@vr_bp.route('/api/vr/export', methods=['POST'])
def export_vr_scene():
    """Export VR scene in specified format"""
    vr = _get_vr_instance()
    if not vr:
        return jsonify({"error": "VR module not available"}), 503
    
    try:
        data = request.json or {}
        scene_id = data.get("scene_id")
        export_format = data.get("format", "json").upper()
        
        # Check if scene is cached
        if scene_id and scene_id in _cached_scenes:
            # Rebuild scene from cache
            cached = _cached_scenes[scene_id]
            # Use cached scene data to generate export
        
        # Generate if chain_log provided
        chain_log = data.get("chain_log")
        if chain_log:
            vr.generate_from_chain_log(chain_log)
        elif not vr.scene:
            return jsonify({"error": "No scene to export. Provide chain_log or scene_id"}), 400
        
        # Map format string to enum
        format_map = {
            "UNITY": "UNITY_SCENE",
            "UNITY_SCENE": "UNITY_SCENE",
            "WEBXR": "WEBXR",
            "THREEJS": "THREE_JS",
            "THREE_JS": "THREE_JS",
            "JSON": "JSON_SCENE",
            "JSON_SCENE": "JSON_SCENE",
            "GLTF": "GLTF"
        }
        
        format_enum = getattr(ExportFormat, format_map.get(export_format, "JSON_SCENE"))
        output_path = vr.export_scene(format_enum)
        
        return jsonify({
            "success": True,
            "format": export_format.lower(),
            "output_path": output_path,
            "download_url": f"/api/vr/download/{os.path.basename(output_path)}"
        })
    
    except Exception as e:
        logger.error(f"VR export error: {e}")
        return jsonify({"error": str(e)}), 500


@vr_bp.route('/api/vr/scene/<scene_id>', methods=['GET'])
def get_scene(scene_id):
    """Get cached scene by ID"""
    if scene_id in _cached_scenes:
        return jsonify(_cached_scenes[scene_id])
    return jsonify({"error": "Scene not found"}), 404


@vr_bp.route('/api/vr/stats', methods=['GET'])
def get_stats():
    """Get current scene statistics"""
    vr = _get_vr_instance()
    if not vr or not vr.scene:
        return jsonify({"error": "No active scene"}), 404
    
    return jsonify(vr.get_scene_stats())


@vr_bp.route('/api/vr/demo', methods=['GET', 'POST'])
def generate_demo():
    """Generate demo VR scene"""
    vr = _get_vr_instance()
    
    demo_log = [
        {"target": "192.168.1.10", "action": "Phishing Email Campaign", "result": "success", "severity": "medium"},
        {"target": "192.168.1.10", "action": "Payload Executed via Macro", "result": "success", "severity": "high"},
        {"target": "192.168.1.10", "action": "Credential Dumping with Mimikatz", "result": "success", "severity": "critical"},
        {"target": "192.168.1.20", "action": "Lateral Movement via PSExec", "result": "success", "severity": "high"},
        {"target": "192.168.1.30", "action": "Database Access", "result": "success", "severity": "high"},
        {"target": "192.168.1.100", "action": "Domain Controller Compromised", "result": "success", "severity": "critical"},
        {"target": "192.168.1.100", "action": "DCSync Attack", "result": "success", "severity": "critical"},
        {"target": "192.168.1.100", "action": "Golden Ticket Forged", "result": "success", "severity": "critical"}
    ]
    
    if not vr:
        return jsonify({
            "success": True,
            "demo": True,
            "fallback": True,
            "scene": _generate_fallback_scene(demo_log),
            "stats": {"total_nodes": len(demo_log) + 1, "total_edges": len(demo_log)}
        })
    
    try:
        scene = vr.generate_from_chain_log(demo_log)
        scene.name = "Demo Attack Chain - BlackHat Edition"
        
        return jsonify({
            "success": True,
            "demo": True,
            "scene": scene.to_dict(),
            "stats": vr.get_scene_stats()
        })
    
    except Exception as e:
        logger.error(f"Demo generation error: {e}")
        return jsonify({
            "success": True,
            "demo": True,
            "fallback": True,
            "scene": _generate_fallback_scene(demo_log)
        })


@vr_bp.route('/api/vr/mitre', methods=['GET'])
def get_mitre_mapping():
    """Get MITRE ATT&CK mapping data"""
    _lazy_import_vr()
    
    try:
        from tools.vr_viz import MITREAttackMapper
        
        return jsonify({
            "tactics": {k: {"color": v["color"].to_hex() if hasattr(v["color"], 'to_hex') else str(v["color"]), "layer": v["layer"]} 
                       for k, v in MITREAttackMapper.TACTICS.items()},
            "techniques": MITREAttackMapper.TECHNIQUES
        })
    except:
        # Fallback MITRE data
        return jsonify({
            "tactics": {
                "initial_access": {"color": "#ff6666", "layer": 2},
                "execution": {"color": "#ff8844", "layer": 3},
                "persistence": {"color": "#ffaa22", "layer": 4},
                "privilege_escalation": {"color": "#ffcc11", "layer": 5},
                "defense_evasion": {"color": "#cccc22", "layer": 6},
                "credential_access": {"color": "#99ff33", "layer": 7},
                "discovery": {"color": "#44ff66", "layer": 8},
                "lateral_movement": {"color": "#22ffaa", "layer": 9},
                "collection": {"color": "#22ccff", "layer": 10},
                "exfiltration": {"color": "#9966ff", "layer": 12},
                "impact": {"color": "#cc44ff", "layer": 13}
            },
            "techniques": {}
        })


@vr_bp.route('/api/vr/webxr', methods=['POST'])
def generate_webxr():
    """Generate WebXR viewer HTML"""
    vr = _get_vr_instance()
    if not vr:
        return jsonify({"error": "VR module not available"}), 503
    
    try:
        data = request.json or {}
        chain_log = data.get("chain_log", [])
        
        if chain_log:
            vr.generate_from_chain_log(chain_log)
        
        if not vr.scene:
            return jsonify({"error": "No scene available"}), 400
        
        output_path = vr.export_scene(ExportFormat.WEBXR)
        
        return jsonify({
            "success": True,
            "webxr_path": output_path,
            "preview_url": f"/api/vr/preview/{os.path.basename(output_path)}"
        })
    
    except Exception as e:
        logger.error(f"WebXR generation error: {e}")
        return jsonify({"error": str(e)}), 500


@vr_bp.route('/api/vr/formats', methods=['GET'])
def list_formats():
    """List supported export formats"""
    return jsonify({
        "formats": [
            {"id": "unity", "name": "Unity Scene", "extension": ".unity", "description": "Unity 3D scene file"},
            {"id": "webxr", "name": "WebXR", "extension": "folder", "description": "Browser-based VR with A-Frame"},
            {"id": "threejs", "name": "Three.js", "extension": ".js", "description": "Three.js JavaScript scene"},
            {"id": "json", "name": "JSON", "extension": ".json", "description": "Raw scene data"},
            {"id": "gltf", "name": "GLTF", "extension": ".gltf", "description": "GL Transmission Format"}
        ],
        "default": "webxr",
        "vr_headsets": ["Oculus Quest", "HTC Vive", "Valve Index", "Windows MR"],
        "ar_supported": True
    })


@vr_bp.route('/api/vr/download/<filename>')
def download_file(filename):
    """Download exported file"""
    vr = _get_vr_instance()
    if not vr:
        return jsonify({"error": "VR module not available"}), 503
    
    file_path = vr.output_dir / filename
    if file_path.exists():
        return send_file(str(file_path), as_attachment=True)
    
    return jsonify({"error": "File not found"}), 404


@vr_bp.route('/api/vr/layouts', methods=['GET'])
def list_layouts():
    """List available layout algorithms"""
    return jsonify({
        "layouts": [
            {
                "id": "hierarchical",
                "name": "Hierarchical",
                "description": "Layered layout based on MITRE ATT&CK phases",
                "best_for": "Attack chain visualization"
            },
            {
                "id": "force_directed",
                "name": "Force-Directed",
                "description": "Physics-based layout with node repulsion",
                "best_for": "Network topology"
            },
            {
                "id": "network",
                "name": "Network Topology",
                "description": "Groups nodes by type (servers, DCs, etc.)",
                "best_for": "Infrastructure visualization"
            }
        ],
        "default": "hierarchical"
    })


# ============== Fallback Scene Generator ==============

def _generate_fallback_scene(chain_log):
    """Generate fallback scene when VR module not available"""
    nodes = []
    edges = []
    
    # Add attacker node
    nodes.append({
        "id": "attacker",
        "type": "attacker",
        "label": "Attacker",
        "position": {"x": -15, "y": 0, "z": 0},
        "color": {"r": 1.0, "g": 0.2, "b": 0.2, "a": 1.0},
        "size": 1.5,
        "severity": "critical",
        "glow_effect": True
    })
    
    prev_id = "attacker"
    
    for i, step in enumerate(chain_log):
        node_id = f"step_{i}"
        
        # Determine severity color
        severity = step.get("severity", "medium")
        colors = {
            "critical": {"r": 0.9, "g": 0.1, "b": 0.1},
            "high": {"r": 1.0, "g": 0.4, "b": 0.0},
            "medium": {"r": 1.0, "g": 0.8, "b": 0.0},
            "low": {"r": 0.2, "g": 0.8, "b": 0.2}
        }
        color = colors.get(severity, colors["medium"])
        color["a"] = 1.0
        
        nodes.append({
            "id": node_id,
            "type": "host",
            "label": step.get("action", "Unknown")[:25],
            "position": {"x": -10 + i * 5, "y": i * 2, "z": (i % 3) * 3},
            "color": color,
            "size": 1.0,
            "description": f"Target: {step.get('target', 'N/A')}\nResult: {step.get('result', 'N/A')}",
            "severity": severity,
            "glow_effect": severity in ["critical", "high"]
        })
        
        edges.append({
            "id": f"edge_{prev_id}_{node_id}",
            "source": prev_id,
            "target": node_id,
            "type": "attack_path",
            "color": {"r": 1.0, "g": 0.3, "b": 0.3, "a": 0.8},
            "animated": True
        })
        
        prev_id = node_id
    
    return {
        "name": "Attack Chain (Fallback)",
        "nodes": nodes,
        "edges": edges,
        "sequences": [],
        "camera": {"position": {"x": 0, "y": 15, "z": -25}, "target": {"x": 0, "y": 5, "z": 0}},
        "environment": {
            "ambient_color": {"r": 0.1, "g": 0.1, "b": 0.15, "a": 1.0},
            "fog_enabled": True,
            "fog_density": 0.02,
            "grid_enabled": True,
            "skybox": "cyber_grid"
        }
    }
