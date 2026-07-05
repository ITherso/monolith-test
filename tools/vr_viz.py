#!/usr/bin/env python3
"""
VR/AR Red Team Visualization - Unity Integration
=================================================
Transform penetration test reports into immersive VR/AR experiences
with interactive 3D attack graphs, MITRE ATT&CK node visualization,
and real-time attack path replay.

BlackHat Demo Ready! 🎮🥽

Features:
- 3D Attack Graph Generation (Unity-compatible)
- MITRE ATT&CK Framework Node Mapping
- Interactive Clickable Nodes with Details
- Attack Path Animation & Replay
- Network Topology Visualization
- Real-time Threat Flow Animation
- VR Headset Support (Oculus, HTC Vive, Quest)
- AR Mode for Mobile Devices
- Unity Scene Export (.unity, .prefab, .fbx)
- WebXR Export for Browser-based VR
- PDF 3D Export for Reports

Author: MONOLITH Red Team
Version: 1.0.0
"""

import json
import os
import subprocess
import hashlib
import math
import random
import logging
import tempfile
import shutil
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Tuple, Set
from enum import Enum
from datetime import datetime
from pathlib import Path
import base64
import struct

logger = logging.getLogger("vr_viz")


class NodeType(Enum):
    """Node types for VR visualization"""
    HOST = "host"
    SERVICE = "service"
    VULNERABILITY = "vulnerability"
    EXPLOIT = "exploit"
    CREDENTIAL = "credential"
    LATERAL_MOVE = "lateral_move"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"
    C2_CHANNEL = "c2_channel"
    MITRE_TACTIC = "mitre_tactic"
    MITRE_TECHNIQUE = "mitre_technique"
    ATTACKER = "attacker"
    TARGET = "target"
    DOMAIN_CONTROLLER = "domain_controller"
    DATABASE = "database"
    WEB_SERVER = "web_server"
    FIREWALL = "firewall"
    CLOUD_INSTANCE = "cloud_instance"


class EdgeType(Enum):
    """Edge types for connections"""
    NETWORK = "network"
    ATTACK_PATH = "attack_path"
    CREDENTIAL_REUSE = "credential_reuse"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_FLOW = "data_flow"
    C2_COMMUNICATION = "c2_communication"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    TRUST_RELATIONSHIP = "trust_relationship"


class ExportFormat(Enum):
    """Supported export formats"""
    UNITY_SCENE = "unity"
    UNITY_PREFAB = "prefab"
    FBX = "fbx"
    GLTF = "gltf"
    WEBXR = "webxr"
    THREE_JS = "threejs"
    PDF_3D = "pdf3d"
    JSON_SCENE = "json"


@dataclass
class Vector3:
    """3D Vector for positions"""
    x: float = 0.0
    y: float = 0.0
    z: float = 0.0
    
    def to_dict(self) -> Dict:
        return {"x": self.x, "y": self.y, "z": self.z}
    
    def distance_to(self, other: 'Vector3') -> float:
        return math.sqrt(
            (self.x - other.x) ** 2 +
            (self.y - other.y) ** 2 +
            (self.z - other.z) ** 2
        )
    
    def normalize(self) -> 'Vector3':
        length = math.sqrt(self.x**2 + self.y**2 + self.z**2)
        if length == 0:
            return Vector3(0, 0, 0)
        return Vector3(self.x/length, self.y/length, self.z/length)


@dataclass
class Color:
    """RGBA Color"""
    r: float = 1.0
    g: float = 1.0
    b: float = 1.0
    a: float = 1.0
    
    def to_dict(self) -> Dict:
        return {"r": self.r, "g": self.g, "b": self.b, "a": self.a}
    
    def to_hex(self) -> str:
        return "#{:02x}{:02x}{:02x}".format(
            int(self.r * 255),
            int(self.g * 255),
            int(self.b * 255)
        )


@dataclass
class VRNode:
    """Node in VR visualization"""
    id: str
    node_type: NodeType
    label: str
    position: Vector3
    color: Color
    size: float = 1.0
    description: str = ""
    metadata: Dict = field(default_factory=dict)
    mitre_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    is_compromised: bool = False
    compromise_time: Optional[float] = None
    severity: str = "medium"
    clickable: bool = True
    glow_effect: bool = False
    particle_effect: Optional[str] = None
    model_path: Optional[str] = None
    animation: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "type": self.node_type.value,
            "label": self.label,
            "position": self.position.to_dict(),
            "color": self.color.to_dict(),
            "size": self.size,
            "description": self.description,
            "metadata": self.metadata,
            "mitre_id": self.mitre_id,
            "mitre_tactic": self.mitre_tactic,
            "is_compromised": self.is_compromised,
            "compromise_time": self.compromise_time,
            "severity": self.severity,
            "clickable": self.clickable,
            "glow_effect": self.glow_effect,
            "particle_effect": self.particle_effect,
            "model_path": self.model_path,
            "animation": self.animation
        }


@dataclass
class VREdge:
    """Edge/Connection in VR visualization"""
    id: str
    source_id: str
    target_id: str
    edge_type: EdgeType
    color: Color
    width: float = 0.1
    animated: bool = True
    animation_speed: float = 1.0
    label: Optional[str] = None
    metadata: Dict = field(default_factory=dict)
    bidirectional: bool = False
    particle_flow: bool = False
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "source": self.source_id,
            "target": self.target_id,
            "type": self.edge_type.value,
            "color": self.color.to_dict(),
            "width": self.width,
            "animated": self.animated,
            "animation_speed": self.animation_speed,
            "label": self.label,
            "metadata": self.metadata,
            "bidirectional": self.bidirectional,
            "particle_flow": self.particle_flow
        }


@dataclass
class AttackSequence:
    """Animated attack sequence for replay"""
    id: str
    name: str
    steps: List[Dict] = field(default_factory=list)
    duration: float = 10.0
    loop: bool = False
    
    def add_step(self, timestamp: float, node_id: str, action: str, details: str = ""):
        self.steps.append({
            "timestamp": timestamp,
            "node_id": node_id,
            "action": action,
            "details": details
        })
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "name": self.name,
            "steps": self.steps,
            "duration": self.duration,
            "loop": self.loop
        }


@dataclass
class VRScene:
    """Complete VR Scene"""
    name: str
    nodes: List[VRNode] = field(default_factory=list)
    edges: List[VREdge] = field(default_factory=list)
    sequences: List[AttackSequence] = field(default_factory=list)
    camera_position: Vector3 = field(default_factory=lambda: Vector3(0, 10, -20))
    camera_target: Vector3 = field(default_factory=lambda: Vector3(0, 0, 0))
    ambient_color: Color = field(default_factory=lambda: Color(0.1, 0.1, 0.15, 1.0))
    fog_enabled: bool = True
    fog_density: float = 0.02
    grid_enabled: bool = True
    skybox: str = "cyber_grid"
    metadata: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "sequences": [s.to_dict() for s in self.sequences],
            "camera": {
                "position": self.camera_position.to_dict(),
                "target": self.camera_target.to_dict()
            },
            "environment": {
                "ambient_color": self.ambient_color.to_dict(),
                "fog_enabled": self.fog_enabled,
                "fog_density": self.fog_density,
                "grid_enabled": self.grid_enabled,
                "skybox": self.skybox
            },
            "metadata": self.metadata
        }


class MITREAttackMapper:
    """Map attacks to MITRE ATT&CK framework"""
    
    TACTICS = {
        "reconnaissance": {"color": Color(0.4, 0.6, 1.0), "layer": 0},
        "resource_development": {"color": Color(0.5, 0.5, 1.0), "layer": 1},
        "initial_access": {"color": Color(1.0, 0.4, 0.4), "layer": 2},
        "execution": {"color": Color(1.0, 0.5, 0.3), "layer": 3},
        "persistence": {"color": Color(1.0, 0.6, 0.2), "layer": 4},
        "privilege_escalation": {"color": Color(1.0, 0.7, 0.1), "layer": 5},
        "defense_evasion": {"color": Color(0.8, 0.8, 0.2), "layer": 6},
        "credential_access": {"color": Color(0.6, 1.0, 0.3), "layer": 7},
        "discovery": {"color": Color(0.3, 1.0, 0.5), "layer": 8},
        "lateral_movement": {"color": Color(0.2, 1.0, 0.7), "layer": 9},
        "collection": {"color": Color(0.2, 0.8, 1.0), "layer": 10},
        "command_and_control": {"color": Color(0.4, 0.6, 1.0), "layer": 11},
        "exfiltration": {"color": Color(0.6, 0.4, 1.0), "layer": 12},
        "impact": {"color": Color(0.8, 0.2, 1.0), "layer": 13}
    }
    
    TECHNIQUES = {
        # Initial Access
        "T1190": {"name": "Exploit Public-Facing Application", "tactic": "initial_access"},
        "T1133": {"name": "External Remote Services", "tactic": "initial_access"},
        "T1566": {"name": "Phishing", "tactic": "initial_access"},
        "T1078": {"name": "Valid Accounts", "tactic": "initial_access"},
        
        # Execution
        "T1059": {"name": "Command and Scripting Interpreter", "tactic": "execution"},
        "T1203": {"name": "Exploitation for Client Execution", "tactic": "execution"},
        "T1047": {"name": "Windows Management Instrumentation", "tactic": "execution"},
        "T1053": {"name": "Scheduled Task/Job", "tactic": "execution"},
        
        # Persistence
        "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "persistence"},
        "T1136": {"name": "Create Account", "tactic": "persistence"},
        "T1543": {"name": "Create or Modify System Process", "tactic": "persistence"},
        "T1098": {"name": "Account Manipulation", "tactic": "persistence"},
        
        # Privilege Escalation
        "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "privilege_escalation"},
        "T1134": {"name": "Access Token Manipulation", "tactic": "privilege_escalation"},
        "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "privilege_escalation"},
        
        # Defense Evasion
        "T1562": {"name": "Impair Defenses", "tactic": "defense_evasion"},
        "T1070": {"name": "Indicator Removal", "tactic": "defense_evasion"},
        "T1036": {"name": "Masquerading", "tactic": "defense_evasion"},
        "T1027": {"name": "Obfuscated Files or Information", "tactic": "defense_evasion"},
        
        # Credential Access
        "T1110": {"name": "Brute Force", "tactic": "credential_access"},
        "T1003": {"name": "OS Credential Dumping", "tactic": "credential_access"},
        "T1558": {"name": "Steal or Forge Kerberos Tickets", "tactic": "credential_access"},
        "T1552": {"name": "Unsecured Credentials", "tactic": "credential_access"},
        
        # Discovery
        "T1087": {"name": "Account Discovery", "tactic": "discovery"},
        "T1482": {"name": "Domain Trust Discovery", "tactic": "discovery"},
        "T1046": {"name": "Network Service Discovery", "tactic": "discovery"},
        "T1018": {"name": "Remote System Discovery", "tactic": "discovery"},
        
        # Lateral Movement
        "T1021": {"name": "Remote Services", "tactic": "lateral_movement"},
        "T1550": {"name": "Use Alternate Authentication Material", "tactic": "lateral_movement"},
        "T1570": {"name": "Lateral Tool Transfer", "tactic": "lateral_movement"},
        
        # Collection
        "T1560": {"name": "Archive Collected Data", "tactic": "collection"},
        "T1005": {"name": "Data from Local System", "tactic": "collection"},
        "T1039": {"name": "Data from Network Shared Drive", "tactic": "collection"},
        
        # Command and Control
        "T1071": {"name": "Application Layer Protocol", "tactic": "command_and_control"},
        "T1573": {"name": "Encrypted Channel", "tactic": "command_and_control"},
        "T1105": {"name": "Ingress Tool Transfer", "tactic": "command_and_control"},
        
        # Exfiltration
        "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "exfiltration"},
        "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "exfiltration"},
        "T1567": {"name": "Exfiltration Over Web Service", "tactic": "exfiltration"},
        
        # Impact
        "T1486": {"name": "Data Encrypted for Impact", "tactic": "impact"},
        "T1489": {"name": "Service Stop", "tactic": "impact"},
        "T1490": {"name": "Inhibit System Recovery", "tactic": "impact"}
    }
    
    @classmethod
    def get_tactic_color(cls, tactic: str) -> Color:
        """Get color for a MITRE tactic"""
        if tactic in cls.TACTICS:
            return cls.TACTICS[tactic]["color"]
        return Color(0.5, 0.5, 0.5)
    
    @classmethod
    def get_tactic_layer(cls, tactic: str) -> int:
        """Get Y-layer for a MITRE tactic"""
        if tactic in cls.TACTICS:
            return cls.TACTICS[tactic]["layer"]
        return 7
    
    @classmethod
    def get_technique_info(cls, technique_id: str) -> Optional[Dict]:
        """Get technique information"""
        return cls.TECHNIQUES.get(technique_id)
    
    @classmethod
    def detect_techniques(cls, action: str) -> List[str]:
        """Detect MITRE techniques from action description"""
        action_lower = action.lower()
        detected = []
        
        keyword_mapping = {
            "phishing": ["T1566"],
            "exploit": ["T1190", "T1203"],
            "credential": ["T1003", "T1110"],
            "kerberos": ["T1558"],
            "golden ticket": ["T1558"],
            "dcsync": ["T1003"],
            "mimikatz": ["T1003"],
            "lateral": ["T1021", "T1570"],
            "psexec": ["T1021"],
            "wmi": ["T1047"],
            "powershell": ["T1059"],
            "persistence": ["T1547", "T1543"],
            "scheduled task": ["T1053"],
            "exfil": ["T1041", "T1048"],
            "c2": ["T1071", "T1573"],
            "beacon": ["T1071"],
            "discovery": ["T1087", "T1046"],
            "scan": ["T1046"],
            "dump": ["T1003"],
            "hash": ["T1003"],
            "pass the hash": ["T1550"],
            "token": ["T1134"],
            "privilege": ["T1068", "T1548"],
            "admin": ["T1078"],
            "rdp": ["T1021"],
            "ssh": ["T1021"],
            "smb": ["T1021"],
            "relay": ["T1557"],
            "ntlm": ["T1557"]
        }
        
        for keyword, techniques in keyword_mapping.items():
            if keyword in action_lower:
                detected.extend(techniques)
        
        return list(set(detected))


class LayoutEngine:
    """3D Layout algorithms for graph visualization"""
    
    @staticmethod
    def force_directed_3d(nodes: List[VRNode], edges: List[VREdge],
                          iterations: int = 100, k: float = 2.0) -> None:
        """Force-directed 3D layout algorithm"""
        if not nodes:
            return
            
        # Initialize random positions if not set
        for node in nodes:
            if node.position.x == 0 and node.position.y == 0 and node.position.z == 0:
                node.position = Vector3(
                    random.uniform(-10, 10),
                    random.uniform(-10, 10),
                    random.uniform(-10, 10)
                )
        
        # Build adjacency
        node_map = {n.id: n for n in nodes}
        
        for _ in range(iterations):
            # Calculate repulsive forces
            forces = {n.id: Vector3() for n in nodes}
            
            for i, n1 in enumerate(nodes):
                for n2 in nodes[i+1:]:
                    dx = n1.position.x - n2.position.x
                    dy = n1.position.y - n2.position.y
                    dz = n1.position.z - n2.position.z
                    dist = max(0.1, math.sqrt(dx*dx + dy*dy + dz*dz))
                    
                    # Repulsive force
                    force = k * k / dist
                    fx, fy, fz = dx/dist * force, dy/dist * force, dz/dist * force
                    
                    forces[n1.id].x += fx
                    forces[n1.id].y += fy
                    forces[n1.id].z += fz
                    forces[n2.id].x -= fx
                    forces[n2.id].y -= fy
                    forces[n2.id].z -= fz
            
            # Calculate attractive forces (edges)
            for edge in edges:
                if edge.source_id in node_map and edge.target_id in node_map:
                    n1 = node_map[edge.source_id]
                    n2 = node_map[edge.target_id]
                    
                    dx = n1.position.x - n2.position.x
                    dy = n1.position.y - n2.position.y
                    dz = n1.position.z - n2.position.z
                    dist = max(0.1, math.sqrt(dx*dx + dy*dy + dz*dz))
                    
                    # Attractive force
                    force = dist * dist / k
                    fx, fy, fz = dx/dist * force, dy/dist * force, dz/dist * force
                    
                    forces[n1.id].x -= fx * 0.5
                    forces[n1.id].y -= fy * 0.5
                    forces[n1.id].z -= fz * 0.5
                    forces[n2.id].x += fx * 0.5
                    forces[n2.id].y += fy * 0.5
                    forces[n2.id].z += fz * 0.5
            
            # Apply forces with damping
            damping = 0.85
            max_displacement = 1.0
            
            for node in nodes:
                f = forces[node.id]
                length = math.sqrt(f.x*f.x + f.y*f.y + f.z*f.z)
                if length > max_displacement:
                    f.x = f.x / length * max_displacement
                    f.y = f.y / length * max_displacement
                    f.z = f.z / length * max_displacement
                
                node.position.x += f.x * damping
                node.position.y += f.y * damping
                node.position.z += f.z * damping
    
    @staticmethod
    def hierarchical_3d(nodes: List[VRNode], edges: List[VREdge]) -> None:
        """Hierarchical 3D layout based on attack phases"""
        if not nodes:
            return
        
        # Group by MITRE tactic layer
        layers: Dict[int, List[VRNode]] = {}
        for node in nodes:
            layer = 0
            if node.mitre_tactic:
                layer = MITREAttackMapper.get_tactic_layer(node.mitre_tactic)
            elif node.node_type == NodeType.ATTACKER:
                layer = 0
            elif node.node_type == NodeType.TARGET:
                layer = 13
            
            if layer not in layers:
                layers[layer] = []
            layers[layer].append(node)
        
        # Position nodes in layers
        layer_spacing = 5.0
        for layer_idx, layer_nodes in layers.items():
            y = layer_idx * layer_spacing
            
            # Arrange nodes in a circle within the layer
            count = len(layer_nodes)
            radius = max(3.0, count * 1.5)
            
            for i, node in enumerate(layer_nodes):
                angle = (2 * math.pi * i) / count if count > 0 else 0
                node.position.x = radius * math.cos(angle)
                node.position.y = y
                node.position.z = radius * math.sin(angle)
    
    @staticmethod
    def network_topology(nodes: List[VRNode], edges: List[VREdge]) -> None:
        """Network topology layout"""
        if not nodes:
            return
        
        # Separate by node type
        type_positions = {
            NodeType.ATTACKER: Vector3(-15, 0, 0),
            NodeType.FIREWALL: Vector3(-8, 0, 0),
            NodeType.WEB_SERVER: Vector3(0, 5, -5),
            NodeType.DATABASE: Vector3(0, -5, -5),
            NodeType.DOMAIN_CONTROLLER: Vector3(8, 0, 0),
            NodeType.TARGET: Vector3(15, 0, 0),
            NodeType.CLOUD_INSTANCE: Vector3(0, 10, 5)
        }
        
        type_groups: Dict[NodeType, List[VRNode]] = {}
        for node in nodes:
            if node.node_type not in type_groups:
                type_groups[node.node_type] = []
            type_groups[node.node_type].append(node)
        
        # Position each group
        for node_type, group_nodes in type_groups.items():
            base_pos = type_positions.get(node_type, Vector3(0, 0, 0))
            
            for i, node in enumerate(group_nodes):
                offset_angle = (2 * math.pi * i) / max(1, len(group_nodes))
                offset_radius = 2.0 if len(group_nodes) > 1 else 0
                
                node.position.x = base_pos.x + offset_radius * math.cos(offset_angle)
                node.position.y = base_pos.y + random.uniform(-1, 1)
                node.position.z = base_pos.z + offset_radius * math.sin(offset_angle)


class VRViz:
    """
    VR/AR Red Team Visualization Engine
    
    Transforms penetration test reports into immersive 3D experiences
    with interactive attack graphs and MITRE ATT&CK mapping.
    """
    
    # Node type to 3D model mapping
    MODEL_MAPPING = {
        NodeType.HOST: "models/server_rack.fbx",
        NodeType.ATTACKER: "models/hacker_terminal.fbx",
        NodeType.TARGET: "models/target_crown.fbx",
        NodeType.DOMAIN_CONTROLLER: "models/domain_controller.fbx",
        NodeType.DATABASE: "models/database_cylinder.fbx",
        NodeType.WEB_SERVER: "models/web_server.fbx",
        NodeType.FIREWALL: "models/firewall_shield.fbx",
        NodeType.CLOUD_INSTANCE: "models/cloud_server.fbx",
        NodeType.VULNERABILITY: "models/vulnerability_warning.fbx",
        NodeType.EXPLOIT: "models/exploit_skull.fbx",
        NodeType.CREDENTIAL: "models/key_gold.fbx",
        NodeType.C2_CHANNEL: "models/antenna_signal.fbx",
        NodeType.MITRE_TACTIC: "models/mitre_hexagon.fbx",
        NodeType.MITRE_TECHNIQUE: "models/mitre_cube.fbx"
    }
    
    # Severity to color mapping
    SEVERITY_COLORS = {
        "critical": Color(0.9, 0.1, 0.1),
        "high": Color(1.0, 0.4, 0.0),
        "medium": Color(1.0, 0.8, 0.0),
        "low": Color(0.2, 0.8, 0.2),
        "info": Color(0.3, 0.5, 1.0)
    }
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize VR Visualization engine"""
        self.config = config or self._default_config()
        self.scene: Optional[VRScene] = None
        self.unity_cli_path = self.config.get("unity_cli_path", "unity-cli")
        self.output_dir = Path(self.config.get("output_dir", "./vr_output"))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Try to import report generator
        self.report_generator = None
        try:
            from cybermodules.report_generator import UltimateReportGenerator
            self.report_generator = UltimateReportGenerator
        except ImportError:
            logger.warning("UltimateReportGenerator not available")
    
    def _default_config(self) -> Dict:
        """Default configuration"""
        return {
            "unity_cli_path": "unity-cli",
            "output_dir": "./vr_output",
            "layout_algorithm": "hierarchical",
            "enable_animations": True,
            "enable_particles": True,
            "enable_glow": True,
            "node_scale": 1.0,
            "edge_width": 0.1,
            "camera_distance": 30.0,
            "fog_density": 0.02,
            "skybox": "cyber_grid",
            "vr_mode": "room_scale",
            "ar_mode": "marker_based",
            "webxr_enabled": True,
            "pdf3d_enabled": False,
            "mitre_visualization": True,
            "attack_replay": True,
            "interactive_nodes": True,
            "node_labels": True,
            "edge_labels": False,
            "ambient_sounds": True,
            "haptic_feedback": True
        }
    
    def create_scene(self, name: str = "Red Team Attack Visualization") -> VRScene:
        """Create a new VR scene"""
        self.scene = VRScene(
            name=name,
            metadata={
                "created": datetime.now().isoformat(),
                "generator": "MONOLITH VR Viz",
                "version": "1.0.0"
            }
        )
        return self.scene
    
    def add_node(self, node_id: str, node_type: NodeType, label: str,
                 position: Optional[Vector3] = None,
                 severity: str = "medium",
                 description: str = "",
                 mitre_id: Optional[str] = None,
                 metadata: Optional[Dict] = None) -> VRNode:
        """Add a node to the scene"""
        if not self.scene:
            self.create_scene()
        
        # Determine color based on severity or MITRE tactic
        if mitre_id:
            technique_info = MITREAttackMapper.get_technique_info(mitre_id)
            if technique_info:
                tactic = technique_info["tactic"]
                color = MITREAttackMapper.get_tactic_color(tactic)
            else:
                color = self.SEVERITY_COLORS.get(severity, Color(0.5, 0.5, 0.5))
        else:
            color = self.SEVERITY_COLORS.get(severity, Color(0.5, 0.5, 0.5))
        
        # Get MITRE tactic if technique ID provided
        mitre_tactic = None
        if mitre_id:
            technique_info = MITREAttackMapper.get_technique_info(mitre_id)
            if technique_info:
                mitre_tactic = technique_info["tactic"]
        
        node = VRNode(
            id=node_id,
            node_type=node_type,
            label=label,
            position=position or Vector3(),
            color=color,
            size=self.config.get("node_scale", 1.0),
            description=description,
            metadata=metadata or {},
            mitre_id=mitre_id,
            mitre_tactic=mitre_tactic,
            severity=severity,
            clickable=self.config.get("interactive_nodes", True),
            glow_effect=self.config.get("enable_glow", True) and severity in ["critical", "high"],
            particle_effect="spark" if severity == "critical" else None,
            model_path=self.MODEL_MAPPING.get(node_type)
        )
        
        self.scene.nodes.append(node)
        return node
    
    def add_edge(self, source_id: str, target_id: str,
                 edge_type: EdgeType = EdgeType.NETWORK,
                 label: Optional[str] = None,
                 animated: bool = True,
                 color: Optional[Color] = None) -> VREdge:
        """Add an edge between nodes"""
        if not self.scene:
            self.create_scene()
        
        edge_id = f"edge_{source_id}_{target_id}"
        
        # Default colors by edge type
        edge_colors = {
            EdgeType.NETWORK: Color(0.3, 0.5, 0.8, 0.6),
            EdgeType.ATTACK_PATH: Color(1.0, 0.2, 0.2, 0.8),
            EdgeType.CREDENTIAL_REUSE: Color(1.0, 0.8, 0.0, 0.7),
            EdgeType.LATERAL_MOVEMENT: Color(0.8, 0.4, 1.0, 0.7),
            EdgeType.DATA_FLOW: Color(0.2, 1.0, 0.5, 0.6),
            EdgeType.C2_COMMUNICATION: Color(0.5, 0.2, 0.8, 0.8),
            EdgeType.PRIVILEGE_ESCALATION: Color(1.0, 0.5, 0.0, 0.8),
            EdgeType.TRUST_RELATIONSHIP: Color(0.4, 0.8, 1.0, 0.5)
        }
        
        edge = VREdge(
            id=edge_id,
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            color=color or edge_colors.get(edge_type, Color(0.5, 0.5, 0.5, 0.5)),
            width=self.config.get("edge_width", 0.1),
            animated=animated and self.config.get("enable_animations", True),
            label=label,
            particle_flow=self.config.get("enable_particles", True) and edge_type == EdgeType.ATTACK_PATH
        )
        
        self.scene.edges.append(edge)
        return edge
    
    def create_attack_sequence(self, name: str, steps: List[Dict]) -> AttackSequence:
        """Create an attack animation sequence"""
        if not self.scene:
            self.create_scene()
        
        sequence = AttackSequence(
            id=f"seq_{hashlib.md5(name.encode()).hexdigest()[:8]}",
            name=name
        )
        
        timestamp = 0.0
        for step in steps:
            sequence.add_step(
                timestamp=timestamp,
                node_id=step.get("node_id", ""),
                action=step.get("action", ""),
                details=step.get("details", "")
            )
            timestamp += step.get("duration", 1.0)
        
        sequence.duration = timestamp
        self.scene.sequences.append(sequence)
        return sequence
    
    def generate_from_chain_log(self, chain_log: List[Dict]) -> VRScene:
        """
        Generate VR scene from attack chain log
        
        Args:
            chain_log: List of attack steps with details
            
        Returns:
            VRScene: Complete 3D visualization scene
        """
        self.create_scene("Attack Chain Visualization")
        
        # Track created nodes
        created_nodes: Set[str] = set()
        attack_steps = []
        
        # Add attacker node
        attacker_node = self.add_node(
            "attacker",
            NodeType.ATTACKER,
            "Attacker",
            severity="critical",
            description="Attack origin point"
        )
        created_nodes.add("attacker")
        
        prev_node_id = "attacker"
        
        for i, step in enumerate(chain_log):
            # Extract step information
            target = step.get("target", step.get("host", f"target_{i}"))
            action = step.get("action", step.get("technique", "Unknown"))
            result = step.get("result", step.get("status", "success"))
            
            # Detect MITRE techniques
            mitre_ids = MITREAttackMapper.detect_techniques(action)
            mitre_id = mitre_ids[0] if mitre_ids else None
            
            # Determine node type from action
            node_type = self._infer_node_type(action)
            
            # Determine severity
            severity = step.get("severity", "medium")
            if "domain" in action.lower() or "admin" in action.lower():
                severity = "critical"
            elif "credential" in action.lower() or "hash" in action.lower():
                severity = "high"
            
            # Create node for this step
            node_id = f"step_{i}_{target}"
            if node_id not in created_nodes:
                node = self.add_node(
                    node_id,
                    node_type,
                    f"{action[:30]}...",
                    severity=severity,
                    description=f"Target: {target}\nAction: {action}\nResult: {result}",
                    mitre_id=mitre_id,
                    metadata=step
                )
                node.is_compromised = result.lower() in ["success", "compromised", "pwned"]
                node.compromise_time = float(i)
                created_nodes.add(node_id)
            
            # Create edge from previous step
            edge_type = self._infer_edge_type(action)
            self.add_edge(
                prev_node_id,
                node_id,
                edge_type=edge_type,
                label=action[:20] if self.config.get("edge_labels") else None
            )
            
            # Add to attack sequence
            attack_steps.append({
                "node_id": node_id,
                "action": action,
                "details": str(step),
                "duration": 1.5
            })
            
            prev_node_id = node_id
        
        # Create attack replay sequence
        if attack_steps and self.config.get("attack_replay", True):
            self.create_attack_sequence("Main Attack Chain", attack_steps)
        
        # Apply layout algorithm
        self._apply_layout()
        
        # Add MITRE tactic overview if enabled
        if self.config.get("mitre_visualization", True):
            self._add_mitre_overlay()
        
        return self.scene
    
    def generate_from_report(self, report: Dict) -> VRScene:
        """Generate VR scene from a pentest report"""
        self.create_scene(report.get("title", "Penetration Test Visualization"))
        
        # Process hosts
        for host in report.get("hosts", []):
            host_id = host.get("ip", host.get("hostname", "unknown"))
            self.add_node(
                host_id,
                self._get_host_type(host),
                host.get("hostname", host_id),
                severity=host.get("severity", "low"),
                description=f"OS: {host.get('os', 'Unknown')}\nServices: {len(host.get('services', []))}",
                metadata=host
            )
            
            # Add services
            for service in host.get("services", []):
                service_id = f"{host_id}_{service.get('port', 0)}"
                self.add_node(
                    service_id,
                    NodeType.SERVICE,
                    f"{service.get('name', 'unknown')}:{service.get('port', 0)}",
                    severity=service.get("severity", "info"),
                    metadata=service
                )
                self.add_edge(host_id, service_id, EdgeType.NETWORK)
        
        # Process vulnerabilities
        for vuln in report.get("vulnerabilities", []):
            vuln_id = f"vuln_{vuln.get('id', hashlib.md5(str(vuln).encode()).hexdigest()[:8])}"
            self.add_node(
                vuln_id,
                NodeType.VULNERABILITY,
                vuln.get("name", "Unknown Vulnerability"),
                severity=vuln.get("severity", "medium"),
                description=vuln.get("description", ""),
                mitre_id=vuln.get("mitre_id"),
                metadata=vuln
            )
            
            # Link to affected host
            if vuln.get("host"):
                self.add_edge(vuln.get("host"), vuln_id, EdgeType.ATTACK_PATH)
        
        # Process attack paths
        for path in report.get("attack_paths", []):
            for i in range(len(path) - 1):
                self.add_edge(path[i], path[i+1], EdgeType.ATTACK_PATH)
        
        self._apply_layout()
        return self.scene
    
    def generate_vr_report(self, chain_log: List[Dict],
                           export_format: ExportFormat = ExportFormat.UNITY_SCENE) -> str:
        """
        Generate VR report from chain log
        
        Args:
            chain_log: Attack chain log data
            export_format: Export format
            
        Returns:
            str: Path to exported file or status message
        """
        # Generate scene
        scene = self.generate_from_chain_log(chain_log)
        
        # Export based on format
        return self.export_scene(export_format)
    
    def export_scene(self, format: ExportFormat = ExportFormat.JSON_SCENE,
                     filename: Optional[str] = None) -> str:
        """Export scene to specified format"""
        if not self.scene:
            raise ValueError("No scene to export")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format == ExportFormat.JSON_SCENE:
            return self._export_json(filename or f"scene_{timestamp}.json")
        elif format == ExportFormat.UNITY_SCENE:
            return self._export_unity(filename or f"scene_{timestamp}.unity")
        elif format == ExportFormat.WEBXR:
            return self._export_webxr(filename or f"scene_{timestamp}_webxr")
        elif format == ExportFormat.THREE_JS:
            return self._export_threejs(filename or f"scene_{timestamp}_threejs.js")
        elif format == ExportFormat.GLTF:
            return self._export_gltf(filename or f"scene_{timestamp}.gltf")
        else:
            return self._export_json(filename or f"scene_{timestamp}.json")
    
    def _export_json(self, filename: str) -> str:
        """Export as JSON"""
        output_path = self.output_dir / filename
        with open(output_path, 'w') as f:
            json.dump(self.scene.to_dict(), f, indent=2)
        logger.info(f"Exported JSON scene to {output_path}")
        return str(output_path)
    
    def _export_unity(self, filename: str) -> str:
        """Export Unity scene"""
        # First export JSON
        json_path = self._export_json(filename.replace('.unity', '.json'))
        unity_path = self.output_dir / filename
        
        # Try to call Unity CLI
        try:
            result = subprocess.run(
                [self.unity_cli_path, '--export-vr', json_path, str(unity_path)],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                logger.info(f"Exported Unity scene to {unity_path}")
                return str(unity_path)
            else:
                logger.warning(f"Unity CLI failed: {result.stderr}")
                # Generate placeholder Unity YAML
                return self._generate_unity_yaml(unity_path)
        except FileNotFoundError:
            logger.warning("Unity CLI not found, generating placeholder")
            return self._generate_unity_yaml(unity_path)
        except subprocess.TimeoutExpired:
            logger.warning("Unity CLI timed out")
            return self._generate_unity_yaml(unity_path)
    
    def _generate_unity_yaml(self, output_path: Path) -> str:
        """Generate Unity scene YAML placeholder"""
        unity_yaml = f"""
%YAML 1.1
%TAG !u! tag:unity3d.com,2011:
--- !u!29 &1
OcclusionCullingSettings:
  m_ObjectHideFlags: 0
  serializedVersion: 2
  m_OcclusionBakeSettings:
    smallestOccluder: 5
    smallestHole: 0.25
    backfaceThreshold: 100
  m_SceneGUID: 00000000000000000000000000000000
  m_OcclusionCullingData: {{fileID: 0}}
--- !u!104 &2
RenderSettings:
  serializedVersion: 9
  m_Fog: {1 if self.scene.fog_enabled else 0}
  m_FogColor: {{r: 0.1, g: 0.1, b: 0.15, a: 1}}
  m_FogMode: 3
  m_FogDensity: {self.scene.fog_density}
  m_LinearFogStart: 0
  m_LinearFogEnd: 300
  m_AmbientSkyColor: {{r: {self.scene.ambient_color.r}, g: {self.scene.ambient_color.g}, b: {self.scene.ambient_color.b}, a: 1}}
  m_AmbientEquatorColor: {{r: 0.114, g: 0.125, b: 0.133, a: 1}}
  m_AmbientGroundColor: {{r: 0.047, g: 0.043, b: 0.035, a: 1}}
  m_AmbientIntensity: 1
  m_AmbientMode: 3
  m_SkyboxMaterial: {{fileID: 0}}
--- !u!157 &3
LightmapSettings:
  serializedVersion: 12
  m_GIWorkflowMode: 1
  m_LightmapEditorSettings:
    serializedVersion: 12
    m_Resolution: 2
    m_BakeResolution: 40
    m_AtlasSize: 1024
    m_AO: 0
    m_AOMaxDistance: 1
    m_CompAOExponent: 1
    m_CompAOExponentDirect: 0
    m_ExtractAmbientOcclusion: 0
    m_Padding: 2
    m_LightmapParameters: {{fileID: 0}}
    m_LightmapsBakeMode: 1
    m_TextureCompression: 1
    m_FinalGather: 0
    m_FinalGatherFiltering: 1
    m_FinalGatherRayCount: 256
    m_ReflectionCompression: 2
    m_MixedBakeMode: 2
    m_BakeBackend: 1
    m_PVRSampling: 1
    m_PVRDirectSampleCount: 32
    m_PVRSampleCount: 512
    m_PVRBounces: 2
    m_PVREnvironmentSampleCount: 256
    m_PVREnvironmentReferencePointCount: 2048
    m_PVRFilteringMode: 1
    m_PVRDenoiserTypeDirect: 1
    m_PVRDenoiserTypeIndirect: 1
    m_PVRDenoiserTypeAO: 1
    m_PVRFilterTypeDirect: 0
    m_PVRFilterTypeIndirect: 0
    m_PVRFilterTypeAO: 0
    m_PVREnvironmentMIS: 1
    m_PVRCulling: 1
    m_PVRFilteringGaussRadiusDirect: 1
    m_PVRFilteringGaussRadiusIndirect: 5
    m_PVRFilteringGaussRadiusAO: 2
    m_PVRFilteringAtrousPositionSigmaDirect: 0.5
    m_PVRFilteringAtrousPositionSigmaIndirect: 2
    m_PVRFilteringAtrousPositionSigmaAO: 1
    m_ExportTrainingData: 0
    m_TrainingDataDestination: TrainingData
    m_LightProbeSampleCountMultiplier: 4
--- !u!1001 &100
Prefab:
  m_ObjectHideFlags: 0
  serializedVersion: 2
  m_Modification:
    m_TransformParent: {{fileID: 0}}
    m_Modifications: []
    m_RemovedComponents: []
  m_ParentPrefab: {{fileID: 0}}
  m_IsPrefabParent: 0
# MONOLITH VR Scene - Generated {datetime.now().isoformat()}
# Nodes: {len(self.scene.nodes)}
# Edges: {len(self.scene.edges)}
# Sequences: {len(self.scene.sequences)}
"""
        
        with open(output_path, 'w') as f:
            f.write(unity_yaml)
        
        logger.info(f"Generated Unity YAML placeholder at {output_path}")
        return str(output_path)
    
    def _export_webxr(self, dirname: str) -> str:
        """Export WebXR-compatible scene"""
        output_dir = self.output_dir / dirname
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate HTML with WebXR
        html_content = self._generate_webxr_html()
        
        with open(output_dir / "index.html", 'w') as f:
            f.write(html_content)
        
        # Export scene JSON
        with open(output_dir / "scene.json", 'w') as f:
            json.dump(self.scene.to_dict(), f, indent=2)
        
        logger.info(f"Exported WebXR scene to {output_dir}")
        return str(output_dir)
    
    def _generate_webxr_html(self) -> str:
        """Generate WebXR HTML viewer"""
        scene_json = json.dumps(self.scene.to_dict())
        
        return f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{self.scene.name} - VR View</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="https://aframe.io/releases/1.4.0/aframe.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/aframe-extras@6.1.1/dist/aframe-extras.min.js"></script>
    <style>
        body {{ margin: 0; overflow: hidden; }}
        .vr-button {{ position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%);
            padding: 15px 30px; background: #7c3aed; color: white; border: none;
            border-radius: 8px; cursor: pointer; font-size: 16px; z-index: 1000; }}
        .vr-button:hover {{ background: #6d28d9; }}
        .info-panel {{ position: fixed; top: 20px; right: 20px; background: rgba(0,0,0,0.8);
            color: white; padding: 20px; border-radius: 10px; max-width: 300px; z-index: 1000; }}
    </style>
</head>
<body>
    <div class="info-panel">
        <h3>🥽 {self.scene.name}</h3>
        <p>Nodes: {len(self.scene.nodes)}</p>
        <p>Edges: {len(self.scene.edges)}</p>
        <p>Click VR button for immersive view</p>
    </div>
    
    <a-scene vr-mode-ui="enabled: true" background="color: #0a0a1a">
        <!-- Lighting -->
        <a-light type="ambient" color="#333"></a-light>
        <a-light type="directional" position="0 10 0" intensity="0.5"></a-light>
        
        <!-- Grid Floor -->
        <a-grid position="0 0 0" rotation="-90 0 0" 
                material="color: #7c3aed; opacity: 0.3; wireframe: true"></a-grid>
        
        <!-- Camera Rig -->
        <a-entity id="rig" movement-controls="fly: true">
            <a-camera position="0 1.6 0" look-controls>
                <a-cursor color="#7c3aed"></a-cursor>
            </a-camera>
        </a-entity>
        
        <!-- Nodes -->
        <a-entity id="nodes">
            {"".join(self._generate_aframe_node(node) for node in self.scene.nodes)}
        </a-entity>
        
        <!-- Edges -->
        <a-entity id="edges">
            {"".join(self._generate_aframe_edge(edge) for edge in self.scene.edges)}
        </a-entity>
    </a-scene>
    
    <script>
        const sceneData = {scene_json};
        
        // Node click handler
        document.querySelectorAll('[data-node-id]').forEach(node => {{
            node.addEventListener('click', function() {{
                const nodeId = this.getAttribute('data-node-id');
                const nodeData = sceneData.nodes.find(n => n.id === nodeId);
                if (nodeData) {{
                    alert(`${{nodeData.label}}\\n\\n${{nodeData.description}}\\n\\nMITRE: ${{nodeData.mitre_id || 'N/A'}}`);
                }}
            }});
        }});
    </script>
</body>
</html>'''
    
    def _generate_aframe_node(self, node: VRNode) -> str:
        """Generate A-Frame entity for a node"""
        color = node.color.to_hex()
        pos = f"{node.position.x} {node.position.y} {node.position.z}"
        
        # Different geometry based on type
        geometry_map = {
            NodeType.HOST: "box",
            NodeType.ATTACKER: "cone",
            NodeType.TARGET: "dodecahedron",
            NodeType.DOMAIN_CONTROLLER: "octahedron",
            NodeType.DATABASE: "cylinder",
            NodeType.WEB_SERVER: "box",
            NodeType.FIREWALL: "tetrahedron",
            NodeType.VULNERABILITY: "sphere",
            NodeType.EXPLOIT: "icosahedron",
            NodeType.CREDENTIAL: "torus",
            NodeType.MITRE_TACTIC: "box",
            NodeType.MITRE_TECHNIQUE: "sphere"
        }
        
        geometry = geometry_map.get(node.node_type, "sphere")
        
        return f'''
            <a-entity position="{pos}" data-node-id="{node.id}" class="clickable">
                <a-{geometry} color="{color}" radius="{node.size * 0.3}" 
                    {"animation='property: rotation; to: 0 360 0; loop: true; dur: 5000'" if node.glow_effect else ""}>
                </a-{geometry}>
                <a-text value="{node.label[:20]}" position="0 {node.size * 0.5} 0" 
                    align="center" color="white" scale="0.5 0.5 0.5"></a-text>
            </a-entity>'''
    
    def _generate_aframe_edge(self, edge: VREdge) -> str:
        """Generate A-Frame line for an edge"""
        # Get source and target positions
        source_node = next((n for n in self.scene.nodes if n.id == edge.source_id), None)
        target_node = next((n for n in self.scene.nodes if n.id == edge.target_id), None)
        
        if not source_node or not target_node:
            return ""
        
        color = edge.color.to_hex()
        start = f"{source_node.position.x} {source_node.position.y} {source_node.position.z}"
        end = f"{target_node.position.x} {target_node.position.y} {target_node.position.z}"
        
        return f'''
            <a-entity line="start: {start}; end: {end}; color: {color}; opacity: 0.7"></a-entity>'''
    
    def _export_threejs(self, filename: str) -> str:
        """Export Three.js scene"""
        output_path = self.output_dir / filename
        
        threejs_code = self._generate_threejs_code()
        
        with open(output_path, 'w') as f:
            f.write(threejs_code)
        
        logger.info(f"Exported Three.js scene to {output_path}")
        return str(output_path)
    
    def _generate_threejs_code(self) -> str:
        """Generate Three.js code"""
        scene_json = json.dumps(self.scene.to_dict())
        
        return f'''// MONOLITH VR Viz - Three.js Scene
// Generated: {datetime.now().isoformat()}

const sceneData = {scene_json};

class VRVizScene {{
    constructor(container) {{
        this.container = container;
        this.scene = new THREE.Scene();
        this.camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
        this.renderer = new THREE.WebGLRenderer({{ antialias: true }});
        this.nodes = new Map();
        this.edges = [];
        this.raycaster = new THREE.Raycaster();
        this.mouse = new THREE.Vector2();
        
        this.init();
    }}
    
    init() {{
        // Setup renderer
        this.renderer.setSize(window.innerWidth, window.innerHeight);
        this.renderer.setClearColor(0x0a0a1a);
        this.container.appendChild(this.renderer.domElement);
        
        // Setup camera
        this.camera.position.set(
            sceneData.camera.position.x,
            sceneData.camera.position.y,
            sceneData.camera.position.z
        );
        this.camera.lookAt(new THREE.Vector3(
            sceneData.camera.target.x,
            sceneData.camera.target.y,
            sceneData.camera.target.z
        ));
        
        // Add lights
        const ambientLight = new THREE.AmbientLight(0x404040, 0.5);
        this.scene.add(ambientLight);
        
        const directionalLight = new THREE.DirectionalLight(0xffffff, 0.8);
        directionalLight.position.set(10, 20, 10);
        this.scene.add(directionalLight);
        
        // Add fog
        if (sceneData.environment.fog_enabled) {{
            this.scene.fog = new THREE.FogExp2(0x0a0a1a, sceneData.environment.fog_density);
        }}
        
        // Add grid
        if (sceneData.environment.grid_enabled) {{
            const gridHelper = new THREE.GridHelper(100, 50, 0x7c3aed, 0x3b2f5e);
            this.scene.add(gridHelper);
        }}
        
        // Create nodes
        this.createNodes();
        
        // Create edges
        this.createEdges();
        
        // Setup controls
        this.controls = new THREE.OrbitControls(this.camera, this.renderer.domElement);
        this.controls.enableDamping = true;
        
        // Event listeners
        window.addEventListener('resize', () => this.onResize());
        this.container.addEventListener('click', (e) => this.onClick(e));
        
        // Start animation
        this.animate();
    }}
    
    createNodes() {{
        sceneData.nodes.forEach(nodeData => {{
            const geometry = this.getGeometryForType(nodeData.type);
            const material = new THREE.MeshPhongMaterial({{
                color: new THREE.Color(nodeData.color.r, nodeData.color.g, nodeData.color.b),
                emissive: nodeData.glow_effect ? new THREE.Color(nodeData.color.r * 0.3, nodeData.color.g * 0.3, nodeData.color.b * 0.3) : 0x000000,
                shininess: 100
            }});
            
            const mesh = new THREE.Mesh(geometry, material);
            mesh.position.set(nodeData.position.x, nodeData.position.y, nodeData.position.z);
            mesh.scale.setScalar(nodeData.size);
            mesh.userData = nodeData;
            
            this.scene.add(mesh);
            this.nodes.set(nodeData.id, mesh);
            
            // Add label
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            canvas.width = 256;
            canvas.height = 64;
            ctx.fillStyle = 'white';
            ctx.font = '24px Arial';
            ctx.textAlign = 'center';
            ctx.fillText(nodeData.label.substring(0, 25), 128, 40);
            
            const texture = new THREE.CanvasTexture(canvas);
            const spriteMaterial = new THREE.SpriteMaterial({{ map: texture }});
            const sprite = new THREE.Sprite(spriteMaterial);
            sprite.position.set(nodeData.position.x, nodeData.position.y + nodeData.size + 0.5, nodeData.position.z);
            sprite.scale.set(4, 1, 1);
            this.scene.add(sprite);
        }});
    }}
    
    getGeometryForType(type) {{
        const geometries = {{
            'host': new THREE.BoxGeometry(1, 1, 1),
            'attacker': new THREE.ConeGeometry(0.5, 1, 8),
            'target': new THREE.DodecahedronGeometry(0.5),
            'domain_controller': new THREE.OctahedronGeometry(0.5),
            'database': new THREE.CylinderGeometry(0.4, 0.4, 1, 16),
            'web_server': new THREE.BoxGeometry(0.8, 1.2, 0.8),
            'firewall': new THREE.TetrahedronGeometry(0.5),
            'vulnerability': new THREE.SphereGeometry(0.4, 16, 16),
            'exploit': new THREE.IcosahedronGeometry(0.4),
            'credential': new THREE.TorusGeometry(0.3, 0.1, 8, 16)
        }};
        return geometries[type] || new THREE.SphereGeometry(0.5, 16, 16);
    }}
    
    createEdges() {{
        sceneData.edges.forEach(edgeData => {{
            const sourceNode = this.nodes.get(edgeData.source);
            const targetNode = this.nodes.get(edgeData.target);
            
            if (sourceNode && targetNode) {{
                const points = [
                    sourceNode.position.clone(),
                    targetNode.position.clone()
                ];
                
                const geometry = new THREE.BufferGeometry().setFromPoints(points);
                const material = new THREE.LineBasicMaterial({{
                    color: new THREE.Color(edgeData.color.r, edgeData.color.g, edgeData.color.b),
                    transparent: true,
                    opacity: edgeData.color.a
                }});
                
                const line = new THREE.Line(geometry, material);
                this.scene.add(line);
                this.edges.push(line);
            }}
        }});
    }}
    
    onClick(event) {{
        this.mouse.x = (event.clientX / window.innerWidth) * 2 - 1;
        this.mouse.y = -(event.clientY / window.innerHeight) * 2 + 1;
        
        this.raycaster.setFromCamera(this.mouse, this.camera);
        const intersects = this.raycaster.intersectObjects(Array.from(this.nodes.values()));
        
        if (intersects.length > 0) {{
            const node = intersects[0].object.userData;
            this.showNodeInfo(node);
        }}
    }}
    
    showNodeInfo(node) {{
        console.log('Node clicked:', node);
        alert(`${{node.label}}\\n\\n${{node.description}}\\n\\nType: ${{node.type}}\\nMITRE: ${{node.mitre_id || 'N/A'}}\\nSeverity: ${{node.severity}}`);
    }}
    
    onResize() {{
        this.camera.aspect = window.innerWidth / window.innerHeight;
        this.camera.updateProjectionMatrix();
        this.renderer.setSize(window.innerWidth, window.innerHeight);
    }}
    
    animate() {{
        requestAnimationFrame(() => this.animate());
        
        // Rotate glowing nodes
        this.nodes.forEach((mesh, id) => {{
            if (mesh.userData.glow_effect) {{
                mesh.rotation.y += 0.01;
            }}
        }});
        
        this.controls.update();
        this.renderer.render(this.scene, this.camera);
    }}
}}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {{
    const container = document.getElementById('vr-container') || document.body;
    window.vrScene = new VRVizScene(container);
}});
'''
    
    def _export_gltf(self, filename: str) -> str:
        """Export GLTF scene"""
        output_path = self.output_dir / filename
        
        # Generate basic GLTF structure
        gltf = {
            "asset": {
                "version": "2.0",
                "generator": "MONOLITH VR Viz"
            },
            "scene": 0,
            "scenes": [{"nodes": list(range(len(self.scene.nodes)))}],
            "nodes": [],
            "meshes": [],
            "materials": [],
            "accessors": [],
            "bufferViews": [],
            "buffers": []
        }
        
        # Add nodes
        for i, node in enumerate(self.scene.nodes):
            gltf["nodes"].append({
                "name": node.id,
                "translation": [node.position.x, node.position.y, node.position.z],
                "mesh": i,
                "extras": {
                    "label": node.label,
                    "type": node.node_type.value,
                    "mitre_id": node.mitre_id,
                    "severity": node.severity,
                    "description": node.description
                }
            })
            
            # Add material
            gltf["materials"].append({
                "name": f"material_{node.id}",
                "pbrMetallicRoughness": {
                    "baseColorFactor": [node.color.r, node.color.g, node.color.b, node.color.a],
                    "metallicFactor": 0.5,
                    "roughnessFactor": 0.5
                }
            })
        
        with open(output_path, 'w') as f:
            json.dump(gltf, f, indent=2)
        
        logger.info(f"Exported GLTF scene to {output_path}")
        return str(output_path)
    
    def _apply_layout(self) -> None:
        """Apply layout algorithm to scene nodes"""
        if not self.scene or not self.scene.nodes:
            return
        
        algorithm = self.config.get("layout_algorithm", "hierarchical")
        
        if algorithm == "force_directed":
            LayoutEngine.force_directed_3d(self.scene.nodes, self.scene.edges)
        elif algorithm == "hierarchical":
            LayoutEngine.hierarchical_3d(self.scene.nodes, self.scene.edges)
        elif algorithm == "network":
            LayoutEngine.network_topology(self.scene.nodes, self.scene.edges)
        else:
            LayoutEngine.hierarchical_3d(self.scene.nodes, self.scene.edges)
    
    def _add_mitre_overlay(self) -> None:
        """Add MITRE ATT&CK framework overlay"""
        if not self.scene:
            return
        
        # Group existing nodes by tactic
        tactics_used: Set[str] = set()
        for node in self.scene.nodes:
            if node.mitre_tactic:
                tactics_used.add(node.mitre_tactic)
        
        # Add tactic header nodes
        x_offset = -30
        for tactic in MITREAttackMapper.TACTICS:
            if tactic in tactics_used:
                layer = MITREAttackMapper.get_tactic_layer(tactic)
                color = MITREAttackMapper.get_tactic_color(tactic)
                
                tactic_node = VRNode(
                    id=f"tactic_{tactic}",
                    node_type=NodeType.MITRE_TACTIC,
                    label=tactic.replace("_", " ").title(),
                    position=Vector3(x_offset, layer * 5, 0),
                    color=color,
                    size=1.5,
                    description=f"MITRE ATT&CK Tactic: {tactic}",
                    clickable=True,
                    glow_effect=True
                )
                self.scene.nodes.append(tactic_node)
    
    def _infer_node_type(self, action: str) -> NodeType:
        """Infer node type from action description"""
        action_lower = action.lower()
        
        if any(k in action_lower for k in ["credential", "password", "hash", "ntlm"]):
            return NodeType.CREDENTIAL
        elif any(k in action_lower for k in ["exploit", "rce", "cve"]):
            return NodeType.EXPLOIT
        elif any(k in action_lower for k in ["lateral", "psexec", "wmi", "pivot"]):
            return NodeType.LATERAL_MOVE
        elif any(k in action_lower for k in ["persistence", "backdoor", "implant"]):
            return NodeType.PERSISTENCE
        elif any(k in action_lower for k in ["exfil", "extract", "steal"]):
            return NodeType.EXFILTRATION
        elif any(k in action_lower for k in ["c2", "beacon", "callback"]):
            return NodeType.C2_CHANNEL
        elif any(k in action_lower for k in ["domain controller", "dc", "ad"]):
            return NodeType.DOMAIN_CONTROLLER
        elif any(k in action_lower for k in ["database", "sql", "mysql"]):
            return NodeType.DATABASE
        elif any(k in action_lower for k in ["web", "http", "apache", "nginx"]):
            return NodeType.WEB_SERVER
        elif any(k in action_lower for k in ["vuln", "vulnerable"]):
            return NodeType.VULNERABILITY
        else:
            return NodeType.HOST
    
    def _infer_edge_type(self, action: str) -> EdgeType:
        """Infer edge type from action"""
        action_lower = action.lower()
        
        if any(k in action_lower for k in ["lateral", "pivot", "move"]):
            return EdgeType.LATERAL_MOVEMENT
        elif any(k in action_lower for k in ["credential", "pass the", "reuse"]):
            return EdgeType.CREDENTIAL_REUSE
        elif any(k in action_lower for k in ["privilege", "escalat"]):
            return EdgeType.PRIVILEGE_ESCALATION
        elif any(k in action_lower for k in ["c2", "beacon", "command"]):
            return EdgeType.C2_COMMUNICATION
        elif any(k in action_lower for k in ["exfil", "data"]):
            return EdgeType.DATA_FLOW
        elif any(k in action_lower for k in ["trust", "delegation"]):
            return EdgeType.TRUST_RELATIONSHIP
        else:
            return EdgeType.ATTACK_PATH
    
    def _get_host_type(self, host: Dict) -> NodeType:
        """Determine node type from host info"""
        hostname = host.get("hostname", "").lower()
        services = [s.get("name", "").lower() for s in host.get("services", [])]
        
        if any(k in hostname for k in ["dc", "domain"]):
            return NodeType.DOMAIN_CONTROLLER
        elif any(k in hostname for k in ["db", "sql", "mysql", "postgres"]):
            return NodeType.DATABASE
        elif any(k in services for k in ["http", "https", "apache", "nginx"]):
            return NodeType.WEB_SERVER
        elif any(k in hostname for k in ["fw", "firewall"]):
            return NodeType.FIREWALL
        elif any(k in hostname for k in ["cloud", "aws", "azure", "gcp"]):
            return NodeType.CLOUD_INSTANCE
        else:
            return NodeType.HOST
    
    def get_scene_stats(self) -> Dict:
        """Get statistics about the current scene"""
        if not self.scene:
            return {}
        
        node_types = {}
        for node in self.scene.nodes:
            t = node.node_type.value
            node_types[t] = node_types.get(t, 0) + 1
        
        edge_types = {}
        for edge in self.scene.edges:
            t = edge.edge_type.value
            edge_types[t] = edge_types.get(t, 0) + 1
        
        mitre_tactics = {}
        for node in self.scene.nodes:
            if node.mitre_tactic:
                mitre_tactics[node.mitre_tactic] = mitre_tactics.get(node.mitre_tactic, 0) + 1
        
        return {
            "name": self.scene.name,
            "total_nodes": len(self.scene.nodes),
            "total_edges": len(self.scene.edges),
            "total_sequences": len(self.scene.sequences),
            "node_types": node_types,
            "edge_types": edge_types,
            "mitre_tactics": mitre_tactics,
            "compromised_nodes": sum(1 for n in self.scene.nodes if n.is_compromised)
        }


# Utility functions for external integration
def create_vr_viz(config: Optional[Dict] = None) -> VRViz:
    """Create VRViz instance with optional config"""
    return VRViz(config)


def generate_vr_from_log(chain_log: List[Dict], output_format: str = "webxr") -> str:
    """Quick function to generate VR from attack log"""
    viz = VRViz()
    viz.generate_from_chain_log(chain_log)
    
    format_map = {
        "webxr": ExportFormat.WEBXR,
        "unity": ExportFormat.UNITY_SCENE,
        "threejs": ExportFormat.THREE_JS,
        "json": ExportFormat.JSON_SCENE,
        "gltf": ExportFormat.GLTF
    }
    
    return viz.export_scene(format_map.get(output_format, ExportFormat.WEBXR))


# Example usage and CLI
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="VR/AR Red Team Visualization")
    parser.add_argument("--input", "-i", help="Input chain log JSON file")
    parser.add_argument("--output", "-o", help="Output directory")
    parser.add_argument("--format", "-f", choices=["unity", "webxr", "threejs", "json", "gltf"],
                        default="webxr", help="Export format")
    parser.add_argument("--layout", "-l", choices=["force_directed", "hierarchical", "network"],
                        default="hierarchical", help="Layout algorithm")
    parser.add_argument("--demo", action="store_true", help="Generate demo scene")
    
    args = parser.parse_args()
    
    viz = VRViz({"layout_algorithm": args.layout, "output_dir": args.output or "./vr_output"})
    
    if args.demo:
        # Generate demo scene
        demo_log = [
            {"target": "192.168.1.10", "action": "Phishing Email Sent", "result": "success"},
            {"target": "192.168.1.10", "action": "Payload Executed", "result": "success"},
            {"target": "192.168.1.10", "action": "Credential Dumping with Mimikatz", "result": "success"},
            {"target": "192.168.1.20", "action": "Lateral Movement via PSExec", "result": "success"},
            {"target": "192.168.1.100", "action": "Domain Controller Compromised", "result": "success", "severity": "critical"},
            {"target": "192.168.1.100", "action": "DCSync Attack", "result": "success", "severity": "critical"},
            {"target": "192.168.1.100", "action": "Golden Ticket Created", "result": "success", "severity": "critical"}
        ]
        
        viz.generate_from_chain_log(demo_log)
        output = viz.export_scene(ExportFormat[args.format.upper()])
        print(f"[+] Demo VR scene exported to: {output}")
        print(f"[+] Scene stats: {viz.get_scene_stats()}")
    
    elif args.input:
        with open(args.input) as f:
            chain_log = json.load(f)
        
        viz.generate_from_chain_log(chain_log)
        output = viz.export_scene(ExportFormat[args.format.upper()])
        print(f"[+] VR scene exported to: {output}")
    
    else:
        print("Use --demo for demo scene or --input for chain log file")
