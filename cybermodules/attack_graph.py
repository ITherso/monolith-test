"""
AI Attack Path Graph Module
LLM kullanarak ağ haritası ve saldırı yolu önerileri üretir.
Frontend'de görselleştirme için graph data çıktısı verir.
"""
import json
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
from cybermodules.llm_engine import analyze_with_llm


@dataclass
class GraphNode:
    """Graph node representation"""
    id: str
    label: str
    type: str  # domain_controller, server, workstation, user, database
    os: Optional[str] = None
    services: List[str] = field(default_factory=list)
    vulns: List[str] = field(default_factory=list)
    severity: str = "medium"  # critical, high, medium, low
    compromised: bool = False


@dataclass
class GraphEdge:
    """Graph edge representation"""
    source: str
    target: str
    relation: str  # trusts, admin_to, has_service, same_domain
    technique: Optional[str] = None  # MITRE ATT&CK technique
    description: str = ""


@dataclass
class AttackPath:
    """Attack path recommendation"""
    nodes: List[str]
    edges: List[str]
    total_score: int
    description: str
    techniques: List[str]
    mitigations: List[str]


class AttackPathGraph:
    """LLM-powered attack path analysis and graph generation"""
    
    def __init__(self, scan_id: int = 0):
        self.scan_id = scan_id
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self.attack_paths: List[AttackPath] = []
    
    def add_node(
        self,
        node_id: str,
        label: str,
        node_type: str,
        os: str = None,
        services: List[str] = None,
        vulns: List[str] = None,
        severity: str = "medium",
        compromised: bool = False
    ) -> GraphNode:
        """Graph'e node ekler"""
        node = GraphNode(
            id=node_id,
            label=label,
            type=node_type,
            os=os,
            services=services or [],
            vulns=vulns or [],
            severity=severity,
            compromised=compromised
        )
        self.nodes[node_id] = node
        return node
    
    def add_edge(
        self,
        source: str,
        target: str,
        relation: str,
        technique: str = None,
        description: str = ""
    ) -> GraphEdge:
        """Graph'e edge ekler"""
        edge = GraphEdge(
            source=source,
            target=target,
            relation=relation,
            technique=technique,
            description=description
        )
        self.edges.append(edge)
        return edge
    
    def generate_from_scan_data(self, scan_data: Dict) -> Dict:
        """
        Scan verilerinden graph oluşturur.
        
        Args:
            scan_data: Tüm tarama verileri (vulns, techs, intel vb.)
        
        Returns:
            Dict: Graph data (nodes, edges, paths)
        """
        # Ana domain controller ekle
        target = scan_data.get("target", "unknown")
        self.add_node(
            node_id="dc-01",
            label=target,
            node_type="domain_controller",
            os="Windows Server 2019",
            services=["LDAP", "Kerberos", "DNS", "SMB"],
            severity="critical",
            compromised=False
        )
        
        # Vulnerability'lardan node'lar oluştur
        vulns = scan_data.get("vulnerabilities", [])
        vuln_count = 0
        
        for vuln in vulns[:10]:  # Max 10 vuln
            vuln_count += 1
            vuln_id = f"vuln-{vuln_count}"
            
            # Severity belirle
            severity = "high"
            if "rce" in vuln.get("type", "").lower() or "remote" in vuln.get("type", "").lower():
                severity = "critical"
            elif "xss" in vuln.get("type", "").lower() or "sql" in vuln.get("type", "").lower():
                severity = "medium"
            
            self.add_node(
                node_id=vuln_id,
                label=vuln.get("type", "Unknown Vuln"),
                node_type="vulnerability",
                services=[],
                vulns=[vuln.get("url", "")],
                severity=severity,
                compromised=False
            )
            
            # DC'ye edge ekle
            self.add_edge(
                source="dc-01",
                target=vuln_id,
                relation="has_vulnerability",
                technique=self._get_mitre_technique(vuln.get("type", "")),
                description=f"Vulnerability: {vuln.get('type', '')}"
            )
        
        # Teknolojilerden node'lar oluştur
        techs = scan_data.get("technologies", [])
        tech_count = 0
        
        for tech in techs[:5]:
            tech_count += 1
            tech_id = f"tech-{tech_count}"
            
            self.add_node(
                node_id=tech_id,
                label=tech.get("name", "Unknown Tech"),
                node_type="technology",
                services=[tech.get("method", "")],
                severity="medium"
            )
            
            self.add_edge(
                source="dc-01",
                target=tech_id,
                relation="runs",
                description=f"Technology: {tech.get('name', '')}"
            )
        
        # Intel verilerinden edge'ler ekle
        intel = scan_data.get("intel", [])
        for info in intel[:5]:
            if "credential" in info.get("type", "").lower() or "hash" in info.get("type", "").lower():
                self.add_node(
                    node_id=f"cred-{hash(info.get('data', ''))[:8]}",
                    label="Credentials Found",
                    node_type="credential",
                    severity="critical",
                    compromised=True
                )
                self.add_edge(
                    source=f"cred-{hash(info.get('data', ''))[:8]}",
                    target="dc-01",
                    relation="can_authenticate_to",
                    technique="T1078",
                    description="Valid credentials found"
                )
        
        # Attack path'leri hesapla
        self._calculate_attack_paths()
        
        # Graph data döndür
        return self.export_graph()
    
    def _get_mitre_technique(self, vuln_type: str) -> str:
        """Vulnerability type'ından MITRE ATT&CK technique alır"""
        techniques = {
            "rce": "T1059",
            "remote code execution": "T1059",
            "sql injection": "T1190",
            "xss": "T1190",
            "lfi": "T1190",
            "rfi": "T1190",
            "ssrf": "T1190",
            "command injection": "T1059",
            "file upload": "T1108",
            "authentication bypass": "T1078",
            "default credentials": "T1078",
            "weak password": "T1110",
            "brute force": "T1110",
            "privilege escalation": "T1068",
            "path traversal": "T1190",
        }
        
        vuln_lower = vuln_type.lower()
        for key, value in techniques.items():
            if key in vuln_lower:
                return value
        
        return "T1190"  # Default: External Remote Services
    
    def _calculate_attack_paths(self):
        """Graph'ten attack path'leri hesaplar"""
        
        # Kritik node'ları bul
        critical_nodes = [
            nid for nid, node in self.nodes.items()
            if node.severity == "critical" and node.type != "domain_controller"
        ]
        
        # Her kritik node için path oluştur
        for node_id in critical_nodes:
            node = self.nodes[node_id]
            
            path = AttackPath(
                nodes=["entry", node_id, "dc-01"],
                edges=[f"entry->{node_id}", f"{node_id}->dc-01"],
                total_score=100 if node.severity == "critical" else 75,
                description=f"Exploit {node.label} to gain initial access, then move to DC",
                techniques=[self._get_mitre_technique(node.vulns[0] if node.vulns else "")],
                mitigations=[f"Patch {node.label}", "Enable WAF", "Implement input validation"]
            )
            
            self.attack_paths.append(path)
        
        # Credential-based path
        cred_nodes = [
            nid for nid, node in self.nodes.items()
            if node.type == "credential" and node.compromised
        ]
        
        if cred_nodes:
            path = AttackPath(
                nodes=cred_nodes + ["dc-01"],
                edges=[f"{n}->dc-01" for n in cred_nodes],
                total_score=150,
                description="Use compromised credentials to authenticate to Domain Controller",
                techniques=["T1078", "T1021"],
                mitigations=["Rotate credentials", "Enable MFA", "Monitor logins"]
            )
            self.attack_paths.append(path)
        
        # Path'leri score'a göre sırala
        self.attack_paths.sort(key=lambda x: x.total_score, reverse=True)
    
    def get_llm_analysis(self) -> str:
        """
        LLM kullanarak graph analizi ve öneriler üretir.
        """
        graph_summary = {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "critical_nodes": sum(1 for n in self.nodes.values() if n.severity == "critical"),
            "node_types": list(set(n.type for n in self.nodes.values())),
            "attack_paths": len(self.attack_paths)
        }
        
        prompt = f"""
        Bir siber güvenlik uzmanı olarak bu Active Directory ortamının 
        saldırı haritasını analiz et ve önerilerde bulun.
        
        Graph Özeti:
        - Toplam Node: {graph_summary['nodes']}
        - Toplam Edge: {graph_summary['edges']}  
        - Kritik Bulunabilirlik: {graph_summary['critical_nodes']}
        - Node Tipleri: {', '.join(graph_summary['node_types'])}
        - Potansiyel Saldırı Yolları: {graph_summary['attack_paths']}
        
        Mevcut Saldırı Yolları:
        """
        
        for i, path in enumerate(self.attack_paths[:3], 1):
            prompt += f"\n{i}. {path.description} (Skor: {path.total_score})"
        
        prompt += """
        
        Lütfen şunları sağla:
        1. En kritik saldırı yolunun açıklaması
        2. Bu yolun neden etkili olduğu
        3. MITRE ATT&CK teknikleri
        4. Alınması gereken önlemler
        5. Sonraki adımlar
        
        Türkçe yanıt ver, teknik ve detaylı ol.
        """
        
        try:
            return analyze_with_llm(prompt)
        except Exception as e:
            return f"LLM analizi başarısız: {str(e)}. Manuel inceleme önerilir."
    
    def export_graph(self) -> Dict:
        """
        Graph'i frontend için JSON formatında döndürür.
        """
        # Nodes'u listeye çevir
        nodes_list = []
        for node_id, node in self.nodes.items():
            node_dict = {
                "id": node.id,
                "label": node.label,
                "type": node.type,
                "os": node.os,
                "services": node.services,
                "vulnerabilities": node.vulns,
                "severity": node.severity,
                "compromised": node.compromised,
                "color": self._get_node_color(node)
            }
            nodes_list.append(node_dict)
        
        # Edges'i listeye çevir
        edges_list = []
        for edge in self.edges:
            edge_dict = {
                "from": edge.source,
                "to": edge.target,
                "relation": edge.relation,
                "technique": edge.technique,
                "description": edge.description,
                "color": self._get_edge_color(edge.relation)
            }
            edges_list.append(edge_dict)
        
        # Attack paths
        paths_list = []
        for path in self.attack_paths:
            path_dict = {
                "nodes": path.nodes,
                "edges": path.edges,
                "score": path.total_score,
                "description": path.description,
                "techniques": path.techniques,
                "mitigations": path.mitigations
            }
            paths_list.append(path_dict)
        
        return {
            "nodes": nodes_list,
            "edges": edges_list,
            "attack_paths": paths_list,
            "llm_analysis": self.get_llm_analysis(),
            "summary": {
                "total_nodes": len(nodes_list),
                "total_edges": len(edges_list),
                "critical_paths": len([p for p in paths_list if p["score"] > 100]),
                "total_risk_score": sum(p["score"] for p in paths_list)
            }
        }
    
    def _get_node_color(self, node: GraphNode) -> str:
        """Node severity'sine göre renk döndürür"""
        colors = {
            "critical": "#ff0000",
            "high": "#ff6600",
            "medium": "#ffcc00",
            "low": "#00cc00"
        }
        return colors.get(node.severity, "#666666")
    
    def _get_edge_color(self, relation: str) -> str:
        """Edge relation'ına göre renk döndürür"""
        colors = {
            "trusts": "#ff0000",
            "admin_to": "#ff0000",
            "has_service": "#00aaff",
            "has_vulnerability": "#ff6600",
            "runs": "#00cc00",
            "can_authenticate_to": "#ff0000"
        }
        return colors.get(relation, "#666666")
    
    def load_from_db(self, scan_id: int) -> Dict:
        """
        Veritabanından scan verilerini yükler ve graph oluşturur.
        """
        try:
            from cyberapp.models.db import db_conn
            
            with db_conn() as conn:
                # Vulns
                vulns = conn.execute(
                    "SELECT type, url, fix FROM vulns WHERE scan_id = ?",
                    (scan_id,)
                ).fetchall()
                
                # Techs
                techs = conn.execute(
                    "SELECT name, version, method FROM techno WHERE scan_id = ?",
                    (scan_id,)
                ).fetchall()
                
                # Intel
                intel = conn.execute(
                    "SELECT type, data FROM intel WHERE scan_id = ?",
                    (scan_id,)
                ).fetchall()
            
            scan_data = {
                "target": "domain-controller",
                "vulnerabilities": [
                    {"type": v[0], "url": v[1], "fix": v[2]}
                    for v in vulns
                ],
                "technologies": [
                    {"name": t[0], "version": t[1], "method": t[2]}
                    for t in techs
                ],
                "intel": [
                    {"type": i[0], "data": i[1]}
                    for i in intel
                ]
            }
            
            return self.generate_from_scan_data(scan_data)
            
        except Exception as e:
            return {
                "error": str(e),
                "nodes": [],
                "edges": [],
                "attack_paths": []
            }
