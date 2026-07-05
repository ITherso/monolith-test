"""
Purple Team Validator PRO Enhancement Module
=============================================
EDR-specific detection heatmap, AI weakness analysis, encrypted PDF reports

This module extends purple_team_validator.py with PRO features.
"""

import json
import hashlib
import base64
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class EDRVendor(Enum):
    """EDR vendors for detection analysis"""
    DEFENDER = "Microsoft Defender"
    CROWDSTRIKE = "CrowdStrike Falcon"
    SENTINELONE = "SentinelOne"
    CARBON_BLACK = "VMware Carbon Black"
    CORTEX_XDR = "Palo Alto Cortex XDR"
    ELASTIC = "Elastic Security"
    SPLUNK = "Splunk Enterprise Security"


@dataclass
class DetectionResult:
    """Detection result for a technique"""
    technique_id: str
    technique_name: str
    edr_vendor: EDRVendor
    detected: bool
    detection_time: Optional[float]  # seconds
    alert_severity: str
    confidence: float  # 0-1
    artifacts_found: List[str]
    false_positive: bool = False


class EDRDetectionHeatmap:
    """Generate EDR-specific detection heatmaps"""
    
    def __init__(self):
        self.detection_matrix = {}
        
        # EDR-specific detection capabilities
        self.edr_capabilities = {
            EDRVendor.DEFENDER: {
                "strong": ["process_injection", "credential_dumping", "powershell"],
                "moderate": ["lateral_movement", "persistence"],
                "weak": ["living_off_land", "fileless"]
            },
            EDRVendor.CROWDSTRIKE: {
                "strong": ["behavioral_analysis", "process_injection", "lateral_movement"],
                "moderate": ["credential_dumping", "persistence"],
                "weak": ["signed_binary_proxy"]
            },
            EDRVendor.SENTINELONE: {
                "strong": ["behavioral_analysis", "ransomware", "process_injection"],
                "moderate": ["credential_access", "defense_evasion"],
                "weak": ["living_off_land"]
            },
            EDRVendor.CARBON_BLACK: {
                "strong": ["process_monitoring", "file_integrity"],
                "moderate": ["network_monitoring", "credential_access"],
                "weak": ["memory_only", "cloud_attacks"]
            },
            EDRVendor.ELASTIC: {
                "strong": ["eql_queries", "ml_anomaly", "osquery"],
                "moderate": ["process_monitoring", "network_analysis"],
                "weak": ["advanced_evasion", "kernel_exploits"]
            }
        }
    
    def generate_heatmap(self, test_results: List[DetectionResult]) -> Dict[str, Any]:
        """Generate EDR-specific detection heatmap"""
        
        # Group by EDR vendor and technique
        heatmap_data = {}
        
        for result in test_results:
            vendor = result.edr_vendor.value
            technique = result.technique_id
            
            if vendor not in heatmap_data:
                heatmap_data[vendor] = {}
            
            if technique not in heatmap_data[vendor]:
                heatmap_data[vendor][technique] = {
                    "technique_name": result.technique_name,
                    "detected": 0,
                    "evaded": 0,
                    "total": 0,
                    "avg_detection_time": 0,
                    "confidence": 0
                }
            
            entry = heatmap_data[vendor][technique]
            entry["total"] += 1
            
            if result.detected:
                entry["detected"] += 1
                if result.detection_time:
                    entry["avg_detection_time"] += result.detection_time
            else:
                entry["evaded"] += 1
            
            entry["confidence"] += result.confidence
        
        # Calculate percentages and averages
        for vendor in heatmap_data:
            for technique in heatmap_data[vendor]:
                entry = heatmap_data[vendor][technique]
                total = entry["total"]
                
                entry["detection_rate"] = (entry["detected"] / total) * 100 if total > 0 else 0
                entry["evasion_rate"] = (entry["evaded"] / total) * 100 if total > 0 else 0
                entry["avg_detection_time"] = entry["avg_detection_time"] / entry["detected"] if entry["detected"] > 0 else 0
                entry["confidence"] = entry["confidence"] / total if total > 0 else 0
        
        return {
            "heatmap_data": heatmap_data,
            "summary": self._generate_summary(heatmap_data),
            "visualization": self._generate_html_heatmap(heatmap_data)
        }
    
    def _generate_summary(self, heatmap_data: Dict) -> Dict[str, Any]:
        """Generate summary statistics"""
        
        summary = {
            "total_vendors": len(heatmap_data),
            "total_techniques": 0,
            "overall_detection_rate": 0,
            "best_edr": None,
            "worst_edr": None,
            "most_detected_technique": None,
            "most_evaded_technique": None
        }
        
        vendor_scores = {}
        technique_detection = {}
        
        for vendor, techniques in heatmap_data.items():
            vendor_detected = 0
            vendor_total = 0
            
            for technique_id, data in techniques.items():
                vendor_detected += data["detected"]
                vendor_total += data["total"]
                
                if technique_id not in technique_detection:
                    technique_detection[technique_id] = {"detected": 0, "total": 0, "name": data["technique_name"]}
                
                technique_detection[technique_id]["detected"] += data["detected"]
                technique_detection[technique_id]["total"] += data["total"]
            
            vendor_scores[vendor] = (vendor_detected / vendor_total * 100) if vendor_total > 0 else 0
        
        if vendor_scores:
            summary["best_edr"] = max(vendor_scores, key=vendor_scores.get)
            summary["worst_edr"] = min(vendor_scores, key=vendor_scores.get)
        
        # Find most/least detected techniques
        if technique_detection:
            summary["most_detected_technique"] = max(
                technique_detection,
                key=lambda t: technique_detection[t]["detected"] / technique_detection[t]["total"]
            )
            summary["most_evaded_technique"] = min(
                technique_detection,
                key=lambda t: technique_detection[t]["detected"] / technique_detection[t]["total"]
            )
        
        summary["total_techniques"] = len(technique_detection)
        
        return summary
    
    def _generate_html_heatmap(self, heatmap_data: Dict) -> str:
        """Generate HTML visualization of heatmap"""
        
        html = """
        <div class="edr-heatmap">
            <style>
                .edr-heatmap { font-family: Arial, sans-serif; }
                .heatmap-table { border-collapse: collapse; width: 100%; margin: 20px 0; }
                .heatmap-table th, .heatmap-table td { border: 1px solid #ddd; padding: 12px; text-align: center; }
                .heatmap-table th { background-color: #2c3e50; color: white; }
                .detected-high { background-color: #e74c3c; color: white; }
                .detected-medium { background-color: #f39c12; }
                .detected-low { background-color: #27ae60; color: white; }
                .detected-none { background-color: #95a5a6; }
            </style>
            <h2>EDR Detection Heatmap</h2>
            <table class="heatmap-table">
                <thead>
                    <tr>
                        <th>Technique</th>
        """
        
        # Add vendor columns
        vendors = list(heatmap_data.keys())
        for vendor in vendors:
            html += f"<th>{vendor}</th>"
        
        html += "</tr></thead><tbody>"
        
        # Collect all unique techniques
        all_techniques = set()
        for vendor_data in heatmap_data.values():
            all_techniques.update(vendor_data.keys())
        
        # Add rows for each technique
        for technique in sorted(all_techniques):
            html += f"<tr><td><strong>{technique}</strong></td>"
            
            for vendor in vendors:
                if technique in heatmap_data[vendor]:
                    data = heatmap_data[vendor][technique]
                    detection_rate = data["detection_rate"]
                    
                    # Color coding
                    if detection_rate >= 75:
                        css_class = "detected-high"
                    elif detection_rate >= 50:
                        css_class = "detected-medium"
                    elif detection_rate >= 25:
                        css_class = "detected-low"
                    else:
                        css_class = "detected-none"
                    
                    html += f'<td class="{css_class}">{detection_rate:.1f}%</td>'
                else:
                    html += '<td class="detected-none">N/A</td>'
            
            html += "</tr>"
        
        html += "</tbody></table></div>"
        
        return html
    
    def compare_edrs(self, test_results: List[DetectionResult]) -> Dict[str, Any]:
        """Compare EDR vendors side-by-side"""
        
        comparison = {}
        
        for result in test_results:
            vendor = result.edr_vendor.value
            
            if vendor not in comparison:
                comparison[vendor] = {
                    "total_tests": 0,
                    "detected": 0,
                    "evaded": 0,
                    "false_positives": 0,
                    "avg_detection_time": 0,
                    "detection_times": []
                }
            
            entry = comparison[vendor]
            entry["total_tests"] += 1
            
            if result.detected:
                entry["detected"] += 1
                if result.detection_time:
                    entry["detection_times"].append(result.detection_time)
            else:
                entry["evaded"] += 1
            
            if result.false_positive:
                entry["false_positives"] += 1
        
        # Calculate metrics
        for vendor, data in comparison.items():
            if data["total_tests"] > 0:
                data["detection_rate"] = (data["detected"] / data["total_tests"]) * 100
                data["evasion_rate"] = (data["evaded"] / data["total_tests"]) * 100
                data["false_positive_rate"] = (data["false_positives"] / data["total_tests"]) * 100
            
            if data["detection_times"]:
                data["avg_detection_time"] = sum(data["detection_times"]) / len(data["detection_times"])
            
            del data["detection_times"]  # Remove raw data
        
        return {
            "comparison": comparison,
            "winner": max(comparison, key=lambda v: comparison[v]["detection_rate"]) if comparison else None
        }


class AIWeaknessAnalyzer:
    """AI-powered weakness analysis and recommendations"""
    
    def __init__(self):
        try:
            from cybermodules.llm_engine import LLMEngine
            self.llm = LLMEngine(scan_id="purple_team_weakness")
            self.has_ai = True
        except:
            self.llm = None
            self.has_ai = False
    
    def analyze_defensive_gaps(self, test_results: List[DetectionResult], environment: Dict[str, Any]) -> Dict[str, Any]:
        """Use AI to analyze defensive gaps and provide recommendations"""
        
        if not self.has_ai:
            return self._heuristic_analysis(test_results)
        
        # Prepare test summary
        evaded_techniques = [r for r in test_results if not r.detected]
        detected_techniques = [r for r in test_results if r.detected]
        
        summary = {
            "total_tests": len(test_results),
            "detected_count": len(detected_techniques),
            "evaded_count": len(evaded_techniques),
            "detection_rate": (len(detected_techniques) / len(test_results) * 100) if test_results else 0,
            "evaded_techniques": [{"id": r.technique_id, "name": r.technique_name} for r in evaded_techniques[:10]],
            "environment": environment
        }
        
        prompt = f"""Analyze this purple team validation and identify defensive weaknesses:

Test Results:
{json.dumps(summary, indent=2)}

Provide:
1. Top 5 critical defensive gaps
2. Specific EDR tuning recommendations
3. SIEM detection rules to implement
4. Security control improvements
5. Prioritized remediation roadmap

Output as JSON with keys: critical_gaps, edr_tuning, siem_rules, control_improvements, remediation_roadmap"""
        
        try:
            response = self.llm.query(prompt)
            analysis = json.loads(response)
            
            # Add AI confidence score
            analysis["ai_confidence"] = 0.85
            analysis["generated_at"] = datetime.now().isoformat()
            
            return analysis
        except Exception as e:
            return self._heuristic_analysis(test_results)
    
    def _heuristic_analysis(self, test_results: List[DetectionResult]) -> Dict[str, Any]:
        """Heuristic analysis when AI not available"""
        
        evaded = [r for r in test_results if not r.detected]
        
        gaps = []
        for result in evaded[:5]:
            gaps.append({
                "technique": result.technique_id,
                "name": result.technique_name,
                "severity": "high",
                "recommendation": f"Implement detection for {result.technique_name}"
            })
        
        return {
            "critical_gaps": gaps,
            "edr_tuning": ["Enable behavioral analysis", "Increase sensitivity"],
            "siem_rules": ["Create correlation rules for undetected techniques"],
            "control_improvements": ["Add endpoint monitoring", "Enhance logging"],
            "remediation_roadmap": [
                {"priority": 1, "action": "Address critical gaps"},
                {"priority": 2, "action": "Tune EDR policies"},
                {"priority": 3, "action": "Implement SIEM rules"}
            ]
        }
    
    def generate_blue_team_playbook(self, weaknesses: Dict[str, Any]) -> Dict[str, Any]:
        """Generate blue team playbook based on identified weaknesses"""
        
        if not self.has_ai:
            return {"error": "AI not available"}
        
        prompt = f"""Generate a blue team playbook for these defensive weaknesses:

{json.dumps(weaknesses, indent=2)}

Create:
1. Detection rules (Sigma/Yara/Snort)
2. Hunt queries (KQL/SPL/EQL)
3. Response procedures
4. Threat intelligence IOCs

Output as JSON with keys: detection_rules, hunt_queries, response_procedures, threat_intel"""
        
        try:
            response = self.llm.query(prompt)
            playbook = json.loads(response)
            return playbook
        except:
            return {"error": "Failed to generate playbook"}


class EncryptedPDFReportGenerator:
    """Generate encrypted PDF reports with executive and technical sections"""
    
    def __init__(self):
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen import canvas
            from reportlab.lib import colors
            from PyPDF2 import PdfWriter, PdfReader
            self.has_pdf_libs = True
        except ImportError:
            self.has_pdf_libs = False
    
    def generate_report(self, test_results: List[DetectionResult], analysis: Dict[str, Any],
                       password: str = None, executive_mode: bool = False) -> bytes:
        """Generate encrypted PDF report"""
        
        if not self.has_pdf_libs:
            return self._generate_html_fallback(test_results, analysis)
        
        import io
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas as pdf_canvas
        from reportlab.lib import colors
        from reportlab.lib.units import inch
        from PyPDF2 import PdfWriter, PdfReader
        
        # Create PDF in memory
        buffer = io.BytesIO()
        c = pdf_canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        
        # Title page
        c.setFont("Helvetica-Bold", 24)
        c.drawString(100, height - 100, "Purple Team Validation Report")
        
        c.setFont("Helvetica", 12)
        c.drawString(100, height - 130, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        c.drawString(100, height - 150, f"Classification: CONFIDENTIAL")
        
        if executive_mode:
            self._add_executive_summary(c, width, height, test_results, analysis)
        else:
            self._add_technical_details(c, width, height, test_results, analysis)
        
        c.save()
        
        # Encrypt PDF if password provided
        if password:
            buffer.seek(0)
            reader = PdfReader(buffer)
            writer = PdfWriter()
            
            for page in reader.pages:
                writer.add_page(page)
            
            # Encrypt with password
            writer.encrypt(password, algorithm="AES-256")
            
            encrypted_buffer = io.BytesIO()
            writer.write(encrypted_buffer)
            encrypted_buffer.seek(0)
            
            return encrypted_buffer.getvalue()
        else:
            buffer.seek(0)
            return buffer.getvalue()
    
    def _add_executive_summary(self, c, width, height, test_results, analysis):
        """Add executive summary page"""
        
        y_position = height - 200
        
        c.setFont("Helvetica-Bold", 16)
        c.drawString(100, y_position, "Executive Summary")
        y_position -= 30
        
        c.setFont("Helvetica", 12)
        
        total = len(test_results)
        detected = sum(1 for r in test_results if r.detected)
        detection_rate = (detected / total * 100) if total > 0 else 0
        
        c.drawString(100, y_position, f"Total Tests: {total}")
        y_position -= 20
        c.drawString(100, y_position, f"Detection Rate: {detection_rate:.1f}%")
        y_position -= 20
        c.drawString(100, y_position, f"Critical Gaps: {len(analysis.get('critical_gaps', []))}")
        
        c.showPage()
    
    def _add_technical_details(self, c, width, height, test_results, analysis):
        """Add technical details pages"""
        
        y_position = height - 200
        
        c.setFont("Helvetica-Bold", 14)
        c.drawString(100, y_position, "Technical Analysis")
        y_position -= 30
        
        c.setFont("Helvetica", 10)
        
        for result in test_results[:20]:  # First 20 results
            if y_position < 100:
                c.showPage()
                y_position = height - 50
            
            c.drawString(100, y_position, f"{result.technique_id}: {result.technique_name}")
            y_position -= 15
            c.drawString(120, y_position, f"Detected: {'Yes' if result.detected else 'No'} | EDR: {result.edr_vendor.value}")
            y_position -= 25
        
        c.showPage()
    
    def _generate_html_fallback(self, test_results, analysis) -> bytes:
        """Generate HTML report if PDF libraries not available"""
        
        html = f"""
        <html>
        <head><title>Purple Team Validation Report</title></head>
        <body>
        <h1>Purple Team Validation Report</h1>
        <p>Generated: {datetime.now()}</p>
        <h2>Summary</h2>
        <p>Total Tests: {len(test_results)}</p>
        <p>Detected: {sum(1 for r in test_results if r.detected)}</p>
        <h2>Results</h2>
        <ul>
        """
        
        for result in test_results:
            html += f"<li>{result.technique_id}: {'Detected' if result.detected else 'Evaded'}</li>"
        
        html += "</ul></body></html>"
        
        return html.encode()


def get_pro_engines():
    """Get all PRO enhancement engines"""
    return {
        "heatmap": EDRDetectionHeatmap(),
        "ai_weakness": AIWeaknessAnalyzer(),
        "pdf_report": EncryptedPDFReportGenerator()
    }
