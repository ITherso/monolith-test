"""
Auto-Report Generation Module
Professional Security Assessment Reports with Executive Summary
"""

import base64
import hashlib
import json
import os
import secrets
from datetime import datetime
from typing import Dict, List, Optional
import re

from fpdf import FPDF


class SecurityReportGenerator:
    """Professional Security Assessment Report Generator"""
    
    def __init__(self, scan_id: int, target: str):
        self.scan_id = scan_id
        self.target = target
        self.findings = []
        self.technologies = []
        self.intelligence = []
        self.risk_score = 0
        self.critical_count = 0
        self.high_count = 0
        self.medium_count = 0
        self.low_count = 0
        self.report_data = {}
        
    def gather_scan_data(self):
        """Scan verilerini topla"""
        from cyberapp.models.db import db_conn
        
        try:
            with db_conn() as conn:
                # Vulnerabilities
                vulns = conn.execute(
                    "SELECT * FROM vulns WHERE scan_id = ?", (self.scan_id,)
                ).fetchall()
                
                # Technologies
                techs = conn.execute(
                    "SELECT * FROM techno WHERE scan_id = ?", (self.scan_id,)
                ).fetchall()
                
                # Intelligence
                intel = conn.execute(
                    "SELECT * FROM intel WHERE scan_id = ?", (self.scan_id,)
                ).fetchall()
                
                # Scan info
                scan = conn.execute(
                    "SELECT * FROM scans WHERE id = ?", (self.scan_id,)
                ).fetchone()
                
                self.findings = self._process_vulnerabilities(vulns)
                self.technologies = self._process_technologies(techs)
                self.intelligence = self._process_intelligence(intel)
                self.scan_info = scan
                
                self._calculate_risk_scores()
                
        except Exception as e:
            print(f"[REPORT] Data gathering error: {e}")
            
    def _process_vulnerabilities(self, vulns: List) -> List[Dict]:
        """Process vulnerability data"""
        processed = []
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        
        for v in vulns:
            vuln = {
                'id': v[0],
                'type': v[2] if len(v) > 2 else 'Unknown',
                'url': v[3] if len(v) > 3 else '',
                'severity': self._determine_severity(v),
                'cvss': self._extract_cvss(v),
                'description': v[4] if len(v) > 4 else '',
                'remediation': self._generate_remediation(v),
                'cve': self._extract_cve(v),
                'impact': self._assess_impact(v)
            }
            processed.append(vuln)
            
        # Sort by severity
        processed.sort(key=lambda x: (severity_order.get(x['severity'], 5), x['type']))
        return processed
    
    def _determine_severity(self, vuln) -> str:
        """Determine vulnerability severity"""
        vuln_type = str(vuln[2]).upper() if len(vuln) > 2 else ''
        description = str(vuln[4]).upper() if len(vuln) > 4 else ''
        
        critical_patterns = ['SQL_INJECTION', 'RCE', 'GIZLI ANAHTAR', 'BACKDOOR', 'PRIVILEGE ESCALATION']
        high_patterns = ['XSS', 'LFI', 'FILE UPLOAD', 'AUTH BYPASS', 'IDOR']
        medium_patterns = ['INFORMATION DISCLOSURE', 'SENSITIVE DATA', 'MISSING HEADERS']
        low_patterns = ['INFO', 'DISCLOSURE', 'WARNING']
        
        for pattern in critical_patterns:
            if pattern in vuln_type or pattern in description:
                return 'CRITICAL'
        for pattern in high_patterns:
            if pattern in vuln_type or pattern in description:
                return 'HIGH'
        for pattern in medium_patterns:
            if pattern in vuln_type or pattern in description:
                return 'MEDIUM'
        for pattern in low_patterns:
            if pattern in vuln_type or pattern in description:
                return 'LOW'
                
        return 'MEDIUM'  # Default
    
    def _extract_cvss(self, vuln) -> float:
        """Extract CVSS score"""
        severity = self._determine_severity(vuln)
        cvss_map = {
            'CRITICAL': 9.0,
            'HIGH': 7.5,
            'MEDIUM': 5.0,
            'LOW': 2.5,
            'INFO': 0.0
        }
        return cvss_map.get(severity, 5.0)
    
    def _extract_cve(self, vuln) -> str:
        """Extract CVE if present"""
        description = str(vuln[4]) if len(vuln) > 4 else ''
        cve_match = re.search(r'CVE-\d{4}-\d{4,7}', description, re.IGNORECASE)
        return cve_match.group(0) if cve_match else 'N/A'
    
    def _generate_remediation(self, vuln) -> str:
        """Generate remediation advice"""
        vuln_type = str(vuln[2]).upper() if len(vuln) > 2 else ''
        
        remediation_map = {
            'SQL_INJECTION': 'Use parameterized queries, input validation, ORM frameworks, WAF deployment',
            'XSS': 'Implement CSP headers, input sanitization, output encoding, DOM-based XSS protection',
            'RCE': 'Avoid system() calls, use safe APIs, restrict command execution, apply patches',
            'LFI': 'Validate file paths, use whitelists, disable allow_url_fopen, chroot jail',
            'AUTHENTICATION': 'Implement MFA, rate limiting, secure session management, password hashing',
            'DEFAULT_CREDENTIALS': 'Change default passwords, implement credential policy, audit accounts',
            'INFORMATION_DISCLOSURE': 'Remove server banners, disable debug mode, secure error handling'
        }
        
        for key, advice in remediation_map.items():
            if key in vuln_type:
                return advice
        return 'Apply security patches, review security headers, implement defense in depth'
    
    def _assess_impact(self, vuln) -> str:
        """Assess business impact"""
        severity = self._determine_severity(vuln)
        
        impact_map = {
            'CRITICAL': 'Complete system compromise, data breach, regulatory non-compliance, reputational damage',
            'HIGH': 'Partial system access, data theft risk, service disruption, compliance violations',
            'MEDIUM': 'Limited information exposure, increased attack surface, partial functionality risk',
            'LOW': 'Minor information disclosure, minimal business impact, low priority remediation',
            'INFO': 'Informational findings, best practice deviations, low priority'
        }
        return impact_map.get(severity, 'Assessment required')
    
    def _process_technologies(self, techs: List) -> List[Dict]:
        """Process technology stack data"""
        processed = []
        for t in techs:
            tech = {
                'name': t[2] if len(t) > 2 else 'Unknown',
                'version': t[3] if len(t) > 3 else '',
                'category': self._categorize_tech(t[2] if len(t) > 2 else ''),
                'risk_level': self._assess_tech_risk(t)
            }
            processed.append(tech)
        return processed
    
    def _categorize_tech(self, tech_name: str) -> str:
        """Categorize technology"""
        name = tech_name.lower()
        
        if any(x in name for x in ['apache', 'nginx', 'iis', 'caddy']):
            return 'Web Server'
        elif any(x in name for x in ['php', 'python', 'ruby', 'node', 'java', 'asp.net']):
            return 'Application Framework'
        elif any(x in name for x in ['wordpress', 'django', 'rails', 'laravel', 'spring']):
            return 'CMS/Framework'
        elif any(x in name for x in ['mysql', 'postgresql', 'mongodb', 'redis', 'oracle']):
            return 'Database'
        elif any(x in name for x in ['jquery', 'bootstrap', 'react', 'vue', 'angular']):
            return 'JavaScript Library'
        elif any(x in name for x in ['cloudflare', 'aws', 'azure', 'gcp']):
            return 'Cloud Service'
        else:
            return 'Other'
    
    def _assess_tech_risk(self, tech) -> str:
        """Assess technology risk"""
        name = str(tech[2]).lower() if len(tech) > 2 else ''
        version = str(tech[3]).lower() if len(tech) > 3 else ''
        
        # Check for outdated versions
        outdated_indicators = ['2000', '2005', '2008', '2010', '2012', '2014', '2016', '1.0', '2.0', '3.0']
        
        if any(x in version for x in outdated_indicators):
            return 'HIGH - Potentially outdated'
        elif any(x in name for x in ['apache', 'nginx', 'openssl', 'php', 'wordpress']):
            return 'MEDIUM - Requires version verification'
        return 'LOW - Standard technology'
    
    def _process_intelligence(self, intel: List) -> List[Dict]:
        """Process intelligence data"""
        processed = []
        for i in intel:
            item = {
                'type': i[2] if len(i) > 2 else 'Unknown',
                'data': i[3] if len(i) > 3 else '',
                'timestamp': i[4] if len(i) > 4 else ''
            }
            processed.append(item)
        return processed
    
    def _calculate_risk_scores(self):
        """Calculate overall risk scores"""
        for finding in self.findings:
            severity = finding['severity']
            if severity == 'CRITICAL':
                self.critical_count += 1
                self.risk_score += 10
            elif severity == 'HIGH':
                self.high_count += 1
                self.risk_score += 7
            elif severity == 'MEDIUM':
                self.medium_count += 1
                self.risk_score += 4
            elif severity == 'LOW':
                self.low_count += 1
                self.risk_score += 1
        
        # Normalize to 100
        self.risk_score = min(100, self.risk_score)
        
    def generate_executive_summary(self) -> Dict:
        """Generate executive summary"""
        return {
            'scan_id': self.scan_id,
            'target': self.target,
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M'),
            'overall_risk': self._get_risk_label(),
            'risk_score': self.risk_score,
            'summary': self._generate_narrative_summary(),
            'key_findings': self._get_key_findings(),
            'statistics': {
                'critical': self.critical_count,
                'high': self.high_count,
                'medium': self.medium_count,
                'low': self.low_count,
                'total': len(self.findings)
            },
            'attack_narrative': self._generate_attack_narrative(),
            'recommendations': self._get_prioritized_recommendations()
        }
    
    def _get_risk_label(self) -> str:
        """Get risk label"""
        if self.risk_score >= 80:
            return 'CRITICAL'
        elif self.risk_score >= 60:
            return 'HIGH'
        elif self.risk_score >= 40:
            return 'MEDIUM'
        elif self.risk_score >= 20:
            return 'LOW'
        return 'MINIMAL'
    
    def _generate_narrative_summary(self) -> str:
        """Generate narrative executive summary"""
        total = len(self.findings)
        
        if total == 0:
            return f"Security assessment of {self.target} revealed no critical vulnerabilities. Standard security best practices were followed during the assessment."
        
        narrative = f"Security assessment of {self.target} identified {total} security findings requiring attention. "
        
        if self.critical_count > 0:
            narrative += f"CRITICAL ALERT: {self.critical_count} critical vulnerability(ies) were detected that could lead to complete system compromise. "
        
        if self.high_count > 0:
            narrative += f"High severity issues ({self.high_count} findings) indicate significant security gaps that should be addressed immediately. "
        
        narrative += f"The assessment revealed a risk score of {self.risk_score}/100, classified as {self._get_risk_label()} risk. "
        
        if self.technologies:
            tech_summary = ", ".join([t['name'] for t in self.technologies[:5]])
            narrative += f"Technology stack identified includes: {tech_summary}. "
        
        return narrative
    
    def _get_key_findings(self) -> List[Dict]:
        """Get most important findings"""
        critical = [f for f in self.findings if f['severity'] == 'CRITICAL']
        high = [f for f in self.findings if f['severity'] == 'HIGH']
        
        key = critical[:3] + high[:2]
        return [{
            'type': f['type'],
            'severity': f['severity'],
            'cvss': f['cvss'],
            'summary': f['description'][:150] + '...' if len(f['description']) > 150 else f['description']
        } for f in key]
    
    def _generate_attack_narrative(self) -> str:
        """Generate attack narrative - storytelling format"""
        if not self.findings:
            return "No attack paths identified during this assessment."
        
        narrative = "ATTACK NARRATIVE:\n\n"
        narrative += f"1. RECONNAISSANCE: Initial scanning of {self.target} revealed the technology stack and potential entry points.\n"
        
        if self.technologies:
            narrative += f"   - Discovered {len(self.technologies)} technology components\n"
            for tech in self.technologies[:3]:
                narrative += f"   - {tech['name']} ({tech['category']})\n"
        
        attack_path = []
        
        for finding in self.findings[:5]:
            if finding['severity'] in ['CRITICAL', 'HIGH']:
                attack_path.append(f"2. EXPLOITATION: Attempted exploitation of {finding['type']} vulnerability")
                attack_path.append(f"   - CVSS Score: {finding['cvss']}")
                attack_path.append(f"   - Impact: {finding['impact']}")
                break
        
        if attack_path:
            narrative += "\n".join(attack_path)
        
        narrative += f"\n3. IMPACT ASSESSMENT: Successful exploitation could result in {self.findings[0]['impact'] if self.findings else 'system compromise'}.\n"
        
        if self.critical_count > 0 or self.high_count > 0:
            narrative += f"\n4. RECOMMENDED MITIGATION: Immediate remediation required for {self.critical_count + self.high_count} high/critical findings.\n"
        
        return narrative
    
    def _get_prioritized_recommendations(self) -> List[Dict]:
        """Get prioritized recommendations"""
        recommendations = []
        
        # Group by severity
        for finding in self.findings:
            rec = {
                'priority': finding['severity'],
                'title': f"Fix: {finding['type']}",
                'description': finding['remediation'],
                'impact': finding['impact']
            }
            recommendations.append(rec)
        
        # Sort by priority
        priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        recommendations.sort(key=lambda x: priority_order.get(x['priority'], 5))
        
        return recommendations[:10]
    
    def generate_full_report(self) -> str:
        """Generate complete HTML report"""
        self.gather_scan_data()
        summary = self.generate_executive_summary()
        
        report_html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Assessment Report - {self.target}</title>
    <style>
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; padding: 40px; background: #0a0a12; color: #e0e0e0; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ text-align: center; padding: 40px; background: linear-gradient(135deg, #0a0a12 0%, #1a1a2e 100%); border-radius: 15px; margin-bottom: 30px; border: 1px solid rgba(0,255,136,0.3); }}
        .logo {{ font-size: 2.5em; font-weight: bold; background: linear-gradient(135deg, #00ff88, #00d4ff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .subtitle {{ color: #888; margin-top: 10px; }}
        .section {{ background: rgba(20, 20, 35, 0.9); border-radius: 15px; padding: 30px; margin-bottom: 25px; border: 1px solid rgba(255,255,255,0.1); }}
        .section-title {{ font-size: 1.5em; font-weight: 600; color: #00ff88; margin-bottom: 20px; display: flex; align-items: center; gap: 10px; }}
        .risk-score {{ display: flex; align-items: center; justify-content: center; gap: 20px; padding: 30px; background: rgba(0,0,0,0.3); border-radius: 15px; margin: 20px 0; }}
        .score-circle {{ width: 150px; height: 150px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 3em; font-weight: bold; border: 8px solid; }}
        .critical {{ border-color: #ff4757; color: #ff4757; }}
        .high {{ border-color: #ffa502; color: #ffa502; }}
        .medium {{ border-color: #eccc68; color: #eccc68; }}
        .low {{ border-color: #2ed573; color: #2ed573; }}
        .finding {{ background: rgba(0,0,0,0.3); border-radius: 10px; padding: 20px; margin-bottom: 15px; border-left: 4px solid; }}
        .finding.critical {{ border-color: #ff4757; }}
        .finding.high {{ border-color: #ffa502; }}
        .finding.medium {{ border-color: #eccc68; }}
        .finding.low {{ border-color: #2ed573; }}
        .severity-badge {{ display: inline-block; padding: 4px 12px; border-radius: 5px; font-weight: 600; font-size: 0.85em; }}
        .severity-badge.critical {{ background: rgba(255,71,87,0.2); color: #ff4757; }}
        .severity-badge.high {{ background: rgba(255,165,2,0.2); color: #ffa502; }}
        .severity-badge.medium {{ background: rgba(236,204,104,0.2); color: #eccc68; }}
        .severity-badge.low {{ background: rgba(46,213,115,0.2); color: #2ed573; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: rgba(0,0,0,0.3); padding: 25px; border-radius: 10px; text-align: center; }}
        .stat-number {{ font-size: 2.5em; font-weight: bold; color: #00ff88; }}
        .stat-label {{ color: #888; margin-top: 5px; }}
        .narrative {{ background: rgba(0,0,0,0.3); padding: 25px; border-radius: 10px; white-space: pre-line; line-height: 1.8; }}
        .remediation {{ background: rgba(255,165,2,0.1); border: 1px solid rgba(255,165,2,0.3); border-radius: 10px; padding: 20px; margin: 10px 0; }}
        .remediation.critical {{ background: rgba(255,71,87,0.1); border-color: rgba(255,71,87,0.3); }}
        .tech-tag {{ display: inline-block; background: rgba(0,212,255,0.2); color: #00d4ff; padding: 5px 12px; border-radius: 20px; margin: 5px; font-size: 0.9em; }}
        .timeline {{ border-left: 3px solid #00ff88; padding-left: 25px; margin: 20px 0; }}
        .timeline-item {{ position: relative; padding-bottom: 25px; }}
        .timeline-item::before {{ content: ''; position: absolute; left: -31px; top: 5px; width: 12px; height: 12px; border-radius: 50%; background: #00ff88; }}
        .footer {{ text-align: center; padding: 30px; color: #666; font-size: 0.9em; margin-top: 40px; border-top: 1px solid rgba(255,255,255,0.1); }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🛡️ MONOLITH SECURITY ASSESSMENT</div>
            <div class="subtitle">Executive Security Report</div>
        </div>
        
        <div class="section">
            <div class="section-title">📋 EXECUTIVE SUMMARY</div>
            
            <div class="risk-score">
                <div class="score-circle {'critical' if self.risk_score >= 80 else 'high' if self.risk_score >= 60 else 'medium' if self.risk_score >= 40 else 'low'}">
                    {self.risk_score}
                </div>
                <div>
                    <div style="font-size: 1.5em; font-weight: bold;">{self._get_risk_label()} RISK</div>
                    <div style="color: #888;">Overall Security Posture Score</div>
                    <div style="margin-top: 15px; color: #00ff88;">Target: {self.target}</div>
                    <div style="color: #888;">Scan ID: #{self.scan_id}</div>
                </div>
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number" style="color: #ff4757;">{self.critical_count}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" style="color: #ffa502;">{self.high_count}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" style="color: #eccc68;">{self.medium_count}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" style="color: #2ed573;">{self.low_count}</div>
                    <div class="stat-label">Low</div>
                </div>
            </div>
            
            <p style="font-size: 1.1em; line-height: 1.8; margin-top: 20px;">{summary['summary']}</p>
        </div>
        
        <div class="section">
            <div class="section-title">🎯 ATTACK NARRATIVE</div>
            <div class="narrative">{summary['attack_narrative']}</div>
        </div>
        
        <div class="section">
            <div class="section-title">🔍 KEY FINDINGS</div>
            {self._generate_findings_html()}
        </div>
        
        <div class="section">
            <div class="section-title">💻 TECHNOLOGY STACK</div>
            <div style="margin: 20px 0;">
                {''.join([f'<span class="tech-tag">{t["name"]}</span>' for t in self.technologies])}
            </div>
            {self._generate_tech_risk_html()}
        </div>
        
        <div class="section">
            <div class="section-title">🛠️ REMEDIATION ROADMAP</div>
            {self._generate_remediation_html()}
        </div>
        
        <div class="footer">
            <p>Generated by MONOLITH Security Assessment Platform</p>
            <p>Report ID: {secrets.token_hex(8)} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p style="margin-top: 15px; font-size: 0.8em;">This report is confidential and intended for authorized personnel only.</p>
        </div>
    </div>
</body>
</html>
"""
        return report_html
    
    def _generate_findings_html(self) -> str:
        """Generate findings HTML"""
        html = ""
        for finding in self.findings[:15]:  # Limit to 15 for readability
            html += f"""
            <div class="finding {finding['severity'].lower()}">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <span class="severity-badge {finding['severity'].lower()}">{finding['severity']}</span>
                    <span style="color: #888;">CVSS: {finding['cvss']}</span>
                </div>
                <div style="font-weight: 600; font-size: 1.1em; margin-bottom: 8px;">{finding['type']}</div>
                <div style="color: #aaa; margin-bottom: 10px;">{finding['description'][:300]}</div>
                <div style="font-size: 0.9em; color: #ff6b6b;">
                    <strong>Impact:</strong> {finding['impact']}
                </div>
            </div>
            """
        return html
    
    def _generate_tech_risk_html(self) -> str:
        """Generate technology risk assessment HTML"""
        if not self.technologies:
            return '<p style="color: #666;">No technology information detected.</p>'
        
        high_risk = [t for t in self.technologies if t['risk_level'].startswith('HIGH')]
        if high_risk:
            html = '<div style="color: #ffa502; margin-bottom: 15px;">⚠️ Potentially outdated components detected:</div>'
            for tech in high_risk:
                html += f'<div style="padding: 10px; background: rgba(255,165,2,0.1); border-radius: 5px; margin: 5px 0;">{tech["name"]} - {tech["risk_level"]}</div>'
            return html
        return '<p style="color: #2ed573;">✓ Technology stack appears to be standard and up-to-date</p>'
    
    def _generate_remediation_html(self) -> str:
        """Generate remediation HTML"""
        html = ""
        for rec in self._get_prioritized_recommendations()[:5]:
            html += f"""
            <div class="remediation {rec['priority'].lower()}">
                <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                    <span class="severity-badge {rec['priority'].lower()}">{rec['priority']}</span>
                    <span style="font-weight: 600;">{rec['title']}</span>
                </div>
                <div style="color: #aaa; margin-bottom: 10px;">{rec['description']}</div>
            </div>
            """
        return html
    
    def save_report(self, output_dir: str = "/tmp") -> Dict:
        """Save report to files"""
        report_html = self.generate_full_report()
        
        # Generate hashes
        content_hash = hashlib.sha256(report_html.encode()).hexdigest()
        
        # Save HTML - sanitize target for safe filename (remove slashes and other invalid chars)
        safe_target = re.sub(r'[^\w\-.]', '_', str(self.target).replace('/', '_'))
        html_path = f"{output_dir}/report_{self.scan_id}_{safe_target}.html"
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(report_html)
        
        # Save JSON summary
        summary = self.generate_executive_summary()
        json_path = f"{output_dir}/report_{self.scan_id}_summary.json"
        with open(json_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        # Save PDF (simple version using PDFReport)
        try:
            from cybermodules.helpers import PDFReport, tr_fix
            pdf = PDFReport()
            pdf.add_page()
            
            pdf.chapter_title(f"Security Assessment Report - {self.target}", (0, 100, 0))
            
            pdf.set_font("Arial", "", 10)
            pdf.cell(0, 10, f"Scan ID: {self.scan_id}", ln=True)
            pdf.cell(0, 10, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}", ln=True)
            pdf.cell(0, 10, f"Risk Score: {self.risk_score}/100 ({self._get_risk_label()})", ln=True)
            pdf.ln(5)
            
            pdf.chapter_title("Executive Summary", (0, 150, 0))
            pdf.set_font("Arial", "", 9)
            summary_text = summary['summary'][:500]
            pdf.cell(0, 10, tr_fix(summary_text), ln=True)
            pdf.ln(5)
            
            pdf.chapter_title("Key Findings", (255, 0, 0))
            for finding in self.findings[:5]:
                pdf.set_font("Arial", "B", 9)
                pdf.cell(0, 8, f"[{finding['severity']}] {finding['type']} (CVSS: {finding['cvss']})", ln=True)
                pdf.set_font("Arial", "", 8)
                desc = finding['description'][:200]
                pdf.cell(0, 6, tr_fix(desc), ln=True)
                pdf.ln(3)
            
            pdf_path = f"{output_dir}/report_{self.scan_id}.pdf"
            pdf.output(pdf_path)
            pdf_result = pdf_path
        except Exception as e:
            print(f"[REPORT] PDF generation error: {e}")
            pdf_result = None
        
        return {
            'html_path': html_path,
            'json_path': json_path,
            'pdf_path': pdf_result,
            'content_hash': content_hash,
            'risk_score': self.risk_score,
            'finding_count': len(self.findings),
            'critical_count': self.critical_count,
            'high_count': self.high_count
        }


def generate_scan_report(scan_id: int) -> Dict:
    """Quick function to generate report for a scan"""
    from cyberapp.models.db import db_conn
    
    try:
        with db_conn() as conn:
            scan = conn.execute("SELECT target FROM scans WHERE id = ?", (scan_id,)).fetchone()
            target = scan[0] if scan else "Unknown"
    except:
        target = "Unknown"
    
    generator = SecurityReportGenerator(scan_id, target)
    return generator.save_report()
