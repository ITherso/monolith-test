# cybermodules/report_generator.py

"""
Geliştirilmiş Rapor Oluşturma Modülü
Kapsamlı Güvenlik Değerlendirme Raporları
"""

import base64
import hashlib
import json
import os
import secrets
import re
from datetime import datetime
from typing import Dict, List, Optional

from fpdf import FPDF


class DetailedSecurityReport:
    """Detaylı Güvenlik Değerlendirme Raporu Oluşturucu"""
    
    def __init__(self, scan_id: int, target: str):
        self.scan_id = scan_id
        self.target = target
        self.findings = []
        self.technologies = []
        self.intelligence = []
        self.vuln_summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        self.risk_score = 0
        self.execution_time = 0
        self.scan_date = ""
        
    def gather_scan_data(self):
        """Tüm tarama verilerini topla"""
        from cyberapp.models.db import db_conn
        
        try:
            with db_conn() as conn:
                # Tüm zafiyetleri getir
                vulns = conn.execute(
                    "SELECT * FROM vulns WHERE scan_id = ?", (self.scan_id,)
                ).fetchall()
                
                # Teknolojileri getir
                techs = conn.execute(
                    "SELECT * FROM techno WHERE scan_id = ?", (self.scan_id,)
                ).fetchall()
                
                # İstihbarat verilerini getir
                intel = conn.execute(
                    "SELECT * FROM intel WHERE scan_id = ?", (self.scan_id,)
                ).fetchall()
                
                # Tarama bilgilerini getir
                scan = conn.execute(
                    "SELECT * FROM scans WHERE id = ?", (self.scan_id,)
                ).fetchone()
                
                # Tool loglarını getir
                tool_logs = conn.execute(
                    "SELECT * FROM tool_logs WHERE scan_id = ?", (self.scan_id,)
                ).fetchall()
                
                self.scan_date = scan[2] if scan else datetime.now().isoformat()
                self.execution_time = self._extract_execution_time(intel)
                
                # Verileri işle
                self.findings = self._process_vulnerabilities(vulns)
                self.technologies = self._process_technologies(techs)
                self.intelligence = self._process_intelligence(intel)
                self.tool_logs = self._process_logs(tool_logs)
                
                self._calculate_risk_scores()
                
        except Exception as e:
            print(f"[REPORT] Data gathering error: {e}")
            
    def _extract_execution_time(self, intel: List) -> float:
        """İstihbarat verilerinden çalışma süresini çıkar"""
        for item in intel:
            if item[2] == 'EXECUTION_TIME':
                try:
                    text = item[3]
                    match = re.search(r'([\d.]+)', text)
                    if match:
                        return float(match.group(1))
                except:
                    pass
        return 0
    
    def _process_vulnerabilities(self, vulns: List) -> List[Dict]:
        """Zafiyet verilerini işle"""
        processed = []
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        
        for v in vulns:
            try:
                vuln = {
                    'id': v[0],
                    'type': v[2] if len(v) > 2 else 'Unknown',
                    'url': v[3] if len(v) > 3 else '',
                    'severity': self._determine_severity(v),
                    'cvss': self._calculate_cvss(v),
                    'description': v[4] if len(v) > 4 else '',
                    'remediation': self._get_remediation(v[2] if len(v) > 2 else ''),
                    'cve': self._extract_cve(v),
                    'impact': self._assess_impact(v),
                    'evidence': self._extract_evidence(v),
                    'affected': self._get_affected_component(v),
                }
                processed.append(vuln)
            except Exception as e:
                print(f"[REPORT] Error processing vuln: {e}")
        
        # Önceliğe göre sırala
        processed.sort(key=lambda x: (severity_order.get(x['severity'], 5), x['type']))
        return processed
    
    def _determine_severity(self, vuln) -> str:
        """Zafiyet ciddiyetini belirle"""
        vuln_type = str(vuln[2]).upper() if len(vuln) > 2 else ''
        description = str(vuln[4]).upper() if len(vuln) > 4 else ''
        
        # Pattern matching
        critical_patterns = [
            'SQL_INJECTION', 'RCE', 'GIZLI ANAHTAR', 'BACKDOOR', 
            'PRIVILEGE ESCALATION', 'COMMAND_INJECTION', 'CRITICAL'
        ]
        high_patterns = [
            'XSS', 'LFI', 'FILE UPLOAD', 'AUTH BYPASS', 'IDOR',
            'PATH_TRAVERSAL', 'HIGH'
        ]
        medium_patterns = [
            'INFORMATION DISCLOSURE', 'SENSITIVE DATA', 'MISSING_HEADERS',
            'DEBUG_ENABLED', 'SENSITIVE_FILE', 'OPEN_REDIRECT', 'SSRF'
        ]
        low_patterns = ['INFO', 'WARNING', 'NOTICE']
        
        for pattern in critical_patterns:
            if pattern in vuln_type or pattern in description:
                self.vuln_summary['critical'] += 1
                return 'CRITICAL'
        for pattern in high_patterns:
            if pattern in vuln_type or pattern in description:
                self.vuln_summary['high'] += 1
                return 'HIGH'
        for pattern in medium_patterns:
            if pattern in vuln_type or pattern in description:
                self.vuln_summary['medium'] += 1
                return 'MEDIUM'
        for pattern in low_patterns:
            if pattern in vuln_type or pattern in description:
                self.vuln_summary['low'] += 1
                return 'LOW'
        
        self.vuln_summary['info'] += 1
        return 'INFO'
    
    def _calculate_cvss(self, vuln) -> float:
        """CVSS puanı hesapla"""
        severity = self._determine_severity(vuln)
        cvss_map = {
            'CRITICAL': 9.0,
            'HIGH': 7.5,
            'MEDIUM': 5.0,
            'LOW': 3.0,
            'INFO': 0.0
        }
        return cvss_map.get(severity, 5.0)
    
    def _extract_cve(self, vuln) -> str:
        """CVE numarası çıkar"""
        description = str(vuln[4]) if len(vuln) > 4 else ''
        cve_match = re.search(r'CVE-\d{4}-\d{4,7}', description, re.IGNORECASE)
        return cve_match.group(0) if cve_match else 'N/A'
    
    def _extract_evidence(self, vuln) -> str:
        """Kanıt bilgisi çıkar"""
        description = str(vuln[4]) if len(vuln) > 4 else ''
        url = str(vuln[3]) if len(vuln) > 3 else ''
        
        evidence_parts = []
        if url:
            evidence_parts.append(f"URL: {url}")
        if description:
            # Uzun açıklamayı kısalt
            desc_short = description[:200] + "..." if len(description) > 200 else description
            evidence_parts.append(f"Detail: {desc_short}")
        
        return " | ".join(evidence_parts) if evidence_parts else 'See URL for details'
    
    def _get_affected_component(self, vuln) -> str:
        """Etkilenen bileşeni belirle"""
        vuln_type = str(vuln[2]).upper() if len(vuln) > 2 else ''
        url = str(vuln[3]) if len(vuln) > 3 else ''
        
        if 'SQL' in vuln_type:
            return "Database Layer"
        elif 'XSS' in vuln_type:
            return "Frontend / Output Encoding"
        elif 'COMMAND' in vuln_type:
            return "Operating System / Shell"
        elif 'FILE' in vuln_type:
            return "File System"
        elif 'HEADER' in vuln_type:
            return "HTTP Response Headers"
        elif 'AUTH' in vuln_type:
            return "Authentication System"
        
        # URL'den bileşen çıkar
        if '/admin' in url.lower():
            return "Administration Panel"
        elif '/login' in url.lower() or '/auth' in url.lower():
            return "Authentication Endpoint"
        elif '/api' in url.lower():
            return "API Endpoint"
        
        return "Web Application"
    
    def _get_remediation(self, vuln_type: str) -> str:
        """Düzeltme önerisi getir"""
        vuln_upper = vuln_type.upper()
        
        remediation_map = {
            'SQL_INJECTION': '''1. Prepared Statements kullanın
2. Stored Procedures tercih edin
3. Input validation ve sanitization uygulayın
4. ORM frameworkleri (SQLAlchemy, Hibernate) kullanın
5. WAF (Web Application Firewall) konuşlandırın''',
            
            'XSS': '''1. Content Security Policy (CSP) header'ı uygulayın
2. Output encoding kullanın
3. Input validation yapın
4. DOM-based XSS için güvenli API'ler tercih edin
5. HTTPOnly ve Secure flag'leri kullanın''',
            
            'COMMAND_INJECTION': '''1. system(), exec() gibi fonksiyonlardan kaçının
2. Command execution API'leri yerine safe API'ler kullanın
3. Input validation ve whitelisting uygulayın
4. Least privilege prensibi uygulayın''',
            
            'PATH_TRAVERSAL': '''1. File path validation yapın
2. Whitelist ile dosya yollarını kontrol edin
3. chroot jail kullanın
4. open_basedir directive'ini ayarlayın''',
            
            'SENSITIVE_FILE': '''1. Sensitive dosyaları web root dışına taşıyın
2. .git, .env gibi dosyaları .htaccess ile engelleyin
3. Düzenli güvenlik taraması yapın
4. Access control list'leri gözden geçirin''',
            
            'MISSING_HEADERS': '''1. X-Frame-Options: DENY veya SAMEORIGIN
2. Content-Security-Policy uygulayın
3. Strict-Transport-Security (HSTS) ayarlayın
4. X-Content-Type-Options: nosniff
5. Referrer-Policy ve Permissions-Policy ekleyin''',
            
            'DEBUG_ENABLED': '''1. Production ortamında debug modunu kapatın
2. display_errors = Off yapın
3. error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT
4. Custom error handler kullanın
5. Log dosyalarını güvenli konumda tutun''',
        }
        
        for key, advice in remediation_map.items():
            if key in vuln_upper:
                return advice
        
        return '''1. Security headers ekleyin
2. Input validation uygulayın
3. Least privilege prensibini uygulayın
4. Düzenli güvenlik taraması yapın
5. Güvenlik güncellemelerini uygulayın'''
    
    def _assess_impact(self, vuln) -> str:
        """İş etkisi değerlendirmesi"""
        severity = self._determine_severity(vuln)
        vuln_type = str(vuln[2]).upper() if len(vuln) > 2 else ''
        
        impact_map = {
            'CRITICAL': '''Sistem compromise riski yüksek
Veri sızıntısı potansiyeli mevcut
Regülasyon ihlali (GDPR, PCI-DSS)
İtibar kaybı ve finansal zarar''',
            
            'HIGH': '''Kısmi sistem erişimi riski
Veri çalınma potansiyeli
Hizmet kesintisi riski
Uyumluluk ihlalleri''',
            
            'MEDIUM': '''Sınırlı bilgi ifşası
Artırılmış saldırı yüzeyi
Kısmi fonksiyon riski''',
            
            'LOW': '''Küçük bilgi ifşası
Minimal iş etkisi
Düşük öncelikli düzeltme''',
            
            'INFO': '''Bilgilendirici bulgu
En iyi uygulama sapması
Düşük öncelik'''
        }
        
        type_impacts = {
            'SQL_INJECTION': 'Direct database access, potential data breach',
            'XSS': 'Session hijacking, credential theft, malware distribution',
            'COMMAND_INJECTION': 'System compromise, lateral movement',
            'PATH_TRAVERSAL': 'Sensitive file access, config leakage',
        }
        
        base_impact = impact_map.get(severity, 'Assessment required')
        
        if vuln_type in type_impacts:
            return f"{type_impacts[vuln_type]}\n\n{base_impact}"
        
        return base_impact
    
    def _process_technologies(self, techs: List) -> List[Dict]:
        """Teknoloji yığını verilerini işle"""
        processed = []
        for t in techs:
            try:
                tech = {
                    'name': t[2] if len(t) > 2 else 'Unknown',
                    'version': t[3] if len(t) > 3 else '',
                    'category': self._categorize_tech(t[2] if len(t) > 2 else ''),
                    'risk_level': self._assess_tech_risk(t),
                    'via': t[4] if len(t) > 4 else 'Unknown'
                }
                processed.append(tech)
            except Exception as e:
                print(f"[REPORT] Error processing tech: {e}")
        return processed
    
    def _categorize_tech(self, tech_name: str) -> str:
        """Teknoloji kategorisi belirle"""
        name = tech_name.lower()
        
        categories = {
            'Web Server': ['apache', 'nginx', 'iis', 'caddy', 'lighttpd'],
            'Application Framework': ['php', 'python', 'ruby', 'node', 'java', 'asp.net', 'go'],
            'CMS/Framework': ['wordpress', 'django', 'rails', 'laravel', 'spring', 'express'],
            'Database': ['mysql', 'postgresql', 'mongodb', 'redis', 'oracle', 'sqlite'],
            'JavaScript Library': ['jquery', 'bootstrap', 'react', 'vue', 'angular', 'lodash'],
            'Cloud Service': ['cloudflare', 'aws', 'azure', 'gcp', 'firebase'],
            'Operating System': ['linux', 'windows', 'unix', 'debian', 'ubuntu', 'centos']
        }
        
        for category, keywords in categories.items():
            if any(kw in name for kw in keywords):
                return category
        return 'Other'
    
    def _assess_tech_risk(self, tech) -> str:
        """Teknoloji risk değerlendirmesi"""
        name = str(tech[2]).lower() if len(tech) > 2 else ''
        version = str(tech[3]).lower() if len(tech) > 3 else ''
        
        # Eski sürüm göstergeleri
        outdated_indicators = ['2000', '2005', '2008', '2010', '2012', '2014', '2016', '1.0', '2.0', '3.0', '4.0', '5.0', '6.0', '7.0']
        
        if any(x in version for x in outdated_indicators):
            return 'HIGH - Potentially outdated version detected'
        elif any(x in name for x in ['php', 'wordpress', 'apache', 'nginx', 'openssl']):
            return 'MEDIUM - Verify latest version is installed'
        return 'LOW - Standard technology'
    
    def _process_intelligence(self, intel: List) -> List[Dict]:
        """İstihbarat verilerini işle"""
        processed = []
        for i in intel:
            try:
                item = {
                    'type': i[2] if len(i) > 2 else 'Unknown',
                    'data': i[3] if len(i) > 3 else '',
                    'timestamp': i[4] if len(i) > 4 else ''
                }
                processed.append(item)
            except:
                pass
        return processed
    
    def _process_logs(self, logs: List) -> List[Dict]:
        """Tool loglarını işle"""
        processed = []
        for log in logs:
            try:
                item = {
                    'tool': log[2] if len(log) > 2 else 'Unknown',
                    'output': log[3] if len(log) > 3 else '',
                    'timestamp': log[4] if len(log) > 4 else ''
                }
                processed.append(item)
            except:
                pass
        return processed
    
    def _calculate_risk_scores(self):
        """Risk skorlarını hesapla"""
        for finding in self.findings:
            severity = finding['severity']
            if severity == 'CRITICAL':
                self.risk_score += 10
            elif severity == 'HIGH':
                self.risk_score += 7
            elif severity == 'MEDIUM':
                self.risk_score += 4
            elif severity == 'LOW':
                self.risk_score += 2
            else:
                self.risk_score += 0.5
        
        # 100 ile sınırla
        self.risk_score = min(100, self.risk_score)
    
    def _get_risk_label(self) -> str:
        """Risk etiketi getir"""
        if self.risk_score >= 80:
            return 'CRITICAL'
        elif self.risk_score >= 60:
            return 'HIGH'
        elif self.risk_score >= 40:
            return 'MEDIUM'
        elif self.risk_score >= 20:
            return 'LOW'
        return 'MINIMAL'
    
    def generate_executive_summary(self) -> Dict:
        """Yönetici özeti oluştur"""
        total = len(self.findings)
        
        return {
            'scan_id': self.scan_id,
            'target': self.target,
            'scan_date': self.scan_date,
            'execution_time': f"{self.execution_time:.2f} seconds",
            'overall_risk': self._get_risk_label(),
            'risk_score': self.risk_score,
            'risk_color': self._get_risk_color(),
            'total_findings': total,
            'vulnerability_summary': self.vuln_summary,
            'technology_count': len(self.technologies),
            'summary': self._generate_narrative_summary(),
            'key_findings': self._get_key_findings(),
            'attack_narrative': self._generate_attack_narrative(),
            'recommendations': self._get_prioritized_recommendations(),
            'compliance_status': self._check_compliance()
        }
    
    def _get_risk_color(self) -> str:
        """Risk rengi getir"""
        if self.risk_score >= 80:
            return '#ff4757'  # Kırmızı
        elif self.risk_score >= 60:
            return '#ffa502'  # Turuncu
        elif self.risk_score >= 40:
            return '#eccc68'  # Sarı
        elif self.risk_score >= 20:
            return '#2ed573'  # Yeşil
        return '#1e90ff'  # Mavi
    
    def _generate_narrative_summary(self) -> str:
        """Anlatı özeti oluştur"""
        total = len(self.findings)
        critical = self.vuln_summary['critical']
        high = self.vuln_summary['high']
        
        if total == 0:
            return f"""Güvenlik değerlendirmesi, {self.target} hedefinde kritik güvenlik açığı tespit etmedi. 
Standart güvenlik en iyi uygulamaları takip edildi. Ancak, eksik güvenlik header'ları ve potansiyel iyileştirme alanları belirlendi."""
        
        summary = f"""Bu güvenlik değerlendirmesi, {self.target} hedefinde {total} adet güvenlik bulgusu tespit etti.
        
Tarama {self.execution_time:.2f} saniyede tamamlandı ve {len(self.technologies)} adet teknoloji bileşeni tespit edildi.

Önemli Bulgular:
- {critical} adet KRİTİK seviye açık tespit edildi
- {high} adet YÜKSEK seviye açık tespit edildi
- Genel risk skoru: {self.risk_score}/100 ({self._get_risk_label()})

Tespit edilen açıklar, sistem compromise'ü, veri sızıntısı ve regülasyon ihlalleri riski taşımaktadır.
Acil müdahale gerektiren bulgular önceliklendirilmiştir."""
        
        return summary
    
    def _get_key_findings(self) -> List[Dict]:
        """Önemli bulguları getir"""
        critical = [f for f in self.findings if f['severity'] == 'CRITICAL']
        high = [f for f in self.findings if f['severity'] == 'HIGH']
        
        key = critical[:3] + high[:2]
        return [{
            'type': f['type'],
            'severity': f['severity'],
            'cvss': f['cvss'],
            'url': f['url'],
            'impact': f['impact'][:100] + '...' if len(f['impact']) > 100 else f['impact']
        } for f in key]
    
    def _generate_attack_narrative(self) -> str:
        """Saldırı anlatısı oluştur"""
        if not self.findings:
            return "Bu değerlendirmede saldırı yolu tespit edilmedi."
        
        narrative = []
        narrative.append("SALDIRI ANLATISI")
        narrative.append("=" * 50)
        narrative.append(f"\n1. KEŞİF (Reconnaissance):\n")
        narrative.append(f"   - {self.target} hedefinde teknoloji yığını analizi yapıldı")
        narrative.append(f"   - Tespit edilen teknolojiler: {', '.join([t['name'] for t in self.technologies[:5]])}")
        
        # En ciddi bulguları al
        serious_findings = [f for f in self.findings if f['severity'] in ['CRITICAL', 'HIGH']]
        
        if serious_findings:
            narrative.append(f"\n2. SALDIRI AŞAMASI:\n")
            for i, finding in enumerate(serious_findings[:3], 1):
                narrative.append(f"   {i}. {finding['type']} açığı tespit edildi")
                narrative.append(f"      - Etkilenen bileşen: {finding['affected']}")
                narrative.append(f"      - CVSS Skoru: {finding['cvss']}")
        
        narrative.append(f"\n3. ETKİ DEĞERLENDİRMESİ:\n")
        if self.vuln_summary['critical'] > 0:
            narrative.append("   - Kritik sistem compromise riski mevcut")
        if self.vuln_summary['high'] > 0:
            narrative.append("   - Yüksek yetki kazanımı potansiyeli")
        
        narrative.append(f"\n4. ÖNERİLEN MİTİGASYON:\n")
        narrative.append("   - Kritik ve yüksek riskli bulgular önceliklendirilmeli")
        narrative.append("   - Defense in depth yaklaşımı uygulanmalı")
        narrative.append("   - Düzenli penetrasyon testleri planlanmalı")
        
        return '\n'.join(narrative)
    
    def _get_prioritized_recommendations(self) -> List[Dict]:
        """Önceliklendirilmiş öneriler"""
        recommendations = []
        
        for finding in self.findings:
            rec = {
                'priority': finding['severity'],
                'type': finding['type'],
                'title': f"Düzeltme: {finding['type']}",
                'description': finding['remediation'],
                'impact': finding['impact'][:150],
                'affected': finding['affected'],
                'cvss': finding['cvss']
            }
            recommendations.append(rec)
        
        # Öncelik sıralaması
        priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        recommendations.sort(key=lambda x: priority_order.get(x['priority'], 5))
        
        return recommendations[:15]  # İlk 15 öneriyi getir
    
    def _check_compliance(self) -> Dict:
        """Uyumluluk durumu kontrol et"""
        compliance = {
            'OWASP': self._check_owasp_compliance(),
            'PCI-DSS': self._check_pcidss_compliance(),
            'GDPR': self._check_gdpr_compliance()
        }
        return compliance
    
    def _check_owasp_compliance(self) -> Dict:
        """OWASP uyumluluğu kontrol et"""
        vuln_types = [f['type'].upper() for f in self.findings]
        
        owasp_categories = {
            'Injection': any('SQL' in v or 'COMMAND' in v for v in vuln_types),
            'Broken Auth': any('AUTH' in v for v in vuln_types),
            'XSS': any('XSS' in v for v in vuln_types),
            'Security Misconfig': any('HEADER' in v or 'DEBUG' in v for v in vuln_types),
            'Sensitive Data': any('SENSITIVE' in v or 'DISCLOSURE' in v for v in vuln_types),
        }
        
        return {
            'status': 'FAIL' if any(owasp_categories.values()) else 'PASS',
            'categories': owasp_categories,
            'score': f"{sum(owasp_categories.values())}/5 categories affected"
        }
    
    def _check_pcidss_compliance(self) -> Dict:
        """PCI-DSS uyumluluğu kontrol et"""
        has_critical = self.vuln_summary['critical'] > 0
        has_high = self.vuln_summary['high'] > 0
        has_ssl_issues = any('SSL' in i['type'].upper() or 'TLS' in i['type'].upper() for i in self.intelligence)
        
        return {
            'status': 'FAIL' if has_critical or has_high else 'WARNING',
            'issues': {
                'critical_vulnerabilities': has_critical,
                'high_risk_findings': has_high,
                'encryption_issues': has_ssl_issues
            },
            'recommendation': 'Immediate remediation required before processing cardholder data'
        }
    
    def _check_gdpr_compliance(self) -> Dict:
        """GDPR uyumluluğu kontrol et"""
        has_sensitive_data = any('SENSITIVE' in f['type'].upper() for f in self.findings)
        has_pii_exposure = any('DISCLOSURE' in f['type'].upper() for f in self.findings)
        
        return {
            'status': 'AT_RISK' if has_sensitive_data or has_pii_exposure else 'CHECK',
            'data_protection_concerns': has_sensitive_data or has_pii_exposure,
            'recommendation': 'Review data handling practices if personal data is processed'
        }
    
    def generate_html_report(self) -> str:
        """HTML raporu oluştur"""
        summary = self.generate_executive_summary()
        
        html = f"""
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Security Assessment Report - {self.target}</title>
    <style>
        :root {{
            --critical: #ff4757;
            --high: #ffa502;
            --medium: #eccc68;
            --low: #2ed573;
            --info: #70a1ff;
            --bg-dark: #0a0a12;
            --bg-card: rgba(20, 20, 35, 0.95);
            --text-primary: #ffffff;
            --text-secondary: #a0a0b0;
            --border: rgba(255,255,255,0.1);
        }}
        
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: linear-gradient(135deg, var(--bg-dark) 0%, #1a1a2e 100%);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }}
        
        .container {{ max-width: 1400px; margin: 0 auto; padding: 40px 20px; }}
        
        /* Header */
        .header {{
            text-align: center;
            padding: 40px;
            background: linear-gradient(135deg, rgba(0,255,136,0.1), rgba(0,212,255,0.1));
            border-radius: 20px;
            margin-bottom: 30px;
            border: 1px solid rgba(0,255,136,0.3);
        }}
        
        .header h1 {{
            font-size: 2.5em;
            background: linear-gradient(135deg, #00ff88, #00d4ff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        
        .header .meta {{
            color: var(--text-secondary);
            margin-top: 15px;
            font-size: 0.9em;
        }}
        
        /* Cards */
        .card {{
            background: var(--bg-card);
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 25px;
            border: 1px solid var(--border);
            backdrop-filter: blur(10px);
        }}
        
        .card-title {{
            font-size: 1.3em;
            color: #00ff88;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        /* Risk Score */
        .risk-section {{
            display: grid;
            grid-template-columns: 200px 1fr;
            gap: 30px;
            align-items: center;
        }}
        
        .score-circle {{
            width: 180px;
            height: 180px;
            border-radius: 50%;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            font-size: 3em;
            font-weight: bold;
            border: 8px solid;
            margin: 0 auto;
        }}
        
        .score-label {{
            font-size: 0.9em;
            margin-top: 5px;
            color: var(--text-secondary);
        }}
        
        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 15px;
            margin: 20px 0;
        }}
        
        .stat-card {{
            background: rgba(0,0,0,0.3);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            border: 1px solid var(--border);
        }}
        
        .stat-card.critical {{ border-color: var(--critical); }}
        .stat-card.high {{ border-color: var(--high); }}
        .stat-card.medium {{ border-color: var(--medium); }}
        .stat-card.low {{ border-color: var(--low); }}
        .stat-card.info {{ border-color: var(--info); }}
        
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
        }}
        
        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.85em;
        }}
        
        /* Findings */
        .finding {{
            background: rgba(0,0,0,0.3);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid;
        }}
        
        .finding.critical {{ border-color: var(--critical); }}
        .finding.high {{ border-color: var(--high); }}
        .finding.medium {{ border-color: var(--medium); }}
        .finding.low {{ border-color: var(--low); }}
        .finding.info {{ border-color: var(--info); }}
        
        .severity-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 5px;
            font-weight: 600;
            font-size: 0.8em;
            margin-bottom: 10px;
        }}
        
        .severity-badge.critical {{ background: rgba(255,71,87,0.2); color: var(--critical); }}
        .severity-badge.high {{ background: rgba(255,165,2,0.2); color: var(--high); }}
        .severity-badge.medium {{ background: rgba(236,204,104,0.2); color: var(--medium); }}
        .severity-badge.low {{ background: rgba(46,213,115,0.2); color: var(--low); }}
        
        .finding-title {{
            font-size: 1.1em;
            font-weight: 600;
            margin-bottom: 8px;
        }}
        
        .finding-meta {{
            color: var(--text-secondary);
            font-size: 0.85em;
            margin-bottom: 10px;
        }}
        
        .finding-description {{
            color: #ccc;
            margin-bottom: 10px;
        }}
        
        .finding-remediation {{
            background: rgba(255,165,2,0.1);
            border: 1px solid rgba(255,165,2,0.3);
            border-radius: 8px;
            padding: 15px;
            margin-top: 15px;
        }}
        
        .finding-remediation h4 {{
            color: var(--high);
            margin-bottom: 10px;
            font-size: 0.9em;
        }}
        
        .finding-remediation ul {{
            margin-left: 20px;
            color: #ccc;
        }}
        
        .finding-remediation li {{
            margin-bottom: 5px;
        }}
        
        /* Technology Stack */
        .tech-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 15px;
        }}
        
        .tech-item {{
            background: rgba(0,212,255,0.1);
            border: 1px solid rgba(0,212,255,0.3);
            border-radius: 8px;
            padding: 15px;
            text-align: center;
        }}
        
        .tech-name {{
            color: #00d4ff;
            font-weight: 600;
        }}
        
        .tech-category {{
            color: var(--text-secondary);
            font-size: 0.8em;
            margin-top: 5px;
        }}
        
        /* Intelligence */
        .intel-item {{
            background: rgba(0,0,0,0.2);
            border-radius: 5px;
            padding: 10px 15px;
            margin-bottom: 10px;
            border-left: 3px solid #00ff88;
        }}
        
        .intel-type {{
            color: #00ff88;
            font-size: 0.8em;
            font-weight: 600;
        }}
        
        .intel-data {{
            color: #ccc;
            margin-top: 5px;
        }}
        
        /* Compliance */
        .compliance-grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
        }}
        
        .compliance-card {{
            background: rgba(0,0,0,0.3);
            border-radius: 10px;
            padding: 20px;
        }}
        
        .compliance-status {{
            font-size: 1.5em;
            font-weight: bold;
            margin: 10px 0;
        }}
        
        .compliance-status.pass {{ color: var(--low); }}
        .compliance-status.fail {{ color: var(--critical); }}
        .compliance-status.warning {{ color: var(--high); }}
        
        /* Footer */
        .footer {{
            text-align: center;
            padding: 30px;
            color: #666;
            margin-top: 40px;
            border-top: 1px solid var(--border);
        }}
        
        /* Print Styles */
        @media print {{
            body {{ background: white; color: black; }}
            .card {{ background: white; border: 1px solid #ccc; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>SECURITY ASSESSMENT REPORT</h1>
            <div class="meta">
                <p><strong>Target:</strong> {self.target}</p>
                <p><strong>Scan ID:</strong> #{self.scan_id}</p>
                <p><strong>Date:</strong> {self.scan_date}</p>
                <p><strong>Execution Time:</strong> {self.execution_time:.2f} seconds</p>
            </div>
        </div>
        
        <!-- Risk Score -->
        <div class="card">
            <h2 class="card-title">RISK ASSESSMENT</h2>
            <div class="risk-section">
                <div class="score-circle" style="border-color: {summary['risk_color']}; color: {summary['risk_color']};">
                    {self.risk_score}
                    <div class="score-label">{summary['overall_risk']}</div>
                </div>
                <div>
                    <h3>Executive Summary</h3>
                    <p style="color: #ccc; margin-top: 15px; line-height: 1.8;">{summary['summary']}</p>
                    
                    <div class="stats-grid">
                        <div class="stat-card critical">
                            <div class="stat-number" style="color: var(--critical);">{self.vuln_summary['critical']}</div>
                            <div class="stat-label">Critical</div>
                        </div>
                        <div class="stat-card high">
                            <div class="stat-number" style="color: var(--high);">{self.vuln_summary['high']}</div>
                            <div class="stat-label">High</div>
                        </div>
                        <div class="stat-card medium">
                            <div class="stat-number" style="color: var(--medium);">{self.vuln_summary['medium']}</div>
                            <div class="stat-label">Medium</div>
                        </div>
                        <div class="stat-card low">
                            <div class="stat-number" style="color: var(--low);">{self.vuln_summary['low']}</div>
                            <div class="stat-label">Low</div>
                        </div>
                        <div class="stat-card info">
                            <div class="stat-number" style="color: var(--info);">{self.vuln_summary['info']}</div>
                            <div class="stat-label">Info</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Key Findings -->
        <div class="card">
            <h2 class="card-title">KEY FINDINGS</h2>
            {self._generate_findings_html()}
        </div>
        
        <!-- Technology Stack -->
        <div class="card">
            <h2 class="card-title">TECHNOLOGY STACK ({len(self.technologies)} detected)</h2>
            {self._generate_tech_html()}
        </div>
        
        <!-- Attack Narrative -->
        <div class="card">
            <h2 class="card-title">ATTACK NARRATIVE</h2>
            <pre style="background: rgba(0,0,0,0.3); padding: 20px; border-radius: 10px; white-space: pre-wrap; color: #ccc; font-family: monospace;">{summary['attack_narrative']}</pre>
        </div>
        
        <!-- Intelligence -->
        <div class="card">
            <h2 class="card-title">SCAN INTELLIGENCE</h2>
            {self._generate_intel_html()}
        </div>
        
        <!-- Compliance -->
        <div class="card">
            <h2 class="card-title">COMPLIANCE STATUS</h2>
            {self._generate_compliance_html(summary['compliance_status'])}
        </div>
        
        <!-- Recommendations -->
        <div class="card">
            <h2 class="card-title">REMEDIATION ROADMAP</h2>
            {self._generate_remediation_html()}
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p>Generated by MONOLITH Security Assessment Platform</p>
            <p>Report ID: {secrets.token_hex(8)} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p style="margin-top: 10px; font-size: 0.8em;">This report is confidential and intended for authorized personnel only.</p>
        </div>
    </div>
</body>
</html>
"""
        return html
    
    def _generate_findings_html(self) -> str:
        """Bulgular HTML'i oluştur"""
        if not self.findings:
            return '<p style="color: #888;">No vulnerabilities detected.</p>'
        
        html = ""
        for finding in self.findings[:20]:  # Limit to 20 findings
            remediation_list = finding['remediation'].split('\n')
            
            html += f"""
            <div class="finding {finding['severity'].lower()}">
                <span class="severity-badge {finding['severity'].lower()}">{finding['severity']} (CVSS: {finding['cvss']})</span>
                
                <div class="finding-title">{finding['type']}</div>
                
                <div class="finding-meta">
                    <strong>URL:</strong> <code>{finding['url'] or 'N/A'}</code> | 
                    <strong>Component:</strong> {finding['affected']}
                </div>
                
                <div class="finding-description">{finding['description'][:300]}</div>
                
                <div class="finding-impact" style="background: rgba(255,71,87,0.1); padding: 10px; border-radius: 5px; margin: 10px 0;">
                    <strong style="color: var(--critical);">Impact:</strong> 
                    <span style="color: #ccc;">{finding['impact'][:200]}</span>
                </div>
                
                <div class="finding-remediation">
                    <h4>Remediation Steps:</h4>
                    <ul>
                        {''.join([f'<li>{step}</li>' for step in remediation_list if step.strip()])}
                    </ul>
                </div>
            </div>
            """
        return html
    
    def _generate_tech_html(self) -> str:
        """Teknoloji HTML'i oluştur"""
        if not self.technologies:
            return '<p style="color: #888;">No technology information detected.</p>'
        
        html = '<div class="tech-grid">'
        for tech in self.technologies:
            html += f"""
            <div class="tech-item">
                <div class="tech-name">{tech['name']}</div>
                <div class="tech-category">{tech['category']}</div>
                <div style="font-size: 0.8em; color: #888; margin-top: 5px;">{tech['version']}</div>
            </div>
            """
        html += '</div>'
        return html
    
    def _generate_intel_html(self) -> str:
        """İstihbarat HTML'i oluştur"""
        if not self.intelligence:
            return '<p style="color: #888;">No intelligence data collected.</p>'
        
        html = ""
        for item in self.intelligence[:30]:
            html += f"""
            <div class="intel-item">
                <div class="intel-type">[{item['type']}]</div>
                <div class="intel-data">{item['data'][:300]}</div>
            </div>
            """
        return html
    
    def _generate_compliance_html(self, compliance: Dict) -> str:
        """Uyumluluk HTML'i oluştur"""
        html = '<div class="compliance-grid">'
        
        for standard, data in compliance.items():
            status = data.get('status', 'UNKNOWN')
            status_class = 'pass' if status == 'PASS' else 'fail' if status == 'FAIL' else 'warning'
            
            html += f"""
            <div class="compliance-card">
                <h4>{standard}</h4>
                <div class="compliance-status {status_class}">{status}</div>
                <p style="font-size: 0.85em; color: #888;">{data.get('score', data.get('recommendation', ''))}</p>
            </div>
            """
        
        html += '</div>'
        return html
    
    def _generate_remediation_html(self) -> str:
        """Düzeltme HTML'i oluştur"""
        recommendations = self._get_prioritized_recommendations()
        
        if not recommendations:
            return '<p style="color: #888;">No remediation needed.</p>'
        
        html = ""
        for i, rec in enumerate(recommendations[:10], 1):
            steps = rec['description'].split('\n')
            
            html += f"""
            <div class="finding {rec['priority'].lower()}">
                <span class="severity-badge {rec['priority'].lower()}">{rec['priority']}</span>
                
                <div class="finding-title">{rec['title']}</div>
                
                <div style="margin: 10px 0; color: #ccc;">{rec['impact']}</div>
                
                <div class="finding-remediation">
                    <h4>Step-by-Step Remediation:</h4>
                    <ul>
                        {''.join([f'<li>{step}</li>' for step in steps if step.strip()])}
                    </ul>
                </div>
            </div>
            """
        return html
    
    def save_report(self, output_dir: str = "/tmp") -> Dict:
        """Raporu kaydet"""
        report_html = self.generate_html_report()
        
        # Hash oluştur
        content_hash = hashlib.sha256(report_html.encode()).hexdigest()
        
        # HTML kaydet
        safe_target = re.sub(r'[^\w\-.]', '_', str(self.target).replace('/', '_'))
        html_path = f"{output_dir}/report_{self.scan_id}_{safe_target}.html"
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(report_html)
        
        # JSON özeti kaydet
        summary = self.generate_executive_summary()
        json_path = f"{output_dir}/report_{self.scan_id}_{safe_target}_summary.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        return {
            'html_path': html_path,
            'json_path': json_path,
            'content_hash': content_hash,
            'risk_score': self.risk_score,
            'finding_count': len(self.findings),
            'critical_count': self.vuln_summary['critical'],
            'high_count': self.vuln_summary['high'],
            'medium_count': self.vuln_summary['medium'],
            'low_count': self.vuln_summary['low']
        }


def generate_detailed_report(scan_id: int) -> Dict:
    """Tarama için detaylı rapor oluştur"""
    from cyberapp.models.db import db_conn
    
    try:
        with db_conn() as conn:
            scan = conn.execute("SELECT target FROM scans WHERE id = ?", (scan_id,)).fetchone()
            target = scan[0] if scan else "Unknown"
    except:
        target = "Unknown"
    
    generator = DetailedSecurityReport(scan_id, target)
    return generator.save_report()
