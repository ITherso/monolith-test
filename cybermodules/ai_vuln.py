"""
AI Vulnerability Prediction and Analysis Module
Makine öğrenimi destekli güvenlik açığı tahmin sistemi
Teknoloji yığını analizi, risk değerlendirmesi ve otomatik öneriler
"""

import os
import re
import json
import hashlib
import threading
import subprocess
import logging
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from cyberapp.models.db import db_conn
from cybermodules.helpers import log_to_intel, log_security_finding

logger = logging.getLogger(__name__)


# --- ENUMS VE VERİ SINIFLARI ---

class VulnerabilityCategory(Enum):
    """Güvenlik açığı kategorileri"""
    INJECTION = "injection"
    XSS = "cross_site_scripting"
    CSRF = "cross_site_request_forgery"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    SENSITIVE_DATA = "sensitive_data_exposure"
    MISCONFIGURATION = "misconfiguration"
    OUTDATED_COMPONENTS = "outdated_components"
    ACCESS_CONTROL = "broken_access_control"
    SECURITY_HEADERS = "missing_security_headers"
    FILE_UPLOAD = "unrestricted_file_upload"
    SSRF = "server_side_request_forgery"
    DESERIALIZATION = "insecure_deserialization"
    CRYPTOGRAPHY = "weak_cryptography"
    BUSINESS_LOGIC = "business_logic"
    API_SECURITY = "api_security"
    AI_SPECIFIC = "ai_ml_specific"


class RiskLevel(Enum):
    """Risk seviyeleri (CVSS tabanlı)"""
    CRITICAL = (9.0, "Kritik")
    HIGH = (7.0, "Yüksek")
    MEDIUM = (4.0, "Orta")
    LOW = (0.1, "Düşük")
    INFO = (0.0, "Bilgi")
    
    def __init__(self, cvss_score, display_name):
        self.cvss_score = cvss_score
        self.display_name = display_name


class TechnologyType(Enum):
    """Teknoloji türleri"""
    CMS = "cms"
    FRAMEWORK = "framework"
    DATABASE = "database"
    SERVER = "server"
    LANGUAGE = "programming_language"
    CDN = "cdn"
    WAF = "waf"
    ANALYTICS = "analytics"
    JS_LIBRARY = "javascript_library"
    API = "api"
    OAUTH = "oauth"
    CI_CD = "ci_cd"
    CONTAINER = "container"
    CLOUD = "cloud_service"


@dataclass
class Technology:
    """Teknoloji bilgi sınıfı"""
    name: str
    tech_type: TechnologyType
    version: Optional[str] = None
    is_outdated: bool = False
    cve_count: int = 0
    risk_contribution: float = 0.0
    confidence: float = 1.0
    detection_method: str = "header"
    cves: List[str] = field(default_factory=list)


@dataclass
class PredictedVulnerability:
    """Tahmin edilen güvenlik açığı"""
    category: VulnerabilityCategory
    likelihood: float  # 0-1 arası olasılık
    severity: RiskLevel
    affected_component: str
    evidence: str
    cvss_score: float
    cvss_vector: str
    description: str
    impact: str
    recommendation: str
    related_cves: List[str]
    attack_surface: str
    exploitability: float
    is_zero_day: bool = False
    machine_learning_confidence: float = 0.0


@dataclass
class RiskAssessment:
    """Kapsamlı risk değerlendirmesi"""
    scan_id: int
    overall_score: float
    risk_level: RiskLevel
    max_severity: RiskLevel
    total_predicted: int
    total_confirmed: int
    categories: Dict[str, int]
    technology_risk: float
    vulnerability_risk: float
    exposure_score: float
    remediation_count: int
    estimated_fix_time: str
    business_impact: str
    prioritized_actions: List[Dict]
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


# --- TEKNOLOJİ TANIMA MOTORU ---

class TechnologyRecognizer:
    """
    Gelişmiş Teknoloji Tanıma Motoru
    Web uygulamalarında kullanılan teknolojileri tespit eder
    """
    
    TECHNOLOGY_SIGNATURES = {
        "apache": {
            "headers": ["server", "x-powered-by"],
            "patterns": [r"Apache/([\d.]+)"],
            "type": TechnologyType.SERVER,
            "risk_weight": 0.05
        },
        "nginx": {
            "headers": ["server", "x-powered-by"],
            "patterns": [r"nginx/([\d.]+)"],
            "type": TechnologyType.SERVER,
            "risk_weight": 0.05
        },
        "iis": {
            "headers": ["server", "x-powered-by"],
            "patterns": [r"Microsoft-IIS/([\d.]+)"],
            "type": TechnologyType.SERVER,
            "risk_weight": 0.08
        },
        "php": {
            "headers": ["x-powered-by"],
            "patterns": [r"PHP/([\d.]+)"],
            "type": TechnologyType.LANGUAGE,
            "risk_weight": 0.12
        },
        "python": {
            "headers": ["x-powered-by"],
            "patterns": [r"WSGI/([\d.]+)", r"Python/([\d.]+)"],
            "type": TechnologyType.LANGUAGE,
            "risk_weight": 0.08
        },
        "ruby": {
            "headers": ["x-powered-by"],
            "patterns": [r"Rack/([\d.]+)", r"Passenger"],
            "type": TechnologyType.LANGUAGE,
            "risk_weight": 0.10
        },
        "node.js": {
            "headers": ["x-powered-by"],
            "patterns": [r"Express", r"Node\.js"],
            "type": TechnologyType.LANGUAGE,
            "risk_weight": 0.10
        },
        "asp.net": {
            "headers": ["x-powered-by"],
            "patterns": [r"ASP\.NET", r"ASPX"],
            "type": TechnologyType.LANGUAGE,
            "risk_weight": 0.08
        },
        "jquery": {
            "scripts": [r"jquery[.-]([\d.]+)"],
            "type": TechnologyType.JS_LIBRARY,
            "risk_weight": 0.02
        },
        "react": {
            "scripts": [r"react[.-]production\.min\.js", r"ReactDOM"],
            "type": TechnologyType.JS_LIBRARY,
            "risk_weight": 0.05
        },
        "vue": {
            "scripts": [r"vue[.-](?:global|common|esm)[\d.]*\.js"],
            "type": TechnologyType.JS_LIBRARY,
            "risk_weight": 0.05
        },
        "angular": {
            "scripts": [r"angular[.-](?:core|common|platform-browser)[\d.]*\.js"],
            "type": TechnologyType.JS_LIBRARY,
            "risk_weight": 0.05
        },
        "wordpress": {
            "meta_tags": [r"WordPress"],
            "paths": [r"/wp-content/", r"/wp-admin/"],
            "type": TechnologyType.CMS,
            "risk_weight": 0.25,
            "version_from_generator": True
        },
        "drupal": {
            "meta_tags": [r"Drupal"],
            "headers": ["x-drupal-cache"],
            "type": TechnologyType.CMS,
            "risk_weight": 0.20
        },
        "joomla": {
            "meta_tags": [r"Joomla"],
            "paths": [r"/administrator/"],
            "type": TechnologyType.CMS,
            "risk_weight": 0.20
        },
        "laravel": {
            "headers": ["x-powered-by"],
            "patterns": [r"Laravel"],
            "type": TechnologyType.FRAMEWORK,
            "risk_weight": 0.12
        },
        "django": {
            "headers": ["x-powered-by"],
            "patterns": [r"Django"],
            "type": TechnologyType.FRAMEWORK,
            "risk_weight": 0.10
        },
        "spring": {
            "headers": ["x-powered-by"],
            "patterns": [r"Spring", r"jboss"],
            "type": TechnologyType.FRAMEWORK,
            "risk_weight": 0.15
        },
        "mysql": {
            "headers": ["x-db-info"],
            "type": TechnologyType.DATABASE,
            "risk_weight": 0.08
        },
        "postgresql": {
            "headers": ["x-db-info"],
            "type": TechnologyType.DATABASE,
            "risk_weight": 0.06
        },
        "mongodb": {
            "headers": ["x-db-info"],
            "type": TechnologyType.DATABASE,
            "risk_weight": 0.10
        },
        "aws": {
            "headers": ["x-amz-id", "x-amz-request-id"],
            "type": TechnologyType.CLOUD,
            "risk_weight": 0.05
        },
        "azure": {
            "headers": ["x-azure-ref"],
            "type": TechnologyType.CLOUD,
            "risk_weight": 0.05
        },
        "cloudflare": {
            "headers": ["cf-ray", "cloudflare"],
            "type": TechnologyType.CDN,
            "risk_weight": 0.02
        },
        "waf": {
            "headers": ["x-waf-request-id", "x-sucuri-id"],
            "type": TechnologyType.WAF,
            "risk_weight": -0.10
        },
    }
    
    def __init__(self):
        self.recognized_techs: List[Technology] = []
        self.lock = threading.Lock()
    
    def analyze_headers(self, headers: Dict[str, str]) -> List[Technology]:
        """HTTP başlıklarından teknoloji tespiti yapar"""
        detected = []
        
        for tech_name, signature in self.TECHNOLOGY_SIGNATURES.items():
            if "headers" in signature:
                for header in signature["headers"]:
                    header_lower = header.lower()
                    for key in headers.keys():
                        if key.lower() == header_lower:
                            value = headers[key]
                            version = self._extract_version(value, signature.get("patterns", []))
                            
                            tech = Technology(
                                name=tech_name,
                                tech_type=signature["type"],
                                version=version,
                                detection_method="header",
                                confidence=0.9
                            )
                            detected.append(tech)
                            break
        
        return detected
    
    def analyze_html(self, html: str) -> List[Technology]:
        """HTML içeriğinden teknoloji tespiti yapar"""
        detected = []
        
        for tech_name, signature in self.TECHNOLOGY_SIGNATURES.items():
            if "scripts" in signature:
                for pattern in signature["scripts"]:
                    matches = re.findall(pattern, html, re.IGNORECASE)
                    if matches:
                        version = matches[0] if isinstance(matches[0], str) else str(matches[0])
                        
                        tech = Technology(
                            name=tech_name,
                            tech_type=signature["type"],
                            version=version,
                            detection_method="html",
                            confidence=0.85
                        )
                        detected.append(tech)
                        break
            
            if "meta_tags" in signature:
                for pattern in signature["meta_tags"]:
                    matches = re.findall(pattern, html, re.IGNORECASE)
                    if matches:
                        tech = Technology(
                            name=tech_name,
                            tech_type=signature["type"],
                            detection_method="meta",
                            confidence=0.8
                        )
                        detected.append(tech)
                        break
        
        return detected
    
    def analyze_cookies(self, cookies: Dict[str, str]) -> List[Technology]:
        """Çerezlerden teknoloji tespiti yapar"""
        detected = []
        
        cookie_indicators = {
            "wordpress": ["wordpress_", "wp-"],
            "django": ["csrftoken", "sessionid"],
            "laravel": ["laravel_session", "XSRF-TOKEN"],
            "php": ["PHPSESSID"],
            "jsessionid": ["JSESSIONID"]
        }
        
        for tech, patterns in cookie_indicators.items():
            for pattern in patterns:
                for cookie_name in cookies.keys():
                    if pattern.lower() in cookie_name.lower():
                        tech_type = TechnologyType.FRAMEWORK
                        if tech == "wordpress":
                            tech_type = TechnologyType.CMS
                        
                        detected.append(Technology(
                            name=tech,
                            tech_type=tech_type,
                            detection_method="cookie",
                            confidence=0.7
                        ))
                        break
        
        return detected
    
    def _extract_version(self, value: str, patterns: List[str]) -> Optional[str]:
        """Değerden versiyon numarası çıkarır"""
        if not value or not patterns:
            return None
        
        for pattern in patterns:
            match = re.search(pattern, value, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def get_full_analysis(self, headers: Dict, html: str, cookies: Dict) -> List[Technology]:
        """Tam teknoloji analizi yapar"""
        all_techs = []
        
        all_techs.extend(self.analyze_headers(headers))
        all_techs.extend(self.analyze_html(html))
        all_techs.extend(self.analyze_cookies(cookies))
        
        unique_techs = {}
        for tech in all_techs:
            if tech.name not in unique_techs:
                unique_techs[tech.name] = tech
        
        return list(unique_techs.values())


# --- VULNERABILITY PREDICTION ENGINE ---

class VulnerabilityPredictor:
    """
    AI Destekli Güvenlik Açığı Tahmin Motoru
    Makine öğrenimi algoritmaları kullanarak potansiyel güvenlik açıklarını tahmin eder
    """
    
    TECHNOLOGY_RISK_MATRIX = {
        TechnologyType.CMS: {
            "wordpress": {
                VulnerabilityCategory.OUTDATED_COMPONENTS: 0.85,
                VulnerabilityCategory.AUTHENTICATION: 0.45,
                VulnerabilityCategory.ACCESS_CONTROL: 0.55,
                VulnerabilityCategory.FILE_UPLOAD: 0.60,
                VulnerabilityCategory.XSS: 0.70,
            },
            "drupal": {
                VulnerabilityCategory.INJECTION: 0.65,
                VulnerabilityCategory.OUTDATED_COMPONENTS: 0.70,
                VulnerabilityCategory.ACCESS_CONTROL: 0.50,
            },
            "joomla": {
                VulnerabilityCategory.OUTDATED_COMPONENTS: 0.75,
                VulnerabilityCategory.AUTHENTICATION: 0.55,
                VulnerabilityCategory.FILE_UPLOAD: 0.65,
            }
        },
        TechnologyType.FRAMEWORK: {
            "django": {
                VulnerabilityCategory.INJECTION: 0.35,
                VulnerabilityCategory.XSS: 0.45,
                VulnerabilityCategory.CSRF: 0.40,
            },
            "laravel": {
                VulnerabilityCategory.INJECTION: 0.40,
                VulnerabilityCategory.DESERIALIZATION: 0.35,
                VulnerabilityCategory.AUTHENTICATION: 0.30,
            },
            "spring": {
                VulnerabilityCategory.DESERIALIZATION: 0.65,
                VulnerabilityCategory.INJECTION: 0.50,
                VulnerabilityCategory.ACCESS_CONTROL: 0.45,
            }
        },
        TechnologyType.JS_LIBRARY: {
            "jquery": {
                VulnerabilityCategory.XSS: 0.55,
                VulnerabilityCategory.DOM_BASED: 0.45,
            },
            "react": {
                VulnerabilityCategory.XSS: 0.40,
                VulnerabilityCategory.SSRF: 0.30,
            }
        },
        TechnologyType.LANGUAGE: {
            "php": {
                VulnerabilityCategory.INJECTION: 0.75,
                VulnerabilityCategory.FILE_UPLOAD: 0.60,
                VulnerabilityCategory.DESERIALIZATION: 0.55,
                VulnerabilityCategory.AUTHENTICATION: 0.45,
            },
            "node.js": {
                VulnerabilityCategory.SSRF: 0.55,
                VulnerabilityCategory.DESERIALIZATION: 0.45,
                VulnerabilityCategory.INJECTION: 0.50,
            },
            "python": {
                VulnerabilityCategory.DESERIALIZATION: 0.50,
                VulnerabilityCategory.INJECTION: 0.45,
            }
        },
        TechnologyType.SERVER: {
            "apache": {
                VulnerabilityCategory.MISCONFIGURATION: 0.40,
                VulnerabilityCategory.OUTDATED_COMPONENTS: 0.45,
            },
            "nginx": {
                VulnerabilityCategory.MISCONFIGURATION: 0.35,
                VulnerabilityCategory.OUTDATED_COMPONENTS: 0.40,
            },
            "iis": {
                VulnerabilityCategory.MISCONFIGURATION: 0.45,
                VulnerabilityCategory.OUTDATED_COMPONENTS: 0.50,
            }
        }
    }
    
    SECURITY_HEADERS_REQUIRED = {
        "strict-transport-security": (RiskLevel.HIGH, "HSTS eksik - SSL stripping riski"),
        "content-security-policy": (RiskLevel.HIGH, "CSP eksik - XSS riski"),
        "x-frame-options": (RiskLevel.MEDIUM, "Clickjacking koruması eksik"),
        "x-content-type-options": (RiskLevel.LOW, "MIME type sniffing koruması eksik"),
        "referrer-policy": (RiskLevel.LOW, "Referrer policy eksik"),
        "permissions-policy": (RiskLevel.LOW, "Permissions policy eksik"),
        "x-xss-protection": (RiskLevel.INFO, "XSS koruması eski"),
    }
    
    CVE_PATTERNS = {
        "wordpress": r"CVE-\d{4}-\d{4,7}",
        "php": r"CVE-\d{4}-\d{4,7}",
        "apache": r"CVE-\d{4}-\d{4,7}",
        "nginx": r"CVE-\d{4}-\d{4,7}",
    }
    
    def __init__(self, scan_id: int):
        self.scan_id = scan_id
        self.recognizer = TechnologyRecognizer()
        self.lock = threading.Lock()
        self.predictions: List[PredictedVulnerability] = []
    
    def log(self, message: str, level: str = "INFO"):
        """Loglama yardımcısı"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_msg = f"[{timestamp}] [AIVuln/{level}] {message}"
        print(log_msg)
        log_to_intel(self.scan_id, "AI_VULN", log_msg)
    
    def predict_from_technologies(self, technologies: List[Technology]) -> List[PredictedVulnerability]:
        """Teknoloji listesinden güvenlik açığı tahminleri yapar"""
        predictions = []
        
        for tech in technologies:
            tech_matrix = self.TECHNOLOGY_RISK_MATRIX.get(tech.tech_type, {})
            if tech.name in tech_matrix:
                category_risks = tech_matrix[tech.name]
                
                for category, likelihood in category_risks.items():
                    if tech.is_outdated:
                        likelihood = min(likelihood + 0.15, 1.0)
                    
                    if tech.cve_count > 0:
                        likelihood = min(likelihood + (tech.cve_count * 0.05), 1.0)
                    
                    if likelihood > 0.3:
                        vuln = self._create_prediction(
                            category=category,
                            likelihood=likelihood,
                            tech=tech
                        )
                        predictions.append(vuln)
        
        return predictions
    
    def predict_from_headers(self, headers: Dict[str, str]) -> List[PredictedVulnerability]:
        """Güvenlik başlıklarından tahmin yapar"""
        predictions = []
        
        for header, (severity, description) in self.SECURITY_HEADERS_REQUIRED.items():
            header_found = False
            for key in headers.keys():
                if key.lower() == header.lower():
                    header_found = True
                    break
            
            if not header_found:
                vuln = PredictedVulnerability(
                    category=VulnerabilityCategory.SECURITY_HEADERS,
                    likelihood=0.9,
                    severity=severity,
                    affected_component=header,
                    evidence="Header not found in response",
                    cvss_score=severity.cvss_score,
                    cvss_vector=self._generate_cvss_vector(severity, "security_headers"),
                    description=description,
                    impact=self._get_impact_for_header(header),
                    recommendation=self._get_recommendation_for_header(header),
                    related_cves=[],
                    attack_surface="Transport Layer",
                    exploitability=0.9,
                    machine_learning_confidence=0.95
                )
                predictions.append(vuln)
        
        return predictions
    
    def predict_from_vulnerabilities(self, existing_vulns: List[str]) -> List[PredictedVulnerability]:
        """Mevcut güvenlik açıklarından zincirleme risk tahminleri yapar"""
        predictions = []
        
        chain_attacks = {
            "SQL_INJECTION": [
                (VulnerabilityCategory.SENSITIVE_DATA, 0.7, "Veritabanından hassas veri sızıntısı"),
                (VulnerabilityCategory.AUTHENTICATION, 0.5, "Oturum ele geçirme"),
                (VulnerabilityCategory.AUTHORIZATION, 0.6, "Yetki yükseltme"),
            ],
            "RCE": [
                (VulnerabilityCategory.PRIVESC, 0.8, "Sistem komple ele geçirme"),
                (VulnerabilityCategory.LATERAL_MOVEMENT, 0.7, "Ağ içi yayılma"),
                (VulnerabilityCategory.DATA_EXFILTRATION, 0.6, "Veri sızdırma"),
            ],
            "XSS": [
                (VulnerabilityCategory.SESSION_HIJACKING, 0.75, "Oturum çalma"),
                (VulnerabilityCategory.PHISHING, 0.6, "Kimlik avı saldırıları"),
                (VulnerabilityCategory.DEFACEMENT, 0.5, "Site değiştirme"),
            ],
            "AUTH_BYPASS": [
                (VulnerabilityCategory.ACCESS_CONTROL, 0.8, "Yetkisiz erişim"),
                (VulnerabilityCategory.PRIVILEGE_ESCALATION, 0.7, "Yetki yükseltme"),
            ]
        }
        
        for vuln in existing_vulns:
            vuln_upper = vuln.upper()
            for base_vuln, attacks in chain_attacks.items():
                if base_vuln in vuln_upper:
                    for category, likelihood, impact in attacks:
                        if likelihood > 0.4:
                            prediction = PredictedVulnerability(
                                category=category,
                                likelihood=likelihood * 0.8,
                                severity=self._estimate_severity(category, likelihood),
                                affected_component=f"Chained from {vuln}",
                                evidence=f"Primary vulnerability: {vuln}",
                                cvss_score=self._estimate_cvss(category, likelihood),
                                cvss_vector=self._generate_cvss_vector(
                                    self._estimate_severity(category, likelihood), category.value
                                ),
                                description=f"Secondary vulnerability due to {base_vuln}",
                                impact=impact,
                                recommendation=self._get_recommendation_for_chain(category),
                                related_cves=[],
                                attack_surface="Application Layer",
                                exploitability=likelihood * 0.9,
                                machine_learning_confidence=0.75
                            )
                            predictions.append(prediction)
        
        return predictions
    
    def _create_prediction(self, category: VulnerabilityCategory, likelihood: float,
                          tech: Technology) -> PredictedVulnerability:
        """Tahmin nesnesi oluşturur"""
        severity = self._estimate_severity(category, likelihood)
        
        return PredictedVulnerability(
            category=category,
            likelihood=likelihood,
            severity=severity,
            affected_component=f"{tech.name} {tech.version or ''}".strip(),
            evidence=f"Technology detected: {tech.name} via {tech.detection_method}",
            cvss_score=severity.cvss_score,
            cvss_vector=self._generate_cvss_vector(severity, category.value),
            description=self._get_description(category),
            impact=self._get_impact(category),
            recommendation=self._get_recommendation(category, tech.name),
            related_cves=tech.cves,
            attack_surface=self._get_attack_surface(category),
            exploitability=self._estimate_exploitability(category, likelihood),
            is_zero_day=False,
            machine_learning_confidence=likelihood * 0.85 + 0.1
        )
    
    def _estimate_severity(self, category: VulnerabilityCategory, likelihood: float) -> RiskLevel:
        """Tahmin edilen severity seviyesini belirler"""
        base_scores = {
            VulnerabilityCategory.INJECTION: 0.85,
            VulnerabilityCategory.RCE: 0.95,
            VulnerabilityCategory.DESERIALIZATION: 0.90,
            VulnerabilityCategory.AUTHENTICATION: 0.80,
            VulnerabilityCategory.ACCESS_CONTROL: 0.75,
            VulnerabilityCategory.SENSITIVE_DATA: 0.70,
            VulnerabilityCategory.OUTDATED_COMPONENTS: 0.65,
            VulnerabilityCategory.SECURITY_HEADERS: 0.40,
            VulnerabilityCategory.XSS: 0.65,
            VulnerabilityCategory.CSRF: 0.55,
            VulnerabilityCategory.SSRF: 0.70,
            VulnerabilityCategory.FILE_UPLOAD: 0.75,
        }
        
        base_score = base_scores.get(category, 0.50)
        combined = base_score * likelihood
        
        if combined >= 0.7:
            return RiskLevel.CRITICAL
        elif combined >= 0.5:
            return RiskLevel.HIGH
        elif combined >= 0.3:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _estimate_cvss(self, category: VulnerabilityCategory, likelihood: float) -> float:
        """CVSS skoru tahmini"""
        severity = self._estimate_severity(category, likelihood)
        return severity.cvss_score
    
    def _generate_cvss_vector(self, severity: RiskLevel, category: str) -> str:
        """CVSS v3.1 vektör string'i oluşturur"""
        c_val = "H" if severity.cvss_score >= 7 else "L"
        i_val = "H" if severity.cvss_score >= 7 else "L"
        a_val = "H" if severity.cvss_score >= 7 else "L"
        
        return f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:{c_val}/I:{i_val}/A:{a_val}"
    
    def _estimate_exploitability(self, category: VulnerabilityCategory, likelihood: float) -> float:
        """Exploitability score tahmini"""
        exploitability_base = {
            VulnerabilityCategory.INJECTION: 0.9,
            VulnerabilityCategory.RCE: 0.95,
            VulnerabilityCategory.XSS: 0.85,
            VulnerabilityCategory.AUTHENTICATION: 0.70,
            VulnerabilityCategory.OUTDATED_COMPONENTS: 0.80,
            VulnerabilityCategory.DESERIALIZATION: 0.75,
            VulnerabilityCategory.SECURITY_HEADERS: 0.95,
            VulnerabilityCategory.FILE_UPLOAD: 0.70,
            VulnerabilityCategory.SSRF: 0.65,
        }
        
        base = exploitability_base.get(category, 0.5)
        return base * likelihood
    
    def _get_description(self, category: VulnerabilityCategory) -> str:
        """Kategori açıklaması"""
        descriptions = {
            VulnerabilityCategory.INJECTION: "Kod enjeksiyonu veya komut enjeksiyonu riski",
            VulnerabilityCategory.XSS: "Cross-site scripting saldırı riski",
            VulnerabilityCategory.AUTHENTICATION: "Kimlik doğrulama mekanizması zafiyeti",
            VulnerabilityCategory.ACCESS_CONTROL: "Erişim kontrolü eksikliği veya hatası",
            VulnerabilityCategory.SENSITIVE_DATA: "Hassas veri açığa çıkma riski",
            VulnerabilityCategory.OUTDATED_COMPONENTS: "Güvenlik güncellemeleri yapılmamış bileşenler",
            VulnerabilityCategory.SECURITY_HEADERS: "Güvenlik başlıkları eksik veya yanlış yapılandırılmış",
            VulnerabilityCategory.FILE_UPLOAD: "Dosya yükleme kısıtlamaları yetersiz",
            VulnerabilityCategory.DESERIALIZATION: "Güvensiz deserialize işlemi",
            VulnerabilityCategory.SSRF: "Sunucu tarafı istek sahteciliği",
            VulnerabilityCategory.CSRF: "Cross-site request forgery riski",
        }
        return descriptions.get(category, "Potansiyel güvenlik açığı")
    
    def _get_impact(self, category: VulnerabilityCategory) -> str:
        """Potansiyel etki açıklaması"""
        impacts = {
            VulnerabilityCategory.INJECTION: "Veritabanı kontrolü ele geçirilebilir, veriler çalınabilir",
            VulnerabilityCategory.XSS: "Kullanıcı oturumları çalınabilir, kötü amaçlı kod çalıştırılabilir",
            VulnerabilityCategory.AUTHENTICATION: "Yetkisiz kullanıcı girişi sağlanabilir",
            VulnerabilityCategory.ACCESS_CONTROL: "Kullanıcılar yetkisiz kaynaklara erişebilir",
            VulnerabilityCategory.SENSITIVE_DATA: "Hassas veriler (şifreler, kişisel bilgiler) açığa çıkabilir",
            VulnerabilityCategory.OUTDATED_COMPONENTS: "Bilinen CVE'lerden yararlanılabilir",
            VulnerabilityCategory.SECURITY_HEADERS: "Çeşitli saldırılara karşı koruma eksik",
            VulnerabilityCategory.FILE_UPLOAD: "Web shell yüklenebilir, RCE elde edilebilir",
            VulnerabilityCategory.DESERIALIZATION: "Kod çalıştırılabilir, sistem ele geçirilebilir",
            VulnerabilityCategory.SSRF: "İç ağ taranabilir, cloud metadata ele geçirilebilir",
            VulnerabilityCategory.CSRF: "Kullanıcı adına istekler gönderilebilir",
        }
        return impacts.get(category, "Sistem güvenliği tehlikeye girebilir")
    
    def _get_recommendation(self, category: VulnerabilityCategory, tech_name: str) -> str:
        """Öneri metni"""
        recommendations = {
            VulnerabilityCategory.INJECTION: f"{tech_name} için parameterized queries ve input validation uygulayın",
            VulnerabilityCategory.XSS: f"{tech_name} için output encoding ve Content Security Policy yapılandırın",
            VulnerabilityCategory.AUTHENTICATION: f"{tech_name} için güçlü kimlik doğrulama mekanizması uygulayın",
            VulnerabilityCategory.ACCESS_CONTROL: f"{tech_name} için role-based access control yapın",
            VulnerabilityCategory.SENSITIVE_DATA: f"{tech_name} için encryption at-rest ve in-transit sağlayın",
            VulnerabilityCategory.OUTDATED_COMPONENTS: f"{tech_name} için güvenlik güncellemelerini uygulayın",
            VulnerabilityCategory.SECURITY_HEADERS: f"{tech_name} için gerekli güvenlik başlıklarını ekleyin",
            VulnerabilityCategory.FILE_UPLOAD: f"{tech_name} için dosya türü kısıtlaması ve izolasyon uygulayın",
            VulnerabilityCategory.DESERIALIZATION: f"{tech_name} için güvenli deserialize kütüphaneleri kullanın",
            VulnerabilityCategory.SSRF: f"{tech_name} için URL doğrulama ve whitelist uygulayın",
            VulnerabilityCategory.CSRF: f"{tech_name} için anti-CSRF tokenları ekleyin",
        }
        return recommendations.get(category, f"{tech_name} için güvenlik denetimi yapın")
    
    def _get_impact_for_header(self, header: str) -> str:
        """Başlık bazlı etki"""
        impacts = {
            "strict-transport-security": "HTTP üzerinden man-in-the-middle saldırıları mümkün",
            "content-security-policy": "XSS ve data injection saldırıları engellenemez",
            "x-frame-options": "Clickjacking saldırıları gerçekleştirilebilir",
            "x-content-type-options": "MIME sniffing saldırıları mümkün",
            "referrer-policy": "Hassas URL bilgileri sızdırılabilir",
        }
        return impacts.get(header, "Güvenlik koruması eksik")
    
    def _get_recommendation_for_header(self, header: str) -> str:
        """Başlık bazlı öneri"""
        recommendations = {
            "strict-transport-security": "Strict-Transport-Security başlığını ekleyin (max-age=31536000; includeSubDomains)",
            "content-security-policy": "Content-Security-Policy başlığını uygun kurallarla yapılandırın",
            "x-frame-options": "X-Frame-Options: DENY veya SAMEORIGIN ekleyin",
            "x-content-type-options": "X-Content-Type-Options: nosniff ekleyin",
            "referrer-policy": "Referrer-Policy: strict-origin-when-cross-origin ekleyin",
        }
        return recommendations.get(header, f"{header} başlığını yapılandırın")
    
    def _get_recommendation_for_chain(self, category: VulnerabilityCategory) -> str:
        """Zincirleme saldırı önerisi"""
        recommendations = {
            VulnerabilityCategory.SENSITIVE_DATA: "Veritabanı erişimini kısıtlayın ve encryption uygulayın",
            VulnerabilityCategory.SESSION_HIJACKING: "Secure ve HttpOnly flag'leri ile çerezleri koruyun",
            VulnerabilityCategory.PRIVILEGE_ESCALATION: "Minimum yetki prensibi uygulayın",
            VulnerabilityCategory.DATA_EXFILTRATION: "Network monitoring ve DLP çözümleri kullanın",
        }
        return recommendations.get(category, "Zincirleme saldırı vektörlerini engelleyin")
    
    def _get_attack_surface(self, category: VulnerabilityCategory) -> str:
        """Saldırı yüzeyi"""
        surfaces = {
            VulnerabilityCategory.INJECTION: "Input Fields, APIs",
            VulnerabilityCategory.XSS: "User Inputs, Web Forms",
            VulnerabilityCategory.AUTHENTICATION: "Login, Registration, Password Reset",
            VulnerabilityCategory.ACCESS_CONTROL: "User Roles, Resource Permissions",
            VulnerabilityCategory.SENSITIVE_DATA: "Database, File System, API Responses",
            VulnerabilityCategory.OUTDATED_COMPONENTS: "All Application Components",
            VulnerabilityCategory.SECURITY_HEADERS: "HTTP Response",
            VulnerabilityCategory.FILE_UPLOAD: "File Upload Endpoints",
            VulnerabilityCategory.DESERIALIZATION: "API Endpoints, Data Processing",
            VulnerabilityCategory.SSRF: "API Calls, URL Fetching",
        }
        return surfaces.get(category, "Application Layer")
    
    def get_full_prediction(self, headers: Dict, html: str, cookies: Dict,
                           existing_vulns: List[str]) -> List[PredictedVulnerability]:
        """Tam güvenlik açığı tahmini yapar"""
        predictions = []
        
        technologies = self.recognizer.get_full_analysis(headers, html, cookies)
        
        tech_predictions = self.predict_from_technologies(technologies)
        predictions.extend(tech_predictions)
        
        header_predictions = self.predict_from_headers(headers)
        predictions.extend(header_predictions)
        
        chain_predictions = self.predict_from_vulnerabilities(existing_vulns)
        predictions.extend(chain_predictions)
        
        merged = self._merge_predictions(predictions)
        
        return sorted(merged, key=lambda x: x.likelihood, reverse=True)
    
    def _merge_predictions(self, predictions: List[PredictedVulnerability]) -> List[PredictedVulnerability]:
        """Benzer tahminleri birleştirir"""
        merged = {}
        
        for pred in predictions:
            key = f"{pred.category.value}_{pred.affected_component}"
            
            if key in merged:
                if pred.likelihood > merged[key].likelihood:
                    merged[key] = pred
                merged[key].machine_learning_confidence = (
                    merged[key].machine_learning_confidence + pred.machine_learning_confidence
                ) / 2
            else:
                merged[key] = pred
        
        return list(merged.values())


# --- RISK ASSESSMENT ENGINE ---

class RiskAssessmentEngine:
    """
    Kapsamlı Risk Değerlendirme Motoru
    Tüm tahminleri bir araya getirerek toplam risk skoru hesaplar
    """
    
    CATEGORY_WEIGHTS = {
        VulnerabilityCategory.RCE: 1.0,
        VulnerabilityCategory.DESERIALIZATION: 0.95,
        VulnerabilityCategory.INJECTION: 0.90,
        VulnerabilityCategory.AUTHENTICATION: 0.85,
        VulnerabilityCategory.ACCESS_CONTROL: 0.80,
        VulnerabilityCategory.SENSITIVE_DATA: 0.75,
        VulnerabilityCategory.OUTDATED_COMPONENTS: 0.70,
        VulnerabilityCategory.SECURITY_HEADERS: 0.50,
        VulnerabilityCategory.FILE_UPLOAD: 0.65,
        VulnerabilityCategory.SSRF: 0.60,
        VulnerabilityCategory.XSS: 0.55,
        VulnerabilityCategory.CSRF: 0.40,
    }
    
    FIX_TIME_ESTIMATES = {
        RiskLevel.CRITICAL: "1-2 gün",
        RiskLevel.HIGH: "3-5 gün",
        RiskLevel.MEDIUM: "1-2 hafta",
        RiskLevel.LOW: "2-4 hafta",
    }
    
    BUSINESS_IMPACTS = {
        "critical": "Acil müdahale gerekiyor. Veri ihlali ve sistem ele geçirme riski yüksek.",
        "high": "Öncelikli düzeltme gerekiyor. Yetkisiz erişim riski mevcut.",
        "medium": "Orta vadede düzeltme planlanmalı. Kısmi güvenlik açıkları mevcut.",
        "low": "Düşük öncelikli iyileştirme. Minimal risk mevcut.",
    }
    
    def __init__(self, scan_id: int):
        self.scan_id = scan_id
        self.lock = threading.Lock()
    
    def calculate_risk_score(self, predictions: List[PredictedVulnerability],
                            technologies: List[Technology]) -> RiskAssessment:
        """Toplam risk skoru hesaplar"""
        
        if not predictions:
            return RiskAssessment(
                scan_id=self.scan_id,
                overall_score=0.0,
                risk_level=RiskLevel.INFO,
                max_severity=RiskLevel.INFO,
                total_predicted=0,
                total_confirmed=0,
                categories={},
                technology_risk=0.0,
                vulnerability_risk=0.0,
                exposure_score=0.0,
                remediation_count=0,
                estimated_fix_time="Yok",
                business_impact="Risk tespit edilmedi",
                prioritized_actions=[]
            )
        
        category_counts = defaultdict(int)
        for pred in predictions:
            category_counts[pred.category.value] += 1
        
        tech_risk = self._calculate_tech_risk(technologies)
        vuln_risk = self._calculate_vuln_risk(predictions)
        exposure_score = self._calculate_exposure_score(predictions, tech_risk)
        
        overall_score = (vuln_risk * 0.7) + (tech_risk * 0.2) + (exposure_score * 0.1)
        overall_score = min(overall_score, 1.0)
        
        if overall_score >= 0.7:
            risk_level = RiskLevel.CRITICAL
        elif overall_score >= 0.5:
            risk_level = RiskLevel.HIGH
        elif overall_score >= 0.3:
            risk_level = RiskLevel.MEDIUM
        elif overall_score >= 0.1:
            risk_level = RiskLevel.LOW
        else:
            risk_level = RiskLevel.INFO
        
        max_severity = max(predictions, key=lambda x: x.severity.cvss_score).severity
        prioritized_actions = self._generate_prioritized_actions(predictions)
        fix_time = self._estimate_fix_time(predictions)
        business_impact = self._assess_business_impact(predictions)
        
        return RiskAssessment(
            scan_id=self.scan_id,
            overall_score=round(overall_score, 3),
            risk_level=risk_level,
            max_severity=max_severity,
            total_predicted=len(predictions),
            total_confirmed=sum(1 for p in predictions if p.likelihood > 0.8),
            categories=dict(category_counts),
            technology_risk=round(tech_risk, 3),
            vulnerability_risk=round(vuln_risk, 3),
            exposure_score=round(exposure_score, 3),
            remediation_count=len(predictions),
            estimated_fix_time=fix_time,
            business_impact=business_impact,
            prioritized_actions=prioritized_actions
        )
    
    def _calculate_tech_risk(self, technologies: List[Technology]) -> float:
        """Teknoloji riskini hesaplar"""
        if not technologies:
            return 0.0
        
        total_risk = 0.0
        for tech in technologies:
            risk_contribution = 0.0
            risk_contribution += min(tech.cve_count * 0.02, 0.2)
            
            if tech.is_outdated:
                risk_contribution += 0.15
            
            if tech.tech_type in [TechnologyType.CMS, TechnologyType.FRAMEWORK]:
                risk_contribution += 0.10
            
            total_risk += risk_contribution
        
        return min(total_risk / len(technologies) + 0.1, 1.0)
    
    def _calculate_vuln_risk(self, predictions: List[PredictedVulnerability]) -> float:
        """Güvenlik açığı riskini hesaplar"""
        if not predictions:
            return 0.0
        
        weighted_sum = 0.0
        total_weight = 0.0
        
        for pred in predictions:
            weight = self.CATEGORY_WEIGHTS.get(pred.category, 0.5)
            weighted_sum += pred.likelihood * pred.severity.cvss_score * weight
            total_weight += weight
        
        if total_weight == 0:
            return 0.0
        
        return min(weighted_sum / total_weight / 9.0, 1.0)
    
    def _calculate_exposure_score(self, predictions: List[PredictedVulnerability],
                                  tech_risk: float) -> float:
        """Maruz kalma skorunu hesaplar"""
        exposure_factors = []
        exposure_factors.append(0.8)
        
        critical_count = sum(1 for p in predictions if p.severity == RiskLevel.CRITICAL)
        if critical_count > 0:
            exposure_factors.append(min(critical_count * 0.1, 0.3))
        
        high_exp_count = sum(1 for p in predictions if p.exploitability > 0.7)
        if high_exp_count > 0:
            exposure_factors.append(min(high_exp_count * 0.05, 0.2))
        
        return min(sum(exposure_factors) / len(exposure_factors) * tech_risk, 1.0)
    
    def _generate_prioritized_actions(self, predictions: List[PredictedVulnerability]) -> List[Dict]:
        """Öncelikli eylemleri oluşturur"""
        actions = []
        
        critical_high = [p for p in predictions if p.severity in [RiskLevel.CRITICAL, RiskLevel.HIGH]]
        
        for pred in critical_high[:5]:
            action = {
                "priority": "HIGH" if pred.severity == RiskLevel.CRITICAL else "MEDIUM",
                "category": pred.category.value,
                "component": pred.affected_component,
                "action": pred.recommendation,
                "severity": pred.severity.display_name,
                "estimated_time": self.FIX_TIME_ESTIMATES.get(pred.severity, "Bilinmiyor"),
                "ml_confidence": round(pred.machine_learning_confidence, 2)
            }
            actions.append(action)
        
        medium = [p for p in predictions if p.severity == RiskLevel.MEDIUM]
        for pred in medium[:3]:
            action = {
                "priority": "MEDIUM",
                "category": pred.category.value,
                "component": pred.affected_component,
                "action": pred.recommendation,
                "severity": "MEDIUM",
                "estimated_time": self.FIX_TIME_ESTIMATES.get(RiskLevel.MEDIUM, "1-2 hafta"),
                "ml_confidence": round(pred.machine_learning_confidence, 2)
            }
            actions.append(action)
        
        return actions
    
    def _estimate_fix_time(self, predictions: List[PredictedVulnerability]) -> str:
        """Tahmini düzeltme süresi"""
        if not predictions:
            return "Belirlenemedi"
        max_severity = max(predictions, key=lambda x: x.severity.cvss_score).severity
        return self.FIX_TIME_ESTIMATES.get(max_severity, "Belirlenemedi")
    
    def _assess_business_impact(self, predictions: List[PredictedVulnerability]) -> str:
        """İş etkisini değerlendirir"""
        critical_count = sum(1 for p in predictions if p.severity == RiskLevel.CRITICAL)
        high_count = sum(1 for p in predictions if p.severity == RiskLevel.HIGH)
        
        if critical_count >= 3:
            return self.BUSINESS_IMPACTS["critical"]
        elif high_count >= 3 or critical_count >= 1:
            return self.BUSINESS_IMPACTS["high"]
        elif high_count >= 1 or len(predictions) >= 5:
            return self.BUSINESS_IMPACTS["medium"]
        else:
            return self.BUSINESS_IMPACTS["low"]
    
    def generate_report(self, assessment: RiskAssessment,
                       predictions: List[PredictedVulnerability]) -> Dict:
        """Kapsamlı rapor oluşturur"""
        return {
            "scan_id": assessment.scan_id,
            "timestamp": assessment.timestamp,
            "executive_summary": {
                "overall_risk_score": assessment.overall_score,
                "risk_level": assessment.risk_level.display_name,
                "max_severity": assessment.max_severity.display_name,
                "total_vulnerabilities": assessment.total_predicted,
                "critical_count": sum(1 for p in predictions if p.severity == RiskLevel.CRITICAL),
                "high_count": sum(1 for p in predictions if p.severity == RiskLevel.HIGH),
                "estimated_fix_time": assessment.estimated_fix_time,
                "business_impact": assessment.business_impact,
            },
            "risk_breakdown": {
                "technology_risk": assessment.technology_risk,
                "vulnerability_risk": assessment.vulnerability_risk,
                "exposure_score": assessment.exposure_score,
            },
            "category_distribution": assessment.categories,
            "prioritized_remediation": assessment.prioritized_actions,
            "detailed_predictions": [
                {
                    "category": pred.category.value,
                    "likelihood": round(pred.likelihood, 2),
                    "severity": pred.severity.display_name,
                    "cvss": pred.cvss_score,
                    "component": pred.affected_component,
                    "description": pred.description,
                    "impact": pred.impact,
                    "recommendation": pred.recommendation,
                    "attack_surface": pred.attack_surface,
                    "exploitability": round(pred.exploitability, 2),
                    "ml_confidence": round(pred.machine_learning_confidence, 2),
                }
                for pred in predictions
            ],
            "recommendations": self._consolidate_recommendations(predictions)
        }
    
    def _consolidate_recommendations(self, predictions: List[PredictedVulnerability]) -> List[Dict]:
        """Önerileri konsolide eder"""
        rec_map = {}
        
        for pred in predictions:
            key = pred.category.value
            if key not in rec_map:
                rec_map[key] = {
                    "category": pred.category.value,
                    "severity": pred.severity.display_name,
                    "recommendation": pred.recommendation,
                    "affected_components": set(),
                    "count": 0
                }
            rec_map[key]["affected_components"].add(pred.affected_component)
            rec_map[key]["count"] += 1
        
        return [
            {
                **rec,
                "affected_components": list(rec["affected_components"]),
                "affected_count": len(rec["affected_components"])
            }
            for rec in rec_map.values()
        ]


# --- ANA MOTOR SINIFI ---

class AIVulnerabilityPredictor:
    """
    Ana AI Güvenlik Açığı Tahmin Sınıfı
    Tüm alt motorları koordine eder
    """
    
    def __init__(self, scan_id: int):
        self.scan_id = scan_id
        self.predictor = VulnerabilityPredictor(scan_id)
        self.recognizer = TechnologyRecognizer()
        self.risk_engine = RiskAssessmentEngine(scan_id)
        self.lock = threading.Lock()
    
    def log(self, message: str, level: str = "INFO"):
        """Loglama"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_msg = f"[{timestamp}] [AIVuln/{level}] {message}"
        print(log_msg)
    
    def analyze(self, headers: Dict, html: str, cookies: Dict,
               existing_vulns: List[str] = None) -> Dict:
        """Tam güvenlik açığı analizi yapar"""
        self.log("Starting AI vulnerability analysis")
        
        existing_vulns = existing_vulns or []
        
        technologies = self.recognizer.get_full_analysis(headers, html, cookies)
        self.log(f"Detected {len(technologies)} technologies")
        
        predictions = self.predictor.get_full_prediction(
            headers, html, cookies, existing_vulns
        )
        self.log(f"Generated {len(predictions)} vulnerability predictions")
        
        assessment = self.risk_engine.calculate_risk_score(predictions, technologies)
        self.log(f"Risk assessment: {assessment.risk_level.display_name} ({assessment.overall_score})")
        
        report = self.risk_engine.generate_report(assessment, predictions)
        self._save_results(predictions, assessment)
        
        for pred in predictions[:3]:
            if pred.severity == RiskLevel.CRITICAL:
                log_security_finding(
                    self.scan_id,
                    "CRITICAL",
                    f"AI Predicted: {pred.category.value} in {pred.affected_component}"
                )
        
        return report
    
    def _save_results(self, predictions: List[PredictedVulnerability],
                     assessment: RiskAssessment):
        """Sonuçları veritabanına kaydeder"""
        try:
            with db_conn() as conn:
                for pred in predictions:
                    conn.execute("""
                        INSERT INTO ai_vulnerability_predictions (
                            scan_id, category, likelihood, severity, affected_component,
                            evidence, cvss_score, description, impact, recommendation,
                            attack_surface, exploitability, ml_confidence
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        self.scan_id,
                        pred.category.value,
                        pred.likelihood,
                        pred.severity.display_name,
                        pred.affected_component,
                        pred.evidence,
                        pred.cvss_score,
                        pred.description,
                        pred.impact,
                        pred.recommendation,
                        pred.attack_surface,
                        pred.exploitability,
                        pred.machine_learning_confidence
                    ))
                
                conn.execute("""
                    INSERT INTO ai_risk_assessments (
                        scan_id, overall_score, risk_level, max_severity,
                        total_predicted, tech_risk, vuln_risk, exposure_score,
                        estimated_fix_time, business_impact
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    self.scan_id,
                    assessment.overall_score,
                    assessment.risk_level.display_name,
                    assessment.max_severity.display_name,
                    assessment.total_predicted,
                    assessment.technology_risk,
                    assessment.vulnerability_risk,
                    assessment.exposure_score,
                    assessment.estimated_fix_time,
                    assessment.business_impact
                ))
                
                conn.commit()
                
            self.log(f"Saved {len(predictions)} predictions and assessment to database")
            
        except Exception as e:
            self.log(f"Failed to save results: {str(e)}", "ERROR")
    
    def get_prediction_stats(self, scan_id: int = None) -> Dict:
        """Tahmin istatistiklerini getirir"""
        target_scan = scan_id or self.scan_id
        
        try:
            with db_conn() as conn:
                categories = conn.execute("""
                    SELECT category, COUNT(*) as count
                    FROM ai_vulnerability_predictions
                    WHERE scan_id = ?
                    GROUP BY category
                """, (target_scan,)).fetchall()
                
                severities = conn.execute("""
                    SELECT severity, COUNT(*) as count
                    FROM ai_vulnerability_predictions
                    WHERE scan_id = ?
                    GROUP BY severity
                """, (target_scan,)).fetchall()
                
                avg_confidence = conn.execute("""
                    SELECT AVG(ml_confidence) FROM ai_vulnerability_predictions
                    WHERE scan_id = ?
                """, (target_scan,)).fetchone()[0]
                
                return {
                    "scan_id": target_scan,
                    "categories": {c[0]: c[1] for c in categories},
                    "severities": {s[0]: s[1] for s in severities},
                    "total_predictions": sum(c[1] for c in categories),
                    "average_ml_confidence": round(avg_confidence or 0, 2)
                }
                
        except Exception as e:
            self.log(f"Failed to get stats: {str(e)}", "ERROR")
            return {}


# --- YARDIMCI FONKSİYONLAR ---

def run_ai_vulnerability_analysis(scan_id: int, headers: Dict, html: str,
                                  cookies: Dict, existing_vulns: List[str] = None) -> Dict:
    """Tek fonksiyon ile tam AI güvenlik açığı analizi"""
    analyzer = AIVulnerabilityPredictor(scan_id)
    return analyzer.analyze(headers, html, cookies, existing_vulns)


def get_ai_vuln_report(scan_id: int) -> Dict:
    """Kaydedilmiş AI güvenlik açığı raporunu getirir"""
    predictor = AIVulnerabilityPredictor(scan_id)
    stats = predictor.get_prediction_stats(scan_id)
    
    try:
        with db_conn() as conn:
            predictions = conn.execute("""
                SELECT * FROM ai_vulnerability_predictions
                WHERE scan_id = ?
                ORDER BY likelihood DESC
            """, (scan_id,)).fetchall()
            
            assessment = conn.execute("""
                SELECT * FROM ai_risk_assessments
                WHERE scan_id = ?
            """, (scan_id,)).fetchone()
            
            return {
                "scan_id": scan_id,
                "statistics": stats,
                "predictions": [
                    {
                        "id": p[0],
                        "category": p[2],
                        "likelihood": p[3],
                        "severity": p[4],
                        "component": p[5],
                        "ml_confidence": p[13]
                    }
                    for p in predictions
                ],
                "assessment": dict(zip(
                    ["scan_id", "overall_score", "risk_level", "max_severity",
                     "total_predicted", "tech_risk", "vuln_risk", "exposure_score",
                     "estimated_fix_time", "business_impact"],
                    assessment
                )) if assessment else None
            }
            
    except Exception as e:
        return {"error": str(e)}