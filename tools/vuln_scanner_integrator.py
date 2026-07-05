#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  AUTOMATED VULNERABILITY SCANNER INTEGRATOR                                   ║
║  Multi-Scanner Integration with AI Priority Ranking                          ║
║  Nuclei • OWASP ZAP • Nikto • SQLMap • Nmap NSE                             ║
╚══════════════════════════════════════════════════════════════════════════════╝

Features:
- Multiple scanner integration (Nuclei, ZAP, Nikto, SQLMap, Nmap)
- AI-powered vulnerability prioritization
- Automated exploit chaining
- Results correlation and deduplication
- Vulnerability heatmap generation
- Integration with lateral movement chain
- Report generation (JSON/PDF/HTML)

Author: CyberGhost Pro Team
Version: 2.0.0
"""

import os
import sys
import json
import uuid
import time
import shutil
import subprocess
import tempfile
import threading
import sqlite3
import hashlib
import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("VulnScannerIntegrator")


# ============================================================================
# ENUMS & CONSTANTS
# ============================================================================

class ScannerType(Enum):
    """Supported vulnerability scanners"""
    NUCLEI = "nuclei"
    OWASP_ZAP = "owasp_zap"
    NIKTO = "nikto"
    SQLMAP = "sqlmap"
    NMAP_NSE = "nmap_nse"
    WPSCAN = "wpscan"
    CUSTOM = "custom"


class VulnerabilityType(Enum):
    """Vulnerability categories"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    RCE = "remote_code_execution"
    SSRF = "ssrf"
    LFI = "lfi"
    RFI = "rfi"
    XXE = "xxe"
    IDOR = "idor"
    AUTH_BYPASS = "authentication_bypass"
    CSRF = "csrf"
    DESERIALIZATION = "deserialization"
    PATH_TRAVERSAL = "path_traversal"
    INFO_DISCLOSURE = "information_disclosure"
    MISCONFIGURATION = "misconfiguration"
    WEAK_CREDENTIALS = "weak_credentials"
    OPEN_REDIRECT = "open_redirect"
    UNKNOWN = "unknown"


class SeverityLevel(Enum):
    """CVSS-based severity levels"""
    CRITICAL = "critical"  # 9.0-10.0
    HIGH = "high"          # 7.0-8.9
    MEDIUM = "medium"      # 4.0-6.9
    LOW = "low"            # 0.1-3.9
    INFO = "info"          # 0.0


class ExploitDifficulty(Enum):
    """Exploit difficulty assessment"""
    TRIVIAL = "trivial"      # One-click/automated
    EASY = "easy"            # Basic tools/scripts
    MEDIUM = "medium"        # Requires customization
    HARD = "hard"            # Advanced techniques
    EXPERT = "expert"        # Research-level


class ScanStatus(Enum):
    """Scan execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# OWASP Top 10 mappings
OWASP_TOP_10 = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery (SSRF)"
}


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class Vulnerability:
    """Vulnerability finding"""
    vuln_id: str
    title: str
    description: str
    vuln_type: VulnerabilityType
    severity: SeverityLevel
    cvss_score: float
    
    # Target information
    target_url: str
    target_host: str
    target_port: int
    endpoint: str
    parameter: Optional[str] = None
    
    # Detection details
    scanner: ScannerType = ScannerType.CUSTOM
    scanner_confidence: float = 0.0
    evidence: str = ""
    payload: str = ""
    request: str = ""
    response: str = ""
    
    # Classification
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    exploit_difficulty: ExploitDifficulty = ExploitDifficulty.MEDIUM
    
    # AI Analysis
    ai_priority_score: float = 0.0
    ai_impact_analysis: str = ""
    ai_exploit_suggestions: List[str] = field(default_factory=list)
    lateral_chain_potential: bool = False
    
    # Metadata
    discovered_at: datetime = field(default_factory=datetime.now)
    verified: bool = False
    false_positive: bool = False
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        d = asdict(self)
        d['vuln_type'] = self.vuln_type.value
        d['severity'] = self.severity.value
        d['scanner'] = self.scanner.value
        d['exploit_difficulty'] = self.exploit_difficulty.value
        d['discovered_at'] = self.discovered_at.isoformat()
        return d


@dataclass
class ScanJob:
    """Vulnerability scan job"""
    job_id: str
    target: str
    scanners: List[ScannerType]
    status: ScanStatus = ScanStatus.PENDING
    
    # Configuration
    scan_type: str = "full"  # full, quick, deep
    max_depth: int = 3
    timeout: int = 3600
    parallel_scanners: bool = True
    
    # Results
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    total_vulns: int = 0
    critical_vulns: int = 0
    high_vulns: int = 0
    
    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    created_by: str = "system"


@dataclass
class ScannerConfig:
    """Scanner configuration"""
    scanner_type: ScannerType
    binary_path: str
    args: List[str] = field(default_factory=list)
    env_vars: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    timeout: int = 1800
    rate_limit: Optional[int] = None


# ============================================================================
# VULNERABILITY SCANNER INTEGRATOR
# ============================================================================

class VulnerabilityScannerIntegrator:
    """Main vulnerability scanner integration class"""
    
    def __init__(self, db_path: str = "/tmp/vuln_scanner.db"):
        self.db_path = db_path
        self.scanners: Dict[ScannerType, ScannerConfig] = {}
        self.active_scans: Dict[str, ScanJob] = {}
        self.executor = ThreadPoolExecutor(max_workers=5)
        
        self._init_database()
        self._detect_scanners()
        
        # AI integration
        try:
            from cybermodules.llm_engine import LLMEngine
            self.llm = LLMEngine(scan_id="vuln_scanner_ai")
            self.has_ai = True
        except:
            self.llm = None
            self.has_ai = False
            logger.warning("AI engine not available - priority ranking disabled")
    
    def _init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Scan jobs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_jobs (
                job_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                scanners JSON,
                status TEXT,
                config JSON,
                results JSON,
                created_at TEXT,
                started_at TEXT,
                completed_at TEXT
            )
        """)
        
        # Vulnerabilities table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                vuln_id TEXT PRIMARY KEY,
                job_id TEXT,
                title TEXT,
                description TEXT,
                vuln_type TEXT,
                severity TEXT,
                cvss_score REAL,
                target_url TEXT,
                scanner TEXT,
                evidence TEXT,
                ai_priority_score REAL,
                discovered_at TEXT,
                verified INTEGER,
                false_positive INTEGER,
                FOREIGN KEY (job_id) REFERENCES scan_jobs(job_id)
            )
        """)
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_severity ON vulnerabilities(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_target ON vulnerabilities(target_url)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cvss ON vulnerabilities(cvss_score)")
        
        conn.commit()
        conn.close()
    
    def _detect_scanners(self):
        """Auto-detect installed vulnerability scanners"""
        scanner_paths = {
            ScannerType.NUCLEI: "nuclei",
            ScannerType.NIKTO: "nikto",
            ScannerType.SQLMAP: "sqlmap",
            ScannerType.NMAP_NSE: "nmap",
            ScannerType.WPSCAN: "wpscan"
        }
        
        for scanner_type, binary_name in scanner_paths.items():
            binary_path = shutil.which(binary_name)
            if binary_path:
                self.scanners[scanner_type] = ScannerConfig(
                    scanner_type=scanner_type,
                    binary_path=binary_path,
                    enabled=True
                )
                logger.info(f"[+] Detected {scanner_type.value}: {binary_path}")
            else:
                logger.warning(f"[-] {scanner_type.value} not found in PATH")
        
        # OWASP ZAP (requires special handling)
        zap_paths = [
            "/usr/share/zaproxy/zap.sh",
            "/opt/zaproxy/zap.sh",
            os.path.expanduser("~/ZAP/zap.sh")
        ]
        
        for zap_path in zap_paths:
            if os.path.exists(zap_path):
                self.scanners[ScannerType.OWASP_ZAP] = ScannerConfig(
                    scanner_type=ScannerType.OWASP_ZAP,
                    binary_path=zap_path,
                    enabled=True
                )
                logger.info(f"[+] Detected OWASP ZAP: {zap_path}")
                break
    
    def scan_target(self, target: str, scanners: Optional[List[ScannerType]] = None,
                   scan_type: str = "full") -> str:
        """
        Start vulnerability scan
        
        Args:
            target: Target URL or IP
            scanners: List of scanners to use (None = all available)
            scan_type: Scan type (quick, full, deep)
        
        Returns:
            job_id: Scan job ID
        """
        job_id = f"scan_{uuid.uuid4().hex[:12]}"
        
        # Use all available scanners if not specified
        if scanners is None:
            scanners = [s for s in self.scanners.keys() if self.scanners[s].enabled]
        
        # Create scan job
        job = ScanJob(
            job_id=job_id,
            target=target,
            scanners=scanners,
            scan_type=scan_type,
            status=ScanStatus.PENDING
        )
        
        self.active_scans[job_id] = job
        
        # Save to database
        self._save_scan_job(job)
        
        # Start scan in background
        self.executor.submit(self._execute_scan, job_id)
        
        logger.info(f"[*] Started scan job {job_id} for {target}")
        
        return job_id
    
    def _execute_scan(self, job_id: str):
        """Execute vulnerability scan"""
        job = self.active_scans.get(job_id)
        if not job:
            logger.error(f"Job {job_id} not found")
            return
        
        job.status = ScanStatus.RUNNING
        job.started_at = datetime.now()
        
        try:
            logger.info(f"[*] Executing scan {job_id} for {job.target}")
            
            # Run scanners in parallel or sequential
            if job.parallel_scanners:
                vulnerabilities = self._run_parallel_scanners(job)
            else:
                vulnerabilities = self._run_sequential_scanners(job)
            
            # Deduplicate results
            unique_vulns = self._deduplicate_vulnerabilities(vulnerabilities)
            
            # AI priority ranking
            if self.has_ai:
                unique_vulns = self._ai_prioritize_vulnerabilities(unique_vulns)
            
            # Correlation analysis
            unique_vulns = self._correlate_vulnerabilities(unique_vulns)
            
            # Save results
            job.vulnerabilities = unique_vulns
            job.total_vulns = len(unique_vulns)
            job.critical_vulns = sum(1 for v in unique_vulns if v.severity == SeverityLevel.CRITICAL)
            job.high_vulns = sum(1 for v in unique_vulns if v.severity == SeverityLevel.HIGH)
            
            job.status = ScanStatus.COMPLETED
            job.completed_at = datetime.now()
            job.duration_seconds = (job.completed_at - job.started_at).total_seconds()
            
            # Save to database
            self._save_scan_results(job)
            
            # Integrate with lateral chain if high-impact vulns found
            self._integrate_with_lateral_chain(job)
            
            logger.info(f"[✓] Scan {job_id} completed - {job.total_vulns} vulnerabilities found")
        
        except Exception as e:
            logger.error(f"[!] Scan {job_id} failed: {e}")
            job.status = ScanStatus.FAILED
            job.completed_at = datetime.now()
    
    def _run_parallel_scanners(self, job: ScanJob) -> List[Vulnerability]:
        """Run scanners in parallel"""
        vulnerabilities = []
        futures = {}
        
        for scanner_type in job.scanners:
            if scanner_type not in self.scanners:
                logger.warning(f"Scanner {scanner_type.value} not available")
                continue
            
            future = self.executor.submit(self._run_scanner, scanner_type, job.target, job)
            futures[future] = scanner_type
        
        for future in as_completed(futures):
            scanner_type = futures[future]
            try:
                results = future.result(timeout=job.timeout)
                vulnerabilities.extend(results)
                logger.info(f"[+] {scanner_type.value}: {len(results)} findings")
            except Exception as e:
                logger.error(f"[!] {scanner_type.value} failed: {e}")
        
        return vulnerabilities
    
    def _run_sequential_scanners(self, job: ScanJob) -> List[Vulnerability]:
        """Run scanners sequentially"""
        vulnerabilities = []
        
        for scanner_type in job.scanners:
            if scanner_type not in self.scanners:
                continue
            
            try:
                results = self._run_scanner(scanner_type, job.target, job)
                vulnerabilities.extend(results)
                logger.info(f"[+] {scanner_type.value}: {len(results)} findings")
            except Exception as e:
                logger.error(f"[!] {scanner_type.value} failed: {e}")
        
        return vulnerabilities
    
    def _run_scanner(self, scanner_type: ScannerType, target: str, job: ScanJob) -> List[Vulnerability]:
        """Run individual scanner"""
        if scanner_type == ScannerType.NUCLEI:
            return self._run_nuclei(target, job)
        elif scanner_type == ScannerType.OWASP_ZAP:
            return self._run_zap(target, job)
        elif scanner_type == ScannerType.NIKTO:
            return self._run_nikto(target, job)
        elif scanner_type == ScannerType.SQLMAP:
            return self._run_sqlmap(target, job)
        elif scanner_type == ScannerType.NMAP_NSE:
            return self._run_nmap_nse(target, job)
        elif scanner_type == ScannerType.WPSCAN:
            return self._run_wpscan(target, job)
        else:
            logger.warning(f"Scanner {scanner_type.value} not implemented")
            return []
    
    # ========================================================================
    # NUCLEI INTEGRATION
    # ========================================================================
    
    def _run_nuclei(self, target: str, job: ScanJob) -> List[Vulnerability]:
        """Run Nuclei vulnerability scanner"""
        config = self.scanners.get(ScannerType.NUCLEI)
        if not config:
            return []
        
        vulnerabilities = []
        
        # Create temp file for results
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_file = f.name
        
        try:
            # Nuclei command with JSON output
            cmd = [
                config.binary_path,
                "-u", target,
                "-json",
                "-o", output_file,
                "-severity", "critical,high,medium,low",
                "-silent"
            ]
            
            # Add scan type specific flags
            if job.scan_type == "quick":
                cmd.extend(["-tags", "cve,exposure"])
            elif job.scan_type == "deep":
                cmd.extend(["-tags", "cve,exposure,network,file"])
            
            logger.info(f"[*] Running Nuclei: {' '.join(cmd)}")
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=config.timeout
            )
            
            # Parse JSON results
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        
                        try:
                            result = json.loads(line)
                            vuln = self._parse_nuclei_result(result, target)
                            if vuln:
                                vulnerabilities.append(vuln)
                        except json.JSONDecodeError:
                            continue
        
        except subprocess.TimeoutExpired:
            logger.error(f"[!] Nuclei scan timed out after {config.timeout}s")
        except Exception as e:
            logger.error(f"[!] Nuclei scan failed: {e}")
        finally:
            # Cleanup
            if os.path.exists(output_file):
                os.unlink(output_file)
        
        return vulnerabilities
    
    def _parse_nuclei_result(self, result: Dict, target: str) -> Optional[Vulnerability]:
        """Parse Nuclei JSON result"""
        try:
            info = result.get("info", {})
            
            # Extract severity
            severity_map = {
                "critical": SeverityLevel.CRITICAL,
                "high": SeverityLevel.HIGH,
                "medium": SeverityLevel.MEDIUM,
                "low": SeverityLevel.LOW,
                "info": SeverityLevel.INFO
            }
            
            severity_str = info.get("severity", "info").lower()
            severity = severity_map.get(severity_str, SeverityLevel.INFO)
            
            # CVSS score estimation
            cvss_score = {
                SeverityLevel.CRITICAL: 9.5,
                SeverityLevel.HIGH: 7.5,
                SeverityLevel.MEDIUM: 5.0,
                SeverityLevel.LOW: 2.5,
                SeverityLevel.INFO: 0.0
            }.get(severity, 0.0)
            
            # Determine vulnerability type
            tags = info.get("tags", [])
            vuln_type = self._classify_vuln_type(tags, info.get("name", ""))
            
            # Extract host/port
            matched_at = result.get("matched-at", result.get("matched", target))
            host, port = self._extract_host_port(matched_at)
            
            vuln = Vulnerability(
                vuln_id=f"nuclei_{uuid.uuid4().hex[:12]}",
                title=info.get("name", "Unknown Vulnerability"),
                description=info.get("description", "No description available"),
                vuln_type=vuln_type,
                severity=severity,
                cvss_score=cvss_score,
                target_url=matched_at,
                target_host=host,
                target_port=port,
                endpoint=matched_at.replace(f"http://{host}:{port}", "").replace(f"https://{host}:{port}", ""),
                scanner=ScannerType.NUCLEI,
                scanner_confidence=0.9,
                evidence=result.get("extracted-results", [""])[0] if result.get("extracted-results") else "",
                payload=result.get("matcher-name", ""),
                cwe_id=self._extract_cwe(tags),
                owasp_category=self._map_to_owasp(vuln_type),
                tags=tags,
                discovered_at=datetime.now()
            )
            
            return vuln
        
        except Exception as e:
            logger.error(f"Failed to parse Nuclei result: {e}")
            return None
    
    # ========================================================================
    # OWASP ZAP INTEGRATION
    # ========================================================================
    
    def _run_zap(self, target: str, job: ScanJob) -> List[Vulnerability]:
        """Run OWASP ZAP scanner"""
        config = self.scanners.get(ScannerType.OWASP_ZAP)
        if not config:
            return []
        
        vulnerabilities = []
        
        try:
            # ZAP baseline scan (for quick/full)
            # For deep scan, use full active scan
            
            output_file = tempfile.mktemp(suffix='.json')
            
            cmd = [
                config.binary_path,
                "-cmd",
                "-quickurl", target,
                "-quickprogress",
                "-quickout", output_file
            ]
            
            if job.scan_type == "deep":
                # Use active scan (slower but more thorough)
                cmd = [
                    config.binary_path,
                    "-cmd",
                    "-quickurl", target,
                    "-quickprogress",
                    "-quickout", output_file
                ]
            
            logger.info(f"[*] Running OWASP ZAP: {' '.join(cmd[:5])}...")
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=config.timeout
            )
            
            # Parse ZAP JSON output
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    data = json.load(f)
                    
                    for site in data.get("site", []):
                        for alert in site.get("alerts", []):
                            vuln = self._parse_zap_alert(alert, target)
                            if vuln:
                                vulnerabilities.append(vuln)
                
                os.unlink(output_file)
        
        except subprocess.TimeoutExpired:
            logger.error(f"[!] ZAP scan timed out after {config.timeout}s")
        except Exception as e:
            logger.error(f"[!] ZAP scan failed: {e}")
        
        return vulnerabilities
    
    def _parse_zap_alert(self, alert: Dict, target: str) -> Optional[Vulnerability]:
        """Parse ZAP alert"""
        try:
            # ZAP risk levels: High, Medium, Low, Informational
            risk_map = {
                "High": SeverityLevel.HIGH,
                "Medium": SeverityLevel.MEDIUM,
                "Low": SeverityLevel.LOW,
                "Informational": SeverityLevel.INFO
            }
            
            risk = alert.get("riskdesc", "Low").split()[0]
            severity = risk_map.get(risk, SeverityLevel.LOW)
            
            # CVSS score
            cvss_score = {
                SeverityLevel.CRITICAL: 9.0,
                SeverityLevel.HIGH: 7.0,
                SeverityLevel.MEDIUM: 5.0,
                SeverityLevel.LOW: 2.0,
                SeverityLevel.INFO: 0.0
            }.get(severity, 0.0)
            
            # Classify vulnerability type
            alert_name = alert.get("alert", "")
            vuln_type = self._classify_vuln_type_by_name(alert_name)
            
            # Extract host/port
            url = alert.get("url", target)
            host, port = self._extract_host_port(url)
            
            vuln = Vulnerability(
                vuln_id=f"zap_{uuid.uuid4().hex[:12]}",
                title=alert.get("alert", "Unknown Vulnerability"),
                description=alert.get("desc", "No description"),
                vuln_type=vuln_type,
                severity=severity,
                cvss_score=cvss_score,
                target_url=url,
                target_host=host,
                target_port=port,
                endpoint=alert.get("url", "").replace(f"http://{host}:{port}", "").replace(f"https://{host}:{port}", ""),
                parameter=alert.get("param", ""),
                scanner=ScannerType.OWASP_ZAP,
                scanner_confidence=0.85,
                evidence=alert.get("evidence", ""),
                payload=alert.get("attack", ""),
                request=alert.get("request", ""),
                response=alert.get("response", ""),
                cwe_id=str(alert.get("cweid", "")),
                owasp_category=self._map_to_owasp(vuln_type),
                tags=[alert.get("pluginid", "")],
                discovered_at=datetime.now()
            )
            
            return vuln
        
        except Exception as e:
            logger.error(f"Failed to parse ZAP alert: {e}")
            return None
    
    # ========================================================================
    # NIKTO INTEGRATION
    # ========================================================================
    
    def _run_nikto(self, target: str, job: ScanJob) -> List[Vulnerability]:
        """Run Nikto web server scanner"""
        config = self.scanners.get(ScannerType.NIKTO)
        if not config:
            return []
        
        vulnerabilities = []
        output_file = tempfile.mktemp(suffix='.json')
        
        try:
            cmd = [
                config.binary_path,
                "-h", target,
                "-Format", "json",
                "-output", output_file,
                "-Tuning", "x"  # All tests
            ]
            
            if job.scan_type == "quick":
                cmd.extend(["-Tuning", "1"])  # Interesting files only
            
            logger.info(f"[*] Running Nikto: {' '.join(cmd)}")
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=config.timeout
            )
            
            # Parse Nikto JSON output
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    data = json.load(f)
                    
                    for vuln_data in data.get("vulnerabilities", []):
                        vuln = self._parse_nikto_result(vuln_data, target)
                        if vuln:
                            vulnerabilities.append(vuln)
                
                os.unlink(output_file)
        
        except subprocess.TimeoutExpired:
            logger.error(f"[!] Nikto scan timed out after {config.timeout}s")
        except Exception as e:
            logger.error(f"[!] Nikto scan failed: {e}")
        
        return vulnerabilities
    
    def _parse_nikto_result(self, result: Dict, target: str) -> Optional[Vulnerability]:
        """Parse Nikto result"""
        try:
            # Nikto doesn't provide severity, estimate based on description
            description = result.get("msg", "").lower()
            severity = self._estimate_severity_from_description(description)
            
            cvss_score = {
                SeverityLevel.CRITICAL: 9.0,
                SeverityLevel.HIGH: 7.0,
                SeverityLevel.MEDIUM: 5.0,
                SeverityLevel.LOW: 2.0,
                SeverityLevel.INFO: 0.0
            }.get(severity, 0.0)
            
            # Classify vulnerability
            vuln_type = self._classify_vuln_type_by_name(description)
            
            host, port = self._extract_host_port(target)
            
            vuln = Vulnerability(
                vuln_id=f"nikto_{uuid.uuid4().hex[:12]}",
                title=result.get("id", "Nikto Finding"),
                description=result.get("msg", "No description"),
                vuln_type=vuln_type,
                severity=severity,
                cvss_score=cvss_score,
                target_url=target,
                target_host=host,
                target_port=port,
                endpoint=result.get("url", ""),
                scanner=ScannerType.NIKTO,
                scanner_confidence=0.7,
                evidence=result.get("msg", ""),
                tags=["nikto", result.get("OSVDB", "")],
                discovered_at=datetime.now()
            )
            
            return vuln
        
        except Exception as e:
            logger.error(f"Failed to parse Nikto result: {e}")
            return None
    
    # ========================================================================
    # SQLMAP INTEGRATION
    # ========================================================================
    
    def _run_sqlmap(self, target: str, job: ScanJob) -> List[Vulnerability]:
        """Run SQLMap for SQL injection testing"""
        config = self.scanners.get(ScannerType.SQLMAP)
        if not config:
            return []
        
        vulnerabilities = []
        
        try:
            # SQLMap basic scan
            cmd = [
                config.binary_path,
                "-u", target,
                "--batch",
                "--level", "1" if job.scan_type == "quick" else "3",
                "--risk", "1" if job.scan_type == "quick" else "2",
                "--threads", "5",
                "--output-dir", "/tmp/sqlmap_output"
            ]
            
            logger.info(f"[*] Running SQLMap: {' '.join(cmd)}")
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=config.timeout
            )
            
            # Parse SQLMap output
            output = process.stdout + process.stderr
            
            if "is vulnerable" in output.lower() or "injectable" in output.lower():
                # Extract injection details
                vuln = self._parse_sqlmap_output(output, target)
                if vuln:
                    vulnerabilities.append(vuln)
        
        except subprocess.TimeoutExpired:
            logger.error(f"[!] SQLMap scan timed out after {config.timeout}s")
        except Exception as e:
            logger.error(f"[!] SQLMap scan failed: {e}")
        
        return vulnerabilities
    
    def _parse_sqlmap_output(self, output: str, target: str) -> Optional[Vulnerability]:
        """Parse SQLMap output"""
        try:
            # Extract parameter
            param_match = re.search(r"Parameter: (.+?) \(", output)
            parameter = param_match.group(1) if param_match else "unknown"
            
            # Extract injection type
            type_match = re.search(r"Type: (.+?)\n", output)
            injection_type = type_match.group(1) if type_match else "SQL Injection"
            
            # Extract payload
            payload_match = re.search(r"Payload: (.+?)\n", output)
            payload = payload_match.group(1) if payload_match else ""
            
            host, port = self._extract_host_port(target)
            
            vuln = Vulnerability(
                vuln_id=f"sqlmap_{uuid.uuid4().hex[:12]}",
                title=f"SQL Injection - {injection_type}",
                description=f"SQL injection vulnerability found in parameter '{parameter}'",
                vuln_type=VulnerabilityType.SQL_INJECTION,
                severity=SeverityLevel.CRITICAL,
                cvss_score=9.0,
                target_url=target,
                target_host=host,
                target_port=port,
                endpoint="/",
                parameter=parameter,
                scanner=ScannerType.SQLMAP,
                scanner_confidence=0.95,
                evidence=output[:500],
                payload=payload,
                cwe_id="CWE-89",
                owasp_category="A03:2021",
                exploit_difficulty=ExploitDifficulty.EASY,
                lateral_chain_potential=True,
                tags=["sqli", "database"],
                discovered_at=datetime.now()
            )
            
            return vuln
        
        except Exception as e:
            logger.error(f"Failed to parse SQLMap output: {e}")
            return None
    
    # ========================================================================
    # NMAP NSE INTEGRATION
    # ========================================================================
    
    def _run_nmap_nse(self, target: str, job: ScanJob) -> List[Vulnerability]:
        """Run Nmap with vulnerability scripts"""
        config = self.scanners.get(ScannerType.NMAP_NSE)
        if not config:
            return []
        
        vulnerabilities = []
        output_file = tempfile.mktemp(suffix='.xml')
        
        try:
            # Extract host from URL if needed
            host, port = self._extract_host_port(target)
            
            # Nmap command with NSE scripts
            cmd = [
                config.binary_path,
                "-sV",
                "--script", "vuln",
                "-oX", output_file,
                host
            ]
            
            if port != 80 and port != 443:
                cmd.extend(["-p", str(port)])
            
            logger.info(f"[*] Running Nmap NSE: {' '.join(cmd)}")
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=config.timeout
            )
            
            # Parse Nmap XML output
            if os.path.exists(output_file):
                vulnerabilities = self._parse_nmap_xml(output_file, target)
                os.unlink(output_file)
        
        except subprocess.TimeoutExpired:
            logger.error(f"[!] Nmap scan timed out after {config.timeout}s")
        except Exception as e:
            logger.error(f"[!] Nmap scan failed: {e}")
        
        return vulnerabilities
    
    def _parse_nmap_xml(self, xml_file: str, target: str) -> List[Vulnerability]:
        """Parse Nmap XML output"""
        vulnerabilities = []
        
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host in root.findall('.//host'):
                for port in host.findall('.//port'):
                    for script in port.findall('.//script'):
                        script_id = script.get('id', '')
                        script_output = script.get('output', '')
                        
                        # Check if vulnerability found
                        if 'VULNERABLE' in script_output or 'vulnerable' in script_output:
                            vuln = self._parse_nmap_script_output(
                                script_id, script_output, target, port.get('portid', '80')
                            )
                            if vuln:
                                vulnerabilities.append(vuln)
        
        except Exception as e:
            logger.error(f"Failed to parse Nmap XML: {e}")
        
        return vulnerabilities
    
    def _parse_nmap_script_output(self, script_id: str, output: str, target: str, port: str) -> Optional[Vulnerability]:
        """Parse Nmap NSE script output"""
        try:
            # Estimate severity based on script output
            severity = self._estimate_severity_from_description(output)
            
            cvss_score = {
                SeverityLevel.CRITICAL: 9.0,
                SeverityLevel.HIGH: 7.0,
                SeverityLevel.MEDIUM: 5.0,
                SeverityLevel.LOW: 2.0,
                SeverityLevel.INFO: 0.0
            }.get(severity, 0.0)
            
            # Classify vulnerability
            vuln_type = self._classify_vuln_type_by_name(script_id + " " + output)
            
            host, _ = self._extract_host_port(target)
            
            vuln = Vulnerability(
                vuln_id=f"nmap_{uuid.uuid4().hex[:12]}",
                title=f"Nmap NSE: {script_id}",
                description=output[:200],
                vuln_type=vuln_type,
                severity=severity,
                cvss_score=cvss_score,
                target_url=f"{target}:{port}",
                target_host=host,
                target_port=int(port),
                endpoint="/",
                scanner=ScannerType.NMAP_NSE,
                scanner_confidence=0.8,
                evidence=output,
                tags=["nmap", script_id],
                discovered_at=datetime.now()
            )
            
            return vuln
        
        except Exception as e:
            logger.error(f"Failed to parse Nmap script output: {e}")
            return None
    
    # ========================================================================
    # WPSCAN INTEGRATION
    # ========================================================================
    
    def _run_wpscan(self, target: str, job: ScanJob) -> List[Vulnerability]:
        """Run WPScan for WordPress vulnerabilities"""
        config = self.scanners.get(ScannerType.WPSCAN)
        if not config:
            return []
        
        vulnerabilities = []
        
        try:
            cmd = [
                config.binary_path,
                "--url", target,
                "--format", "json",
                "--no-banner"
            ]
            
            if job.scan_type == "deep":
                cmd.extend([
                    "--enumerate", "ap,at,cb,dbe",
                    "--plugins-detection", "aggressive"
                ])
            
            logger.info(f"[*] Running WPScan: {' '.join(cmd)}")
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=config.timeout
            )
            
            # Parse WPScan JSON output
            try:
                data = json.loads(process.stdout)
                
                # Parse vulnerabilities from plugins, themes, etc.
                for plugin_data in data.get("plugins", {}).values():
                    for vuln_data in plugin_data.get("vulnerabilities", []):
                        vuln = self._parse_wpscan_vuln(vuln_data, target, "plugin")
                        if vuln:
                            vulnerabilities.append(vuln)
                
                for theme_data in data.get("themes", {}).values():
                    for vuln_data in theme_data.get("vulnerabilities", []):
                        vuln = self._parse_wpscan_vuln(vuln_data, target, "theme")
                        if vuln:
                            vulnerabilities.append(vuln)
            
            except json.JSONDecodeError:
                pass
        
        except subprocess.TimeoutExpired:
            logger.error(f"[!] WPScan timed out after {config.timeout}s")
        except Exception as e:
            logger.error(f"[!] WPScan failed: {e}")
        
        return vulnerabilities
    
    def _parse_wpscan_vuln(self, vuln_data: Dict, target: str, component: str) -> Optional[Vulnerability]:
        """Parse WPScan vulnerability"""
        try:
            title = vuln_data.get("title", "WordPress Vulnerability")
            
            # Parse CVSS score
            cvss_score = 0.0
            if "cvss" in vuln_data:
                cvss_score = float(vuln_data["cvss"].get("score", 0.0))
            
            # Determine severity from CVSS
            if cvss_score >= 9.0:
                severity = SeverityLevel.CRITICAL
            elif cvss_score >= 7.0:
                severity = SeverityLevel.HIGH
            elif cvss_score >= 4.0:
                severity = SeverityLevel.MEDIUM
            elif cvss_score > 0.0:
                severity = SeverityLevel.LOW
            else:
                severity = SeverityLevel.INFO
            
            # Classify vulnerability type
            vuln_type = self._classify_vuln_type_by_name(title)
            
            host, port = self._extract_host_port(target)
            
            vuln = Vulnerability(
                vuln_id=f"wpscan_{uuid.uuid4().hex[:12]}",
                title=f"{component.title()}: {title}",
                description=vuln_data.get("description", ""),
                vuln_type=vuln_type,
                severity=severity,
                cvss_score=cvss_score,
                target_url=target,
                target_host=host,
                target_port=port,
                endpoint="/",
                scanner=ScannerType.WPSCAN,
                scanner_confidence=0.9,
                evidence=str(vuln_data.get("references", {})),
                tags=["wordpress", component],
                discovered_at=datetime.now()
            )
            
            return vuln
        
        except Exception as e:
            logger.error(f"Failed to parse WPScan vulnerability: {e}")
            return None
    
    # ========================================================================
    # AI ANALYSIS & PRIORITIZATION
    # ========================================================================
    
    def _ai_prioritize_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Use AI to prioritize vulnerabilities"""
        if not self.has_ai or not vulnerabilities:
            return vulnerabilities
        
        logger.info(f"[*] AI prioritizing {len(vulnerabilities)} vulnerabilities...")
        
        for vuln in vulnerabilities:
            try:
                # Create analysis prompt
                prompt = f"""Analyze this vulnerability and provide:
1. Real-world exploitability (0-100)
2. Business impact assessment
3. Exploit chain potential
4. Specific exploit suggestions

Vulnerability:
- Title: {vuln.title}
- Type: {vuln.vuln_type.value}
- Severity: {vuln.severity.value}
- CVSS: {vuln.cvss_score}
- Description: {vuln.description}
- Evidence: {vuln.evidence[:200]}

Output as JSON: {{"priority_score": 85, "impact": "...", "exploitable": true, "suggestions": [...]}}"""
                
                response = self.llm.query(prompt)
                
                # Parse AI response
                try:
                    analysis = json.loads(response)
                    vuln.ai_priority_score = analysis.get("priority_score", 0) / 100.0
                    vuln.ai_impact_analysis = analysis.get("impact", "")
                    vuln.ai_exploit_suggestions = analysis.get("suggestions", [])
                    vuln.lateral_chain_potential = analysis.get("exploitable", False)
                except json.JSONDecodeError:
                    vuln.ai_priority_score = vuln.cvss_score / 10.0
            
            except Exception as e:
                logger.error(f"AI analysis failed for {vuln.vuln_id}: {e}")
                vuln.ai_priority_score = vuln.cvss_score / 10.0
        
        # Sort by AI priority score
        vulnerabilities.sort(key=lambda v: v.ai_priority_score, reverse=True)
        
        return vulnerabilities
    
    # ========================================================================
    # HELPER METHODS
    # ========================================================================
    
    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities"""
        seen = set()
        unique = []
        
        for vuln in vulnerabilities:
            # Create fingerprint
            fingerprint = hashlib.md5(
                f"{vuln.title}{vuln.target_url}{vuln.parameter}{vuln.vuln_type.value}".encode()
            ).hexdigest()
            
            if fingerprint not in seen:
                seen.add(fingerprint)
                unique.append(vuln)
        
        logger.info(f"[*] Deduplicated {len(vulnerabilities)} -> {len(unique)} vulnerabilities")
        
        return unique
    
    def _correlate_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Correlate vulnerabilities to find exploit chains"""
        # Group by target
        by_target = {}
        for vuln in vulnerabilities:
            key = f"{vuln.target_host}:{vuln.target_port}"
            if key not in by_target:
                by_target[key] = []
            by_target[key].append(vuln)
        
        # Look for exploit chains
        for target, vulns in by_target.items():
            # Check for SQLi + RCE chains
            has_sqli = any(v.vuln_type == VulnerabilityType.SQL_INJECTION for v in vulns)
            has_file_upload = any("upload" in v.title.lower() for v in vulns)
            
            if has_sqli and has_file_upload:
                for vuln in vulns:
                    if vuln.vuln_type == VulnerabilityType.SQL_INJECTION:
                        vuln.lateral_chain_potential = True
                        vuln.ai_exploit_suggestions.append("Chain with file upload for RCE")
        
        return vulnerabilities
    
    def _classify_vuln_type(self, tags: List[str], name: str) -> VulnerabilityType:
        """Classify vulnerability type from tags"""
        tags_str = " ".join(tags).lower() + " " + name.lower()
        
        if any(x in tags_str for x in ["sqli", "sql", "injection"]):
            return VulnerabilityType.SQL_INJECTION
        elif any(x in tags_str for x in ["xss", "cross-site"]):
            return VulnerabilityType.XSS
        elif any(x in tags_str for x in ["rce", "command", "exec"]):
            return VulnerabilityType.RCE
        elif any(x in tags_str for x in ["ssrf", "server-side request"]):
            return VulnerabilityType.SSRF
        elif any(x in tags_str for x in ["lfi", "file inclusion"]):
            return VulnerabilityType.LFI
        elif any(x in tags_str for x in ["xxe", "xml external"]):
            return VulnerabilityType.XXE
        elif any(x in tags_str for x in ["idor", "insecure direct"]):
            return VulnerabilityType.IDOR
        elif any(x in tags_str for x in ["auth", "bypass"]):
            return VulnerabilityType.AUTH_BYPASS
        elif any(x in tags_str for x in ["csrf", "cross-site request"]):
            return VulnerabilityType.CSRF
        else:
            return VulnerabilityType.UNKNOWN
    
    def _classify_vuln_type_by_name(self, name: str) -> VulnerabilityType:
        """Classify vulnerability type from name/description"""
        name_lower = name.lower()
        
        if "sql" in name_lower or "injection" in name_lower:
            return VulnerabilityType.SQL_INJECTION
        elif "xss" in name_lower or "cross-site scripting" in name_lower:
            return VulnerabilityType.XSS
        elif "command" in name_lower or "rce" in name_lower or "exec" in name_lower:
            return VulnerabilityType.COMMAND_INJECTION
        elif "ssrf" in name_lower:
            return VulnerabilityType.SSRF
        elif "lfi" in name_lower or "file inclusion" in name_lower:
            return VulnerabilityType.LFI
        elif "traverse" in name_lower or "path" in name_lower:
            return VulnerabilityType.PATH_TRAVERSAL
        elif "disclosure" in name_lower or "information" in name_lower:
            return VulnerabilityType.INFO_DISCLOSURE
        elif "misconfigur" in name_lower:
            return VulnerabilityType.MISCONFIGURATION
        elif "redirect" in name_lower:
            return VulnerabilityType.OPEN_REDIRECT
        else:
            return VulnerabilityType.UNKNOWN
    
    def _estimate_severity_from_description(self, description: str) -> SeverityLevel:
        """Estimate severity from description"""
        desc_lower = description.lower()
        
        if any(x in desc_lower for x in ["critical", "remote code", "rce", "sql injection"]):
            return SeverityLevel.CRITICAL
        elif any(x in desc_lower for x in ["high", "authentication", "bypass", "privilege"]):
            return SeverityLevel.HIGH
        elif any(x in desc_lower for x in ["medium", "xss", "csrf", "disclosure"]):
            return SeverityLevel.MEDIUM
        elif any(x in desc_lower for x in ["low", "information", "version"]):
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO
    
    def _extract_cwe(self, tags: List[str]) -> Optional[str]:
        """Extract CWE ID from tags"""
        for tag in tags:
            if "cwe" in tag.lower():
                match = re.search(r'cwe-(\d+)', tag.lower())
                if match:
                    return f"CWE-{match.group(1)}"
        return None
    
    def _map_to_owasp(self, vuln_type: VulnerabilityType) -> Optional[str]:
        """Map vulnerability type to OWASP Top 10"""
        mapping = {
            VulnerabilityType.SQL_INJECTION: "A03:2021",
            VulnerabilityType.XSS: "A03:2021",
            VulnerabilityType.COMMAND_INJECTION: "A03:2021",
            VulnerabilityType.AUTH_BYPASS: "A07:2021",
            VulnerabilityType.IDOR: "A01:2021",
            VulnerabilityType.SSRF: "A10:2021",
            VulnerabilityType.MISCONFIGURATION: "A05:2021",
            VulnerabilityType.WEAK_CREDENTIALS: "A07:2021"
        }
        return mapping.get(vuln_type)
    
    def _extract_host_port(self, url: str) -> Tuple[str, int]:
        """Extract host and port from URL"""
        # Remove protocol
        url = url.replace("https://", "").replace("http://", "")
        
        # Extract host:port
        if ":" in url:
            parts = url.split(":")
            host = parts[0].split("/")[0]
            try:
                port = int(parts[1].split("/")[0])
            except:
                port = 443 if "https" in url else 80
        else:
            host = url.split("/")[0]
            port = 443 if "https" in url else 80
        
        return host, port
    
    # ========================================================================
    # INTEGRATION WITH LATERAL CHAIN
    # ========================================================================
    
    def _integrate_with_lateral_chain(self, job: ScanJob):
        """Integrate high-impact vulnerabilities with lateral movement chain"""
        try:
            from cybermodules.ai_lateral_guide import get_lateral_guide
            
            lateral_guide = get_lateral_guide()
            
            # Find exploitable vulnerabilities
            exploitable = [
                v for v in job.vulnerabilities
                if v.lateral_chain_potential and v.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
            ]
            
            if exploitable:
                logger.info(f"[*] Found {len(exploitable)} exploitable vulnerabilities for lateral chain")
                
                for vuln in exploitable:
                    # Add to lateral chain
                    lateral_guide.add_entry_point({
                        "type": "vulnerability",
                        "vuln_id": vuln.vuln_id,
                        "title": vuln.title,
                        "severity": vuln.severity.value,
                        "target": vuln.target_url,
                        "exploit_suggestions": vuln.ai_exploit_suggestions
                    })
        
        except Exception as e:
            logger.error(f"Failed to integrate with lateral chain: {e}")
    
    # ========================================================================
    # DATABASE OPERATIONS
    # ========================================================================
    
    def _save_scan_job(self, job: ScanJob):
        """Save scan job to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO scan_jobs (job_id, target, scanners, status, config, results, created_at, started_at, completed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            job.job_id,
            job.target,
            json.dumps([s.value for s in job.scanners]),
            job.status.value,
            json.dumps({
                "scan_type": job.scan_type,
                "max_depth": job.max_depth,
                "timeout": job.timeout
            }),
            json.dumps({
                "total_vulns": job.total_vulns,
                "critical_vulns": job.critical_vulns,
                "high_vulns": job.high_vulns
            }),
            job.created_at.isoformat(),
            job.started_at.isoformat() if job.started_at else None,
            job.completed_at.isoformat() if job.completed_at else None
        ))
        
        conn.commit()
        conn.close()
    
    def _save_scan_results(self, job: ScanJob):
        """Save scan results to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Update job
        self._save_scan_job(job)
        
        # Save vulnerabilities
        for vuln in job.vulnerabilities:
            cursor.execute("""
                INSERT OR REPLACE INTO vulnerabilities 
                (vuln_id, job_id, title, description, vuln_type, severity, cvss_score, target_url, scanner, evidence, ai_priority_score, discovered_at, verified, false_positive)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                vuln.vuln_id,
                job.job_id,
                vuln.title,
                vuln.description,
                vuln.vuln_type.value,
                vuln.severity.value,
                vuln.cvss_score,
                vuln.target_url,
                vuln.scanner.value,
                vuln.evidence[:1000],
                vuln.ai_priority_score,
                vuln.discovered_at.isoformat(),
                1 if vuln.verified else 0,
                1 if vuln.false_positive else 0
            ))
        
        conn.commit()
        conn.close()
    
    # ========================================================================
    # PUBLIC API
    # ========================================================================
    
    def get_scan_status(self, job_id: str) -> Dict[str, Any]:
        """Get scan job status"""
        job = self.active_scans.get(job_id)
        if not job:
            # Try loading from database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scan_jobs WHERE job_id = ?", (job_id,))
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                return {"success": False, "error": "Scan job not found"}
        
        if job:
            return {
                "success": True,
                "job_id": job.job_id,
                "target": job.target,
                "status": job.status.value,
                "total_vulns": job.total_vulns,
                "critical_vulns": job.critical_vulns,
                "high_vulns": job.high_vulns,
                "started_at": job.started_at.isoformat() if job.started_at else None,
                "completed_at": job.completed_at.isoformat() if job.completed_at else None,
                "duration_seconds": job.duration_seconds
            }
        
        return {"success": False, "error": "Failed to load job"}
    
    def get_vulnerabilities(self, job_id: str, severity: Optional[SeverityLevel] = None) -> List[Dict]:
        """Get vulnerabilities for scan job"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if severity:
            cursor.execute("""
                SELECT * FROM vulnerabilities 
                WHERE job_id = ? AND severity = ?
                ORDER BY ai_priority_score DESC
            """, (job_id, severity.value))
        else:
            cursor.execute("""
                SELECT * FROM vulnerabilities 
                WHERE job_id = ?
                ORDER BY ai_priority_score DESC
            """, (job_id,))
        
        rows = cursor.fetchall()
        conn.close()
        
        vulnerabilities = []
        for row in rows:
            vulnerabilities.append({
                "vuln_id": row[0],
                "title": row[2],
                "description": row[3],
                "vuln_type": row[4],
                "severity": row[5],
                "cvss_score": row[6],
                "target_url": row[7],
                "scanner": row[8],
                "ai_priority_score": row[10],
                "discovered_at": row[11]
            })
        
        return vulnerabilities
    
    def generate_heatmap(self, job_id: str) -> Dict[str, Any]:
        """Generate vulnerability heatmap"""
        vulnerabilities = self.get_vulnerabilities(job_id)
        
        # Count by severity
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        # Count by type
        type_counts = {}
        
        for vuln in vulnerabilities:
            severity_counts[vuln["severity"]] += 1
            
            vuln_type = vuln["vuln_type"]
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        
        return {
            "severity_distribution": severity_counts,
            "type_distribution": type_counts,
            "total_vulnerabilities": len(vulnerabilities)
        }
    
    def export_report(self, job_id: str, format: str = "json") -> str:
        """Export scan report"""
        vulnerabilities = self.get_vulnerabilities(job_id)
        heatmap = self.generate_heatmap(job_id)
        
        report = {
            "job_id": job_id,
            "timestamp": datetime.now().isoformat(),
            "summary": heatmap,
            "vulnerabilities": vulnerabilities
        }
        
        if format == "json":
            return json.dumps(report, indent=2)
        elif format == "html":
            return self._generate_html_report(report)
        else:
            return json.dumps(report)
    
    def _generate_html_report(self, report: Dict) -> str:
        """Generate HTML report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .summary {{ background: #f0f0f0; padding: 15px; border-radius: 5px; }}
        .vuln {{ border: 1px solid #ddd; padding: 10px; margin: 10px 0; border-radius: 5px; }}
        .critical {{ border-left: 5px solid #d32f2f; }}
        .high {{ border-left: 5px solid #f57c00; }}
        .medium {{ border-left: 5px solid #fbc02d; }}
        .low {{ border-left: 5px solid #388e3c; }}
    </style>
</head>
<body>
    <h1>Vulnerability Scan Report</h1>
    <p>Generated: {report['timestamp']}</p>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Vulnerabilities: {report['summary']['total_vulnerabilities']}</p>
        <ul>
            <li>Critical: {report['summary']['severity_distribution']['critical']}</li>
            <li>High: {report['summary']['severity_distribution']['high']}</li>
            <li>Medium: {report['summary']['severity_distribution']['medium']}</li>
            <li>Low: {report['summary']['severity_distribution']['low']}</li>
        </ul>
    </div>
    
    <h2>Vulnerabilities</h2>
"""
        
        for vuln in report['vulnerabilities']:
            html += f"""
    <div class="vuln {vuln['severity']}">
        <h3>{vuln['title']}</h3>
        <p><strong>Severity:</strong> {vuln['severity'].upper()} (CVSS: {vuln['cvss_score']})</p>
        <p><strong>Type:</strong> {vuln['vuln_type']}</p>
        <p><strong>Target:</strong> {vuln['target_url']}</p>
        <p>{vuln['description']}</p>
    </div>
"""
        
        html += """
</body>
</html>
"""
        
        return html


# ============================================================================
# SINGLETON & API
# ============================================================================

_vuln_scanner = None

def get_vuln_scanner() -> VulnerabilityScannerIntegrator:
    """Get vulnerability scanner singleton"""
    global _vuln_scanner
    if _vuln_scanner is None:
        _vuln_scanner = VulnerabilityScannerIntegrator()
    return _vuln_scanner


# ============================================================================
# CLI INTERFACE
# ============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Automated Vulnerability Scanner Integrator")
    parser.add_argument("target", help="Target URL or IP")
    parser.add_argument("--scanners", nargs="+", help="Scanners to use (nuclei, zap, nikto, sqlmap, nmap)")
    parser.add_argument("--scan-type", default="full", choices=["quick", "full", "deep"])
    parser.add_argument("--output", help="Output file (JSON or HTML)")
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = get_vuln_scanner()
    
    # Parse scanner types
    scanner_types = None
    if args.scanners:
        scanner_map = {
            "nuclei": ScannerType.NUCLEI,
            "zap": ScannerType.OWASP_ZAP,
            "nikto": ScannerType.NIKTO,
            "sqlmap": ScannerType.SQLMAP,
            "nmap": ScannerType.NMAP_NSE,
            "wpscan": ScannerType.WPSCAN
        }
        scanner_types = [scanner_map[s] for s in args.scanners if s in scanner_map]
    
    # Start scan
    print(f"[*] Starting vulnerability scan of {args.target}")
    job_id = scanner.scan_target(args.target, scanner_types, args.scan_type)
    
    print(f"[*] Scan job ID: {job_id}")
    print(f"[*] Waiting for scan to complete...")
    
    # Wait for completion
    while True:
        status = scanner.get_scan_status(job_id)
        if status["success"]:
            if status["status"] in ["completed", "failed"]:
                break
        time.sleep(5)
    
    # Print results
    status = scanner.get_scan_status(job_id)
    print(f"\n[✓] Scan completed!")
    print(f"    Total vulnerabilities: {status['total_vulns']}")
    print(f"    Critical: {status['critical_vulns']}")
    print(f"    High: {status['high_vulns']}")
    print(f"    Duration: {status['duration_seconds']:.1f}s")
    
    # Export report
    if args.output:
        format = "html" if args.output.endswith(".html") else "json"
        report = scanner.export_report(job_id, format)
        
        with open(args.output, 'w') as f:
            f.write(report)
        
        print(f"\n[+] Report saved to {args.output}")
