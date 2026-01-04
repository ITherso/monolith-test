# --- SOCIAL ENGINEERING MODULE ---
import datetime
import json
import re
import secrets
import socket
import ssl
import urllib.request
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

from cyberapp.models.db import db_conn


class GhostEngine:
    def __init__(self, target, scan_id):
        self.target = target.strip()
        self.scan_id = scan_id
        self.base_url = self._normalize_target(self.target)
        self.domain = urlparse(self.base_url).netloc
        self.timeout = 10
        self.vulnerabilities_found = []
        
    def _normalize_target(self, target):
        if not target.startswith(("http://", "https://")):
            return f"http://{target}"
        return target

    def get_headers(self):
        try:
            req = urllib.request.Request(self.base_url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return dict(resp.headers)
        except Exception as e:
            self.log("tool_logs", "GHOST_HEADER_ERROR", str(e)[:100])
            return {}

    def get_page_content(self):
        try:
            req = urllib.request.Request(self.base_url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.read().decode('utf-8', errors='ignore')
        except Exception as e:
            self.log("tool_logs", "GHOST_CONTENT_ERROR", str(e)[:100])
            return ""

    def log(self, table, col, val, extra=None):
        try:
            with db_conn() as conn:
                if table == "intel":
                    conn.execute(
                        "INSERT INTO intel (scan_id, type, data) VALUES (?, ?, ?)",
                        (self.scan_id, col, val),
                    )
                elif table == "tool_logs":
                    conn.execute(
                        "INSERT INTO tool_logs (scan_id, tool_name, output) VALUES (?, ?, ?)",
                        (self.scan_id, col, val),
                    )
                elif table == "vulns":
                    conn.execute(
                        "INSERT INTO vulns (scan_id, type, url, fix, severity) VALUES (?, ?, ?, ?, ?)",
                        (self.scan_id, col, extra or self.base_url, val, self._determine_severity(col)),
                    )
                conn.commit()
        except Exception:
            pass

    def _determine_severity(self, vuln_type):
        """Determine severity based on vulnerability type"""
        severe_types = ['SQL_INJECTION', 'RCE', 'GIZLI ANAHTAR', 'BACKDOOR', 'PRIVILEGE ESCALATION', 'AUTH BYPASS']
        high_types = ['XSS', 'LFI', 'FILE UPLOAD', 'IDOR', 'SSRF', 'OPEN_REDIRECT']
        medium_types = ['INFORMATION DISCLOSURE', 'SENSITIVE DATA', 'MISSING HEADERS', 'DEBUG_ENABLED']
        
        vuln_upper = vuln_type.upper()
        for t in severe_types:
            if t in vuln_upper:
                return 'CRITICAL'
        for t in high_types:
            if t in vuln_upper:
                return 'HIGH'
        for t in medium_types:
            if t in vuln_upper:
                return 'MEDIUM'
        return 'MEDIUM'

    def verify_file(self, url):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status < 400
        except Exception:
            return False

    def crawl_links(self, content):
        if not content:
            return []
        return list(set(re.findall(r'href=["\']([^"\']+)["\']', content)))

    def check_path(self, path):
        try:
            url = urljoin(self.base_url, path)
            return self.verify_file(url)
        except Exception:
            return False

    def ai_suggestions(self, headers):
        suggestions = []
        if headers:
            if "X-Frame-Options" not in headers:
                suggestions.append("Missing X-Frame-Options header")
            if "Content-Security-Policy" not in headers:
                suggestions.append("Missing Content-Security-Policy header")
            if "Strict-Transport-Security" not in headers:
                suggestions.append("Missing HSTS header")
            if "X-Content-Type-Options" not in headers:
                suggestions.append("Missing X-Content-Type-Options header")
            if "Server" in headers:
                suggestions.append(f"Server banner exposed: {headers['Server']}")
            if "X-Powered-By" in headers:
                suggestions.append(f"X-Powered-By exposed: {headers['X-Powered-By']}")
        return suggestions

    # ==================== VULNERABILITY SCANNERS ====================

    def _check_sql_injection(self, content):
        """Check for SQL injection vulnerabilities"""
        sql_patterns = [
            "mysql_fetch_array()",
            "You have an error in your SQL syntax",
            "Warning: mysql_",
            "ORA-01756",
            "SQLSTATE[23000]",
            "Microsoft OLE DB Provider for SQL Server",
            "Unclosed quotation mark",
            "PostgreSQL query failed",
        ]
        for pattern in sql_patterns:
            if pattern.lower() in content.lower():
                self.log("vulns", "SQL_INJECTION", "Potential SQL injection detected", self.base_url)
                return True
        return False

    def _check_xss(self, content):
        """Check for XSS vulnerabilities"""
        xss_patterns = [
            "<script>",
            "javascript:",
            "onerror=",
            "onload=",
            "onmouseover=",
            "alert(",
            "eval(",
        ]
        for pattern in xss_patterns:
            if pattern.lower() in content.lower():
                self.log("vulns", "XSS", "Potential XSS pattern found", self.base_url)
                return True
        return False

    def _check_information_disclosure(self, content):
        """Check for information disclosure"""
        info_patterns = [
            "Warning:",
            "Notice:",
            "PHP Notice",
            "PHP Warning",
            "Stack trace:",
            "at line",
            ".php on line",
            "Traceback (most recent call last):",
            "Directory listing",
            "Index of /",
        ]
        for pattern in info_patterns:
            if pattern in content:
                self.log("vulns", "INFORMATION DISCLOSURE", f"Information disclosure: {pattern}", self.base_url)
                return True
        return False

    def _check_common_files(self):
        """Check for common sensitive files"""
        common_files = [
            "/.git/config",
            "/.env",
            "/backup.sql",
            "/wp-config.php.bak",
            "/.DS_Store",
            "/phpinfo.php",
            "/test.php",
            "/admin.php",
            "/robots.txt",
            "/sitemap.xml",
            "/.htaccess",
            "/web.config",
            "/debug.log",
            "/error.log",
            "/application.log",
            "/config.php",
            "/db.php",
            "/database.yml",
            "/.gitignore",
            "/README.md",
            "/CHANGELOG.md",
        ]
        for file_path in common_files:
            url = urljoin(self.base_url, file_path)
            if self.verify_file(url):
                self.log("vulns", "SENSITIVE FILE", f"Sensitive file accessible: {file_path}", url)
        return len(common_files)

    def _check_directory_listing(self, content):
        """Check for directory listing"""
        if "Index of /" in content or "Directory listing" in content:
            self.log("vulns", "DIRECTORY LISTING", "Directory listing enabled", self.base_url)
            return True
        return False

    def _check_open_redirect(self, content):
        """Check for open redirect patterns"""
        redirect_patterns = [
            "url=",
            "redirect=",
            "next=",
            "return_url=",
            "returnTo=",
            "goto=",
        ]
        for pattern in redirect_patterns:
            if pattern in content.lower():
                self.log("vulns", "OPEN_REDIRECT", f"Potential open redirect parameter: {pattern}", self.base_url)
                return True
        return False

    def _check_debug_mode(self, headers, content):
        """Check for debug mode enabled"""
        if "X-Debug" in headers or "X-Drupal-Cache" in headers:
            self.log("vulns", "DEBUG_ENABLED", "Debug headers detected", self.base_url)
        
        debug_strings = [
            "debug mode",
            "debugging enabled",
            "error_reporting(e_all)",
            "display_errors = on",
        ]
        for s in debug_strings:
            if s.lower() in content.lower():
                self.log("vulns", "DEBUG_ENABLED", "Debug mode detected in content", self.base_url)
                return True
        return False

    def _check_tech_stack(self, headers, content):
        """Detect technology stack"""
        tech_info = []
        
        server = headers.get('Server', '')
        powered_by = headers.get('X-Powered-By', '')
        
        if server:
            tech_info.append(f"Server: {server}")
        if powered_by:
            tech_info.append(f"Powered-By: {powered_by}")
        
        tech_signatures = {
            'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
            'Drupal': ['Drupal.settings', 'drupal'],
            'Joomla': ['joomla', 'com_content'],
            'PHP': ['.php', 'PHP/'],
            'ASP.NET': ['__VIEWSTATE', 'ASP.NET'],
            'Python': ['python', 'Flask', 'Django'],
            'Java': ['jvm', 'servlet'],
            'Node.js': ['node', 'Express'],
            'React': ['react', '_react'],
            'Angular': ['angular', 'ng-'],
            'jQuery': ['jquery'],
            'Bootstrap': ['bootstrap'],
        }
        
        content_lower = content.lower()
        for tech, signatures in tech_signatures.items():
            for sig in signatures:
                if sig.lower() in content_lower:
                    tech_info.append(tech)
                    break
        
        if tech_info:
            with db_conn() as conn:
                for tech in set(tech_info):
                    conn.execute(
                        "INSERT INTO techno (scan_id, name, version, via) VALUES (?, ?, ?, ?)",
                        (self.scan_id, tech, "", "Ghost Scanner"),
                    )
                conn.commit()

    def _check_security_headers(self, headers):
        """Check for missing security headers"""
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'Content-Security-Policy': 'XSS protection',
            'Strict-Transport-Security': 'HTTPS enforcement',
            'X-Content-Type-Options': 'MIME type sniffing',
            'X-XSS-Protection': 'XSS filter',
            'Referrer-Policy': 'Referrer leakage',
            'Permissions-Policy': 'Feature permissions',
        }
        
        for header, description in security_headers.items():
            if header not in headers:
                self.log("vulns", "MISSING_HEADERS", f"Missing {header}: {description}", self.base_url)

    def _scan_ports(self):
        """Quick port scan for common ports"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
        open_ports = []
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.domain, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        
        if open_ports:
            self.log("intel", "OPEN_PORTS", f"Open ports detected: {open_ports}")
            with db_conn() as conn:
                conn.execute(
                    "INSERT INTO intel (scan_id, type, data) VALUES (?, ?, ?)",
                    (self.scan_id, "PORT_SCAN", f"Open: {open_ports}"),
                )
                conn.commit()

    def _check_ssl(self):
        """Check SSL/TLS configuration"""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    self.log("intel", "SSL_INFO", f"SSL Certificate: {cert.get('subject', 'Unknown')}")
        except Exception as e:
            self.log("tool_logs", "SSL_CHECK", str(e)[:100])

    def _check_subdomain_takeover(self):
        """Basic subdomain enumeration"""
        subdomains = ["www", "mail", "admin", "api", "dev", "test", "staging"]
        found = []
        for sub in subdomains:
            try:
                ip = socket.gethostbyname(f"{sub}.{self.domain}")
                found.append(f"{sub}.{self.domain}")
            except socket.gaierror:
                pass
        if found:
            self.log("intel", "SUBDOMAINS", f"Found subdomains: {found}")

    # ==================== MAIN SCAN FUNCTION ====================

    def start(self):
        """Comprehensive vulnerability scan"""
        self.log("tool_logs", "GHOST_ENGINE", f"Starting comprehensive scan: {self.base_url}")
        
        headers = self.get_headers()
        content = self.get_page_content()
        
        if headers:
            self.log("intel", "GHOST_HEADERS", json.dumps(headers))
        
        self._check_security_headers(headers)
        self._check_ssl()
        self._scan_ports()
        
        if content:
            soup = BeautifulSoup(content, 'html.parser')
            
            self._check_sql_injection(content)
            self._check_xss(content)
            self._check_information_disclosure(content)
            self._check_directory_listing(content)
            self._check_open_redirect(content)
            self._check_debug_mode(headers, content)
            
            self._check_tech_stack(headers, content)
            
            self._check_common_files()
            
            self._check_subdomain_takeover()
        
        for suggestion in self.ai_suggestions(headers):
            self.log("vulns", "Header Eksik", self.base_url)
            self.log("intel", "GHOST_SUGGESTION", suggestion)

        self.log("tool_logs", "GHOST_ENGINE", f"Ghost scan completed for {self.base_url}")


class SocialEngineeringAI:
    def __init__(self, target_info):
        self.target_info = target_info or {}

    def _derive_domain(self):
        email = (self.target_info.get("email") or "").strip()
        company_domain = (self.target_info.get("company_domain") or "").strip()
        if company_domain:
            return company_domain
        if "@" in email:
            return email.split("@", 1)[1]
        return "example.com"

    def start_campaign(self, target_info=None):
        info = target_info or self.target_info
        domain = self._derive_domain()
        campaign_id = f"camp_{secrets.token_hex(4)}"
        fake_domain = f"secure-{domain}"
        phishing_url = f"https://{fake_domain}/login"

        return {
            "campaign_id": campaign_id,
            "fake_domain": fake_domain,
            "phishing_url": phishing_url,
            "template": "Office 365 Login",
            "created_at": datetime.datetime.utcnow().isoformat(),
            "target": {
                "name": info.get("name"),
                "email": info.get("email"),
                "company": info.get("company"),
                "position": info.get("position"),
            },
        }
