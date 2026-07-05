import json
import random
import re
import ssl
import socket
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime
from typing import List, Dict, Optional

from cyberapp.models.db import db_conn


class APISecurityScanner:
    """
    Kapsamlı API güvenlik tarama modülü.
    REST API endpoint'lerini keşfeder, HTTP metodlarını test eder ve
    yaygın API güvenlik açıklarını tespit eder.
    """

    # Varsayılan API wordlist (fallback)
    DEFAULT_API_PATHS = [
        "api", "api/v1", "api/v2", "v1", "v2", "v3", "api/v3",
        "rest", "rest/api", "rest/v1", "graphql", "api/graphql",
        "health", "healthcheck", "status", "ping", "info",
        "users", "user", "auth", "login", "logout", "register",
        "admin", "administrator", "dashboard", "panel",
        "config", "settings", "configuration",
        "files", "upload", "download", "assets",
        "search", "query", "find", "filter",
        "data", "dataset", "datasets", "records",
        "products", "orders", "transactions", "payment",
        "comments", "posts", "articles", "blog",
        "notifications", "messages", "alerts",
        "analytics", "stats", "statistics", "metrics",
        "export", "import", "sync", "webhook",
        "webhooks", "hooks", "events", "event",
        "integrations", "services", "service",
        "keys", "tokens", "credentials", "secrets",
    ]

    # Yaygın hassas parametre adları
    SENSITIVE_PARAMS = [
        "api_key", "apikey", "token", "access_token", "auth_token",
        "secret", "password", "passwd", "pwd",
        "client_secret", "private_key", "encryption_key",
        "session_id", "user_id", "admin_id",
        "signature", "sig", "hmac",
    ]

    # SQL Injection payloadları
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR 1=1#",
        "') OR ('1'='1",
        "admin' --",
        "admin' #",
        "admin'/*",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT 1,2,3,4--",
        "1; DROP TABLE users--",
        "1 OR 1=1",
        "1 OR '1'='1'",
    ]

    # XSS payloadları
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "{{constructor.constructor('alert(1)')()}}",
        "${alert('XSS')}",
        "<body onload=alert('XSS')>",
        "javascript:alert('XSS')",
    ]

    def __init__(self, target, scan_id):
        self.target = target.rstrip("/")
        self.scan_id = scan_id
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE
        self.discovered_endpoints = []
        self.vulnerabilities = []
        self.requests = None
        self.session = None
        self._import_requests()
        if self.requests:
            self.session = self.requests.Session()

    def _import_requests(self):
        """Optionally import requests library."""
        try:
            import requests
            self.requests = requests
            return True
        except ImportError:
            return False

    def _headers(self):
        """Rastgele User-Agent ile HTTP başlıkları oluştur."""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (compatible; APISecurityScanner/1.0)",
        ]
        return {
            'User-Agent': random.choice(user_agents),
            'Accept': 'application/json, application/xml, text/html, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
        }

    def log_endpoint(self, url: str, method: str, status: int, parameters: Optional[str] = None, content_type: Optional[str] = None):
        """Tespit edilen endpoint'i veritabanına kaydet."""
        try:
            with db_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO api_endpoints (scan_id, url, method, status, parameters, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (self.scan_id, url, method, status, parameters, datetime.now().isoformat()),
                )
            self.discovered_endpoints.append({
                "url": url,
                "method": method,
                "status": status,
                "parameters": parameters,
                "content_type": content_type
            })
        except Exception as e:
            print(f"[APIScanner] Endpoint logging error: {e}")

    def log_vulnerability(self, url: str, method: str, vuln_type: str, severity: str, evidence: str):
        """Tespit edilen güvenlik açığını kaydet."""
        try:
            with db_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO vulns (scan_id, type, url, severity, fix)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (self.scan_id, vuln_type, url, severity, evidence),
                )
            self.vulnerabilities.append({
                "url": url,
                "method": method,
                "type": vuln_type,
                "severity": severity,
                "evidence": evidence
            })
        except Exception as e:
            print(f"[APIScanner] Vulnerability logging error: {e}")

    def _load_wordlist(self, path: str, fallback: List[str]) -> List[str]:
        """Wordlist dosyasını yükle veya fallback kullan."""
        try:
            with open(path, 'r') as f:
                items = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            return items if items else fallback
        except Exception:
            return fallback

    def _make_request(self, url: str, method: str = "GET", data: Optional[Dict] = None, 
                      headers: Optional[Dict] = None, timeout: int = 10) -> Optional[object]:
        """HTTP isteği yap ve yanıtı döndür."""
        try:
            if self.session and self.requests:
                # requests kütüphphanesi mevcutsa daha iyi kontrol
                req_headers = {**self._headers(), **(headers or {})}
                req = self.requests.Request(method, url, headers=req_headers, data=data)
                prepared = req.prepare()
                response = self.session.send(prepared, timeout=timeout, allow_redirects=True)
                return response
            else:
                # Standart urllib kullan
                req_headers = {**self._headers(), **(headers or {})}
                
                if data:
                    if isinstance(data, dict):
                        data = urllib.parse.urlencode(data).encode()
                    elif isinstance(data, str):
                        data = data.encode()

                req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
                with urllib.request.urlopen(req, context=self.ctx, timeout=timeout) as res:
                    return res
        except urllib.error.HTTPError as e:
            return e
        except urllib.error.URLError as e:
            print(f"[APIScanner] Request error: {e}")
            return None
        except Exception as e:
            print(f"[APIScanner] Unexpected error: {e}")
            return None

    def _is_json_response(self, response) -> bool:
        """Yanıtın JSON olup olmadığını kontrol et."""
        if not response:
            return False
        content_type = response.headers.get('Content-Type', '')
        return 'application/json' in content_type or 'application/vnd.api' in content_type

    def discover_api_endpoints(self, limit: int = 200):
        """
        API endpoint'lerini keşfet.
        Wordlist tabanlı brute-force ile yaygın API path'lerini dener.
        """
        candidates = self._load_wordlist(
            "/usr/share/wordlists/SecLists/Discovery/Web-Content/api/api-endpoints.txt",
            self.DEFAULT_API_PATHS
        )

        for path in candidates[:limit]:
            url = f"{self.target}/{path.lstrip('/')}"
            self._probe_endpoint(url)

    def _probe_endpoint(self, url: str):
        """Tek bir endpoint'i çeşitli metodlarla test et."""
        methods = ["GET", "HEAD", "OPTIONS"]
        
        for method in methods:
            try:
                if self.session and self.requests:
                    response = self._make_request(url, method=method)
                else:
                    req = urllib.request.Request(url, headers=self._headers(), method=method)
                    response = urllib.request.urlopen(req, context=self.ctx, timeout=8)

                status = response.status if hasattr(response, 'status') else response.getcode()
                content_type = response.headers.get('Content-Type', '')

                if status in (200, 201, 204, 301, 302, 401, 403, 405):
                    self.log_endpoint(url, method, status, None, content_type)
                    
                    # JSON yanıt varsa içeriği analiz et
                    if self._is_json_response(response):
                        self._analyze_json_response(url, method, response)

            except urllib.error.HTTPError as e:
                status = e.code
                if status in (401, 403, 405):
                    self.log_endpoint(url, method, status, None)
            except Exception:
                pass

    def _analyze_json_response(self, url: str, method: str, response):
        """JSON yanıtını analiz et ve potansiyel endpoint'ler çıkar."""
        try:
            content = response.read().decode('utf-8', errors='ignore')
            data = json.loads(content)

            # JSON içindeki URL'leri bul
            url_pattern = re.compile(r'["\'](https?://[^"\']+)["\']')
            found_urls = url_pattern.findall(content)
            
            for found_url in found_urls[:5]:  # İlk 5 URL
                if self.target in found_url:
                    self.log_endpoint(found_url, "GET", 200, None, "linked")

            # API versioning bilgisi çıkar
            if isinstance(data, dict):
                for key in data.keys():
                    if re.match(r'^v\d+', str(key)):
                        versioned_url = f"{url}/{key}"
                        if versioned_url != url:
                            self.log_endpoint(versioned_url, "GET", 200, None, "discovered")

        except (json.JSONDecodeError, Exception):
            pass

    def test_http_methods(self, url: str):
        """
        Endpoint üzerinde çeşitli HTTP metodlarını test et.
        Potansiyel güvenlik açıklarını tespit eder.
        """
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
        
        for method in methods:
            if method in ["GET", "HEAD", "OPTIONS"]:
                response = self._make_request(url, method=method)
            else:
                # Değiştirici metodlar için test verisi
                test_data = {"test": "monolith_api_security_scan"}
                response = self._make_request(url, method=method, data=test_data)

            if response:
                status = getattr(response, 'status', None) or getattr(response, 'code', 0)

                # Method yetkilendirme kontrolleri
                if status in (200, 201, 204):
                    self.log_endpoint(url, method, status, None)

                # Potansiyel güvenlik sorunları
                if status == 405 and method == "OPTIONS":
                    # OPTIONS methodu engelleniyor - bu iyi bir güvenlik uygulaması olabilir
                    pass
                elif status == 501:
                    self.log_vulnerability(url, method, "Unsupported HTTP Method", "INFO",
                                          f"Method {method} not implemented")

    def test_parameter_injection(self, url: str, base_params: List[str] = None):
        """
        Parameter manipülasyonu ve injection testleri yap.
        SQL Injection, XSS ve IDOR açıklarını kontrol eder.
        """
        params_to_test = base_params or ["id", "user_id", "page", "limit", "filter"]

        for param in params_to_test:
            # SQL Injection testleri
            for payload in self.SQLI_PAYLOADS[:3]:  # İlk 3 payload
                try:
                    query = urllib.parse.urlencode({param: payload})
                    test_url = f"{url}?{query}"
                    response = self._make_request(test_url)

                    if response:
                        content = getattr(response, 'text', '') or ''
                        if any(indicator in content.lower() for indicator in 
                               ["sql syntax", "mysql", "postgresql", "ora-", "syntax error", "warning"]):
                            self.log_vulnerability(test_url, "GET", "SQL Injection", "HIGH",
                                                  f"SQL error triggered with param={param}")
                            break

                except Exception:
                    pass

            # XSS testleri
            for payload in self.XSS_PAYLOADS[:2]:  # İlk 2 payload
                try:
                    query = urllib.parse.urlencode({param: payload})
                    test_url = f"{url}?{query}"
                    response = self._make_request(test_url)

                    if response:
                        content = getattr(response, 'text', '') or ''
                        if payload in content or payload.replace('<', '&lt;') in content:
                            self.log_vulnerability(test_url, "GET", "Reflected XSS", "MEDIUM",
                                                  f"XSS payload reflected in response for param={param}")
                            break

                except Exception:
                    pass

    def test_authentication_endpoints(self):
        """
        Kimlik doğrulama endpoint'lerini test et.
        Güvenli olmayan authentication mekanizmalarını tespit eder.
        """
        auth_endpoints = [
            ("/api/auth/login", "POST"),
            ("/api/auth/signin", "POST"),
            ("/api/login", "POST"),
            ("/api/user/login", "POST"),
            ("/api/v1/auth", "POST"),
        ]

        for endpoint, method in auth_endpoints:
            url = f"{self.target}{endpoint}"

            # Test credentials ile istek
            test_data = {"username": "admin'--", "password": "test"}
            response = self._make_request(url, method=method, data=test_data)

            if response:
                status = response.status if hasattr(response, 'status') else response.getcode()

                # Güvenlik kontrolleri
                if status == 200:
                    content = getattr(response, 'text', '') or ''
                    # Hassas bilgi sızıntısı kontrolü
                    if any(leak in content.lower() for leak in ["password", "token", "secret", "api_key"]):
                        self.log_vulnerability(url, method, "Information Disclosure", "MEDIUM",
                                              "Response may contain sensitive data")

                # Login bypass attempts
                if "admin' OR 1=1" in str(test_data) and status == 200:
                    content = getattr(response, 'text', '') or ''
                    if "token" in content.lower() or "session" in content.lower():
                        self.log_vulnerability(url, method, "Authentication Bypass", "CRITICAL",
                                              "SQLi-based login bypass possible")

    def test_sensitive_data_exposure(self):
        """
        Hassas veri açığa çıkma kontrolleri yapar.
        Yanıtlarda hassas bilgilerin varlığını kontrol eder.
        """
        sensitive_patterns = [
            (r'"password"\s*:\s*"[^"]*"', "Password in response"),
            (r'"api_?key"\s*:\s*"[a-zA-Z0-9]{20,}"', "API Key exposure"),
            (r'"token"\s*:\s*"[a-zA-Z0-9\-_.]{20,}"', "Auth Token exposure"),
            (r'"secret"\s*:\s*"[^"]*"', "Secret exposure"),
            (r'AWS_ACCESS_KEY_ID', "AWS Credentials"),
            (r'-----BEGIN RSA PRIVATE KEY-----', "Private Key"),
        ]

        for endpoint in self.discovered_endpoints[:20]:  # İlk 20 endpoint
            url = endpoint["url"]
            response = self._make_request(url)

            if response:
                content = getattr(response, 'text', '') or ''
                for pattern, description in sensitive_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        self.log_vulnerability(url, "GET", "Sensitive Data Exposure", "HIGH",
                                              description)

    def analyze_api_structure(self):
        """
        Tespit edilen API yapısını analiz et.
        REST API best practice'lere uygunluğu değerlendir.
        """
        for endpoint in self.discovered_endpoints:
            url = endpoint["url"]
            method = endpoint["method"]

            # URL yapısı kontrolleri
            if "/wp-admin" in url or "/wp-login" in url:
                self.log_vulnerability(url, method, "WordPress Detection", "INFO",
                                      "WordPress administrative interface found")

            # Sensitive paths
            sensitive_paths = ["/etc/passwd", "/.env", "/config.php", "/.git/config"]
            for path in sensitive_paths:
                if path in url:
                    self.log_vulnerability(url, method, "Sensitive Path Access", "HIGH",
                                          f"Access to sensitive path: {path}")

    def start(self, endpoint_limit: int = 200):
        """
        Tam API güvenlik taramasını başlat.
        Tüm kontrolleri sırayla çalıştırır.
        """
        self.discovered_endpoints = []
        self.vulnerabilities = []

        # Ana tarama
        self.discover_api_endpoints(limit=endpoint_limit)

        # Tespit edilen endpoint'ler üzerinde detaylı testler
        for endpoint in self.discovered_endpoints[:50]:  # İlk 50 endpoint
            url = endpoint["url"]
            method = endpoint["method"]

            # HTTP metod testleri
            if method == "GET":
                self.test_http_methods(url)
                self.test_parameter_injection(url)

        # Kimlik doğrulama endpoint testleri
        self.test_authentication_endpoints()

        # Hassas veri analizi
        self.test_sensitive_data_exposure()

        # API yapı analizi
        self.analyze_api_structure()

        return {
            "endpoints_found": len(self.discovered_endpoints),
            "vulnerabilities_found": len(self.vulnerabilities),
            "endpoints": self.discovered_endpoints[:20],
            "vulnerabilities": self.vulnerabilities[:20]
        }
