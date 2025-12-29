import json
import random
import ssl
import urllib

from cyberapp.models.db import db_conn

API_WORDLIST = "/usr/share/wordlists/SecLists/Discovery/Web-Content/api/api-endpoints.txt"
PARAM_WORDLIST = "/usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]


class APISecurityScanner:
    def __init__(self, target, scan_id):
        self.target = target.rstrip("/")
        self.scan_id = scan_id
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def _headers(self):
        return {'User-Agent': random.choice(USER_AGENTS)}

    def log_endpoint(self, url, method, status, parameters=None):
        try:
            with db_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO api_endpoints (scan_id, url, method, status, parameters)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (self.scan_id, url, method, status, parameters),
                )
        except Exception:
            pass

    def _load_wordlist(self, path, fallback):
        try:
            with open(path, 'r') as f:
                items = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            return items or fallback
        except Exception:
            return fallback

    def discover_api_endpoints(self, limit=300):
        candidates = self._load_wordlist(API_WORDLIST, ["api", "api/v1", "api/v2", "v1", "v2", "health"])
        parameters = self._load_wordlist(PARAM_WORDLIST, ["id", "user", "token", "q", "search"])

        for path in candidates[:limit]:
            url = f"{self.target}/{path.lstrip('/')}"
            try:
                req = urllib.request.Request(url, headers=self._headers(), method="GET")
                with urllib.request.urlopen(req, context=self.ctx, timeout=8) as res:
                    status = res.getcode()
                    if status in (200, 204, 301, 302, 401, 403):
                        self.log_endpoint(url, "GET", status, None)
            except Exception:
                continue

            # Basic parameter probe
            for param in parameters[:10]:
                try:
                    query = urllib.parse.urlencode({param: "1"})
                    qurl = f"{url}?{query}"
                    req = urllib.request.Request(qurl, headers=self._headers(), method="GET")
                    with urllib.request.urlopen(req, context=self.ctx, timeout=5) as res:
                        status = res.getcode()
                        if status in (200, 204, 401, 403):
                            self.log_endpoint(url, "GET", status, json.dumps([param]))
                except Exception:
                    continue

    def start(self):
        self.discover_api_endpoints()
