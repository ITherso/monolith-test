import random
import re
import ssl
import urllib

from cyberapp.models.db import db_conn

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]


class ZeroDayResearchEngine:
    def __init__(self, target, scan_id):
        self.target = target
        self.scan_id = scan_id
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def log(self, data):
        try:
            with db_conn() as conn:
                conn.execute(
                    "INSERT INTO intel (scan_id, type, data) VALUES (?, ?, ?)",
                    (self.scan_id, "ZERODAY", data),
                )
        except Exception:
            pass

    def start(self):
        self.log("Zero-day research started for: " + self.target)

        try:
            req = urllib.request.Request(self.target, headers={'User-Agent': random.choice(USER_AGENTS)})
            with urllib.request.urlopen(req, context=self.ctx, timeout=15) as res:
                headers = str(res.headers).lower()
                content = res.read(1024 * 1024).decode('utf-8', 'ignore')

                if "x-powered-by" in headers:
                    powered_by = re.search(r'x-powered-by:\s*([^\r\n]+)', headers)
                    if powered_by:
                        self.log(f"X-Powered-By header leak: {powered_by.group(1)}")

                if "laravel" in content.lower():
                    self.log("Laravel framework detected - checking for known exploits")
                if "django" in content.lower():
                    self.log("Django framework detected - checking for debug mode exposure")
                if "wordpress" in content:
                    self.log("WordPress detected - WPScan recommended for plugin vulns")
                if "wp-json" in content or "/wp-admin" in headers:
                    self.log("WordPress REST API exposed")

        except Exception as e:
            self.log(f"Error during zero-day research: {str(e)}")
