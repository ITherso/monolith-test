# --- SOCIAL ENGINEERING MODULE ---
import datetime
import re
import secrets
import urllib.request
from urllib.parse import urljoin

from cyberapp.models.db import db_conn


class GhostEngine:
    def __init__(self, target, scan_id):
        self.target = target.strip()
        self.scan_id = scan_id
        self.base_url = self._normalize_target(self.target)

    def _normalize_target(self, target):
        if not target.startswith(("http://", "https://")):
            return f"http://{target}"
        return target

    def get_headers(self):
        try:
            req = urllib.request.Request(self.base_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                return dict(resp.headers)
        except Exception:
            return {}

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
                        (self.scan_id, col, extra or self.base_url, "", "MEDIUM"),
                    )
                conn.commit()
        except Exception:
            pass

    def verify_file(self, url):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status < 400
        except Exception:
            return False

    def crawl_links(self, content):
        if not content:
            return []
        return list(set(re.findall(r'href=[\"\\\']([^\"\\\']+)[\"\\\']', content)))

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
        return suggestions

    def start(self):
        headers = self.get_headers()
        if headers:
            self.log("intel", "GHOST_HEADERS", json.dumps(headers))

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
