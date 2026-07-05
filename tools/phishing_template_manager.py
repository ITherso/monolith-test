#!/usr/bin/env python3
"""
Advanced Phishing Template Manager
===================================
Template library, dynamic fields, HTML editor, responsive designs

Author: CyberGhost Pro Team
"""

import json
import sqlite3
import secrets
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class TemplateCategory(Enum):
    """Template categories"""
    IT_SUPPORT = "it_support"
    HR_ANNOUNCEMENT = "hr_announcement"
    SECURITY_ALERT = "security_alert"
    INVOICE = "invoice"
    SHIPPING = "shipping"
    PASSWORD_RESET = "password_reset"
    ACCOUNT_VERIFY = "account_verification"
    PRIZE_WINNER = "prize_winner"
    MEETING_INVITE = "meeting_invite"
    DOCUMENT_SHARE = "document_share"
    CUSTOM = "custom"


@dataclass
class EmailTemplate:
    """Email template"""
    template_id: str
    name: str
    category: TemplateCategory
    subject_line: str
    html_content: str
    text_content: str
    
    # Dynamic fields
    dynamic_fields: List[str] = field(default_factory=list)
    
    # Metadata
    description: str = ""
    language: str = "en"
    responsive: bool = True
    include_unsubscribe: bool = False
    
    # Assets
    inline_images: List[Dict] = field(default_factory=list)
    attachments: List[Dict] = field(default_factory=list)
    
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


class PhishingTemplateManager:
    """Advanced template management system"""
    
    def __init__(self, db_path: str = "/tmp/phishing_templates.db"):
        self.db_path = db_path
        self._init_database()
        self._load_default_templates()
    
    def _init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS templates (
                template_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                category TEXT,
                subject_line TEXT,
                html_content TEXT,
                text_content TEXT,
                dynamic_fields JSON,
                metadata JSON,
                created_at TEXT,
                updated_at TEXT
            )
        """)
        
        conn.commit()
        conn.close()
    
    def create_template(self, template: EmailTemplate) -> Dict[str, Any]:
        """Create new email template"""
        if not template.template_id:
            template.template_id = self._generate_template_id()
        
        # Extract dynamic fields from content
        template.dynamic_fields = self._extract_dynamic_fields(template.html_content)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        metadata = {
            "description": template.description,
            "language": template.language,
            "responsive": template.responsive,
            "include_unsubscribe": template.include_unsubscribe,
            "inline_images": template.inline_images,
            "attachments": template.attachments
        }
        
        cursor.execute("""
            INSERT INTO templates (template_id, name, category, subject_line, html_content, text_content, dynamic_fields, metadata, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            template.template_id,
            template.name,
            template.category.value,
            template.subject_line,
            template.html_content,
            template.text_content,
            json.dumps(template.dynamic_fields),
            json.dumps(metadata),
            template.created_at.isoformat(),
            template.updated_at.isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        return {
            "success": True,
            "template_id": template.template_id,
            "message": f"Template '{template.name}' created successfully"
        }
    
    def get_template(self, template_id: str) -> Optional[EmailTemplate]:
        """Get template by ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM templates WHERE template_id = ?", (template_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            metadata = json.loads(row[7])
            return EmailTemplate(
                template_id=row[0],
                name=row[1],
                category=TemplateCategory(row[2]),
                subject_line=row[3],
                html_content=row[4],
                text_content=row[5],
                dynamic_fields=json.loads(row[6]),
                description=metadata.get("description", ""),
                language=metadata.get("language", "en"),
                responsive=metadata.get("responsive", True),
                include_unsubscribe=metadata.get("include_unsubscribe", False),
                inline_images=metadata.get("inline_images", []),
                attachments=metadata.get("attachments", []),
                created_at=datetime.fromisoformat(row[8]),
                updated_at=datetime.fromisoformat(row[9])
            )
        
        return None
    
    def list_templates(self, category: Optional[TemplateCategory] = None) -> List[Dict[str, Any]]:
        """List all templates"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if category:
            cursor.execute("SELECT template_id, name, category, subject_line, created_at FROM templates WHERE category = ?", (category.value,))
        else:
            cursor.execute("SELECT template_id, name, category, subject_line, created_at FROM templates")
        
        rows = cursor.fetchall()
        conn.close()
        
        templates = []
        for row in rows:
            templates.append({
                "template_id": row[0],
                "name": row[1],
                "category": row[2],
                "subject_line": row[3],
                "created_at": row[4]
            })
        
        return templates
    
    def render_template(self, template_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Render template with dynamic fields"""
        template = self.get_template(template_id)
        if not template:
            return {"success": False, "error": "Template not found"}
        
        # Replace dynamic fields in HTML
        html_rendered = template.html_content
        text_rendered = template.text_content
        subject_rendered = template.subject_line
        
        for field in template.dynamic_fields:
            value = context.get(field, f"[{field}]")
            html_rendered = html_rendered.replace(f"{{{{{field}}}}}", str(value))
            text_rendered = text_rendered.replace(f"{{{{{field}}}}}", str(value))
            subject_rendered = subject_rendered.replace(f"{{{{{field}}}}}", str(value))
        
        return {
            "success": True,
            "template_id": template_id,
            "subject": subject_rendered,
            "html_content": html_rendered,
            "text_content": text_rendered,
            "metadata": {
                "responsive": template.responsive,
                "language": template.language
            }
        }
    
    def clone_real_email(self, source_html: str, extract_links: bool = True) -> Dict[str, Any]:
        """Clone real email template"""
        # Extract useful patterns
        title = self._extract_title(source_html)
        links = self._extract_links(source_html) if extract_links else []
        images = self._extract_images(source_html)
        
        # Clean and prepare HTML
        cleaned_html = self._clean_html(source_html)
        
        # Generate text version
        text_version = self._html_to_text(cleaned_html)
        
        return {
            "success": True,
            "title": title,
            "html_content": cleaned_html,
            "text_content": text_version,
            "links": links,
            "images": images,
            "dynamic_fields": self._extract_dynamic_fields(cleaned_html)
        }
    
    def _extract_dynamic_fields(self, content: str) -> List[str]:
        """Extract dynamic field placeholders from content"""
        # Match {{field_name}} pattern
        pattern = r'\{\{([a-zA-Z_][a-zA-Z0-9_]*)\}\}'
        matches = re.findall(pattern, content)
        return list(set(matches))
    
    def _extract_title(self, html: str) -> str:
        """Extract title from HTML"""
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
        return match.group(1) if match else "Untitled"
    
    def _extract_links(self, html: str) -> List[str]:
        """Extract all links from HTML"""
        pattern = r'href=["\']([^"\']+)["\']'
        matches = re.findall(pattern, html, re.IGNORECASE)
        return list(set(matches))
    
    def _extract_images(self, html: str) -> List[str]:
        """Extract all image sources from HTML"""
        pattern = r'src=["\']([^"\']+)["\']'
        matches = re.findall(pattern, html, re.IGNORECASE)
        return [m for m in set(matches) if any(ext in m.lower() for ext in ['.jpg', '.png', '.gif', '.svg'])]
    
    def _clean_html(self, html: str) -> str:
        """Clean and sanitize HTML"""
        # Remove scripts
        html = re.sub(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', '', html, flags=re.IGNORECASE)
        
        # Remove tracking pixels
        html = re.sub(r'<img[^>]*1x1[^>]*>', '', html, flags=re.IGNORECASE)
        
        return html
    
    def _html_to_text(self, html: str) -> str:
        """Convert HTML to plain text"""
        # Simple HTML to text conversion
        text = re.sub(r'<[^>]+>', '', html)
        text = re.sub(r'\s+', ' ', text)
        return text.strip()
    
    def _generate_template_id(self) -> str:
        """Generate unique template ID"""
        return f"tpl_{secrets.token_hex(8)}"
    
    def _load_default_templates(self):
        """Load default template library"""
        # Check if templates already loaded
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM templates")
        count = cursor.fetchone()[0]
        conn.close()
        
        if count > 0:
            return  # Already loaded
        
        # IT Support Template
        it_support = EmailTemplate(
            template_id="tpl_it_support_001",
            name="IT Support - Password Reset",
            category=TemplateCategory.IT_SUPPORT,
            subject_line="[URGENT] Reset Your Password - Action Required",
            html_content=self._get_it_support_html(),
            text_content="Your password will expire soon. Please reset it immediately.",
            description="IT support password reset template"
        )
        
        # Security Alert Template
        security_alert = EmailTemplate(
            template_id="tpl_security_001",
            name="Security Alert - Suspicious Activity",
            category=TemplateCategory.SECURITY_ALERT,
            subject_line="🔒 Security Alert: Unusual login detected",
            html_content=self._get_security_alert_html(),
            text_content="We detected unusual activity on your account. Please verify your identity.",
            description="Security alert template"
        )
        
        # HR Announcement Template
        hr_announcement = EmailTemplate(
            template_id="tpl_hr_001",
            name="HR - Employee Benefits Update",
            category=TemplateCategory.HR_ANNOUNCEMENT,
            subject_line="Important: New Employee Benefits Portal",
            html_content=self._get_hr_announcement_html(),
            text_content="Access the new benefits portal to view your updated package.",
            description="HR announcement template"
        )
        
        # Save templates
        for template in [it_support, security_alert, hr_announcement]:
            self.create_template(template)
    
    def _get_it_support_html(self) -> str:
        """Get IT support template HTML"""
        return """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Reset Required</title>
</head>
<body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
    <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
        <div style="background-color: #0078d4; color: white; padding: 20px; border-radius: 8px 8px 0 0;">
            <h1 style="margin: 0;">IT Support</h1>
        </div>
        <div style="padding: 30px;">
            <p>Dear {{name}},</p>
            <p>Your password will expire in <strong>24 hours</strong>. To maintain access to your account, please reset your password immediately.</p>
            <div style="text-align: center; margin: 30px 0;">
                <a href="{{reset_link}}" style="background-color: #0078d4; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; display: inline-block;">Reset Password Now</a>
            </div>
            <p>If you don't reset your password, you will lose access to:</p>
            <ul>
                <li>Email and calendar</li>
                <li>Shared drives and documents</li>
                <li>Internal applications</li>
            </ul>
            <p style="color: #666; font-size: 12px; margin-top: 30px;">This is an automated message. Please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>
"""
    
    def _get_security_alert_html(self) -> str:
        """Get security alert template HTML"""
        return """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Alert</title>
</head>
<body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
    <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
        <div style="background-color: #d32f2f; color: white; padding: 20px; border-radius: 8px 8px 0 0;">
            <h1 style="margin: 0;">🔒 Security Alert</h1>
        </div>
        <div style="padding: 30px;">
            <p>Dear {{name}},</p>
            <p><strong>We detected a suspicious login attempt</strong> on your account from an unrecognized device:</p>
            <div style="background-color: #f5f5f5; padding: 15px; border-left: 4px solid #d32f2f; margin: 20px 0;">
                <p style="margin: 5px 0;"><strong>Location:</strong> {{location}}</p>
                <p style="margin: 5px 0;"><strong>Device:</strong> {{device}}</p>
                <p style="margin: 5px 0;"><strong>Time:</strong> {{timestamp}}</p>
            </div>
            <p>If this was you, you can ignore this message. If not, please secure your account immediately:</p>
            <div style="text-align: center; margin: 30px 0;">
                <a href="{{verify_link}}" style="background-color: #d32f2f; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; display: inline-block;">Verify Your Identity</a>
            </div>
            <p style="color: #666; font-size: 12px; margin-top: 30px;">Security Team | {{company}}</p>
        </div>
    </div>
</body>
</html>
"""
    
    def _get_hr_announcement_html(self) -> str:
        """Get HR announcement template HTML"""
        return """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HR Announcement</title>
</head>
<body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
    <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
        <div style="background-color: #4caf50; color: white; padding: 20px; border-radius: 8px 8px 0 0;">
            <h1 style="margin: 0;">Human Resources</h1>
        </div>
        <div style="padding: 30px;">
            <p>Dear {{name}},</p>
            <p>We're excited to announce the launch of our <strong>New Employee Benefits Portal</strong>!</p>
            <p>You can now access and manage:</p>
            <ul>
                <li>Health insurance plans</li>
                <li>401(k) contributions</li>
                <li>Vacation and PTO balance</li>
                <li>Wellness programs</li>
            </ul>
            <div style="text-align: center; margin: 30px 0;">
                <a href="{{portal_link}}" style="background-color: #4caf50; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; display: inline-block;">Access Portal</a>
            </div>
            <p>Please log in within 7 days to activate your account.</p>
            <p style="color: #666; font-size: 12px; margin-top: 30px;">HR Department | {{company}}</p>
        </div>
    </div>
</body>
</html>
"""


# Singleton
_template_manager = None

def get_template_manager() -> PhishingTemplateManager:
    """Get template manager singleton"""
    global _template_manager
    if _template_manager is None:
        _template_manager = PhishingTemplateManager()
    return _template_manager
