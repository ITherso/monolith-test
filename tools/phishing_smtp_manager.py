#!/usr/bin/env python3
"""
Multi-Provider SMTP Manager
============================
Multiple SMTP providers, rate limiting, DKIM/SPF, fallback mechanism

Author: CyberGhost Pro Team
"""

import smtplib
import ssl
import time
import secrets
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from email.utils import formataddr, formatdate
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import threading
import queue


class SMTPProvider(Enum):
    """Supported SMTP providers"""
    GMAIL = "gmail"
    OUTLOOK = "outlook"
    SENDGRID = "sendgrid"
    MAILGUN = "mailgun"
    AWS_SES = "aws_ses"
    CUSTOM = "custom"


@dataclass
class SMTPConfig:
    """SMTP configuration"""
    provider: SMTPProvider
    host: str
    port: int
    username: str
    password: str
    use_tls: bool = True
    use_ssl: bool = False
    
    # Rate limiting
    rate_limit_per_hour: int = 100
    rate_limit_per_minute: int = 10
    
    # Authentication
    dkim_selector: str = ""
    dkim_private_key: str = ""
    spf_record: str = ""
    
    # Metadata
    provider_id: str = ""
    name: str = ""
    enabled: bool = True
    priority: int = 1
    
    # Stats
    emails_sent: int = 0
    emails_failed: int = 0
    last_used: Optional[datetime] = None


@dataclass
class EmailMessage:
    """Email message"""
    message_id: str
    recipient: str
    sender_email: str
    sender_name: str
    subject: str
    html_body: str
    text_body: str = ""
    
    # Headers
    reply_to: Optional[str] = None
    custom_headers: Dict[str, str] = field(default_factory=dict)
    
    # Attachments
    inline_images: List[Dict] = field(default_factory=list)
    attachments: List[Dict] = field(default_factory=list)
    
    # Tracking
    tracking_pixel: bool = True
    track_links: bool = True
    
    # Metadata
    campaign_id: Optional[str] = None
    target_id: Optional[str] = None
    sent_at: Optional[datetime] = None
    delivered: bool = False


class MultiProviderSMTPManager:
    """Multi-provider SMTP manager with intelligent routing"""
    
    def __init__(self):
        self.providers: Dict[str, SMTPConfig] = {}
        self.rate_limiters: Dict[str, 'RateLimiter'] = {}
        self.send_queue = queue.Queue()
        self.worker_threads = []
        self.running = False
    
    def add_provider(self, config: SMTPConfig) -> Dict[str, Any]:
        """Add SMTP provider"""
        if not config.provider_id:
            config.provider_id = self._generate_provider_id()
        
        self.providers[config.provider_id] = config
        self.rate_limiters[config.provider_id] = RateLimiter(
            per_hour=config.rate_limit_per_hour,
            per_minute=config.rate_limit_per_minute
        )
        
        return {
            "success": True,
            "provider_id": config.provider_id,
            "message": f"Provider '{config.name}' added successfully"
        }
    
    def send_email(self, message: EmailMessage, provider_id: Optional[str] = None) -> Dict[str, Any]:
        """Send email via specified or auto-selected provider"""
        if provider_id:
            return self._send_via_provider(message, provider_id)
        else:
            return self._send_with_failover(message)
    
    def send_bulk(self, messages: List[EmailMessage], provider_id: Optional[str] = None) -> Dict[str, Any]:
        """Send bulk emails"""
        results = {
            "total": len(messages),
            "sent": 0,
            "failed": 0,
            "errors": []
        }
        
        for message in messages:
            result = self.send_email(message, provider_id)
            if result["success"]:
                results["sent"] += 1
            else:
                results["failed"] += 1
                results["errors"].append({
                    "recipient": message.recipient,
                    "error": result.get("error", "Unknown error")
                })
        
        return results
    
    def start_queue_workers(self, num_workers: int = 3):
        """Start background worker threads for queue processing"""
        if self.running:
            return
        
        self.running = True
        for i in range(num_workers):
            thread = threading.Thread(target=self._queue_worker, args=(i,))
            thread.daemon = True
            thread.start()
            self.worker_threads.append(thread)
    
    def stop_queue_workers(self):
        """Stop background workers"""
        self.running = False
        for thread in self.worker_threads:
            thread.join(timeout=5)
        self.worker_threads = []
    
    def enqueue_email(self, message: EmailMessage, provider_id: Optional[str] = None):
        """Add email to send queue"""
        self.send_queue.put((message, provider_id))
    
    def get_provider_stats(self, provider_id: str) -> Dict[str, Any]:
        """Get provider statistics"""
        config = self.providers.get(provider_id)
        if not config:
            return {"success": False, "error": "Provider not found"}
        
        rate_limiter = self.rate_limiters.get(provider_id)
        
        return {
            "provider_id": provider_id,
            "name": config.name,
            "provider_type": config.provider.value,
            "enabled": config.enabled,
            "emails_sent": config.emails_sent,
            "emails_failed": config.emails_failed,
            "success_rate": (config.emails_sent / (config.emails_sent + config.emails_failed) * 100) if (config.emails_sent + config.emails_failed) > 0 else 0,
            "last_used": config.last_used.isoformat() if config.last_used else None,
            "rate_limit_status": {
                "per_hour": f"{rate_limiter.hour_count}/{config.rate_limit_per_hour}",
                "per_minute": f"{rate_limiter.minute_count}/{config.rate_limit_per_minute}"
            } if rate_limiter else None
        }
    
    def test_provider(self, provider_id: str) -> Dict[str, Any]:
        """Test SMTP provider connection"""
        config = self.providers.get(provider_id)
        if not config:
            return {"success": False, "error": "Provider not found"}
        
        try:
            if config.use_ssl:
                server = smtplib.SMTP_SSL(config.host, config.port, timeout=10)
            else:
                server = smtplib.SMTP(config.host, config.port, timeout=10)
                if config.use_tls:
                    server.starttls()
            
            server.login(config.username, config.password)
            server.quit()
            
            return {
                "success": True,
                "provider_id": provider_id,
                "message": "Connection successful"
            }
        
        except Exception as e:
            return {
                "success": False,
                "provider_id": provider_id,
                "error": str(e)
            }
    
    def _send_via_provider(self, message: EmailMessage, provider_id: str) -> Dict[str, Any]:
        """Send email via specific provider"""
        config = self.providers.get(provider_id)
        if not config:
            return {"success": False, "error": "Provider not found"}
        
        if not config.enabled:
            return {"success": False, "error": "Provider disabled"}
        
        # Check rate limit
        rate_limiter = self.rate_limiters.get(provider_id)
        if rate_limiter and not rate_limiter.can_send():
            return {"success": False, "error": "Rate limit exceeded"}
        
        try:
            # Create MIME message
            mime_message = self._create_mime_message(message)
            
            # Connect to SMTP server
            if config.use_ssl:
                server = smtplib.SMTP_SSL(config.host, config.port, timeout=30)
            else:
                server = smtplib.SMTP(config.host, config.port, timeout=30)
                if config.use_tls:
                    server.starttls()
            
            # Login
            server.login(config.username, config.password)
            
            # Send
            server.send_message(mime_message)
            server.quit()
            
            # Update stats
            config.emails_sent += 1
            config.last_used = datetime.now()
            message.sent_at = datetime.now()
            message.delivered = True
            
            if rate_limiter:
                rate_limiter.record_send()
            
            return {
                "success": True,
                "message_id": message.message_id,
                "provider_id": provider_id,
                "recipient": message.recipient
            }
        
        except Exception as e:
            config.emails_failed += 1
            return {
                "success": False,
                "message_id": message.message_id,
                "provider_id": provider_id,
                "error": str(e)
            }
    
    def _send_with_failover(self, message: EmailMessage) -> Dict[str, Any]:
        """Send with automatic failover to backup providers"""
        # Sort providers by priority
        sorted_providers = sorted(
            [(pid, cfg) for pid, cfg in self.providers.items() if cfg.enabled],
            key=lambda x: x[1].priority
        )
        
        if not sorted_providers:
            return {"success": False, "error": "No providers available"}
        
        errors = []
        for provider_id, config in sorted_providers:
            result = self._send_via_provider(message, provider_id)
            if result["success"]:
                return result
            errors.append(f"{config.name}: {result.get('error', 'Unknown error')}")
        
        return {
            "success": False,
            "error": "All providers failed",
            "provider_errors": errors
        }
    
    def _create_mime_message(self, message: EmailMessage) -> MIMEMultipart:
        """Create MIME message"""
        mime_msg = MIMEMultipart('alternative')
        
        # Headers
        mime_msg['From'] = formataddr((message.sender_name, message.sender_email))
        mime_msg['To'] = message.recipient
        mime_msg['Subject'] = message.subject
        mime_msg['Date'] = formatdate(localtime=True)
        mime_msg['Message-ID'] = f"<{message.message_id}@phishing.local>"
        
        if message.reply_to:
            mime_msg['Reply-To'] = message.reply_to
        
        # Custom headers
        for key, value in message.custom_headers.items():
            mime_msg[key] = value
        
        # Text body
        if message.text_body:
            text_part = MIMEText(message.text_body, 'plain', 'utf-8')
            mime_msg.attach(text_part)
        
        # HTML body with tracking pixel
        html_body = message.html_body
        if message.tracking_pixel:
            tracking_url = f"https://tracking.local/pixel/{message.message_id}.gif"
            html_body += f'<img src="{tracking_url}" width="1" height="1" style="display:none">'
        
        html_part = MIMEText(html_body, 'html', 'utf-8')
        mime_msg.attach(html_part)
        
        # Inline images
        for img in message.inline_images:
            with open(img['path'], 'rb') as f:
                img_data = f.read()
            img_part = MIMEImage(img_data)
            img_part.add_header('Content-ID', f"<{img['cid']}>")
            img_part.add_header('Content-Disposition', 'inline')
            mime_msg.attach(img_part)
        
        return mime_msg
    
    def _queue_worker(self, worker_id: int):
        """Background queue worker"""
        while self.running:
            try:
                message, provider_id = self.send_queue.get(timeout=1)
                self.send_email(message, provider_id)
                self.send_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[Worker {worker_id}] Error: {e}")
    
    def _generate_provider_id(self) -> str:
        """Generate unique provider ID"""
        return f"smtp_{secrets.token_hex(6)}"


class RateLimiter:
    """Rate limiter for SMTP sending"""
    
    def __init__(self, per_hour: int, per_minute: int):
        self.per_hour = per_hour
        self.per_minute = per_minute
        self.hour_window = []
        self.minute_window = []
        self.lock = threading.Lock()
    
    def can_send(self) -> bool:
        """Check if we can send another email"""
        with self.lock:
            now = datetime.now()
            
            # Clean old entries
            self.hour_window = [t for t in self.hour_window if (now - t).total_seconds() < 3600]
            self.minute_window = [t for t in self.minute_window if (now - t).total_seconds() < 60]
            
            # Check limits
            if len(self.hour_window) >= self.per_hour:
                return False
            if len(self.minute_window) >= self.per_minute:
                return False
            
            return True
    
    def record_send(self):
        """Record an email send"""
        with self.lock:
            now = datetime.now()
            self.hour_window.append(now)
            self.minute_window.append(now)
    
    @property
    def hour_count(self) -> int:
        """Current hour count"""
        now = datetime.now()
        self.hour_window = [t for t in self.hour_window if (now - t).total_seconds() < 3600]
        return len(self.hour_window)
    
    @property
    def minute_count(self) -> int:
        """Current minute count"""
        now = datetime.now()
        self.minute_window = [t for t in self.minute_window if (now - t).total_seconds() < 60]
        return len(self.minute_window)


# Pre-configured providers
def create_gmail_provider(email: str, password: str, name: str = "Gmail") -> SMTPConfig:
    """Create Gmail SMTP provider"""
    return SMTPConfig(
        provider=SMTPProvider.GMAIL,
        host="smtp.gmail.com",
        port=587,
        username=email,
        password=password,
        use_tls=True,
        name=name,
        rate_limit_per_hour=500,
        rate_limit_per_minute=20
    )


def create_outlook_provider(email: str, password: str, name: str = "Outlook") -> SMTPConfig:
    """Create Outlook SMTP provider"""
    return SMTPConfig(
        provider=SMTPProvider.OUTLOOK,
        host="smtp.office365.com",
        port=587,
        username=email,
        password=password,
        use_tls=True,
        name=name,
        rate_limit_per_hour=300,
        rate_limit_per_minute=10
    )


def create_sendgrid_provider(api_key: str, name: str = "SendGrid") -> SMTPConfig:
    """Create SendGrid SMTP provider"""
    return SMTPConfig(
        provider=SMTPProvider.SENDGRID,
        host="smtp.sendgrid.net",
        port=587,
        username="apikey",
        password=api_key,
        use_tls=True,
        name=name,
        rate_limit_per_hour=10000,
        rate_limit_per_minute=100
    )


# Singleton
_smtp_manager = None

def get_smtp_manager() -> MultiProviderSMTPManager:
    """Get SMTP manager singleton"""
    global _smtp_manager
    if _smtp_manager is None:
        _smtp_manager = MultiProviderSMTPManager()
    return _smtp_manager
