"""
tools/hunter_pacing.py
======================
Adaptive Hunting Throttling — Yavaş Adımlı Akıllı Avcı.

autonomous_hunter.py şu an bodoslama dalıyor. Eğer jüri network içine
Honey Token (sahte aktif dizin hesabı) veya Decoy IP (tuzak domain controller)
koyduysa, otonom avcı bunları mass LDAP sorgusuyla tetikler ve anında SOC
alarmı üretip bizi yarışmadan diskalifiye ettirir.

Silah: AD veritabanındaki kullanıcıların badpwdcount ve pwdlastset zaman
damgalarını, makinelerin ise network response sürelerini analiz eden ve jüri
tuzaklarının yanından sessizce geçmesini sağlayan Gaussian jitter tabanlı
yavaş adımlı (slow-pacing) otonom kontrolcü.
"""

from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class PaceResult:
    """
    Bir pacing kararının sonucu.
    """
    action: str                 # "execute", "skip", "delay"
    delay_seconds: float = 0.0
    reason: str = ""
    target_info: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DecoyProfile:
    """
    Jüri tuzaklarının (Honey Token / Decoy DC) profili.
    """
    indicators: List[str]
    min_badpwdcount: int = 0
    max_response_time_ms: int = 50
    suspicious_names: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# HunterPacer
# ---------------------------------------------------------------------------

class HunterPacer:
    """
    Gaussian jitter tabanlı yavaş adımlı (slow-pacing) otonom kontrolcü.

    Hedefler:
    1. Jüri tuzaklarını (Honey Tokens / Decoy DCs) tanımla ve es geç.
    2. EDR'ın 'Mass Spreading' alarmlarını tetiklememek için insani gecikmeler ekle.
    3. AD objelerinin davranışsal imzalarını analiz et (badpwdcount, pwdlastset).
    """

    def __init__(
        self,
        jitter_mean: float = 6.0,
        jitter_stddev: float = 1.5,
        min_delay: float = 2.0,
        decoy_indicators: Optional[List[str]] = None,
    ) -> None:
        self.jitter_mean = jitter_mean
        self.jitter_stddev = jitter_stddev
        self.min_delay = min_delay

        self.decoy_indicators = decoy_indicators or [
            "canary", "trap", "honey", "decoy", "fake", "testuser",
            "honeytoken", "alert", "monitor", "sensor", "watcher",
        ]

        self.decoy_profile = DecoyProfile(
            indicators=self.decoy_indicators,
            suspicious_names=self.decoy_indicators,
        )

        self._action_log: List[Dict[str, Any]] = []

    def filter_decoy_assets(self, sampled_users: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Active Directory'den dönen jüri tuzaklarını (Honey Tokens) eler.

        Parametreler
        ------------
        sampled_users : [{"username": ..., "badpwdcount": ..., "pwdlastset": ...}, ...]

        Dönüş
        ------
        Güvenli kullanıcı listesi.
        """
        safe_fleet = []
        for user in sampled_users:
            username = user.get("username", "").lower()
            if any(decoy in username for decoy in self.decoy_indicators):
                logger.warning("[PACER] Jüri tuzağı tespit edildi, es geçiliyor la: %s", username)
                self._action_log.append({
                    "action": "skip",
                    "reason": f"decoy_indicator: {username}",
                    "target": username,
                    "timestamp": time.time(),
                })
                continue

            badpwdcount = user.get("badpwdcount", 0)
            if isinstance(badpwdcount, (int, float)) and badpwdcount > 100:
                logger.warning(
                    "[PACER] Şüpheli yüksek badpwdcount (%s) — %s, es geçiliyor.",
                    badpwdcount,
                    username,
                )
                self._action_log.append({
                    "action": "skip",
                    "reason": f"high_badpwdcount: {badpwdcount}",
                    "target": username,
                    "timestamp": time.time(),
                })
                continue

            safe_fleet.append(user)

        logger.info("[PACER] Decoy filter applied. %s/%s users passed.", len(safe_fleet), len(sampled_users))
        return safe_fleet

    def is_decoy_target(self, target_ip: str, target_hostname: str = "") -> bool:
        """
        IP veya hostname'e bakarak jüri tuzak olup olmadığını kontrol eder.
        """
        haystack = f"{target_ip} {target_hostname}".lower()
        if any(ind in haystack for ind in self.decoy_indicators):
            logger.warning("[PACER] Decoy target detected: %s (%s)", target_hostname or target_ip, target_ip)
            return True
        return False

    def pace_target(self, target_ip: str, action_fn: Callable, *args: Any, **kwargs: Any) -> Any:
        """
        EDR'ın 'Mass Spreading' alarmlarını tetiklememek için Gaussian gecikme
        çakar ve hedefe `action_fn`'yi uygular.

        Parametreler
        ------------
        target_ip : Hedef IP.
        action_fn : Çağrılacak fonksiyon.

        Dönüş
        ------
        action_fn'den dönen değer.
        """
        if self.is_decoy_target(target_ip):
            self._action_log.append({
                "action": "skip",
                "reason": "decoy_target",
                "target": target_ip,
                "timestamp": time.time(),
            })
            return None

        jitter = random.gauss(self.jitter_mean, self.jitter_stddev)
        delay = max(self.min_delay, jitter)

        logger.info("[PACER] Delaying action on %s by %.2f seconds.", target_ip, delay)
        time.sleep(delay)

        result = action_fn(*args, **kwargs)

        self._action_log.append({
            "action": "execute",
            "delay": delay,
            "target": target_ip,
            "timestamp": time.time(),
        })

        return result

    def execute_with_jitter(
        self,
        target_ip: str,
        action_fn: Callable,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """
        EDR'ın 'Mass Spreading' alarmlarını tetiklememek için Gaussian gecikme çakar.

        Bu metod `pace_target` için bir alias olarak kalır — geriye dönük
        uyumluluk için korunur.
        """
        return self.pace_target(target_ip, action_fn, *args, **kwargs)

    def analyze_ad_user_risk(
        self,
        username: str,
        badpwdcount: int = 0,
        pwdlastset: Optional[str] = None,
        logon_count: int = 0,
    ) -> Dict[str, Any]:
        """
        AD kullanıcısının honey token risk analizini yapar.

        Yüksek risk belirteçleri:
        - badpwdcount çok yüksek (test kullanıcıları genellikle yüksek başarısız giriş).
        - pwdlastset çok eski (pasif ama izlenen hesaplar).
        - logon_count çok düşük (asla kullanılmayan hesaplar).
        """
        risk_score = 0
        risk_factors: List[str] = []

        if badpwdcount > 100:
            risk_score += 50
            risk_factors.append(f"high_badpwdcount ({badpwdcount})")

        if logon_count == 0:
            risk_score += 30
            risk_factors.append("zero_logon_count")

        if pwdlastset:
            try:
                from datetime import datetime
                pwd_dt = datetime.fromisoformat(pwdlastset.replace("Z", "+00:00"))
                days_since = (datetime.now(pwd_dt.tzinfo) - pwd_dt).days
                if days_since > 365:
                    risk_score += 20
                    risk_factors.append(f"stale_password ({days_since}d)")
            except Exception:
                pass

        is_decoy = any(ind in username.lower() for ind in self.decoy_indicators)
        if is_decoy:
            risk_score += 100
            risk_factors.append("decoy_name_pattern")

        return {
            "username": username,
            "risk_score": risk_score,
            "is_decoy": risk_score >= 50,
            "risk_factors": risk_factors,
            "recommendation": "skip" if risk_score >= 50 else "proceed",
        }

    def analyze_machine_risk(
        self,
        hostname: str,
        ip: str,
        response_time_ms: int = 0,
        is_dc: bool = False,
    ) -> Dict[str, Any]:
        """
        Makine (host) seviyesinde decoy risk analizi.
        """
        risk_score = 0
        risk_factors: List[str] = []

        if is_dc and response_time_ms < 5:
            risk_score += 40
            risk_factors.append(f"hyperresponsive_dc ({response_time_ms}ms)")

        if any(ind in hostname.lower() for ind in self.decoy_indicators):
            risk_score += 100
            risk_factors.append("decoy_hostname_pattern")

        if not is_dc and response_time_ms < 2:
            risk_score += 20
            risk_factors.append(f"hyperresponsive_non_dc ({response_time_ms}ms)")

        return {
            "hostname": hostname,
            "ip": ip,
            "risk_score": risk_score,
            "is_decoy": risk_score >= 50,
            "risk_factors": risk_factors,
            "recommendation": "skip" if risk_score >= 50 else "proceed",
        }

    def get_pace_log(self) -> List[Dict[str, Any]]:
        """
        Tüm pacing aksiyonlarının kaydını döndürür.
        """
        return list(self._action_log)

    def clear_log(self) -> None:
        """
        Pacing aksiyon kaydını temizler.
        """
        self._action_log.clear()
