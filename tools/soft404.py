# tools/soft404.py
"""
Soft-404 (sahte 200) tespiti.

Bazı uygulamalar var olmayan sayfalar icin 404 donmek yerine 200 ile
"Sayfa bulunamadi" sablonu doner (soft-404). Tarayicilar bu sayfalari
gercek endpoint zannedip formlara payload yazar ve yanki (reflection)
uyaklari yuzunden yanlis pozitif (ornegin "giris basarili" goruntusu)
uretebilir.

Bu modul hem web_app_scanner hem de autopwn tarayicisinda kullanilabilen
paylasimli bir Soft404Detector saglar.
"""

import hashlib
import logging
import re
import urllib.parse
from typing import Dict, Optional, Set

logger = logging.getLogger(__name__)

# Kesin 404/soft-404 isaretleyicileri (baslik + govde). Turkce/ingilizce.
_NOT_FOUND_MARKERS = [
    "404",
    "not found",
    "page not found",
    "sayfa bulunamad",
    "bulunamad",
    "does not exist",
    "could not be found",
    "error 404",
    "this page could not be found",
    "the requested url was not found",
    "no se encontro",
    "nicht gefunden",
    "introuvable",
    "non trovata",
]

# Baslik etiketini cikar (soft-404 sablonlari genelde ayni basliga sahip)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _normalize(text: str) -> str:
    text = re.sub(r"\s+", " ", text or "").strip().lower()
    return text


def _title_of(text: str) -> str:
    m = _TITLE_RE.search(text or "")
    if not m:
        return ""
    return _normalize(m.group(1))


class Soft404Detector:
    """
    Bir hedef icin soft-404 imzasini olusturur ve sonraki yanitlari
    bu imzayla karsilastirir.

    Kullanim:
        det = Soft404Detector(session)
        det.build_baseline("https://site.com")
        if det.is_soft_404(response, "https://site.com"):
            ...  # sahte 200, gercekte yok
    """

    def __init__(self, session, baseline_timeout: int = 10, verify: bool = False):
        self.session = session
        self.baseline_timeout = baseline_timeout
        self.verify = verify
        # Hedef bazli imza on bellegi: netloc -> signature
        self._baseline: Dict[str, str] = {}
        # Boylecek tura (discovered) sayfalar icin sonuc on bellegi
        self.cache: Dict[str, bool] = {}

    def _signature(self, response) -> str:
        text = response.text or ""
        norm = _normalize(text)
        title = _title_of(text)
        length = len(text)
        # Uzunluk + baslik + ilk 256 karakterlik ozet. Icerik benzerse
        # ayni hash duser (soft-404 sablonlari icin beklenen davranis).
        digest_input = f"{length}|{title}|{norm[:256]}"
        return hashlib.md5(digest_input.encode("utf-8", "ignore")).hexdigest()

    def _looks_like_not_found(self, response) -> bool:
        text = _normalize(response.text or "")
        if not text:
            return False
        title = _title_of(response.text or "")
        if any(marker in title for marker in _NOT_FOUND_MARKERS):
            return True
        if any(marker in text[:400] for marker in _NOT_FOUND_MARKERS):
            return True
        return False

    def build_baseline(self, base_url: str, probes: int = 3) -> Optional[str]:
        """
        Kesinlikle var olmayan birkac URL cekip soft-404 imzasini olusturur.
        Yonlendirme (3xx) olanlar yok sayilir; en az 2 probe ayni imzayi
        dondururse o imza soft-404 olarak kabul edilir (gorultu onleme).
        """
        try:
            import uuid

            parsed = urllib.parse.urlparse(base_url)
            sigs: Dict[str, int] = {}
            for _ in range(probes):
                token = uuid.uuid4().hex
                test_url = f"{parsed.scheme}://{parsed.netloc}/{token}"
                try:
                    resp = self.session.get(
                        test_url, timeout=self.baseline_timeout, verify=self.verify,
                        allow_redirects=False,
                    )
                except Exception:
                    continue
                # Sadece dogrudan 200 donen "bulunamadi" sayfalarini imza al
                if resp.status_code != 200:
                    continue
                sig = self._signature(resp)
                sigs[sig] = sigs.get(sig, 0) + 1

            if sigs:
                best = max(sigs, key=sigs.get)
                if sigs[best] >= 2 or probes == 1:
                    self._baseline[parsed.netloc] = best
                    logger.debug("Soft-404 baseline for %s: %s", parsed.netloc, best)
                    return best
        except Exception as e:  # pragma: no cover - network dependent
            logger.debug("build_baseline failed for %s: %s", base_url, e)
        return None

    def is_soft_404(self, response, base_url: str) -> bool:
        """
        Yanit 200 donuyorsa ve gercekte var olmayan bir sayfaya aitse True.

        Mantik:
          1) status 200 degilse -> soft-404 degil (gercek 404/3xx/5xx)
          2) hedef icin imza varsa -> imza eslesiyorsa soft-404
          3) imza yoksa -> icerik 404 isaretleyicileri tasiyorsa soft-404
        """
        if getattr(response, "status_code", 0) != 200:
            return False

        parsed = urllib.parse.urlparse(base_url)
        netloc = parsed.netloc

        if netloc in self._baseline:
            return self._signature(response) == self._baseline[netloc]

        # Imza olusturulmamissa en azindan bariz 404 isaretleyicilerine bak
        return self._looks_like_not_found(response)

    def filter_soft_404(self, urls: Set[str], base_url: str) -> Set[str]:
        """Bir URL kumesini soft-404 olmayanlarla sinirla (on bellekli)."""
        kept: Set[str] = set()
        for url in urls:
            if url in self.cache:
                if not self.cache[url]:
                    kept.add(url)
                continue
            try:
                resp = self.session.get(url, timeout=self.baseline_timeout, verify=self.verify)
                is_dead = self.is_soft_404(resp, base_url)
                self.cache[url] = is_dead
                if not is_dead:
                    kept.add(url)
            except Exception:
                # Cekilemeyen sayfayi guvenli tarafta tut (gercek sayfa olabilir)
                kept.add(url)
        return kept
