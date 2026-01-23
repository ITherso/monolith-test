"""
HTTP Header Rotation Module
Browser-like traffic mimicry to evade network-based detection
"""
import random
from typing import Dict, List, Optional
from dataclasses import dataclass
import time
import hashlib


@dataclass
class BrowserProfile:
    """Browser fingerprint profile"""
    name: str
    user_agent: str
    accept: str
    accept_language: str
    accept_encoding: str
    sec_ch_ua: str
    sec_ch_ua_mobile: str
    sec_ch_ua_platform: str
    sec_fetch_dest: str
    sec_fetch_mode: str
    sec_fetch_site: str


# Real browser profiles captured from actual browsers
BROWSER_PROFILES = [
    BrowserProfile(
        name="Chrome_Windows_124",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br, zstd",
        sec_ch_ua='"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        sec_ch_ua_mobile="?0",
        sec_ch_ua_platform='"Windows"',
        sec_fetch_dest="document",
        sec_fetch_mode="navigate",
        sec_fetch_site="none"
    ),
    BrowserProfile(
        name="Chrome_MacOS_124",
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua='"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        sec_ch_ua_mobile="?0",
        sec_ch_ua_platform='"macOS"',
        sec_fetch_dest="document",
        sec_fetch_mode="navigate",
        sec_fetch_site="same-origin"
    ),
    BrowserProfile(
        name="Firefox_Windows_125",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        accept_language="en-US,en;q=0.5",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua="",  # Firefox doesn't send these
        sec_ch_ua_mobile="",
        sec_ch_ua_platform="",
        sec_fetch_dest="document",
        sec_fetch_mode="navigate",
        sec_fetch_site="none"
    ),
    BrowserProfile(
        name="Firefox_Linux_125",
        user_agent="Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        accept_language="en-US,en;q=0.5",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua="",
        sec_ch_ua_mobile="",
        sec_ch_ua_platform="",
        sec_fetch_dest="document",
        sec_fetch_mode="navigate",
        sec_fetch_site="cross-site"
    ),
    BrowserProfile(
        name="Edge_Windows_124",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.67",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br, zstd",
        sec_ch_ua='"Chromium";v="124", "Microsoft Edge";v="124", "Not-A.Brand";v="99"',
        sec_ch_ua_mobile="?0",
        sec_ch_ua_platform='"Windows"',
        sec_fetch_dest="document",
        sec_fetch_mode="navigate",
        sec_fetch_site="none"
    ),
    BrowserProfile(
        name="Safari_MacOS_17",
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua="",  # Safari doesn't send these
        sec_ch_ua_mobile="",
        sec_ch_ua_platform="",
        sec_fetch_dest="document",
        sec_fetch_mode="navigate",
        sec_fetch_site="same-origin"
    ),
    BrowserProfile(
        name="Chrome_Android_124",
        user_agent="Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua='"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        sec_ch_ua_mobile="?1",
        sec_ch_ua_platform='"Android"',
        sec_fetch_dest="document",
        sec_fetch_mode="navigate",
        sec_fetch_site="none"
    ),
    BrowserProfile(
        name="Safari_iOS_17",
        user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua="",
        sec_ch_ua_mobile="",
        sec_ch_ua_platform="",
        sec_fetch_dest="document",
        sec_fetch_mode="navigate",
        sec_fetch_site="same-origin"
    ),
]


class HeaderRotator:
    """
    Rotate HTTP headers to mimic real browser traffic.
    Evades signature-based detection and network fingerprinting.
    """
    
    def __init__(self, sticky: bool = False, sticky_duration: int = 3600):
        """
        Initialize header rotator.
        
        Args:
            sticky: Keep same profile for duration (more realistic)
            sticky_duration: How long to keep same profile (seconds)
        """
        self.sticky = sticky
        self.sticky_duration = sticky_duration
        self._current_profile: Optional[BrowserProfile] = None
        self._profile_timestamp: float = 0
        self._request_count = 0
        
    def get_profile(self) -> BrowserProfile:
        """Get current or new browser profile"""
        now = time.time()
        
        if self.sticky:
            # Keep same profile for duration
            if (self._current_profile is None or 
                now - self._profile_timestamp > self.sticky_duration):
                self._current_profile = random.choice(BROWSER_PROFILES)
                self._profile_timestamp = now
            return self._current_profile
        else:
            # Random profile each time
            return random.choice(BROWSER_PROFILES)
    
    def get_headers(self, 
                    content_type: str = None,
                    custom_headers: Dict[str, str] = None,
                    include_cookies: bool = False) -> Dict[str, str]:
        """
        Generate browser-like HTTP headers.
        
        Args:
            content_type: Override content-type
            custom_headers: Additional custom headers
            include_cookies: Include fake session cookies
        """
        profile = self.get_profile()
        self._request_count += 1
        
        headers = {
            "User-Agent": profile.user_agent,
            "Accept": profile.accept,
            "Accept-Language": self._randomize_language(profile.accept_language),
            "Accept-Encoding": profile.accept_encoding,
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        
        # Add Sec-CH-UA headers for Chromium browsers
        if profile.sec_ch_ua:
            headers["Sec-CH-UA"] = profile.sec_ch_ua
            headers["Sec-CH-UA-Mobile"] = profile.sec_ch_ua_mobile
            headers["Sec-CH-UA-Platform"] = profile.sec_ch_ua_platform
        
        # Sec-Fetch headers
        headers["Sec-Fetch-Dest"] = profile.sec_fetch_dest
        headers["Sec-Fetch-Mode"] = profile.sec_fetch_mode
        headers["Sec-Fetch-Site"] = profile.sec_fetch_site
        headers["Sec-Fetch-User"] = "?1"
        
        # Override content type if specified
        if content_type:
            headers["Content-Type"] = content_type
        
        # Add fake cookies for session persistence
        if include_cookies:
            headers["Cookie"] = self._generate_fake_cookies()
        
        # Add cache headers randomly
        if random.random() < 0.7:
            headers["Cache-Control"] = random.choice([
                "max-age=0",
                "no-cache",
                "no-store, no-cache, must-revalidate"
            ])
        
        # Merge custom headers
        if custom_headers:
            headers.update(custom_headers)
        
        return headers
    
    def _randomize_language(self, base_language: str) -> str:
        """Add slight variations to accept-language"""
        variations = [
            base_language,
            base_language.replace("en-US", "en-GB"),
            base_language + ",de;q=0.3",
            base_language + ",fr;q=0.3",
        ]
        return random.choice(variations)
    
    def _generate_fake_cookies(self) -> str:
        """Generate realistic-looking session cookies"""
        cookies = []
        
        # Common cookie patterns
        patterns = [
            ("_ga", f"GA1.2.{random.randint(100000000, 999999999)}.{int(time.time())}"),
            ("_gid", f"GA1.2.{random.randint(100000000, 999999999)}.{int(time.time())}"),
            ("session", hashlib.md5(str(random.random()).encode()).hexdigest()[:32]),
            ("csrf_token", hashlib.sha256(str(random.random()).encode()).hexdigest()[:32]),
            ("PHPSESSID", hashlib.md5(str(random.random()).encode()).hexdigest()),
        ]
        
        # Select random subset
        selected = random.sample(patterns, k=random.randint(2, 4))
        cookies = [f"{name}={value}" for name, value in selected]
        
        return "; ".join(cookies)
    
    def get_ajax_headers(self, referer: str = None) -> Dict[str, str]:
        """Get headers for AJAX/XHR requests"""
        headers = self.get_headers()
        headers.update({
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/json",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
        })
        
        if referer:
            headers["Referer"] = referer
            headers["Origin"] = referer.split('/')[0] + '//' + referer.split('/')[2]
        
        return headers
    
    def get_api_headers(self, api_key: str = None) -> Dict[str, str]:
        """Get headers for API requests"""
        headers = {
            "User-Agent": self.get_profile().user_agent,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Accept-Encoding": "gzip, deflate, br",
        }
        
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        
        return headers


class TLSFingerprint:
    """
    TLS fingerprint randomization.
    JA3/JA3S fingerprint modification to evade TLS-based detection.
    """
    
    # Common cipher suites for different browsers
    CIPHER_SUITES = {
        'chrome': [
            0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f,
            0xcca9, 0xcca8, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c
        ],
        'firefox': [
            0x1301, 0x1303, 0x1302, 0xc02c, 0xc02b, 0xc024, 0xc023,
            0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c
        ],
        'safari': [
            0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f,
            0xc024, 0xc023, 0xc014, 0xc013
        ]
    }
    
    @staticmethod
    def get_cipher_suite_order(browser: str = 'chrome') -> List[int]:
        """Get cipher suite order for specific browser"""
        suites = TLSFingerprint.CIPHER_SUITES.get(browser, 
                                                   TLSFingerprint.CIPHER_SUITES['chrome'])
        # Add slight randomization to order
        if random.random() < 0.3:
            random.shuffle(suites)
        return suites


# Singleton instance
_rotator = None

def get_header_rotator(sticky: bool = True) -> HeaderRotator:
    """Get singleton header rotator"""
    global _rotator
    if _rotator is None:
        _rotator = HeaderRotator(sticky=sticky)
    return _rotator
