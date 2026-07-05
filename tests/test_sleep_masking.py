"""
Test Suite: Sleepmask & Runtime Masking
========================================
Beacon Sleep tarzı memory masking testleri

Test Scenarios:
1. MaskingCrypto: XOR, RC4, ChaCha20
2. SleepSkipDetector: Anomaly detection
3. SleepmaskEngine: Masked sleep operations
4. DripLoader: Slow memory loading
5. RuntimeMaskingCycle: decrypt → execute → re-mask
6. BeaconSleepAgent: Long-term sleep test (5-10 dk)
"""

import pytest
import time
import threading
import secrets
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evasion.sleep_masking import (
    SleepTechnique,
    MaskingMode,
    SleepmaskConfig,
    MaskedRegion,
    SleepMetrics,
    MaskingCrypto,
    DripLoader,
    SleepSkipDetector,
    SleepmaskEngine,
    RuntimeMaskingCycle,
    BeaconSleepAgent,
)


# ============================================================
# MASKING CRYPTO TESTS
# ============================================================

class TestMaskingCrypto:
    """MaskingCrypto test suite"""
    
    def test_generate_key_default_size(self):
        """Test key generation with default size"""
        key = MaskingCrypto.generate_key()
        assert len(key) == 32
        assert isinstance(key, bytes)
    
    def test_generate_key_custom_size(self):
        """Test key generation with custom size"""
        key = MaskingCrypto.generate_key(64)
        assert len(key) == 64
    
    def test_xor_encrypt_decrypt(self):
        """Test XOR encryption is reversible"""
        data = b"Test data for XOR encryption"
        key = MaskingCrypto.generate_key(16)
        
        encrypted = MaskingCrypto.xor_encrypt(data, key)
        decrypted = MaskingCrypto.xor_encrypt(encrypted, key)
        
        assert encrypted != data
        assert decrypted == data
    
    def test_xor_different_keys_different_output(self):
        """Test XOR with different keys produces different output"""
        data = b"Same data"
        key1 = MaskingCrypto.generate_key(16)
        key2 = MaskingCrypto.generate_key(16)
        
        enc1 = MaskingCrypto.xor_encrypt(data, key1)
        enc2 = MaskingCrypto.xor_encrypt(data, key2)
        
        assert enc1 != enc2
    
    def test_rc4_encrypt_decrypt(self):
        """Test RC4 encryption is reversible"""
        data = b"Test data for RC4 stream cipher"
        key = MaskingCrypto.generate_key(16)
        
        encrypted = MaskingCrypto.rc4_crypt(data, key)
        decrypted = MaskingCrypto.rc4_crypt(encrypted, key)
        
        assert encrypted != data
        assert decrypted == data
    
    def test_chacha20_encrypt_decrypt(self):
        """Test ChaCha20 encryption"""
        data = b"Test data for ChaCha20"
        key = MaskingCrypto.generate_key(32)
        
        encrypted = MaskingCrypto.chacha20_crypt(data, key)
        decrypted = MaskingCrypto.chacha20_crypt(encrypted, key)
        
        assert encrypted != data
        assert decrypted == data
    
    def test_encrypt_with_mode(self):
        """Test encrypt method with different modes"""
        data = b"Test data"
        key = MaskingCrypto.generate_key(32)
        
        for mode in MaskingMode:
            encrypted = MaskingCrypto.encrypt(data, key, mode)
            decrypted = MaskingCrypto.decrypt(encrypted, key, mode)
            assert decrypted == data, f"Failed for mode: {mode}"
    
    def test_empty_data(self):
        """Test encryption of empty data"""
        data = b""
        key = MaskingCrypto.generate_key(16)
        
        encrypted = MaskingCrypto.xor_encrypt(data, key)
        assert encrypted == b""
    
    def test_large_data(self):
        """Test encryption of large data"""
        data = secrets.token_bytes(1024 * 1024)  # 1MB
        key = MaskingCrypto.generate_key(32)
        
        encrypted = MaskingCrypto.encrypt(data, key, MaskingMode.XOR)
        decrypted = MaskingCrypto.decrypt(encrypted, key, MaskingMode.XOR)
        
        assert decrypted == data


# ============================================================
# SLEEP SKIP DETECTOR TESTS
# ============================================================

class TestSleepSkipDetector:
    """SleepSkipDetector test suite"""
    
    def test_normal_sleep(self):
        """Test no skip detected for normal sleep"""
        detector = SleepSkipDetector(tolerance_percent=0.2)
        
        skip, reason = detector.check_sleep_skip(1000, 1000)
        assert not skip
        assert reason == "Normal"
    
    def test_sleep_shortened(self):
        """Test skip detection when sleep is shortened"""
        detector = SleepSkipDetector(tolerance_percent=0.2)
        
        # Sleep was 50% shorter
        skip, reason = detector.check_sleep_skip(1000, 500)
        
        assert skip
        assert "shortened" in reason.lower()
    
    def test_sleep_within_tolerance(self):
        """Test no skip for sleep within tolerance"""
        detector = SleepSkipDetector(tolerance_percent=0.2)
        
        # Sleep was 15% shorter (within 20% tolerance)
        skip, reason = detector.check_sleep_skip(1000, 850)
        
        assert not skip
    
    def test_sleep_extended_debugger(self):
        """Test skip detection for extended sleep (debugger)"""
        detector = SleepSkipDetector(tolerance_percent=0.2)
        
        # Sleep was 4x longer
        skip, reason = detector.check_sleep_skip(1000, 4000)
        
        assert skip
        assert "extended" in reason.lower() or "debug" in reason.lower()
    
    def test_anomaly_report_empty(self):
        """Test anomaly report with no data"""
        detector = SleepSkipDetector()
        report = detector.get_anomaly_report()
        
        assert report["status"] == "no_data"
    
    def test_anomaly_report_with_data(self):
        """Test anomaly report after measurements"""
        detector = SleepSkipDetector()
        
        # Simulate measurements
        detector.check_sleep_skip(1000, 1000)  # Normal
        detector.check_sleep_skip(1000, 500)   # Skip
        detector.check_sleep_skip(1000, 950)   # Normal
        
        detector.measurements = [
            {"expected": 1000, "tick": 1000, "skip_detected": False},
            {"expected": 1000, "tick": 500, "skip_detected": True},
            {"expected": 1000, "tick": 950, "skip_detected": False},
        ]
        
        report = detector.get_anomaly_report()
        
        assert report["total_checks"] == 3
        assert report["skips_detected"] == 1
        assert report["skip_ratio"] == pytest.approx(1/3, rel=0.01)


# ============================================================
# SLEEPMASK ENGINE TESTS
# ============================================================

class TestSleepmaskEngine:
    """SleepmaskEngine test suite"""
    
    def test_default_config(self):
        """Test engine with default config"""
        engine = SleepmaskEngine()
        
        assert engine.config.technique == SleepTechnique.EKKO
        assert engine.config.masking_mode == MaskingMode.XOR
    
    def test_custom_config(self):
        """Test engine with custom config"""
        config = SleepmaskConfig(
            technique=SleepTechnique.DEATH_SLEEP,
            masking_mode=MaskingMode.RC4,
            min_sleep_ms=2000,
            max_sleep_ms=10000,
        )
        engine = SleepmaskEngine(config)
        
        assert engine.config.technique == SleepTechnique.DEATH_SLEEP
        assert engine.config.masking_mode == MaskingMode.RC4
    
    def test_basic_sleep(self):
        """Test basic sleep without masking"""
        config = SleepmaskConfig(
            technique=SleepTechnique.BASIC,
            check_sleep_skip=False,
            jitter_percent=0.0,  # No jitter for predictable test
        )
        engine = SleepmaskEngine(config)
        
        start = time.time()
        result = engine.masked_sleep(500)  # 500ms
        elapsed = (time.time() - start) * 1000
        
        assert result["success"]
        assert 400 <= elapsed <= 1200  # Allow for system variance
    
    def test_sleep_with_jitter(self):
        """Test sleep includes jitter"""
        config = SleepmaskConfig(
            jitter_percent=0.5,  # 50% jitter
            min_sleep_ms=1000,
            max_sleep_ms=2000,
        )
        engine = SleepmaskEngine(config)
        
        # Multiple sleeps should have varying durations
        durations = []
        for _ in range(5):
            start = time.time()
            engine.masked_sleep(1000)
            durations.append((time.time() - start) * 1000)
        
        # With 50% jitter on 1000ms, range should be 500-1500ms
        # Check there's some variance
        assert max(durations) - min(durations) > 100  # At least 100ms variance
    
    def test_metrics_tracking(self):
        """Test metrics are tracked"""
        engine = SleepmaskEngine()
        
        engine.masked_sleep(100)
        engine.masked_sleep(100)
        
        metrics = engine.get_metrics()
        
        assert metrics["total_sleeps"] == 2
        assert metrics["total_sleep_time_ms"] > 0
    
    def test_ekko_sleep_technique(self):
        """Test Ekko sleep technique"""
        config = SleepmaskConfig(technique=SleepTechnique.EKKO)
        engine = SleepmaskEngine(config)
        
        result = engine.masked_sleep(200)
        
        assert result["technique_used"] == "ekko"
    
    def test_foliage_sleep_technique(self):
        """Test Foliage sleep technique"""
        config = SleepmaskConfig(technique=SleepTechnique.FOLIAGE)
        engine = SleepmaskEngine(config)
        
        result = engine.masked_sleep(200)
        
        assert result["technique_used"] == "foliage"
    
    def test_death_sleep_technique(self):
        """Test Death Sleep technique"""
        config = SleepmaskConfig(technique=SleepTechnique.DEATH_SLEEP)
        engine = SleepmaskEngine(config)
        
        result = engine.masked_sleep(200)
        
        assert result["technique_used"] == "death_sleep"


# ============================================================
# DRIP LOADER TESTS
# ============================================================

class TestDripLoader:
    """DripLoader test suite"""
    
    def test_init_default_params(self):
        """Test DripLoader initialization"""
        loader = DripLoader()
        
        assert loader.chunk_size == 4096
        assert loader.delay_ms == 100
    
    def test_init_custom_params(self):
        """Test DripLoader with custom params"""
        loader = DripLoader(chunk_size=1024, delay_ms=50)
        
        assert loader.chunk_size == 1024
        assert loader.delay_ms == 50
    
    def test_cleanup(self):
        """Test cleanup method"""
        loader = DripLoader()
        loader.loaded_regions = [(0x1000, 100), (0x2000, 200)]
        loader.total_loaded = 300
        
        loader.cleanup()
        
        assert loader.loaded_regions == []
        assert loader.total_loaded == 0


# ============================================================
# RUNTIME MASKING CYCLE TESTS
# ============================================================

class TestRuntimeMaskingCycle:
    """RuntimeMaskingCycle test suite"""
    
    def test_init(self):
        """Test cycle initialization"""
        engine = SleepmaskEngine()
        cycle = RuntimeMaskingCycle(engine)
        
        assert cycle.engine == engine
        assert cycle.code_regions == []
        assert cycle.heap_regions == []
    
    def test_register_code_region(self):
        """Test registering code region"""
        cycle = RuntimeMaskingCycle()
        
        cycle.register_code_region(0x1000, 4096)
        
        assert (0x1000, 4096) in cycle.code_regions
    
    def test_register_heap_region(self):
        """Test registering heap region"""
        cycle = RuntimeMaskingCycle()
        
        cycle.register_heap_region(0x2000, 8192)
        
        assert (0x2000, 8192) in cycle.heap_regions
    
    def test_execute_with_masking(self):
        """Test execute with masking"""
        cycle = RuntimeMaskingCycle()
        
        def test_func(x, y):
            return x + y
        
        result = cycle.execute_with_masking(test_func, 3, 5)
        
        assert result == 8
        assert cycle._cycle_count == 1
    
    def test_stop(self):
        """Test stop method"""
        cycle = RuntimeMaskingCycle()
        cycle._active = True
        
        cycle.stop()
        
        assert not cycle._active


# ============================================================
# BEACON SLEEP AGENT TESTS
# ============================================================

class TestBeaconSleepAgent:
    """BeaconSleepAgent test suite"""
    
    def test_init_default(self):
        """Test agent initialization"""
        agent = BeaconSleepAgent()
        
        assert not agent._running
        assert agent.check_in_count == 0
    
    def test_init_with_callback(self):
        """Test agent with callback"""
        callback = Mock()
        agent = BeaconSleepAgent(c2_callback=callback)
        
        assert agent.c2_callback == callback
    
    def test_get_status(self):
        """Test status reporting"""
        agent = BeaconSleepAgent()
        status = agent.get_status()
        
        assert "running" in status
        assert "check_ins" in status
        assert "uptime_seconds" in status
        assert "sleep_metrics" in status
    
    def test_start_stop(self):
        """Test agent start and stop"""
        agent = BeaconSleepAgent()
        
        agent.start(sleep_ms=100)
        assert agent._running
        
        time.sleep(0.3)  # Let it run a bit
        
        agent.stop()
        assert not agent._running
    
    def test_check_in_callback(self):
        """Test callback is called on check-in"""
        callback = Mock()
        agent = BeaconSleepAgent(c2_callback=callback)
        
        agent.start(sleep_ms=100)
        time.sleep(0.3)
        agent.stop()
        
        assert callback.call_count > 0
    
    @pytest.mark.slow
    def test_short_run(self):
        """Test short beacon run"""
        agent = BeaconSleepAgent()
        result = agent.run_test(duration_seconds=2, sleep_ms=500)
        
        assert "test_duration_seconds" in result
        assert "total_check_ins" in result
        assert result["total_check_ins"] >= 2  # At least 2 check-ins in 2s with 500ms sleep


# ============================================================
# INTEGRATION TESTS
# ============================================================

class TestSleepmaskIntegration:
    """Integration tests for sleepmask module"""
    
    def test_full_masking_cycle(self):
        """Test complete masking cycle"""
        config = SleepmaskConfig(
            technique=SleepTechnique.BASIC,
            masking_mode=MaskingMode.XOR,
            min_sleep_ms=100,
            max_sleep_ms=200,
            jitter_percent=0.1,
        )
        
        engine = SleepmaskEngine(config)
        cycle = RuntimeMaskingCycle(engine)
        
        # Execute function with masking
        call_count = [0]
        
        def test_callback():
            call_count[0] += 1
            return call_count[0]
        
        result = cycle.execute_with_masking(test_callback)
        assert result == 1
        
        # Sleep
        sleep_result = cycle.masked_sleep_cycle(100)
        assert sleep_result["success"]
    
    def test_beacon_with_skip_detection(self):
        """Test beacon with skip detection enabled"""
        config = SleepmaskConfig(
            check_sleep_skip=True,
            min_sleep_ms=100,
            max_sleep_ms=200,
        )
        
        agent = BeaconSleepAgent(config=config)
        agent.start(sleep_ms=100)
        time.sleep(0.5)
        agent.stop()
        
        status = agent.get_status()
        assert "skip_detector" in status


# ============================================================
# LONG-DURATION TESTS (Optional)
# ============================================================

class TestLongDurationSleep:
    """Long-duration sleep tests (5-10 dakika)"""
    
    @pytest.mark.skip(reason="Long-running test - enable manually")
    def test_5_minute_beacon(self):
        """Test beacon for 5 minutes"""
        callback_log = []
        
        def log_callback(status):
            callback_log.append({
                "time": time.time(),
                "check_ins": status["check_ins"],
                "metrics": status["sleep_metrics"]
            })
        
        agent = BeaconSleepAgent(c2_callback=log_callback)
        result = agent.run_test(duration_seconds=300, sleep_ms=5000)  # 5 min, 5s sleep
        
        # Should have ~60 check-ins (300s / 5s)
        assert result["total_check_ins"] >= 50
        assert len(callback_log) >= 50
        
        # Check for anomalies
        assert result["anomalies_detected"] == 0 or result["conclusion"] == "ANOMALIES_DETECTED"
    
    @pytest.mark.skip(reason="Long-running test - enable manually")
    def test_10_minute_beacon(self):
        """Test beacon for 10 minutes"""
        agent = BeaconSleepAgent()
        result = agent.run_test(duration_seconds=600, sleep_ms=10000)  # 10 min, 10s sleep
        
        # Should have ~60 check-ins (600s / 10s)
        assert result["total_check_ins"] >= 50


# ============================================================
# WINDOWS-ONLY TESTS
# ============================================================

@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only tests")
class TestWindowsSpecific:
    """Windows-specific sleepmask tests"""
    
    def test_virtual_protect(self):
        """Test VirtualProtect calls"""
        import ctypes
        
        engine = SleepmaskEngine()
        
        # Allocate memory
        addr = ctypes.windll.kernel32.VirtualAlloc(
            0, 4096, 0x3000, 0x40
        )
        
        if addr:
            try:
                # Try to change protection
                result = engine._protect_memory(addr, 4096, 0x02)  # PAGE_READONLY
                # Result depends on Windows API success
            finally:
                ctypes.windll.kernel32.VirtualFree(addr, 0, 0x8000)
    
    def test_waitable_timer(self):
        """Test WaitableTimer for Ekko sleep"""
        import ctypes
        
        timer = ctypes.windll.kernel32.CreateWaitableTimerExW(
            None, None, 0, 0x1F0003
        )
        
        if timer:
            ctypes.windll.kernel32.CloseHandle(timer)
            assert True
        else:
            pytest.skip("CreateWaitableTimer not available")


# ============================================================
# STRESS TESTS
# ============================================================

class TestSleepmaskStress:
    """Stress tests for sleepmask"""
    
    def test_rapid_sleep_cycles(self):
        """Test many rapid sleep cycles"""
        config = SleepmaskConfig(
            technique=SleepTechnique.BASIC,
            check_sleep_skip=False,
        )
        engine = SleepmaskEngine(config)
        
        for _ in range(20):
            result = engine.masked_sleep(50)  # 50ms
            assert result["success"]
        
        metrics = engine.get_metrics()
        assert metrics["total_sleeps"] == 20
    
    def test_encryption_stress(self):
        """Test encryption with many operations"""
        key = MaskingCrypto.generate_key()
        
        for _ in range(100):
            data = secrets.token_bytes(1024)
            
            for mode in [MaskingMode.XOR, MaskingMode.RC4]:
                encrypted = MaskingCrypto.encrypt(data, key, mode)
                decrypted = MaskingCrypto.decrypt(encrypted, key, mode)
                assert decrypted == data


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
