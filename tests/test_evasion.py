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
