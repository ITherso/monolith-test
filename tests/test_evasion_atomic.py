"""
Atomic Red Team Evasion Tests
Tests for T1055 (Process Injection) and T1562.001 (AMSI Bypass)
Validates evasion profiles work correctly

Run: pytest tests/test_evasion_atomic.py -v
"""

import pytest
import time
import sys
import os
from unittest.mock import MagicMock, patch

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cybermodules.lateral_evasion import (
    EvasionProfile,
    EvasionConfig,
    LateralEvasionLayer,
    ProfileMetrics,
    PROFILE_METRICS,
    get_evasion_config_for_profile,
    get_profile_metrics,
    SRDIGenerator
)

from cybermodules.ai_lateral_guide import (
    AILateralGuide,
    HostIntel,
    CredentialIntel,
    JumpSuggestion
)


class TestAtomicT1055ProcessInjection:
    """
    Atomic Red Team T1055 - Process Injection Tests
    Tests various process injection techniques
    """
    
    def test_t1055_003_thread_hijacking_config(self):
        """T1055.003: Thread Execution Hijacking configuration"""
        config = get_evasion_config_for_profile("stealth")
        
        assert config.injection_technique == "thread_hijacking"
        assert config.target_process == "explorer.exe"
        assert config.syscall_mode == "indirect"
    
    def test_t1055_004_apc_injection_config(self):
        """T1055.004: Asynchronous Procedure Call injection"""
        config = get_evasion_config_for_profile("aggressive")
        
        assert config.injection_technique == "apc_injection"
        assert config.use_process_injection is True
    
    def test_t1055_012_process_hollowing_config(self):
        """T1055.012: Process Hollowing configuration"""
        config = get_evasion_config_for_profile("paranoid")
        
        assert config.use_process_hollowing is True
        assert config.ppid_spoof is True
        assert config.ppid_target == "services.exe"
    
    def test_t1055_013_doppelganging_config(self):
        """T1055.013: Process Doppelgänging configuration"""
        config = get_evasion_config_for_profile("paranoid")
        
        assert config.use_doppelganging is True
        assert config.use_ghosting is True
    
    def test_process_injection_layer_init(self):
        """Test process injection layer initialization"""
        config = get_evasion_config_for_profile("stealth")
        layer = LateralEvasionLayer(scan_id=1, config=config)
        
        assert layer.config.injection_technique == "thread_hijacking"
        assert layer.config.use_process_injection is True
    
    def test_injection_technique_selection(self):
        """Test correct injection technique is selected per profile"""
        techniques = {
            "none": None,  # No injection
            "default": "apc_injection",
            "stealth": "thread_hijacking",
            "paranoid": "early_bird",
            "aggressive": "apc_injection"
        }
        
        for profile_name, expected_technique in techniques.items():
            config = get_evasion_config_for_profile(profile_name)
            if expected_technique:
                assert config.injection_technique == expected_technique, \
                    f"Profile {profile_name} should use {expected_technique}"
            else:
                assert config.use_process_injection is False
    
    def test_fallback_processes_configured(self):
        """Test fallback injection targets are configured"""
        config = get_evasion_config_for_profile("paranoid")
        
        assert len(config.fallback_processes) >= 2
        assert "SearchProtocolHost.exe" in config.fallback_processes
    
    def test_syscall_modes(self):
        """Test syscall mode configuration per profile"""
        modes = {
            "stealth": "indirect",
            "paranoid": "direct",
            "aggressive": "ntdll"
        }
        
        for profile_name, expected_mode in modes.items():
            config = get_evasion_config_for_profile(profile_name)
            assert config.syscall_mode == expected_mode


class TestAtomicT1562001AMSIBypass:
    """
    Atomic Red Team T1562.001 - Disable or Modify Tools (AMSI)
    Tests AMSI bypass configurations
    """
    
    def test_t1562_001_amsi_bypass_enabled(self):
        """T1562.001: AMSI bypass is enabled for relevant profiles"""
        for profile in ["default", "stealth", "paranoid", "aggressive"]:
            config = get_evasion_config_for_profile(profile)
            assert config.bypass_amsi is True, f"Profile {profile} should have AMSI bypass"
    
    def test_amsi_bypass_disabled_none(self):
        """AMSI bypass disabled for 'none' profile"""
        config = get_evasion_config_for_profile("none")
        assert config.bypass_amsi is False
    
    def test_amsi_technique_selection(self):
        """Test AMSI bypass technique selection"""
        techniques = {
            "default": "patch_amsi_init",
            "stealth": "hardware_breakpoint",
            "paranoid": "hardware_breakpoint",
            "aggressive": "patch_amsi_init"
        }
        
        for profile_name, expected_technique in techniques.items():
            config = get_evasion_config_for_profile(profile_name)
            assert config.amsi_technique == expected_technique
    
    def test_etw_bypass_configuration(self):
        """Test ETW bypass configuration"""
        # ETW bypass enabled for stealth and paranoid
        for profile in ["stealth", "paranoid"]:
            config = get_evasion_config_for_profile(profile)
            assert config.bypass_etw is True
        
        # ETW bypass disabled for default and aggressive
        for profile in ["none", "default", "aggressive"]:
            config = get_evasion_config_for_profile(profile)
            assert config.bypass_etw is False
    
    def test_ntdll_unhook_paranoid(self):
        """Test NTDLL unhooking for paranoid profile"""
        config = get_evasion_config_for_profile("paranoid")
        
        assert config.unhook_ntdll is True
        assert config.unhook_technique == "map_fresh_ntdll"
    
    def test_amsi_bypass_oneliner(self):
        """Test AMSI bypass one-liner generation"""
        config = get_evasion_config_for_profile("stealth")
        layer = LateralEvasionLayer(scan_id=1, config=config)
        
        bypass = layer._get_amsi_bypass_oneliner()
        
        assert "AmsiUtils" in bypass
        assert "amsiInitFailed" in bypass


class TestEvasionProfileMetrics:
    """Test evasion profile metrics for AI scoring"""
    
    def test_all_profiles_have_metrics(self):
        """All profiles should have defined metrics"""
        for profile in EvasionProfile:
            metrics = get_profile_metrics(profile)
            assert metrics is not None
            assert metrics.profile == profile
    
    def test_paranoid_lowest_detection_risk(self):
        """Paranoid profile should have lowest detection risk"""
        paranoid = get_profile_metrics(EvasionProfile.PARANOID)
        stealth = get_profile_metrics(EvasionProfile.STEALTH)
        default = get_profile_metrics(EvasionProfile.DEFAULT)
        
        assert paranoid.detection_risk < stealth.detection_risk
        assert stealth.detection_risk < default.detection_risk
    
    def test_paranoid_slowest(self):
        """Paranoid profile should be slowest"""
        paranoid = get_profile_metrics(EvasionProfile.PARANOID)
        
        for profile in [EvasionProfile.NONE, EvasionProfile.DEFAULT, 
                       EvasionProfile.STEALTH, EvasionProfile.AGGRESSIVE]:
            other = get_profile_metrics(profile)
            assert paranoid.speed_multiplier >= other.speed_multiplier
    
    def test_none_highest_reliability(self):
        """None profile should have highest reliability"""
        none_profile = get_profile_metrics(EvasionProfile.NONE)
        
        for profile in [EvasionProfile.DEFAULT, EvasionProfile.STEALTH,
                       EvasionProfile.PARANOID]:
            other = get_profile_metrics(profile)
            assert none_profile.reliability >= other.reliability
    
    def test_metric_summary_generation(self):
        """Test metric summary string generation"""
        metrics = get_profile_metrics(EvasionProfile.PARANOID)
        summary = metrics.get_summary()
        
        assert "paranoid" in summary.lower()
        assert "%" in summary  # Detection reduction percentage


class TestSleepObfuscationWithEntropy:
    """Test sleep obfuscation with entropy jitter"""
    
    def test_entropy_jitter_enabled_stealth(self):
        """Entropy jitter enabled for stealth profile"""
        config = get_evasion_config_for_profile("stealth")
        assert config.entropy_jitter is True
    
    def test_entropy_jitter_disabled_aggressive(self):
        """Entropy jitter disabled for aggressive profile"""
        config = get_evasion_config_for_profile("aggressive")
        assert config.entropy_jitter is False
    
    def test_reencrypt_cycle_paranoid(self):
        """Decrypt-run-reencrypt cycle enabled for paranoid"""
        config = get_evasion_config_for_profile("paranoid")
        
        assert config.reencrypt_on_wake is True
        assert config.memory_guard_on_sleep is True
    
    def test_sleep_technique_selection(self):
        """Test sleep technique per profile"""
        techniques = {
            "stealth": "ekko",
            "paranoid": "death_sleep"
        }
        
        for profile_name, expected in techniques.items():
            config = get_evasion_config_for_profile(profile_name)
            assert config.sleep_technique == expected
    
    def test_entropy_pool_size(self):
        """Test entropy pool size configuration"""
        stealth = get_evasion_config_for_profile("stealth")
        paranoid = get_evasion_config_for_profile("paranoid")
        
        assert stealth.entropy_pool_size == 64
        assert paranoid.entropy_pool_size == 128
    
    def test_hardware_entropy_paranoid_only(self):
        """Hardware entropy only for paranoid profile"""
        paranoid = get_evasion_config_for_profile("paranoid")
        stealth = get_evasion_config_for_profile("stealth")
        
        assert paranoid.use_hardware_entropy is True
        assert stealth.use_hardware_entropy is False
    
    def test_evasive_sleep_jitter_range(self):
        """Test sleep jitter is within expected range"""
        config = get_evasion_config_for_profile("stealth")
        layer = LateralEvasionLayer(scan_id=1, config=config)
        
        # Mock sleep to avoid actual delays
        with patch('time.sleep'):
            durations = [layer.evasive_sleep(1000) for _ in range(10)]
        
        # All durations should be within jitter range
        for d in durations:
            assert 600 <= d <= 1500  # 1000 ± 40% (jitter + entropy)


class TestSRDIGenerator:
    """Test sRDI shellcode generator"""
    
    def test_srdi_generator_init(self):
        """Test sRDI generator initialization"""
        config = get_evasion_config_for_profile("stealth")
        generator = SRDIGenerator(config)
        
        assert generator.config.srdi_obfuscate_imports is True
        assert generator.config.srdi_clear_header is True
    
    def test_srdi_pe_stomping_paranoid(self):
        """PE stomping enabled for paranoid"""
        config = get_evasion_config_for_profile("paranoid")
        
        assert config.srdi_stomp_pe is True
    
    def test_prepend_migrate_stealth(self):
        """Prepend migrate stub for stealth/paranoid"""
        for profile in ["stealth", "paranoid"]:
            config = get_evasion_config_for_profile(profile)
            assert config.prepend_migrate is True
    
    def test_srdi_generate_shellcode(self):
        """Test basic shellcode generation"""
        config = get_evasion_config_for_profile("stealth")
        generator = SRDIGenerator(config)
        
        # Mock DLL bytes
        dll_bytes = b"MZ" + b"\x00" * 100
        
        shellcode = generator.generate_srdi_shellcode(dll_bytes)
        
        assert len(shellcode) > len(dll_bytes)
        assert shellcode[:2] != b"MZ"  # Header should be cleared


class TestAIEvasionScoring:
    """Test AI guidance evasion scoring"""
    
    def test_scoring_for_dc(self):
        """Domain Controller should get paranoid recommendation"""
        guide = AILateralGuide(scan_id=1)
        
        guide.add_host_intel(HostIntel(
            hostname="DC01",
            ip="192.168.1.10",
            os_type="windows",
            is_dc=True,
            av_product="CrowdStrike Falcon"
        ))
        
        profile, details = guide.recommend_evasion_for_jump("DC01")
        
        assert profile == "paranoid"
        assert "DC" in details.get('reason', '') or "EDR" in details.get('reason', '')
    
    def test_scoring_for_workstation(self):
        """Normal workstation should get stealth"""
        guide = AILateralGuide(scan_id=1)
        
        guide.add_host_intel(HostIntel(
            hostname="WS01",
            ip="192.168.1.100",
            os_type="windows",
            av_product="Windows Defender"
        ))
        
        profile, _ = guide.recommend_evasion_for_jump("WS01")
        
        assert profile in ["stealth", "default"]
    
    def test_time_critical_uses_aggressive(self):
        """Time critical operations prefer aggressive"""
        guide = AILateralGuide(scan_id=1)
        
        guide.add_host_intel(HostIntel(
            hostname="WS01",
            ip="192.168.1.100",
            os_type="windows"
        ))
        
        profile, details = guide.recommend_evasion_for_jump("WS01", time_critical=True)
        
        assert profile in ["aggressive", "default"]
        assert "Time-critical" in details.get('reason', '') or "hız" in details.get('reason', '').lower()
    
    def test_detection_risk_by_profile(self):
        """Test detection risk varies by profile"""
        guide = AILateralGuide(scan_id=1)
        
        guide.add_host_intel(HostIntel(
            hostname="TARGET",
            ip="192.168.1.50",
            os_type="windows",
            av_product="CrowdStrike"
        ))
        
        scoring = guide.get_evasion_profile_scoring("TARGET")
        
        # Paranoid should have lowest risk
        assert scoring['paranoid']['detection_risk'] < scoring['stealth']['detection_risk']
        assert scoring['stealth']['detection_risk'] < scoring['default']['detection_risk']
        assert scoring['default']['detection_risk'] < scoring['none']['detection_risk']
    
    def test_jump_suggestion_includes_evasion(self):
        """Jump suggestions should include evasion scoring"""
        guide = AILateralGuide(scan_id=1)
        
        guide.add_host_intel(HostIntel(
            hostname="DC01",
            ip="192.168.1.10",
            is_dc=True
        ))
        
        guide.add_credential_intel(CredentialIntel(
            username="admin",
            domain="CORP",
            is_domain_admin=True
        ))
        
        suggestions = guide.get_next_best_jump()
        
        assert len(suggestions) > 0
        
        dc_suggestion = next((s for s in suggestions if s.target == "DC01"), None)
        if dc_suggestion:
            assert dc_suggestion.recommended_profile in ["paranoid", "stealth"]
            assert len(dc_suggestion.evasion_notes) > 0


class TestProfileYAMLConfigs:
    """Test profile YAML configurations exist and are valid"""
    
    @pytest.fixture
    def config_dir(self):
        return os.path.join(os.path.dirname(os.path.dirname(__file__)), 'configs')
    
    def test_profile_yamls_exist(self, config_dir):
        """All profile YAML files should exist"""
        profiles = ['none', 'default', 'stealth', 'paranoid', 'aggressive']
        
        for profile in profiles:
            yaml_path = os.path.join(config_dir, f'evasion_profile_{profile}.yaml')
            assert os.path.exists(yaml_path), f"Missing {yaml_path}"
    
    def test_profile_yamls_parseable(self, config_dir):
        """Profile YAMLs should be parseable"""
        import yaml
        
        profiles = ['none', 'default', 'stealth', 'paranoid', 'aggressive']
        
        for profile in profiles:
            yaml_path = os.path.join(config_dir, f'evasion_profile_{profile}.yaml')
            
            with open(yaml_path, 'r') as f:
                data = yaml.safe_load(f)
            
            assert data['profile'] == profile
            assert 'metrics' in data
            assert 'detection_risk' in data['metrics']


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
