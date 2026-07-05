"""
Tests for Process Injection & LOTL Modules
==========================================
Tests for:
- evasion/process_injection.py (extended)
- cybermodules/lotl_execution.py
- Integration with lateral_evasion.py
"""

import pytest
import sys
import os
import base64
from unittest.mock import Mock, patch, MagicMock
from dataclasses import asdict

# Test that modules can be imported
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ============================================================
# PROCESS INJECTION TESTS
# ============================================================

class TestProcessInjectionImports:
    """Test process injection module imports"""
    
    def test_import_injection_module(self):
        """Test basic import"""
        from evasion.process_injection import (
            ProcessInjector,
            InjectionConfig,
            InjectionTechnique,
            InjectionStatus,
            InjectionResult,
        )
        
        assert ProcessInjector is not None
        assert InjectionConfig is not None
        assert InjectionTechnique is not None
    
    def test_import_convenience_functions(self):
        """Test convenience function imports"""
        from evasion.process_injection import (
            inject_shellcode,
            inject_with_fallback,
            get_best_technique,
            get_technique_by_stealth,
        )
        
        assert callable(inject_shellcode)
        assert callable(inject_with_fallback)
        assert callable(get_best_technique)


class TestInjectionTechnique:
    """Test InjectionTechnique enum"""
    
    def test_all_techniques_exist(self):
        """Test all expected techniques are defined"""
        from evasion.process_injection import InjectionTechnique
        
        expected = [
            "PROCESS_GHOSTING",
            "PROCESS_DOPPELGANGING",
            "TRANSACTED_HOLLOWING",
            "MODULE_STOMPING",
            "EARLY_BIRD_APC",
            "PHANTOM_DLL",
            "THREAD_HIJACK",
            "PROCESS_HOLLOWING",
            "SYSCALL_INJECTION",
            "CLASSIC_CRT",
        ]
        
        for tech in expected:
            assert hasattr(InjectionTechnique, tech), f"Missing technique: {tech}"
    
    def test_technique_values(self):
        """Test technique enum values"""
        from evasion.process_injection import InjectionTechnique
        
        assert InjectionTechnique.PROCESS_GHOSTING.value == "ghosting"
        assert InjectionTechnique.CLASSIC_CRT.value == "classic_crt"
        assert InjectionTechnique.EARLY_BIRD_APC.value == "early_bird_apc"


class TestInjectionConfig:
    """Test InjectionConfig dataclass"""
    
    def test_default_config(self):
        """Test default configuration"""
        from evasion.process_injection import InjectionConfig, InjectionTechnique
        
        config = InjectionConfig()
        
        assert config.technique == InjectionTechnique.EARLY_BIRD_APC
        assert config.fallback_enabled is True
        assert len(config.fallback_chain) > 0
        assert config.use_syscalls is True
    
    def test_custom_config(self):
        """Test custom configuration"""
        from evasion.process_injection import InjectionConfig, InjectionTechnique
        
        config = InjectionConfig(
            technique=InjectionTechnique.PROCESS_GHOSTING,
            fallback_enabled=False,
            use_syscalls=False,
        )
        
        assert config.technique == InjectionTechnique.PROCESS_GHOSTING
        assert config.fallback_enabled is False
        assert config.use_syscalls is False


class TestInjectionResult:
    """Test InjectionResult dataclass"""
    
    def test_result_creation(self):
        """Test creating injection result"""
        from evasion.process_injection import (
            InjectionResult, 
            InjectionTechnique, 
            InjectionStatus
        )
        
        result = InjectionResult(
            success=True,
            technique=InjectionTechnique.EARLY_BIRD_APC,
            status=InjectionStatus.SUCCESS,
            target_pid=1234,
            thread_id=5678,
        )
        
        assert result.success is True
        assert result.technique == InjectionTechnique.EARLY_BIRD_APC
        assert result.target_pid == 1234


class TestProcessInjector:
    """Test ProcessInjector class"""
    
    def test_injector_creation(self):
        """Test creating injector instance"""
        from evasion.process_injection import ProcessInjector, InjectionConfig
        
        injector = ProcessInjector()
        assert injector is not None
        assert injector.config is not None
        
        custom_config = InjectionConfig(fallback_enabled=False)
        injector2 = ProcessInjector(custom_config)
        assert injector2.config.fallback_enabled is False
    
    def test_get_injection_techniques(self):
        """Test getting technique list"""
        from evasion.process_injection import ProcessInjector
        
        injector = ProcessInjector()
        techniques = injector.get_injection_techniques()
        
        assert len(techniques) >= 10  # At least 10 techniques
        
        # Check structure
        for tech in techniques:
            assert "name" in tech
            assert "technique" in tech
            assert "stealth" in tech
            assert "reliability" in tech
            assert "mitre" in tech
    
    def test_technique_stealth_ordering(self):
        """Test techniques are ordered by stealth"""
        from evasion.process_injection import ProcessInjector
        
        injector = ProcessInjector()
        techniques = injector.get_injection_techniques()
        
        # Ghosting should be highest stealth
        ghosting = [t for t in techniques if t["name"] == "ghosting"][0]
        classic = [t for t in techniques if t["name"] == "classic_crt"][0]
        
        assert ghosting["stealth"] > classic["stealth"]
    
    @patch('sys.platform', 'linux')
    def test_non_windows_returns_error(self):
        """Test non-Windows platform handling"""
        from evasion.process_injection import ProcessInjector, InjectionTechnique
        
        injector = ProcessInjector()
        injector._is_windows = False
        
        result = injector._early_bird_apc_injection(1234, b"\x90\x90")
        
        assert result.success is False
        assert "Windows" in result.error


class TestCodeGeneration:
    """Test code generation methods"""
    
    def test_generate_apc_injection_code(self):
        """Test APC injection code generation"""
        from evasion.process_injection import ProcessInjector
        
        injector = ProcessInjector()
        shellcode = b"\x90\x90\x90\x90"  # NOP sled
        
        code = injector.generate_apc_injection_code(shellcode)
        
        assert "early_bird_apc" in code
        assert "NtQueueApcThread" in code
        assert base64.b64encode(shellcode).decode() in code
    
    def test_generate_thread_hijack_code(self):
        """Test thread hijack code generation"""
        from evasion.process_injection import ProcessInjector
        
        injector = ProcessInjector()
        shellcode = b"\xcc\xcc"
        
        code = injector.generate_thread_hijack_code(shellcode)
        
        assert "hijack_thread" in code
        assert "SuspendThread" in code
        assert "SetThreadContext" in code
    
    def test_generate_ghosting_code(self):
        """Test ghosting code generation"""
        from evasion.process_injection import ProcessInjector
        
        injector = ProcessInjector()
        shellcode = b"\x90" * 100
        
        code = injector.generate_process_ghosting_code(shellcode)
        
        assert "Process Ghosting" in code
        assert "pending delete" in code.lower() or "delete" in code.lower()
    
    def test_generate_doppelganging_code(self):
        """Test doppelganging code generation"""
        from evasion.process_injection import ProcessInjector
        
        injector = ProcessInjector()
        shellcode = b"\x90" * 50
        
        code = injector.generate_doppelganging_code(shellcode)
        
        assert "Doppelgänging" in code or "Doppelganging" in code
        assert "transaction" in code.lower()


class TestConvenienceFunctions:
    """Test convenience functions"""
    
    def test_get_best_technique_no_edr(self):
        """Test best technique without EDR"""
        from evasion.process_injection import get_best_technique, InjectionTechnique
        
        result = get_best_technique(edr_detected=False)
        
        assert result == InjectionTechnique.EARLY_BIRD_APC
    
    def test_get_best_technique_with_edr(self):
        """Test best technique with EDR"""
        from evasion.process_injection import get_best_technique, InjectionTechnique
        
        result = get_best_technique(edr_detected=True)
        
        assert result == InjectionTechnique.PROCESS_GHOSTING
    
    def test_get_technique_by_stealth(self):
        """Test filtering by stealth level"""
        from evasion.process_injection import get_technique_by_stealth, InjectionTechnique
        
        # High stealth only
        high_stealth = get_technique_by_stealth(min_stealth=9)
        
        assert InjectionTechnique.PROCESS_GHOSTING in high_stealth
        assert InjectionTechnique.CLASSIC_CRT not in high_stealth


# ============================================================
# LOTL EXECUTION TESTS
# ============================================================

class TestLOTLImports:
    """Test LOTL module imports"""
    
    def test_import_lotl_module(self):
        """Test basic import"""
        from cybermodules.lotl_execution import (
            LOTLExecutor,
            LOTLConfig,
            LOTLResult,
            LOLBin,
            LOLMethod,
            LateralLOTL,
        )
        
        assert LOTLExecutor is not None
        assert LOLBin is not None
        assert LateralLOTL is not None


class TestLOLBin:
    """Test LOLBin enum"""
    
    def test_all_lolbins_exist(self):
        """Test all expected LOLBins are defined"""
        from cybermodules.lotl_execution import LOLBin
        
        expected = [
            "WMI", "WMIC", "RUNDLL32", "REGSVR32", "CMSTP",
            "MSHTA", "CERTUTIL", "BITSADMIN", "MSIEXEC",
            "WSCRIPT", "CSCRIPT", "INSTALLUTIL", "REGASM",
            "FORFILES", "PCALUA", "ODBCCONF",
        ]
        
        for bin in expected:
            assert hasattr(LOLBin, bin), f"Missing LOLBin: {bin}"
    
    def test_lolbin_values(self):
        """Test LOLBin enum values"""
        from cybermodules.lotl_execution import LOLBin
        
        assert LOLBin.WMI.value == "wmi"
        assert LOLBin.RUNDLL32.value == "rundll32"
        assert LOLBin.MSHTA.value == "mshta"


class TestLOTLConfig:
    """Test LOTLConfig dataclass"""
    
    def test_default_config(self):
        """Test default configuration"""
        from cybermodules.lotl_execution import LOTLConfig, LOLBin
        
        config = LOTLConfig()
        
        assert LOLBin.WMI in config.preferred_bins
        assert config.fallback_enabled is True
        assert config.cleanup_artifacts is True
    
    def test_custom_config(self):
        """Test custom configuration"""
        from cybermodules.lotl_execution import LOTLConfig, LOLBin
        
        config = LOTLConfig(
            preferred_bins=[LOLBin.MSHTA, LOLBin.CMSTP],
            fallback_enabled=False,
            remote_host="192.168.1.100",
        )
        
        assert config.preferred_bins[0] == LOLBin.MSHTA
        assert config.fallback_enabled is False
        assert config.remote_host == "192.168.1.100"


class TestLOTLResult:
    """Test LOTLResult dataclass"""
    
    def test_result_creation(self):
        """Test creating LOTL result"""
        from cybermodules.lotl_execution import LOTLResult, LOLBin, LOLMethod
        
        result = LOTLResult(
            success=True,
            method=LOLMethod.PROCESS_CREATE,
            lolbin=LOLBin.WMI,
            target="192.168.1.100",
            pid=1234,
        )
        
        assert result.success is True
        assert result.lolbin == LOLBin.WMI
        assert result.pid == 1234


class TestLOTLExecutor:
    """Test LOTLExecutor class"""
    
    def test_executor_creation(self):
        """Test creating executor instance"""
        from cybermodules.lotl_execution import LOTLExecutor, LOTLConfig
        
        executor = LOTLExecutor()
        assert executor is not None
        assert executor.config is not None
        
        custom_config = LOTLConfig(fallback_enabled=False)
        executor2 = LOTLExecutor(custom_config)
        assert executor2.config.fallback_enabled is False
    
    def test_get_lolbin_info(self):
        """Test getting LOLBin information"""
        from cybermodules.lotl_execution import LOTLExecutor, LOLBin
        
        info = LOTLExecutor.get_lolbin_info(LOLBin.WMI)
        
        assert "name" in info
        assert "mitre" in info
        assert "risk" in info
        assert info["name"] == "WMI"
        assert info["mitre"] == "T1047"
    
    def test_generate_sct(self):
        """Test SCT generation"""
        from cybermodules.lotl_execution import LOTLExecutor
        
        executor = LOTLExecutor()
        sct = executor._generate_sct("calc.exe")
        
        assert "<?XML" in sct
        assert "scriptlet" in sct
        assert "calc.exe" in sct
    
    def test_generate_inf(self):
        """Test INF generation"""
        from cybermodules.lotl_execution import LOTLExecutor
        
        executor = LOTLExecutor()
        inf = executor._generate_inf("notepad.exe")
        
        assert "[version]" in inf
        assert "notepad.exe" in inf


class TestLateralLOTL:
    """Test LateralLOTL class"""
    
    def test_lateral_lotl_creation(self):
        """Test creating LateralLOTL instance"""
        from cybermodules.lotl_execution import LateralLOTL
        
        lateral = LateralLOTL()
        assert lateral is not None
        assert lateral.executor is not None


# ============================================================
# AI LATERAL GUIDE INTEGRATION TESTS
# ============================================================

class TestAILateralGuideIntegration:
    """Test AI Lateral Guide LOTL integration"""
    
    def test_recommend_lotl_fallback(self):
        """Test LOTL fallback recommendation"""
        from cybermodules.ai_lateral_guide import AILateralGuide
        
        guide = AILateralGuide()
        
        recommendation = guide.recommend_lotl_fallback("classic_crt")
        
        assert "primary" in recommendation
        assert "alternatives" in recommendation
        assert "guidance" in recommendation
        assert recommendation["primary"]["name"] in ["wmi", "forfiles", "pcalua"]
    
    def test_auto_select_execution_method(self):
        """Test automatic execution method selection"""
        from cybermodules.ai_lateral_guide import AILateralGuide
        
        guide = AILateralGuide()
        
        # No blocked techniques
        result = guide.auto_select_execution_method("target1")
        
        assert "method_type" in result
        assert result["method_type"] == "injection"
        assert "technique" in result
    
    def test_auto_select_with_all_injection_blocked(self):
        """Test fallback to LOTL when all injection blocked"""
        from cybermodules.ai_lateral_guide import AILateralGuide
        
        guide = AILateralGuide()
        
        blocked = [
            "ghosting", "doppelganging", "transacted_hollowing",
            "syscall", "module_stomping", "early_bird_apc",
            "phantom_dll", "thread_hijack", "process_hollowing",
            "classic_crt"
        ]
        
        result = guide.auto_select_execution_method(
            "target1",
            blocked_techniques=blocked
        )
        
        assert result["method_type"] == "lotl"
        assert result["fallback_to_lotl"] is True


# ============================================================
# LATERAL EVASION INTEGRATION TESTS
# ============================================================

class TestLateralEvasionIntegration:
    """Test lateral_evasion.py integration"""
    
    def test_has_lotl_flag(self):
        """Test LOTL availability flag"""
        from cybermodules import lateral_evasion
        
        assert hasattr(lateral_evasion, 'HAS_LOTL')
    
    def test_has_process_injection_imports(self):
        """Test process injection imports"""
        from cybermodules import lateral_evasion
        
        assert hasattr(lateral_evasion, 'HAS_PROCESS_INJECTION')
    
    def test_lateral_evasion_lotl_methods(self):
        """Test LateralEvasionLayer has LOTL methods"""
        from cybermodules.lateral_evasion import LateralEvasionLayer
        
        evasion = LateralEvasionLayer()
        
        assert hasattr(evasion, 'lotl_execute')
        assert hasattr(evasion, 'lotl_lateral_jump')
        assert hasattr(evasion, 'inject_with_lotl_fallback')
        assert hasattr(evasion, 'get_available_lotl_methods')
    
    def test_get_available_lotl_methods(self):
        """Test getting available LOTL methods"""
        from cybermodules.lateral_evasion import LateralEvasionLayer
        
        evasion = LateralEvasionLayer()
        methods = evasion.get_available_lotl_methods()
        
        if methods:  # Only test if LOTL is available
            assert len(methods) >= 5
            for method in methods:
                assert "name" in method
                assert "mitre" in method
                assert "stealth" in method
    
    def test_advanced_inject_method(self):
        """Test advanced injection method exists"""
        from cybermodules.lateral_evasion import LateralEvasionLayer
        
        evasion = LateralEvasionLayer()
        
        assert hasattr(evasion, 'advanced_inject')
        assert callable(evasion.advanced_inject)


# ============================================================
# YAML CONFIG TESTS
# ============================================================

class TestYAMLConfig:
    """Test YAML configuration for injection/LOTL"""
    
    def test_paranoid_profile_has_injection_config(self):
        """Test paranoid profile has injection configuration"""
        import yaml
        
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "configs/evasion_profile_paranoid.yaml"
        )
        
        with open(config_path) as f:
            config = yaml.safe_load(f)
        
        assert "process_injection" in config
        assert "fallback_chain" in config["process_injection"]
        assert "ghosting" in config["process_injection"]["fallback_chain"]
    
    def test_paranoid_profile_has_lotl_config(self):
        """Test paranoid profile has LOTL configuration"""
        import yaml
        
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "configs/evasion_profile_paranoid.yaml"
        )
        
        with open(config_path) as f:
            config = yaml.safe_load(f)
        
        assert "lotl" in config
        assert config["lotl"]["enabled"] is True
        assert "wmi" in config["lotl"]["preferred_bins"]


# ============================================================
# RUN TESTS
# ============================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
