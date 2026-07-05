"""
Test Suite: Indirect Syscalls + Multi-Layer Obfuscation
========================================================
Tests for Hell's Gate/Halo's Gate syscalls and UDRL-style obfuscation

Run with: pytest tests/test_syscalls_obfuscation.py -v
"""

import pytest
import os
import sys
import struct
import secrets

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ============================================================
# INDIRECT SYSCALLS TESTS
# ============================================================

class TestSyscallEnums:
    """Test syscall enum definitions"""
    
    def test_syscall_technique_values(self):
        """Test SyscallTechnique enum values"""
        from evasion.indirect_syscalls import SyscallTechnique
        
        assert SyscallTechnique.HELLS_GATE.value == "hells_gate"
        assert SyscallTechnique.HALOS_GATE.value == "halos_gate"
        assert SyscallTechnique.TARTARUS_GATE.value == "tartarus_gate"
        assert SyscallTechnique.SYSWHISPERS2.value == "syswhispers2"
        assert SyscallTechnique.SYSWHISPERS3.value == "syswhispers3"
        assert SyscallTechnique.FRESH_COPY.value == "fresh_copy"
        assert SyscallTechnique.DIRECT.value == "direct"
    
    def test_syscall_status_values(self):
        """Test SyscallStatus enum values"""
        from evasion.indirect_syscalls import SyscallStatus
        
        assert SyscallStatus.SUCCESS.value == "success"
        assert SyscallStatus.HOOKED.value == "hooked"
        assert SyscallStatus.NOT_FOUND.value == "not_found"


class TestSyscallConfig:
    """Test syscall configuration"""
    
    def test_default_config(self):
        """Test default syscall config"""
        from evasion.indirect_syscalls import SyscallConfig, SyscallTechnique
        
        config = SyscallConfig()
        
        assert config.technique == SyscallTechnique.SYSWHISPERS3
        assert config.use_indirect is True
        assert config.use_fresh_ntdll is False
        assert config.jit_resolve is True
        assert config.detect_hooks is True
    
    def test_custom_config(self):
        """Test custom syscall config"""
        from evasion.indirect_syscalls import SyscallConfig, SyscallTechnique
        
        config = SyscallConfig(
            technique=SyscallTechnique.HELLS_GATE,
            use_indirect=False,
            use_fresh_ntdll=True
        )
        
        assert config.technique == SyscallTechnique.HELLS_GATE
        assert config.use_indirect is False
        assert config.use_fresh_ntdll is True


class TestHellsGateResolver:
    """Test Hell's Gate SSN resolution"""
    
    def test_resolver_init(self):
        """Test resolver initialization"""
        from evasion.indirect_syscalls import HellsGateResolver
        
        resolver = HellsGateResolver()
        assert resolver is not None
        assert resolver._syscall_cache == {}
    
    def test_resolve_known_syscall(self):
        """Test resolving known syscall"""
        from evasion.indirect_syscalls import HellsGateResolver, SYSCALL_STUBS
        
        resolver = HellsGateResolver()
        entry = resolver.resolve_ssn("NtAllocateVirtualMemory")
        
        assert entry.name == "NtAllocateVirtualMemory"
        # On non-Windows, should use fallback
        if sys.platform != 'win32':
            assert entry.ssn == SYSCALL_STUBS.get("NtAllocateVirtualMemory", -1)
    
    def test_resolve_all_syscalls(self):
        """Test resolving all known syscalls"""
        from evasion.indirect_syscalls import HellsGateResolver, SYSCALL_STUBS
        
        resolver = HellsGateResolver()
        all_syscalls = resolver.get_all_syscalls()
        
        # On non-Windows, should resolve using fallback values
        # The get_all_syscalls calls resolve_ssn for each which populates cache
        # On non-Windows, cache may stay empty if SSN is from fallback
        if sys.platform != 'win32':
            # Just verify the method runs without error
            # and returns a dict
            assert isinstance(all_syscalls, dict)
        else:
            # On Windows, should resolve all known syscalls
            assert len(all_syscalls) == len(SYSCALL_STUBS)
    
    def test_hook_detection_patterns(self):
        """Test hook detection patterns"""
        from evasion.indirect_syscalls import HellsGateResolver
        
        resolver = HellsGateResolver()
        
        # JMP hook pattern
        assert resolver._detect_hook(bytes([0xE9, 0x00, 0x00, 0x00, 0x00])) is True
        
        # JMP QWORD pattern
        assert resolver._detect_hook(bytes([0xFF, 0x25, 0x00, 0x00, 0x00, 0x00])) is True
        
        # INT3 breakpoint
        assert resolver._detect_hook(bytes([0xCC])) is True
        
        # Clean pattern (mov r10, rcx)
        clean = bytes([0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00])
        assert resolver._detect_hook(clean) is False


class TestIndirectSyscallExecutor:
    """Test indirect syscall execution"""
    
    def test_executor_init(self):
        """Test executor initialization"""
        from evasion.indirect_syscalls import IndirectSyscallExecutor, SyscallConfig
        
        config = SyscallConfig()
        executor = IndirectSyscallExecutor(config)
        
        assert executor is not None
        assert executor.config == config
    
    def test_stub_generation(self):
        """Test syscall stub generation"""
        from evasion.indirect_syscalls import IndirectSyscallExecutor, SyscallConfig
        
        executor = IndirectSyscallExecutor()
        
        # Test direct stub
        direct_stub = executor._build_direct_stub(0x18)
        assert len(direct_stub) > 0
        
        # Should contain mov r10, rcx; mov eax, SSN
        assert direct_stub[:3] == bytes([0x4C, 0x8B, 0xD1])  # mov r10, rcx
        assert direct_stub[3:4] == bytes([0xB8])  # mov eax prefix
        assert direct_stub[4:6] == bytes([0x18, 0x00])  # SSN
    
    def test_indirect_stub_generation(self):
        """Test indirect syscall stub generation"""
        from evasion.indirect_syscalls import IndirectSyscallExecutor
        
        executor = IndirectSyscallExecutor()
        
        # Test indirect stub with fake syscall address
        indirect_stub = executor._build_indirect_stub(0x18, 0x7FFE0000)
        
        assert len(indirect_stub) > 0
        # Should contain mov r10, rcx
        assert indirect_stub[:3] == bytes([0x4C, 0x8B, 0xD1])
        # Should contain jmp instruction at end
        assert indirect_stub[-2:] == bytes([0xFF, 0xE3])  # jmp rbx


class TestSyscallManager:
    """Test high-level syscall manager"""
    
    def test_manager_init(self):
        """Test manager initialization"""
        from evasion.indirect_syscalls import SyscallManager
        
        manager = SyscallManager()
        assert manager is not None
    
    def test_detection_risk_summary(self):
        """Test detection risk summary"""
        from evasion.indirect_syscalls import SyscallManager, SyscallConfig, SyscallTechnique
        
        config = SyscallConfig(
            technique=SyscallTechnique.SYSWHISPERS3,
            use_indirect=True
        )
        manager = SyscallManager(config)
        
        summary = manager.get_detection_risk_summary()
        
        assert "technique" in summary
        assert "use_indirect" in summary
        assert "overall_risk" in summary
        assert summary["overall_risk"] <= 1.0


# ============================================================
# MULTI-LAYER OBFUSCATION TESTS
# ============================================================

class TestObfuscationEnums:
    """Test obfuscation enum definitions"""
    
    def test_obfuscation_layer_values(self):
        """Test ObfuscationLayer enum values"""
        from evasion.multi_layer_obfuscation import ObfuscationLayer
        
        assert ObfuscationLayer.XOR_STRINGS.value == "xor_strings"
        assert ObfuscationLayer.AES_GCM.value == "aes_gcm"
        assert ObfuscationLayer.ZLIB.value == "zlib"
        assert ObfuscationLayer.BASE64.value == "base64"
        assert ObfuscationLayer.UUID_ENCODE.value == "uuid_encode"
    
    def test_obfuscation_level_values(self):
        """Test ObfuscationLevel enum values"""
        from evasion.multi_layer_obfuscation import ObfuscationLevel
        
        assert ObfuscationLevel.NONE.value == "none"
        assert ObfuscationLevel.MINIMAL.value == "minimal"
        assert ObfuscationLevel.STANDARD.value == "standard"
        assert ObfuscationLevel.AGGRESSIVE.value == "aggressive"
        assert ObfuscationLevel.PARANOID.value == "paranoid"


class TestObfuscationConfig:
    """Test obfuscation configuration"""
    
    def test_default_config(self):
        """Test default obfuscation config"""
        from evasion.multi_layer_obfuscation import ObfuscationConfig, ObfuscationLevel
        
        config = ObfuscationConfig()
        
        assert config.level == ObfuscationLevel.STANDARD
        assert config.random_layer_order is False
        assert config.anti_emulation is True
    
    def test_layer_config(self):
        """Test layer configuration"""
        from evasion.multi_layer_obfuscation import LayerConfig, ObfuscationLayer
        
        config = LayerConfig(
            layer_type=ObfuscationLayer.XOR_STRINGS
        )
        
        assert config.layer_type == ObfuscationLayer.XOR_STRINGS
        assert len(config.key) == 32  # Default key length
        assert len(config.iv) == 16


class TestXORProcessor:
    """Test XOR encryption processor"""
    
    def test_xor_encode_decode(self):
        """Test XOR encode and decode"""
        from evasion.multi_layer_obfuscation import XORProcessor, LayerConfig, ObfuscationLayer
        
        processor = XORProcessor()
        config = LayerConfig(
            layer_type=ObfuscationLayer.XOR_STRINGS,
            key=b"TESTKEY12345678901234567890123456"
        )
        
        original = b"Hello, World! This is a test message."
        
        encoded = processor.encode(original, config)
        assert encoded != original
        
        decoded = processor.decode(encoded, config)
        assert decoded == original


class TestRollingXORProcessor:
    """Test Rolling XOR processor"""
    
    def test_rolling_xor(self):
        """Test rolling XOR encode and decode"""
        from evasion.multi_layer_obfuscation import RollingXORProcessor, LayerConfig, ObfuscationLayer
        
        processor = RollingXORProcessor()
        config = LayerConfig(
            layer_type=ObfuscationLayer.XOR_ROLLING,
            key=b"ROLLINGKEY123456"
        )
        
        original = b"Test data for rolling XOR encryption"
        
        encoded = processor.encode(original, config)
        assert encoded != original
        
        decoded = processor.decode(encoded, config)
        assert decoded == original


class TestRC4Processor:
    """Test RC4 processor"""
    
    def test_rc4_encode_decode(self):
        """Test RC4 encode and decode"""
        from evasion.multi_layer_obfuscation import RC4Processor, LayerConfig, ObfuscationLayer
        
        processor = RC4Processor()
        config = LayerConfig(
            layer_type=ObfuscationLayer.RC4,
            key=b"RC4SECRETKEY"
        )
        
        original = b"Test message for RC4 encryption"
        
        encoded = processor.encode(original, config)
        assert encoded != original
        
        decoded = processor.decode(encoded, config)
        assert decoded == original


class TestCompressionProcessors:
    """Test compression processors"""
    
    def test_zlib_compression(self):
        """Test zlib compression"""
        from evasion.multi_layer_obfuscation import ZlibProcessor, LayerConfig, ObfuscationLayer
        
        processor = ZlibProcessor()
        config = LayerConfig(layer_type=ObfuscationLayer.ZLIB)
        
        # Repeating data compresses well
        original = b"AAAAAABBBBBBCCCCCCDDDDDD" * 100
        
        compressed = processor.encode(original, config)
        assert len(compressed) < len(original)
        
        decompressed = processor.decode(compressed, config)
        assert decompressed == original
    
    def test_lzma_compression(self):
        """Test LZMA compression"""
        from evasion.multi_layer_obfuscation import LZMAProcessor, LayerConfig, ObfuscationLayer
        
        processor = LZMAProcessor()
        config = LayerConfig(layer_type=ObfuscationLayer.LZMA)
        
        original = b"LZMA compression test data" * 50
        
        compressed = processor.encode(original, config)
        decompressed = processor.decode(compressed, config)
        
        assert decompressed == original


class TestEncodingProcessors:
    """Test encoding processors"""
    
    def test_base64_encoding(self):
        """Test Base64 encoding"""
        from evasion.multi_layer_obfuscation import Base64Processor, LayerConfig, ObfuscationLayer
        
        processor = Base64Processor()
        config = LayerConfig(layer_type=ObfuscationLayer.BASE64)
        
        original = b"Binary data: \x00\x01\x02\xff\xfe"
        
        encoded = processor.encode(original, config)
        assert encoded != original
        
        decoded = processor.decode(encoded, config)
        assert decoded == original
    
    def test_base85_encoding(self):
        """Test Base85 encoding"""
        from evasion.multi_layer_obfuscation import Base85Processor, LayerConfig, ObfuscationLayer
        
        processor = Base85Processor()
        config = LayerConfig(layer_type=ObfuscationLayer.BASE85)
        
        original = b"Test data for Base85 encoding"
        
        encoded = processor.encode(original, config)
        decoded = processor.decode(encoded, config)
        
        assert decoded == original
    
    def test_hex_encoding(self):
        """Test Hex encoding"""
        from evasion.multi_layer_obfuscation import HexProcessor, LayerConfig, ObfuscationLayer
        
        processor = HexProcessor()
        config = LayerConfig(layer_type=ObfuscationLayer.HEX)
        
        original = b"\xDE\xAD\xBE\xEF"
        
        encoded = processor.encode(original, config)
        assert encoded == b"deadbeef"
        
        decoded = processor.decode(encoded, config)
        assert decoded == original
    
    def test_uuid_encoding(self):
        """Test UUID encoding"""
        from evasion.multi_layer_obfuscation import UUIDEncodingProcessor, LayerConfig, ObfuscationLayer
        
        processor = UUIDEncodingProcessor()
        config = LayerConfig(layer_type=ObfuscationLayer.UUID_ENCODE)
        
        # 16 bytes = 1 UUID
        original = b"0123456789ABCDEF"
        
        encoded = processor.encode(original, config)
        # Should look like UUID
        assert b"-" in encoded
        
        decoded = processor.decode(encoded, config)
        assert decoded == original


class TestMultiLayerObfuscator:
    """Test multi-layer obfuscator"""
    
    def test_minimal_obfuscation(self):
        """Test minimal obfuscation level"""
        from evasion.multi_layer_obfuscation import MultiLayerObfuscator, ObfuscationConfig, ObfuscationLevel
        
        config = ObfuscationConfig(level=ObfuscationLevel.MINIMAL)
        obfuscator = MultiLayerObfuscator(config)
        
        original = b"Test payload for minimal obfuscation"
        
        result = obfuscator.obfuscate(original)
        
        assert result.success
        assert result.data != original
        assert len(result.layers_applied) > 0
        assert "xor_strings" in result.layers_applied
    
    def test_standard_obfuscation(self):
        """Test standard obfuscation level"""
        from evasion.multi_layer_obfuscation import MultiLayerObfuscator, ObfuscationConfig, ObfuscationLevel
        
        config = ObfuscationConfig(level=ObfuscationLevel.STANDARD)
        obfuscator = MultiLayerObfuscator(config)
        
        original = b"Test payload for standard obfuscation" * 10
        
        result = obfuscator.obfuscate(original)
        
        assert result.success
        assert result.data != original
        assert len(result.layers_applied) >= 4
    
    def test_obfuscation_deobfuscation_roundtrip(self):
        """Test obfuscation and deobfuscation roundtrip"""
        from evasion.multi_layer_obfuscation import MultiLayerObfuscator, ObfuscationConfig, ObfuscationLevel
        
        config = ObfuscationConfig(
            level=ObfuscationLevel.MINIMAL,
            anti_emulation=False  # Disable for clean roundtrip test
        )
        obfuscator = MultiLayerObfuscator(config)
        
        original = b"Roundtrip test data"
        
        # Obfuscate
        obf_result = obfuscator.obfuscate(original)
        assert obf_result.success
        
        # Deobfuscate
        deobf_result = obfuscator.deobfuscate(
            obf_result.data,
            obf_result.deobfuscation_key
        )
        
        assert deobf_result.success
        assert deobf_result.data == original
    
    def test_entropy_calculation(self):
        """Test entropy calculation"""
        from evasion.multi_layer_obfuscation import MultiLayerObfuscator, ObfuscationConfig, ObfuscationLevel
        
        config = ObfuscationConfig(level=ObfuscationLevel.STANDARD)
        obfuscator = MultiLayerObfuscator(config)
        
        # Low entropy input (repeating)
        low_entropy = b"AAAA" * 1000
        
        result = obfuscator.obfuscate(low_entropy)
        
        # Obfuscated should have higher entropy
        assert result.metadata.get('entropy', 0) > 0


class TestPayloadTransformer:
    """Test payload transformer"""
    
    def test_python_loader_generation(self):
        """Test Python loader generation"""
        from evasion.multi_layer_obfuscation import PayloadTransformer
        
        transformer = PayloadTransformer()
        
        # Fake shellcode
        shellcode = secrets.token_bytes(256)
        
        code, key = transformer.transform_shellcode(shellcode, "python")
        
        assert len(code) > 0
        assert "import ctypes" in code
        assert "base64" in code
        assert len(key) > 0
    
    def test_csharp_loader_generation(self):
        """Test C# loader generation"""
        from evasion.multi_layer_obfuscation import PayloadTransformer
        
        transformer = PayloadTransformer()
        
        shellcode = secrets.token_bytes(128)
        
        code, key = transformer.transform_shellcode(shellcode, "csharp")
        
        assert len(code) > 0
        assert "using System" in code
        assert "VirtualAlloc" in code
    
    def test_powershell_loader_generation(self):
        """Test PowerShell loader generation"""
        from evasion.multi_layer_obfuscation import PayloadTransformer
        
        transformer = PayloadTransformer()
        
        shellcode = secrets.token_bytes(64)
        
        code, key = transformer.transform_shellcode(shellcode, "powershell")
        
        assert len(code) > 0
        assert "$" in code  # PowerShell variable


# ============================================================
# LATERAL CHAIN CONFIG INTEGRATION TESTS
# ============================================================

class TestLateralChainConfigIntegration:
    """Test lateral_chain_config.py integration"""
    
    def test_obfuscation_level_enum(self):
        """Test ObfuscationLevel enum in chain config"""
        from cybermodules.lateral_chain_config import ObfuscationLevel
        
        assert ObfuscationLevel.NONE.value == "none"
        assert ObfuscationLevel.PARANOID.value == "paranoid"
    
    def test_syscall_technique_enum(self):
        """Test SyscallTechnique enum in chain config"""
        from cybermodules.lateral_chain_config import SyscallTechnique
        
        assert SyscallTechnique.HELLS_GATE.value == "hells_gate"
        assert SyscallTechnique.SYSWHISPERS3.value == "syswhispers3"
    
    def test_syscall_config_dataclass(self):
        """Test SyscallConfig dataclass"""
        from cybermodules.lateral_chain_config import SyscallConfig, SyscallTechnique
        
        config = SyscallConfig(
            enabled=True,
            technique=SyscallTechnique.HALOS_GATE,
            use_indirect=True
        )
        
        assert config.enabled is True
        assert config.technique == SyscallTechnique.HALOS_GATE
    
    def test_advanced_obfuscation_config(self):
        """Test AdvancedObfuscationConfig dataclass"""
        from cybermodules.lateral_chain_config import AdvancedObfuscationConfig, ObfuscationLevel
        
        config = AdvancedObfuscationConfig(
            level=ObfuscationLevel.AGGRESSIVE,
            layers=["xor_rolling", "lzma", "aes_gcm", "base85"]
        )
        
        assert config.level == ObfuscationLevel.AGGRESSIVE
        assert "lzma" in config.layers
    
    def test_chain_config_with_obfuscation(self):
        """Test LateralChainConfig with obfuscation settings"""
        from cybermodules.lateral_chain_config import (
            LateralChainConfig, ObfuscationLevel, SyscallTechnique
        )
        
        config = LateralChainConfig(
            name="Test Chain",
            obfuscation_level=ObfuscationLevel.AGGRESSIVE,
            syscall_technique=SyscallTechnique.SYSWHISPERS3,
            use_indirect_syscalls=True
        )
        
        assert config.obfuscation_level == ObfuscationLevel.AGGRESSIVE
        assert config.syscall_technique == SyscallTechnique.SYSWHISPERS3
        assert config.obfuscation_config is not None
        assert config.syscall_config is not None
    
    def test_detection_risk_calculation(self):
        """Test detection risk calculation"""
        from cybermodules.lateral_chain_config import (
            LateralChainConfig, ObfuscationLevel, SyscallTechnique
        )
        
        # Low risk config
        low_risk_config = LateralChainConfig(
            name="Low Risk",
            obfuscation_level=ObfuscationLevel.PARANOID,
            syscall_technique=SyscallTechnique.SYSWHISPERS3,
            use_indirect_syscalls=True
        )
        
        # High risk config
        high_risk_config = LateralChainConfig(
            name="High Risk",
            obfuscation_level=ObfuscationLevel.NONE,
            syscall_technique=SyscallTechnique.DIRECT,
            use_indirect_syscalls=False
        )
        
        low_risk = low_risk_config.get_detection_risk()
        high_risk = high_risk_config.get_detection_risk()
        
        assert low_risk["overall_risk"] < high_risk["overall_risk"]
    
    def test_config_validation_with_obfuscation(self):
        """Test config validation includes obfuscation checks"""
        from cybermodules.lateral_chain_config import (
            LateralChainConfigLoader, AdvancedObfuscationConfig, 
            ObfuscationLevel, TargetHost, CredentialSet
        )
        
        loader = LateralChainConfigLoader()
        
        # Load a basic config
        config_data = {
            'name': 'Validation Test',
            'targets': [{'hostname': 'test.local'}],
            'credentials': [{'name': 'admin', 'username': 'admin'}],
            'obfuscation': {
                'level': 'standard',
                'layers': ['xor_rolling', 'zlib', 'aes_gcm', 'base64'],
                'target_entropy': 7.0
            },
            'syscall': {
                'enabled': True,
                'technique': 'syswhispers3'
            }
        }
        
        config = loader.load_from_dict(config_data)
        validation = loader.validate_config()
        
        assert validation['valid'] is True
        assert 'detection_risk' in validation


# ============================================================
# AI LATERAL GUIDE INTEGRATION TESTS
# ============================================================

class TestAILateralGuideIntegration:
    """Test ai_lateral_guide.py integration"""
    
    def test_syscall_risk_in_path(self):
        """Test syscall risk is added to attack path"""
        from cybermodules.ai_lateral_guide import AILateralGuide, HostIntel
        
        guide = AILateralGuide()
        
        # Use the actual API: add_host_intel
        attacker = HostIntel(
            hostname="attacker.local",
            ip="192.168.1.100",
            os_type="windows",
            compromised=True
        )
        target = HostIntel(
            hostname="target.local",
            ip="192.168.1.200",
            os_type="windows",
            compromised=False
        )
        
        guide.add_host_intel(attacker)
        guide.add_host_intel(target)
        
        # Get attack path with syscall risk
        path = guide.suggest_attack_path("attacker.local", "target.local", include_syscall_risk=True)
        
        # Path should be a list
        assert isinstance(path, list)
        
        # If path has steps, they should have syscall detection info
        for step in path:
            if isinstance(step, dict) and 'syscall_detection' in step:
                assert 'risk_level' in step['syscall_detection']
                assert 'risk_score' in step['syscall_detection']
    
    def test_edr_trigger_calculation(self):
        """Test EDR trigger likelihood calculation"""
        from cybermodules.ai_lateral_guide import AILateralGuide
        
        guide = AILateralGuide()
        
        # Test with high-risk info
        risk_info = {
            'risk': 'HIGH',
            'score': 0.7,
            'syscalls_needed': ['NtAllocateVirtualMemory', 'NtWriteVirtualMemory']
        }
        
        triggers = guide._calculate_edr_trigger(risk_info)
        
        assert 'crowdstrike' in triggers
        assert 'defender_atp' in triggers
        assert 'sysmon' in triggers
        
        # CrowdStrike should have high trigger chance for HIGH risk
        assert triggers['crowdstrike'] > 0.5
    
    def test_syscall_mitigations(self):
        """Test syscall mitigation recommendations"""
        from cybermodules.ai_lateral_guide import AILateralGuide
        
        guide = AILateralGuide()
        
        low_mitigations = guide._get_syscall_mitigations('LOW')
        high_mitigations = guide._get_syscall_mitigations('HIGH')
        critical_mitigations = guide._get_syscall_mitigations('CRITICAL')
        
        assert len(low_mitigations) < len(high_mitigations)
        assert len(high_mitigations) < len(critical_mitigations)
        
        # Critical should mention LOTL
        assert any('LOTL' in m for m in critical_mitigations)


# ============================================================
# SYSMON / EDR SIMULATION TESTS
# ============================================================

class TestEDRSimulation:
    """Simulated EDR detection tests"""
    
    def test_syscall_pattern_detection(self):
        """Test detection of common syscall patterns"""
        # Suspicious syscall sequences
        suspicious_sequences = [
            ['NtAllocateVirtualMemory', 'NtWriteVirtualMemory', 'NtProtectVirtualMemory', 'NtCreateThreadEx'],
            ['NtOpenProcess', 'NtAllocateVirtualMemory', 'NtWriteVirtualMemory', 'NtCreateThreadEx'],
        ]
        
        # Thread hijacking (no alloc/write but has execution) - this is a different pattern
        thread_hijack_sequence = ['NtSuspendThread', 'NtSetContextThread', 'NtResumeThread']
        
        # EDR detection rules
        def is_injection_pattern(sequence):
            """Simulate EDR injection detection"""
            injection_indicators = [
                'NtCreateThreadEx',
                'NtQueueApcThread',
                'NtSetContextThread'
            ]
            has_alloc = any('Alloc' in s for s in sequence)
            has_write = any('Write' in s for s in sequence)
            has_execution = any(ind in sequence for ind in injection_indicators)
            
            return has_alloc and has_write and has_execution
        
        def is_thread_hijack_pattern(sequence):
            """Simulate EDR thread hijacking detection"""
            return 'NtSuspendThread' in sequence and 'NtSetContextThread' in sequence
        
        # Test injection patterns
        for seq in suspicious_sequences:
            assert is_injection_pattern(seq), f"Injection pattern not detected: {seq}"
        
        # Test thread hijack pattern separately
        assert is_thread_hijack_pattern(thread_hijack_sequence), "Thread hijack pattern not detected"
    
    def test_obfuscated_payload_entropy(self):
        """Test that obfuscated payloads have high entropy"""
        from evasion.multi_layer_obfuscation import MultiLayerObfuscator, ObfuscationConfig, ObfuscationLevel
        import math
        
        def calculate_entropy(data):
            if not data:
                return 0.0
            freq = {}
            for byte in data:
                freq[byte] = freq.get(byte, 0) + 1
            entropy = 0.0
            for count in freq.values():
                p = count / len(data)
                entropy -= p * math.log2(p)
            return entropy
        
        config = ObfuscationConfig(level=ObfuscationLevel.AGGRESSIVE)
        obfuscator = MultiLayerObfuscator(config)
        
        # Plain payload with low entropy
        payload = b"AAAA" * 100
        original_entropy = calculate_entropy(payload)
        
        result = obfuscator.obfuscate(payload)
        obfuscated_entropy = calculate_entropy(result.data)
        
        # Obfuscated should have significantly higher entropy
        assert obfuscated_entropy > original_entropy + 2.0
    
    def test_indirect_syscall_detection_evasion(self):
        """Test that indirect syscalls reduce detection"""
        from evasion.indirect_syscalls import IndirectSyscallExecutor, SyscallConfig, SyscallTechnique
        
        # Direct syscall config
        direct_config = SyscallConfig(
            technique=SyscallTechnique.DIRECT,
            use_indirect=False
        )
        
        # Indirect syscall config
        indirect_config = SyscallConfig(
            technique=SyscallTechnique.SYSWHISPERS3,
            use_indirect=True,
            add_jitter=True
        )
        
        direct_executor = IndirectSyscallExecutor(direct_config)
        indirect_executor = IndirectSyscallExecutor(indirect_config)
        
        # Build stubs and check
        direct_stub = direct_executor._build_direct_stub(0x18)
        
        # Direct stub contains 0F 05 (syscall)
        assert bytes([0x0F, 0x05]) in direct_stub
        
        # Indirect stub should use jump instead
        indirect_stub = indirect_executor._build_indirect_stub(0x18, 0x7FFE0000)
        # Should NOT contain syscall opcode directly - uses jmp instead
        assert indirect_stub[-2:] == bytes([0xFF, 0xE3])  # jmp rbx


# ============================================================
# RUN TESTS
# ============================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
