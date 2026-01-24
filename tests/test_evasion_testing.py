"""
Tests for Evasion Testing Module
================================
"""

import pytest
import os
import tempfile
from unittest.mock import Mock, patch, MagicMock

from cybermodules.evasion_testing import (
    DetectionLevel,
    TestCategory,
    YARAMatch,
    StringMatch,
    EntropyResult,
    BehaviorMatch,
    EvasionReport,
    YARAScanner,
    StringScanner,
    EntropyAnalyzer,
    BehavioralAnalyzer,
    EvasionTester,
)


# ============================================================
# ENUM TESTS
# ============================================================

class TestEnums:
    """Tests for evasion testing enums"""
    
    def test_detection_levels(self):
        """Test DetectionLevel enum"""
        assert DetectionLevel.CLEAN.value == "clean"
        assert DetectionLevel.LOW.value == "low"
        assert DetectionLevel.MEDIUM.value == "medium"
        assert DetectionLevel.HIGH.value == "high"
        assert DetectionLevel.CRITICAL.value == "critical"
    
    def test_test_categories(self):
        """Test TestCategory enum"""
        assert TestCategory.YARA.value == "yara"
        assert TestCategory.ENTROPY.value == "entropy"
        assert TestCategory.BEHAVIOR.value == "behavior"


# ============================================================
# DATACLASS TESTS
# ============================================================

class TestYARAMatch:
    """Tests for YARAMatch dataclass"""
    
    def test_yara_match_creation(self):
        """Test YARAMatch creation"""
        match = YARAMatch(
            rule_name="suspicious_shellcode",
            rule_source="builtin",
            strings_matched=["VirtualAlloc", "CreateRemoteThread"],
            severity="high"
        )
        
        assert match.rule_name == "suspicious_shellcode"
        assert match.severity == "high"
        assert len(match.strings_matched) == 2


class TestStringMatch:
    """Tests for StringMatch dataclass"""
    
    def test_string_match_creation(self):
        """Test StringMatch creation"""
        match = StringMatch(
            string="VirtualAllocEx",
            offset=0x1000,
            context="call VirtualAllocEx",
            category="process_injection"
        )
        
        assert match.string == "VirtualAllocEx"
        assert match.category == "process_injection"


class TestEntropyResult:
    """Tests for EntropyResult dataclass"""
    
    def test_entropy_result_creation(self):
        """Test EntropyResult creation"""
        result = EntropyResult(
            overall_entropy=7.5,
            section_entropy={"0x00001000": 7.8, "0x00002000": 6.2},
            high_entropy_sections=["0x00001000"],
            is_packed=True,
            is_encrypted=False
        )
        
        assert result.overall_entropy == 7.5
        assert result.is_packed is True
        assert len(result.high_entropy_sections) == 1


class TestBehaviorMatch:
    """Tests for BehaviorMatch dataclass"""
    
    def test_behavior_match_creation(self):
        """Test BehaviorMatch creation"""
        match = BehaviorMatch(
            pattern_name="Classic Process Injection",
            apis_matched=["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
            risk_level=DetectionLevel.CRITICAL,
            description="Classic injection pattern",
            mitigation="Use direct syscalls"
        )
        
        assert match.pattern_name == "Classic Process Injection"
        assert match.risk_level == DetectionLevel.CRITICAL


class TestEvasionReport:
    """Tests for EvasionReport dataclass"""
    
    def test_report_creation(self):
        """Test EvasionReport creation"""
        report = EvasionReport(
            scan_id="scan_123",
            target_file="test.exe",
            scan_time="2024-01-01T00:00:00"
        )
        
        assert report.scan_id == "scan_123"
        assert report.overall_risk == DetectionLevel.CLEAN
        assert report.total_score == 0
    
    def test_report_to_dict(self):
        """Test report serialization"""
        report = EvasionReport(
            scan_id="scan_456",
            target_file="payload.dll",
            scan_time="2024-01-01",
            overall_risk=DetectionLevel.HIGH,
            total_score=85
        )
        
        data = report.to_dict()
        
        assert data['scan_id'] == "scan_456"
        assert data['overall_risk'] == "high"
        assert data['total_score'] == 85


# ============================================================
# YARA SCANNER TESTS
# ============================================================

class TestYARAScanner:
    """Tests for YARAScanner class"""
    
    def test_scanner_initialization(self):
        """Test YARA scanner initialization"""
        scanner = YARAScanner()
        assert scanner is not None
    
    def test_builtin_rules_exist(self):
        """Test that builtin rules are defined"""
        scanner = YARAScanner()
        assert scanner.BUILTIN_RULES is not None
        assert "suspicious_shellcode" in scanner.BUILTIN_RULES
        assert "process_injection_strings" in scanner.BUILTIN_RULES
    
    def test_scan_bytes_no_match(self):
        """Test scanning clean bytes"""
        scanner = YARAScanner()
        clean_data = b"Hello World! This is clean data."
        
        matches = scanner.scan_bytes(clean_data)
        
        # With YARA not installed, this may return empty
        assert isinstance(matches, list)
    
    def test_scan_bytes_with_suspicious_content(self):
        """Test scanning suspicious bytes"""
        scanner = YARAScanner()
        
        # Data with NOP sled pattern
        suspicious_data = b"\x90" * 20 + b"VirtualAllocEx" + b"\x00" * 10
        
        matches = scanner.scan_bytes(suspicious_data)
        
        # Results depend on YARA availability
        assert isinstance(matches, list)


# ============================================================
# STRING SCANNER TESTS
# ============================================================

class TestStringScanner:
    """Tests for StringScanner class"""
    
    def test_scanner_initialization(self):
        """Test string scanner initialization"""
        scanner = StringScanner()
        assert len(scanner.suspicious_strings) > 0
    
    def test_scanner_with_custom_strings(self):
        """Test scanner with custom strings"""
        scanner = StringScanner(custom_strings=["CustomMalware", "EvilFunc"])
        
        assert "CustomMalware" in scanner.suspicious_strings
        assert "EvilFunc" in scanner.suspicious_strings
    
    def test_scan_bytes_with_injection_strings(self):
        """Test scanning bytes with injection strings"""
        scanner = StringScanner()
        
        data = b"code before VirtualAllocEx code after WriteProcessMemory more code"
        
        matches = scanner.scan_bytes(data)
        
        assert len(matches) >= 2
        assert any(m.string == "VirtualAllocEx" for m in matches)
        assert any(m.string == "WriteProcessMemory" for m in matches)
    
    def test_scan_bytes_clean(self):
        """Test scanning clean bytes"""
        scanner = StringScanner()
        
        data = b"This is just regular text with no suspicious content."
        
        matches = scanner.scan_bytes(data)
        
        assert len(matches) == 0
    
    def test_categorize_string_injection(self):
        """Test string categorization for injection"""
        scanner = StringScanner()
        
        category = scanner._categorize_string("VirtualAllocEx")
        assert category == "process_injection"
        
        category = scanner._categorize_string("CreateRemoteThread")
        assert category == "process_injection"
    
    def test_categorize_string_credential_theft(self):
        """Test string categorization for credential theft"""
        scanner = StringScanner()
        
        category = scanner._categorize_string("mimikatz")
        assert category == "credential_theft"
        
        category = scanner._categorize_string("lsass")
        assert category == "credential_theft"
    
    def test_categorize_string_defense_evasion(self):
        """Test string categorization for defense evasion"""
        scanner = StringScanner()
        
        category = scanner._categorize_string("AmsiScanBuffer")
        assert category == "defense_evasion"
        
        category = scanner._categorize_string("EtwEventWrite")
        assert category == "defense_evasion"


# ============================================================
# ENTROPY ANALYZER TESTS
# ============================================================

class TestEntropyAnalyzer:
    """Tests for EntropyAnalyzer class"""
    
    def test_analyzer_initialization(self):
        """Test entropy analyzer initialization"""
        analyzer = EntropyAnalyzer()
        assert analyzer is not None
    
    def test_analyze_low_entropy_data(self):
        """Test analyzing low entropy data"""
        analyzer = EntropyAnalyzer()
        
        # Repetitive data has low entropy
        data = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        
        result = analyzer.analyze_bytes(data)
        
        assert result.overall_entropy < 1.0
        assert result.is_packed is False
        assert result.is_encrypted is False
    
    def test_analyze_high_entropy_data(self):
        """Test analyzing high entropy data"""
        analyzer = EntropyAnalyzer()
        
        # Random-looking data has high entropy
        import os
        data = os.urandom(1024)
        
        result = analyzer.analyze_bytes(data)
        
        assert result.overall_entropy > 7.0
        assert result.is_encrypted is True
    
    def test_analyze_medium_entropy_data(self):
        """Test analyzing medium entropy data"""
        analyzer = EntropyAnalyzer()
        
        # Normal text has medium entropy
        data = b"The quick brown fox jumps over the lazy dog. " * 20
        
        result = analyzer.analyze_bytes(data)
        
        assert 3.0 < result.overall_entropy < 5.0
    
    def test_section_entropy_calculation(self):
        """Test section-by-section entropy"""
        analyzer = EntropyAnalyzer()
        
        # Create data with different entropy sections
        data = b"A" * 4096 + os.urandom(4096)
        
        result = analyzer.analyze_bytes(data, section_size=4096)
        
        assert len(result.section_entropy) == 2
    
    def test_empty_data(self):
        """Test analyzing empty data"""
        analyzer = EntropyAnalyzer()
        
        result = analyzer.analyze_bytes(b"")
        
        assert result.overall_entropy == 0.0


# ============================================================
# BEHAVIORAL ANALYZER TESTS
# ============================================================

class TestBehavioralAnalyzer:
    """Tests for BehavioralAnalyzer class"""
    
    def test_analyzer_initialization(self):
        """Test behavioral analyzer initialization"""
        analyzer = BehavioralAnalyzer()
        assert len(analyzer.api_patterns) > 0
    
    def test_analyze_injection_pattern(self):
        """Test detecting injection pattern"""
        analyzer = BehavioralAnalyzer()
        
        strings = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
        
        matches = analyzer.analyze_strings(strings)
        
        assert len(matches) >= 1
        assert any(m.pattern_name == "Classic Process Injection" for m in matches)
    
    def test_analyze_apc_injection_pattern(self):
        """Test detecting APC injection pattern"""
        analyzer = BehavioralAnalyzer()
        
        strings = ["OpenThread", "QueueUserAPC", "ResumeThread"]
        
        matches = analyzer.analyze_strings(strings)
        
        assert len(matches) >= 1
        assert any(m.pattern_name == "APC Injection" for m in matches)
    
    def test_analyze_credential_dump_pattern(self):
        """Test detecting credential dump pattern"""
        analyzer = BehavioralAnalyzer()
        
        strings = ["OpenProcess", "MiniDumpWriteDump"]
        
        matches = analyzer.analyze_strings(strings)
        
        assert len(matches) >= 1
        assert any(m.risk_level == DetectionLevel.CRITICAL for m in matches)
    
    def test_analyze_clean_strings(self):
        """Test analyzing clean strings"""
        analyzer = BehavioralAnalyzer()
        
        strings = ["printf", "malloc", "fopen", "strcmp"]
        
        matches = analyzer.analyze_strings(strings)
        
        assert len(matches) == 0
    
    def test_identify_behavior_injection(self):
        """Test behavior identification for injection"""
        analyzer = BehavioralAnalyzer()
        
        behavior = analyzer._identify_behavior(["VirtualAllocEx", "CreateRemoteThread"])
        
        assert behavior['name'] == "Classic Process Injection"
        assert behavior['risk'] == DetectionLevel.CRITICAL


# ============================================================
# EVASION TESTER TESTS
# ============================================================

class TestEvasionTester:
    """Tests for EvasionTester class"""
    
    def test_tester_initialization(self):
        """Test evasion tester initialization"""
        tester = EvasionTester(scan_id=123)
        
        assert tester.scan_id == 123
        assert tester.yara_scanner is not None
        assert tester.string_scanner is not None
        assert tester.entropy_analyzer is not None
        assert tester.behavior_analyzer is not None
    
    def test_test_bytes_clean(self):
        """Test testing clean bytes"""
        tester = EvasionTester()
        
        clean_data = b"This is just normal text with no malicious content."
        
        report = tester.test_bytes(clean_data, name="clean.txt")
        
        assert report.overall_risk == DetectionLevel.CLEAN
        assert report.total_score == 0
    
    def test_test_bytes_suspicious(self):
        """Test testing suspicious bytes"""
        tester = EvasionTester()
        
        suspicious_data = b"VirtualAllocEx WriteProcessMemory CreateRemoteThread"
        
        report = tester.test_bytes(suspicious_data, name="suspicious.bin")
        
        assert report.overall_risk != DetectionLevel.CLEAN
        assert len(report.string_matches) > 0
        assert len(report.behavior_matches) > 0
    
    def test_test_code_pattern_clean(self):
        """Test testing clean code"""
        tester = EvasionTester()
        
        code = """
def hello():
    print("Hello World")
"""
        
        report = tester.test_code_pattern(code, language="python")
        
        assert report.total_score < 30
    
    def test_test_code_pattern_suspicious(self):
        """Test testing suspicious code"""
        tester = EvasionTester()
        
        code = """
import ctypes
kernel32 = ctypes.windll.kernel32
VirtualAlloc = kernel32.VirtualAlloc
"""
        
        report = tester.test_code_pattern(code, language="python")
        
        assert report.total_score > 0
        assert len(report.string_matches) > 0
    
    def test_calculate_risk_level(self):
        """Test risk level calculation"""
        tester = EvasionTester()
        
        assert tester._calculate_risk_level(0) == DetectionLevel.CLEAN
        assert tester._calculate_risk_level(20) == DetectionLevel.LOW
        assert tester._calculate_risk_level(45) == DetectionLevel.MEDIUM
        assert tester._calculate_risk_level(80) == DetectionLevel.HIGH
        assert tester._calculate_risk_level(150) == DetectionLevel.CRITICAL
    
    def test_generate_recommendations(self):
        """Test recommendation generation"""
        tester = EvasionTester()
        
        report = EvasionReport(
            scan_id="test",
            target_file="test.exe",
            scan_time="2024-01-01"
        )
        
        # Add some matches
        report.string_matches.append(StringMatch(
            string="VirtualAllocEx",
            offset=0,
            context="test",
            category="process_injection"
        ))
        report.behavior_matches.append(BehaviorMatch(
            pattern_name="Test Pattern",
            apis_matched=["api1"],
            risk_level=DetectionLevel.HIGH,
            description="Test",
            mitigation="Use different method"
        ))
        
        recommendations = tester._generate_recommendations(report)
        
        assert len(recommendations) > 0
    
    def test_generate_report_markdown(self):
        """Test markdown report generation"""
        tester = EvasionTester()
        
        report = EvasionReport(
            scan_id="test123",
            target_file="payload.exe",
            scan_time="2024-01-01T12:00:00",
            overall_risk=DetectionLevel.HIGH,
            total_score=75
        )
        
        markdown = tester.generate_report_markdown(report)
        
        assert "# Evasion Analysis Report" in markdown
        assert "test123" in markdown
        assert "HIGH" in markdown


# ============================================================
# INTEGRATION TESTS
# ============================================================

class TestEvasionIntegration:
    """Integration tests for evasion module"""
    
    def test_full_analysis_workflow(self):
        """Test full analysis workflow"""
        tester = EvasionTester()
        
        # Create test data with various characteristics
        test_data = (
            b"Normal code section " * 10 +
            b"VirtualAllocEx" +
            b"\x90" * 16 +  # NOP sled
            b"CreateRemoteThread" +
            b"More normal code " * 10
        )
        
        report = tester.test_bytes(test_data, name="test_payload.bin")
        
        # Verify all analysis components ran
        assert report.scan_id is not None
        assert report.entropy_result is not None
        assert isinstance(report.yara_matches, list)
        assert isinstance(report.string_matches, list)
        assert isinstance(report.behavior_matches, list)
    
    def test_file_analysis(self):
        """Test file analysis"""
        tester = EvasionTester()
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"Test content with VirtualAlloc API call")
            temp_path = f.name
        
        try:
            report = tester.test_file(temp_path)
            
            assert report.target_file == temp_path
            assert report.scan_time is not None
        finally:
            os.unlink(temp_path)
    
    def test_report_consistency(self):
        """Test report data consistency"""
        tester = EvasionTester()
        
        data = b"AmsiScanBuffer EtwEventWrite bypass code"
        
        report = tester.test_bytes(data)
        
        # Total score should match component scores
        expected_total = (
            report.yara_score +
            report.string_score +
            report.entropy_score +
            report.behavior_score
        )
        
        assert report.total_score == expected_total
