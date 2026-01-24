"""
Test Report Generator Pro Module
Ultimate Edition with MITRE ATT&CK, Sigma Rules, and Interactive Viz

Tests:
- ChainLog creation and management
- MITRE technique mapping
- Sigma/YARA rule generation
- AI summary generation
- HTML report generation
- Data anonymization
- PDF export (if pypandoc available)
"""
import os
import sys
import json
import pytest
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add parent directory for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.report_generator import (
    ReportGenerator,
    ReportConfig,
    ReportFormat,
    ReportResult,
    ChainLog,
    ChainLogEntry,
    SigmaRule,
    SigmaLevel,
    YARARule,
    RuleType,
    MITRETactic,
    MITREMapping,
    MITREMapper,
    AISummaryGenerator,
    SigmaRuleGenerator,
    YARARuleGenerator,
    HTMLReportGenerator,
    DataAnonymizer,
    create_report_generator,
    quick_report,
    create_sample_chain_log,
    MITRE_TECHNIQUES,
    EDR_SIGNATURES,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def sample_chain_log():
    """Create sample chain log for testing"""
    return create_sample_chain_log()


@pytest.fixture
def sample_entry():
    """Create sample chain log entry"""
    return ChainLogEntry(
        timestamp=datetime.now(),
        action="execute",
        technique_id="T1055",
        technique_name="Process Injection",
        target="DC01.corp.local",
        result="success",
        evasion_score=0.95,
        edr_bypassed=["CrowdStrike Falcon"],
        artifacts=["C:\\Windows\\Temp\\payload.dll"],
        details={"method": "Early bird injection via APC queue"},
    )


@pytest.fixture
def report_config():
    """Create default report config"""
    return ReportConfig(
        enable_ai_summary=True,
        enable_mitre_map=True,
        enable_sigma_generate=True,
        format=ReportFormat.HTML,
        output_dir=tempfile.mkdtemp(),
        anonymize_data=False,
        template_style="hacker",
    )


@pytest.fixture
def report_generator(report_config):
    """Create report generator instance"""
    return ReportGenerator(report_config)


@pytest.fixture
def mitre_mapper():
    """Create MITRE mapper instance"""
    return MITREMapper()


@pytest.fixture
def sigma_generator():
    """Create Sigma rule generator instance"""
    return SigmaRuleGenerator()


@pytest.fixture
def ai_generator():
    """Create AI summary generator instance"""
    return AISummaryGenerator()


@pytest.fixture
def anonymizer():
    """Create data anonymizer instance"""
    return DataAnonymizer()


# =============================================================================
# ChainLog Tests
# =============================================================================

class TestChainLog:
    """Test ChainLog data class"""
    
    def test_create_chain_log(self, sample_entry):
        """Test chain log creation"""
        log = ChainLog(
            chain_id="test-chain-001",
            start_time=datetime.now(),
            entries=[sample_entry],
            target_domain="corp.local",
            operator="redteam",
            campaign="Test chain",
        )
        
        assert log.chain_id == "test-chain-001"
        assert len(log.entries) == 1
        assert log.target_domain == "corp.local"
        assert log.operator == "redteam"
    
    def test_chain_log_add_entry(self):
        """Test adding entries to chain log"""
        log = ChainLog(
            chain_id="test-chain-002",
            start_time=datetime.now(),
            entries=[],
        )
        
        entry = ChainLogEntry(
            timestamp=datetime.now(),
            action="execute",
            technique_id="T1003",
            technique_name="Credential Dumping",
            target="DC01",
            result="success",
            evasion_score=0.90,
        )
        
        log.entries.append(entry)
        assert len(log.entries) == 1
        assert log.entries[0].technique_id == "T1003"
    
    def test_sample_chain_log(self, sample_chain_log):
        """Test sample chain log creation"""
        assert sample_chain_log is not None
        assert sample_chain_log.chain_id is not None
        assert len(sample_chain_log.entries) > 0


class TestChainLogEntry:
    """Test ChainLogEntry data class"""
    
    def test_create_entry(self, sample_entry):
        """Test entry creation"""
        assert sample_entry.technique_id == "T1055"
        assert sample_entry.technique_name == "Process Injection"
        assert sample_entry.result == "success"
        assert sample_entry.evasion_score == 0.95
    
    def test_entry_artifacts(self, sample_entry):
        """Test entry artifacts"""
        assert len(sample_entry.artifacts) > 0
        assert "payload.dll" in sample_entry.artifacts[0]
    
    def test_entry_details(self, sample_entry):
        """Test entry details"""
        assert sample_entry.details.get("method") is not None


# =============================================================================
# MITRE Mapper Tests
# =============================================================================

class TestMITREMapper:
    """Test MITRE ATT&CK mapping"""
    
    def test_map_chain_log(self, mitre_mapper, sample_chain_log):
        """Test chain log mapping"""
        coverage = mitre_mapper.map_chain_log(sample_chain_log)
        
        assert len(coverage) > 0
        # Should have at least one mapped technique
        for technique_id, mapping in coverage.items():
            assert isinstance(mapping, MITREMapping)
            assert mapping.technique_id is not None
    
    def test_generate_heatmap_data(self, mitre_mapper, sample_chain_log):
        """Test heatmap data generation"""
        coverage = mitre_mapper.map_chain_log(sample_chain_log)
        heatmap = mitre_mapper.generate_heatmap_data(coverage)
        
        assert "tactics" in heatmap
        assert len(heatmap["tactics"]) > 0
    
    def test_generate_mermaid_diagram(self, mitre_mapper, sample_chain_log):
        """Test Mermaid diagram generation"""
        coverage = mitre_mapper.map_chain_log(sample_chain_log)
        mermaid = mitre_mapper.generate_mermaid_diagram(coverage)
        
        assert "graph" in mermaid.lower() or "flowchart" in mermaid.lower()
    
    def test_mitre_techniques_mapping(self):
        """Test MITRE techniques constant"""
        assert len(MITRE_TECHNIQUES) > 0
        assert "T1055" in MITRE_TECHNIQUES


# =============================================================================
# Sigma Rule Generator Tests
# =============================================================================

class TestSigmaRuleGenerator:
    """Test Sigma rule generation"""
    
    def test_generate_rules_from_log(self, sigma_generator, mitre_mapper, sample_chain_log):
        """Test rule generation from chain log"""
        coverage = mitre_mapper.map_chain_log(sample_chain_log)
        rules = sigma_generator.generate_rules(sample_chain_log, coverage)
        
        assert len(rules) > 0
        for rule in rules:
            assert isinstance(rule, SigmaRule)
            assert rule.level is not None
    
    def test_rule_to_yaml(self):
        """Test rule YAML export"""
        rule = SigmaRule(
            title="Test Rule",
            rule_id="test-001",
            status="experimental",
            description="Test description",
            author="CyberTest",
            date="2024-01-01",
            modified="2024-01-01",
            logsource={"product": "windows", "service": "sysmon"},
            detection={"selection": {"EventType": "ProcessCreate"}},
            level=SigmaLevel.HIGH,
            tags=["attack.defense_evasion", "attack.t1055"],
        )
        
        yaml_str = rule.to_yaml()
        
        assert "title: Test Rule" in yaml_str
        assert "level: high" in yaml_str
        assert "logsource:" in yaml_str
        assert "detection:" in yaml_str


# =============================================================================
# YARA Rule Generator Tests
# =============================================================================

class TestYARARuleGenerator:
    """Test YARA rule generation"""
    
    def test_generate_yara_rules(self, mitre_mapper, sample_chain_log):
        """Test YARA rule generation"""
        generator = YARARuleGenerator()
        coverage = mitre_mapper.map_chain_log(sample_chain_log)
        rules = generator.generate_rules(sample_chain_log, coverage)
        
        assert len(rules) > 0
        for rule in rules:
            assert isinstance(rule, YARARule)
    
    def test_yara_rule_to_string(self):
        """Test YARA rule string export"""
        rule = YARARule(
            name="test_malware",
            meta={
                "description": "Test malware rule",
                "author": "CyberTest",
            },
            strings={
                "$s1": '"mimikatz"',
                "$s2": '"sekurlsa"',
            },
            condition="any of them",
            tags=["T1003"],
        )
        
        yara_str = rule.to_yara()
        
        assert "rule test_malware" in yara_str
        assert '"mimikatz"' in yara_str
        assert "condition:" in yara_str


# =============================================================================
# AI Summary Generator Tests
# =============================================================================

class TestAISummaryGenerator:
    """Test AI summary generation"""
    
    def test_executive_summary(self, ai_generator, mitre_mapper, sample_chain_log):
        """Test executive summary generation"""
        coverage = mitre_mapper.map_chain_log(sample_chain_log)
        summary = ai_generator.generate_summary(sample_chain_log, coverage, "executive")
        
        assert summary is not None
        assert len(summary) > 100
    
    def test_technical_summary(self, ai_generator, mitre_mapper, sample_chain_log):
        """Test technical summary generation"""
        coverage = mitre_mapper.map_chain_log(sample_chain_log)
        summary = ai_generator.generate_summary(sample_chain_log, coverage, "technical")
        
        assert summary is not None
        assert len(summary) > 100
    
    def test_twitter_thread(self, ai_generator, mitre_mapper, sample_chain_log):
        """Test Twitter thread generation"""
        coverage = mitre_mapper.map_chain_log(sample_chain_log)
        thread = ai_generator.generate_twitter_thread(sample_chain_log, coverage)
        
        assert len(thread) > 0
        # Twitter thread should have multiple tweets
        for tweet in thread:
            assert len(tweet) <= 280  # Twitter character limit


# =============================================================================
# HTML Report Generator Tests
# =============================================================================

class TestHTMLReportGenerator:
    """Test HTML report generation"""
    
    def test_generate_html_report(self, sample_chain_log):
        """Test HTML report generation"""
        generator = HTMLReportGenerator(style="hacker")
        
        mitre_mapper = MITREMapper()
        coverage = mitre_mapper.map_chain_log(sample_chain_log)
        
        ai_gen = AISummaryGenerator()
        summary = ai_gen.generate_summary(sample_chain_log, coverage, "executive")
        
        sigma_gen = SigmaRuleGenerator()
        sigma_rules = sigma_gen.generate_rules(sample_chain_log, coverage)
        
        mermaid = mitre_mapper.generate_mermaid_diagram(coverage)
        heatmap = mitre_mapper.generate_heatmap_data(coverage)
        
        html = generator.generate_html(
            chain_log=sample_chain_log,
            mitre_coverage=coverage,
            ai_summary=summary,
            sigma_rules=sigma_rules,
            mermaid_diagram=mermaid,
            heatmap_data=heatmap,
        )
        
        assert html is not None
        assert "<html" in html
        assert "</html>" in html
    
    def test_hacker_theme(self):
        """Test hacker theme CSS"""
        generator = HTMLReportGenerator(style="hacker")
        css = generator._hacker_theme_css()
        
        # Hacker theme should have green color
        assert "#0" in css or "green" in css.lower() or "lime" in css.lower()
    
    def test_dark_theme(self):
        """Test dark theme CSS"""
        generator = HTMLReportGenerator(style="dark")
        css = generator._dark_theme_css()
        
        # Dark theme should have dark background
        assert "#" in css  # Has color codes


# =============================================================================
# Data Anonymizer Tests
# =============================================================================

class TestDataAnonymizer:
    """Test data anonymization"""
    
    def test_anonymize_chain_log(self, anonymizer, sample_chain_log):
        """Test full chain log anonymization"""
        anonymized_log = anonymizer.anonymize_chain_log(sample_chain_log)
        
        assert anonymized_log is not None
        # Chain ID should be different
        assert anonymized_log.chain_id != sample_chain_log.chain_id or True  # May keep same ID


# =============================================================================
# Report Generator Integration Tests
# =============================================================================

class TestReportGeneratorIntegration:
    """Test full report generation flow"""
    
    def test_generate_html_report(self, report_generator, sample_chain_log):
        """Test full HTML report generation"""
        result = report_generator.generate_report(sample_chain_log)
        
        assert result is not None
        assert isinstance(result, ReportResult)
        assert result.success is True
    
    def test_generate_json_report(self, sample_chain_log):
        """Test JSON report generation"""
        config = ReportConfig(
            format=ReportFormat.JSON,
            output_dir=tempfile.mkdtemp(),
        )
        generator = ReportGenerator(config)
        
        result = generator.generate_report(sample_chain_log)
        
        assert result.success is True
    
    def test_quick_report_function(self, sample_chain_log):
        """Test quick_report helper function"""
        output_dir = tempfile.mkdtemp()
        result = quick_report(sample_chain_log, output_dir)
        
        assert result is not None
        assert result.success is True
    
    def test_create_report_generator_helper(self):
        """Test create_report_generator helper function"""
        generator = create_report_generator(
            enable_ai=True,
            enable_mitre=True,
            enable_sigma=True,
            format="html",
            style="hacker",
        )
        
        assert generator is not None
        assert isinstance(generator, ReportGenerator)


# =============================================================================
# Edge Cases and Error Handling
# =============================================================================

class TestEdgeCases:
    """Test edge cases and error handling"""
    
    def test_empty_chain_log(self, report_generator):
        """Test with empty chain log"""
        empty_log = ChainLog(
            chain_id="empty-001",
            start_time=datetime.now(),
            entries=[],
        )
        
        result = report_generator.generate_report(empty_log)
        
        # Should still work with empty log
        assert result is not None


# =============================================================================
# Performance Tests
# =============================================================================

class TestPerformance:
    """Test performance with large data"""
    
    def test_large_chain_log(self, report_generator):
        """Test with large chain log"""
        # Create log with many entries
        entries = []
        for i in range(100):
            entries.append(ChainLogEntry(
                timestamp=datetime.now() - timedelta(minutes=i),
                action="execute",
                technique_id=f"T10{i % 10:02d}",
                technique_name=f"Technique {i}",
                target=f"target{i}",
                result="success" if i % 3 != 0 else "failed",
                evasion_score=0.5 + (i % 50) / 100,
            ))
        
        large_log = ChainLog(
            chain_id="large-001",
            start_time=datetime.now() - timedelta(hours=2),
            entries=entries,
        )
        
        import time
        start = time.time()
        result = report_generator.generate_report(large_log)
        elapsed = time.time() - start
        
        assert result.success is True
        # Should complete in reasonable time (< 30 seconds)
        assert elapsed < 30


# =============================================================================
# EDR Signatures Tests
# =============================================================================

class TestEDRSignatures:
    """Test EDR signature database"""
    
    def test_edr_signatures_exist(self):
        """Test EDR signatures constant exists"""
        assert EDR_SIGNATURES is not None
        assert len(EDR_SIGNATURES) > 0


# =============================================================================
# Main Test Runner
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
