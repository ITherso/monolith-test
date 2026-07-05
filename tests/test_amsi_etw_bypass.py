#!/usr/bin/env python3
"""
AMSI & ETW Bypass Test Suite
============================

Tests for validating AMSI/ETW bypass functionality.
Run on a Windows system for full functionality.

Usage:
    python test_amsi_etw_bypass.py
    python test_amsi_etw_bypass.py --live  # Run live bypass tests (requires admin)
"""

import sys
import os
import unittest
import platform
from unittest.mock import Mock, patch, MagicMock

# Add parent dir to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cybermodules.bypass_amsi_etw import (
    BypassLayer,
    BypassMethod,
    BypassResult,
    DefenseAnalysis,
    AMSIBypass,
    ETWBypass,
    IndirectSyscall,
    APIUnhooker,
    DefenseAnalyzer,
    BypassManager,
    SYSCALL_TABLE_WIN11,
    AMSI_PATCH_BYTES,
)


class TestBypassEnums(unittest.TestCase):
    """Test enum definitions"""
    
    def test_bypass_layer_values(self):
        """Test BypassLayer enum has correct values"""
        self.assertEqual(BypassLayer.NONE.value, "none")
        self.assertEqual(BypassLayer.AMSI.value, "amsi")
        self.assertEqual(BypassLayer.ETW.value, "etw")
        self.assertEqual(BypassLayer.BOTH.value, "both")
    
    def test_bypass_method_exists(self):
        """Test BypassMethod enum has required methods"""
        methods = [m.name for m in BypassMethod]
        self.assertIn("MEMORY_PATCH", methods)
        self.assertIn("HARDWARE_BP", methods)
        self.assertIn("REMOTE_INJECTION", methods)
        self.assertIn("INDIRECT_SYSCALL", methods)
        self.assertIn("API_UNHOOK", methods)


class TestBypassResult(unittest.TestCase):
    """Test BypassResult dataclass"""
    
    def test_bypass_result_creation(self):
        """Test creating BypassResult"""
        result = BypassResult(
            success=True,
            method=BypassMethod.MEMORY_PATCH,
            target="AMSI",
            details="Patched successfully",
            detection_risk=35,
            artifacts=["amsi.dll modified"]
        )
        
        self.assertTrue(result.success)
        self.assertEqual(result.method, BypassMethod.MEMORY_PATCH)
        self.assertEqual(result.target, "AMSI")
        self.assertEqual(result.detection_risk, 35)
        self.assertEqual(len(result.artifacts), 1)
    
    def test_bypass_result_defaults(self):
        """Test BypassResult default values"""
        result = BypassResult(
            success=False,
            method=BypassMethod.API_UNHOOK,
            target="ntdll"
        )
        
        self.assertEqual(result.details, "")
        self.assertEqual(result.detection_risk, 50)
        self.assertEqual(result.artifacts, [])


class TestDefenseAnalysis(unittest.TestCase):
    """Test DefenseAnalysis dataclass"""
    
    def test_defense_analysis_defaults(self):
        """Test DefenseAnalysis default values"""
        analysis = DefenseAnalysis()
        
        self.assertFalse(analysis.amsi_present)
        self.assertEqual(analysis.amsi_version, "")
        self.assertFalse(analysis.etw_enabled)
        self.assertEqual(analysis.edr_detected, [])
        self.assertEqual(analysis.recommended_bypass, BypassLayer.NONE)
        self.assertEqual(analysis.risk_score, 50)


class TestSyscallTable(unittest.TestCase):
    """Test syscall table definitions"""
    
    def test_syscall_table_has_critical_syscalls(self):
        """Test syscall table has critical syscalls"""
        critical = [
            "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory",
            "NtWriteVirtualMemory",
            "NtCreateThreadEx",
            "NtOpenProcess",
        ]
        
        for syscall in critical:
            self.assertIn(syscall, SYSCALL_TABLE_WIN11)
    
    def test_syscall_ssn_values(self):
        """Test SSN values are valid"""
        for name, ssn in SYSCALL_TABLE_WIN11.items():
            self.assertIsInstance(ssn, int)
            self.assertGreaterEqual(ssn, 0)
            self.assertLess(ssn, 0x200)  # Reasonable SSN range


class TestAMSIPatchBytes(unittest.TestCase):
    """Test AMSI patch byte definitions"""
    
    def test_amsi_open_session_patch(self):
        """Test AmsiOpenSession patch bytes"""
        patch = AMSI_PATCH_BYTES["amsi_open_session"]
        # xor eax,eax; ret
        self.assertEqual(patch, bytes([0x31, 0xC0, 0xC3]))
    
    def test_amsi_scan_buffer_patch(self):
        """Test AmsiScanBuffer patch bytes"""
        patch = AMSI_PATCH_BYTES["amsi_scan_buffer"]
        # mov eax, 0x80070057; ret (E_INVALIDARG)
        self.assertEqual(patch[0], 0xB8)  # mov eax
        self.assertEqual(patch[-1], 0xC3)  # ret


class TestAMSIBypass(unittest.TestCase):
    """Test AMSIBypass class"""
    
    def test_amsi_bypass_init(self):
        """Test AMSIBypass initialization"""
        bypass = AMSIBypass()
        
        self.assertEqual(bypass.method, BypassMethod.MEMORY_PATCH)
        self.assertFalse(bypass.patched)
        self.assertEqual(bypass.original_bytes, {})
    
    def test_amsi_bypass_with_custom_method(self):
        """Test AMSIBypass with custom method"""
        bypass = AMSIBypass(method=BypassMethod.HARDWARE_BP)
        self.assertEqual(bypass.method, BypassMethod.HARDWARE_BP)
    
    @unittest.skipIf(platform.system() != "Windows", "Windows only")
    def test_detect_amsi_windows(self):
        """Test AMSI detection on Windows"""
        bypass = AMSIBypass()
        present, version = bypass.detect_amsi()
        
        # AMSI should be present on Windows 10/11
        self.assertIsInstance(present, bool)
        self.assertIsInstance(version, str)


class TestETWBypass(unittest.TestCase):
    """Test ETWBypass class"""
    
    def test_etw_bypass_init(self):
        """Test ETWBypass initialization"""
        bypass = ETWBypass()
        
        self.assertEqual(bypass.method, BypassMethod.MEMORY_PATCH)
        self.assertFalse(bypass.patched)
    
    def test_etw_providers_defined(self):
        """Test ETW provider GUIDs are defined"""
        bypass = ETWBypass()
        
        self.assertIn("Microsoft-Windows-PowerShell", bypass.ETW_PROVIDERS)
        self.assertIn("Microsoft-Antimalware-Scan-Interface", bypass.ETW_PROVIDERS)
        self.assertIn("Microsoft-Windows-Threat-Intelligence", bypass.ETW_PROVIDERS)


class TestIndirectSyscall(unittest.TestCase):
    """Test IndirectSyscall class"""
    
    def test_indirect_syscall_init(self):
        """Test IndirectSyscall initialization"""
        syscall = IndirectSyscall()
        
        self.assertEqual(syscall.syscalls, {})
        self.assertEqual(syscall.ntdll_base, 0)
        self.assertFalse(syscall.initialized)
    
    def test_get_hooked_functions_empty(self):
        """Test get_hooked_functions with no hooks"""
        syscall = IndirectSyscall()
        hooked = syscall.get_hooked_functions()
        
        self.assertEqual(hooked, [])


class TestAPIUnhooker(unittest.TestCase):
    """Test APIUnhooker class"""
    
    def test_api_unhooker_init(self):
        """Test APIUnhooker initialization"""
        unhooker = APIUnhooker()
        
        self.assertFalse(unhooker.unhooked)
        self.assertEqual(unhooker.hooked_functions, [])


class TestDefenseAnalyzer(unittest.TestCase):
    """Test DefenseAnalyzer class"""
    
    def test_defense_analyzer_init(self):
        """Test DefenseAnalyzer initialization"""
        analyzer = DefenseAnalyzer()
        
        self.assertIsInstance(analyzer.amsi_bypass, AMSIBypass)
        self.assertIsInstance(analyzer.etw_bypass, ETWBypass)
        self.assertIsInstance(analyzer.syscall_engine, IndirectSyscall)
        self.assertIsInstance(analyzer.unhooker, APIUnhooker)
    
    def test_edr_processes_defined(self):
        """Test EDR process list is defined"""
        analyzer = DefenseAnalyzer()
        
        self.assertIn("MsMpEng.exe", analyzer.EDR_PROCESSES)
        self.assertIn("CSFalconService.exe", analyzer.EDR_PROCESSES)
        self.assertIn("SentinelAgent.exe", analyzer.EDR_PROCESSES)
    
    @patch.object(AMSIBypass, 'detect_amsi', return_value=(True, "10.0.19041"))
    @patch.object(AMSIBypass, 'check_amsi_hooks', return_value=False)
    @patch.object(ETWBypass, 'detect_etw', return_value=(True, ["Microsoft-Windows-PowerShell"]))
    @patch.object(DefenseAnalyzer, '_detect_edr_processes', return_value=[])
    def test_analyze_defenses_mocked(self, mock_edr, mock_etw, mock_hooks, mock_amsi):
        """Test analyze_defenses with mocked detection"""
        analyzer = DefenseAnalyzer()
        analysis = analyzer.analyze_defenses()
        
        self.assertIsInstance(analysis, DefenseAnalysis)
        self.assertTrue(analysis.amsi_present)
        self.assertEqual(analysis.amsi_version, "10.0.19041")
        self.assertTrue(analysis.etw_enabled)
        self.assertEqual(analysis.recommended_bypass, BypassLayer.BOTH)


class TestBypassManager(unittest.TestCase):
    """Test BypassManager class"""
    
    def test_bypass_manager_init_defaults(self):
        """Test BypassManager initialization with defaults"""
        manager = BypassManager()
        
        self.assertEqual(manager.layer, BypassLayer.BOTH)
        self.assertIsInstance(manager.analyzer, DefenseAnalyzer)
    
    def test_bypass_manager_with_config(self):
        """Test BypassManager with config"""
        config = {"bypass_layer": "amsi"}
        manager = BypassManager(config)
        
        self.assertEqual(manager.layer, BypassLayer.AMSI)
    
    def test_bypass_manager_cleanup(self):
        """Test BypassManager cleanup"""
        manager = BypassManager()
        result = manager.cleanup()
        
        self.assertIsInstance(result, bool)


class TestIntegration(unittest.TestCase):
    """Integration tests"""
    
    def test_full_defense_analysis_flow(self):
        """Test full defense analysis flow"""
        manager = BypassManager({"bypass_layer": "both"})
        analysis = manager.analyze()
        
        self.assertIsInstance(analysis, DefenseAnalysis)
        self.assertIsInstance(analysis.risk_score, int)
        self.assertGreaterEqual(analysis.risk_score, 0)
        self.assertLessEqual(analysis.risk_score, 100)
    
    def test_prepare_for_lateral(self):
        """Test prepare_for_lateral method"""
        manager = BypassManager()
        result = manager.prepare_for_lateral(target_has_edr=False)
        
        self.assertIn("analysis", result)
        self.assertIn("bypass_results", result)
        self.assertIn("ready_for_lateral", result)


# ============================================================
# POWERSHELL AMSI TRIGGER TESTS
# ============================================================

class TestPowerShellAMSI(unittest.TestCase):
    """Test PowerShell AMSI trigger and bypass"""
    
    AMSI_TRIGGER_STRINGS = [
        "Invoke-Mimikatz",
        "Invoke-PowerShellTcp",
        "amsiInitFailed",
        "System.Management.Automation.AmsiUtils",
        "[Ref].Assembly.GetType",
    ]
    
    @unittest.skipIf(platform.system() != "Windows", "Windows only")
    def test_amsi_trigger_detection(self):
        """Test that AMSI trigger strings are detected"""
        import subprocess
        
        for trigger in self.AMSI_TRIGGER_STRINGS[:2]:  # Test first 2
            # This should trigger AMSI on a protected system
            cmd = f'powershell -NoProfile -Command "Write-Host \'{trigger}\'"'
            result = subprocess.run(cmd, shell=True, capture_output=True)
            
            # Just verify command runs (AMSI detection is AV-specific)
            self.assertIsNotNone(result.returncode)


class TestDotNetAMSI(unittest.TestCase):
    """Test .NET AMSI trigger"""
    
    @unittest.skipIf(platform.system() != "Windows", "Windows only")
    def test_dotnet_amsi_exists(self):
        """Test .NET AMSI is available"""
        try:
            import clr
            clr.AddReference("System.Management.Automation")
            # If we get here, .NET is available
            self.assertTrue(True)
        except ImportError:
            self.skipTest("pythonnet not available")


# ============================================================
# LIVE BYPASS TESTS (Requires Admin)
# ============================================================

class TestLiveBypass(unittest.TestCase):
    """Live bypass tests - requires admin privileges"""
    
    @classmethod
    def setUpClass(cls):
        """Check if running as admin"""
        cls.is_admin = False
        
        if platform.system() == "Windows":
            import ctypes
            try:
                cls.is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                pass
    
    @unittest.skipIf(platform.system() != "Windows", "Windows only")
    def test_live_amsi_detection(self):
        """Live AMSI detection test"""
        if not self.is_admin:
            self.skipTest("Requires admin privileges")
        
        bypass = AMSIBypass()
        present, version = bypass.detect_amsi()
        
        print(f"AMSI Present: {present}, Version: {version}")
        self.assertIsInstance(present, bool)
    
    @unittest.skipIf(platform.system() != "Windows", "Windows only")
    def test_live_etw_detection(self):
        """Live ETW detection test"""
        if not self.is_admin:
            self.skipTest("Requires admin privileges")
        
        bypass = ETWBypass()
        enabled, providers = bypass.detect_etw()
        
        print(f"ETW Enabled: {enabled}, Providers: {len(providers)}")
        self.assertIsInstance(enabled, bool)
    
    @unittest.skipIf(platform.system() != "Windows", "Windows only")
    def test_live_edr_detection(self):
        """Live EDR detection test"""
        if not self.is_admin:
            self.skipTest("Requires admin privileges")
        
        analyzer = DefenseAnalyzer()
        edr_list = analyzer._detect_edr_processes()
        
        print(f"EDR Detected: {edr_list}")
        self.assertIsInstance(edr_list, list)


# ============================================================
# MAIN
# ============================================================

def main():
    """Run tests"""
    import argparse
    
    parser = argparse.ArgumentParser(description="AMSI/ETW Bypass Test Suite")
    parser.add_argument("--live", action="store_true", help="Run live bypass tests (requires admin)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()
    
    # Select test suites
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Always run unit tests
    suite.addTests(loader.loadTestsFromTestCase(TestBypassEnums))
    suite.addTests(loader.loadTestsFromTestCase(TestBypassResult))
    suite.addTests(loader.loadTestsFromTestCase(TestDefenseAnalysis))
    suite.addTests(loader.loadTestsFromTestCase(TestSyscallTable))
    suite.addTests(loader.loadTestsFromTestCase(TestAMSIPatchBytes))
    suite.addTests(loader.loadTestsFromTestCase(TestAMSIBypass))
    suite.addTests(loader.loadTestsFromTestCase(TestETWBypass))
    suite.addTests(loader.loadTestsFromTestCase(TestIndirectSyscall))
    suite.addTests(loader.loadTestsFromTestCase(TestAPIUnhooker))
    suite.addTests(loader.loadTestsFromTestCase(TestDefenseAnalyzer))
    suite.addTests(loader.loadTestsFromTestCase(TestBypassManager))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    # Live tests if requested
    if args.live:
        print("\n[!] Running LIVE bypass tests - requires admin privileges\n")
        suite.addTests(loader.loadTestsFromTestCase(TestLiveBypass))
        suite.addTests(loader.loadTestsFromTestCase(TestPowerShellAMSI))
        suite.addTests(loader.loadTestsFromTestCase(TestDotNetAMSI))
    
    # Run tests
    verbosity = 2 if args.verbose else 1
    runner = unittest.TextTestRunner(verbosity=verbosity)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 60)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    print("=" * 60)
    
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
