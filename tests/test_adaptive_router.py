"""Test adaptive evasion router integration with beacon."""

import unittest
import sys
import os
from unittest.mock import Mock, patch

# Add paths
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evasion.adaptive_router import AdaptiveEvasionRouter


class TestAdaptiveRouter(unittest.TestCase):
    """Test SIEM-aware adaptive routing."""

    def setUp(self):
        self.router = AdaptiveEvasionRouter()

    def test_stealth_level_determination(self):
        """Test stealth level determination."""
        # Default paranoid (can't reach endpoint)
        level = self.router.determine_stealth_level(use_cache=False)
        self.assertIn(level, ["paranoid", "balanced", "aggressive"])

    def test_sleep_jitter_paranoid(self):
        """Test paranoid mode jitter (high variance)."""
        jitter_times = [
            self.router.calculate_sleep_jitter(10.0, "paranoid")
            for _ in range(10)
        ]
        # All should be 15-30 seconds (1.5-3.0x of 10)
        for t in jitter_times:
            self.assertGreaterEqual(t, 15.0)
            self.assertLessEqual(t, 30.1)

    def test_sleep_jitter_balanced(self):
        """Test balanced mode jitter (normal variance)."""
        jitter_times = [
            self.router.calculate_sleep_jitter(10.0, "balanced")
            for _ in range(10)
        ]
        # All should be 8-15 seconds (0.8-1.5x of 10)
        for t in jitter_times:
            self.assertGreaterEqual(t, 7.9)
            self.assertLessEqual(t, 15.1)

    def test_sleep_jitter_aggressive(self):
        """Test aggressive mode jitter (minimal variance)."""
        jitter_times = [
            self.router.calculate_sleep_jitter(10.0, "aggressive")
            for _ in range(10)
        ]
        # All should be 1-3 seconds (0.1-0.3x of 10)
        for t in jitter_times:
            self.assertGreaterEqual(t, 0.99)
            self.assertLessEqual(t, 3.01)

    def test_memory_protection_modes(self):
        """Test memory protection mode selection."""
        self.assertEqual(
            self.router.get_memory_protection_mode("paranoid"),
            "page_noaccess"
        )
        self.assertEqual(
            self.router.get_memory_protection_mode("balanced"),
            "page_guard"
        )
        self.assertEqual(
            self.router.get_memory_protection_mode("aggressive"),
            "none"
        )

    @patch('requests.get')
    def test_siem_health_analysis_degraded(self, mock_get):
        """Test analysis when SIEM is degraded."""
        # Mock response showing SIEM down
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "report": {
                "services": [
                    {"name": "rsyslog", "available": True, "active": False},
                ],
                "destinations": [
                    {"host": "siem.lab", "port": 514, "reachable": False},
                ],
                "signals": {
                    "issues": ["Service not active: rsyslog"],
                    "recent_config_changes": []
                }
            }
        }
        mock_get.return_value = mock_resp

        level = self.router.determine_stealth_level(use_cache=False)
        self.assertEqual(level, "aggressive")

    @patch('requests.get')
    def test_siem_health_analysis_healthy(self, mock_get):
        """Test analysis when SIEM is healthy."""
        # Mock response showing SIEM ok
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "report": {
                "services": [
                    {"name": "rsyslog", "available": True, "active": True},
                    {"name": "auditd", "available": True, "active": True},
                ],
                "destinations": [
                    {"host": "siem.lab", "port": 514, "reachable": True},
                ],
                "signals": {
                    "issues": [],
                    "recent_config_changes": []
                }
            }
        }
        mock_get.return_value = mock_resp

        level = self.router.determine_stealth_level(use_cache=False)
        self.assertEqual(level, "paranoid")


if __name__ == "__main__":
    unittest.main()
