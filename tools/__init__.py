"""
MONOLITH Tools Package
=====================
Advanced tools for red team operations

Modules:
- report_generator: Ultimate report generation with MITRE mapping
- vr_viz: VR/AR Red Team Visualization with Unity integration
"""

from typing import TYPE_CHECKING

# Lazy imports to avoid circular dependencies
if TYPE_CHECKING:
    from tools.report_generator import ReportGenerator
    from tools.vr_viz import VRViz

__all__ = [
    'ReportGenerator',
    'VRViz'
]
