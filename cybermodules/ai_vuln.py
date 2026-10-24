"""Legacy API for offline, rule-based vulnerability review.

Normal cybermodules package imports retain the host safety stop. The standalone
analysis engine lives in cyberapp.vulnerability_analysis and performs no probing.
"""

import logging

from cyberapp.vulnerability_analysis import (
    OfflineVulnerabilityAnalyzer,
    PredictedVulnerability,
    RiskAssessment,
    RiskAssessmentEngine,
    RiskLevel,
    Technology,
    TechnologyRecognizer,
    TechnologyType,
    VulnerabilityCategory,
    VulnerabilityPredictor,
)
from cyberapp.vulnerability_store import (
    get_vulnerability_report,
    save_vulnerability_report,
)

__all__ = [
    "AIVulnerabilityPredictor",
    "PredictedVulnerability",
    "RiskAssessment",
    "RiskAssessmentEngine",
    "RiskLevel",
    "Technology",
    "TechnologyRecognizer",
    "TechnologyType",
    "VulnerabilityCategory",
    "VulnerabilityPredictor",
    "run_ai_vulnerability_analysis",
    "get_ai_vuln_report",
]
logger = logging.getLogger(__name__)


class AIVulnerabilityPredictor(OfflineVulnerabilityAnalyzer):
    """Retain the legacy class/API while keeping inference separate from storage."""

    def __init__(self, scan_id: int, *, connection_factory=None):
        super().__init__(scan_id)
        self.connection_factory = connection_factory

    def log(self, message: str, level: str = "INFO"):
        logger.log(getattr(logging, level, logging.INFO), "%s", message)

    def analyze(
        self,
        headers=None,
        html="",
        cookies=None,
        existing_vulns=None,
        *,
        persist=True,
        technologies=None,
        response_scheme=None,
    ):
        if type(persist) is not bool:
            raise ValueError("persist must be a boolean")
        report = super().analyze(
            headers,
            html,
            cookies,
            existing_vulns,
            technologies=technologies,
            response_scheme=response_scheme,
        )
        report["persistence"] = {"requested": persist, "saved": persist}
        if persist:
            # A storage failure propagates; it is never reported as saved.
            save_vulnerability_report(self.scan_id, report, self.connection_factory)
        return report

    def get_prediction_stats(self, scan_id=None):
        target = self.scan_id if scan_id is None else scan_id
        report = get_vulnerability_report(target, self.connection_factory)
        if report is None:
            return {
                "scan_id": target,
                "categories": {},
                "severities": {},
                "total_predictions": 0,
                "average_ml_confidence": 0.0,
                "trained_model": False,
            }
        return report.get("statistics", {})


def run_ai_vulnerability_analysis(
    scan_id,
    headers,
    html,
    cookies,
    existing_vulns=None,
    *,
    persist=True,
    technologies=None,
    response_scheme=None,
    connection_factory=None,
):
    return AIVulnerabilityPredictor(
        scan_id, connection_factory=connection_factory
    ).analyze(
        headers,
        html,
        cookies,
        existing_vulns,
        persist=persist,
        technologies=technologies,
        response_scheme=response_scheme,
    )


def get_ai_vuln_report(scan_id, *, connection_factory=None):
    report = get_vulnerability_report(scan_id, connection_factory)
    return (
        report
        if report is not None
        else {"scan_id": scan_id, "error": "report_not_found"}
    )
