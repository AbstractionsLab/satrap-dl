"""
Suspicious Login Analyzer

Analyzes IOCs related to suspicious login attempts with real-time
threat intelligence from MISP if available.
"""

from pydantic import BaseModel
from datetime import datetime

from .registry import AnalyzerRegistry
from .scenario_analyzer import MISPCTIAnalyzer
from ..settings import AnalysisScenario


class SuspiciousLoginAlert(BaseModel):
    """
    Schema for alerts related to suspicious login threat scenarios.

    Attributes:
        username: The username used in the login attempt.
        target_host: IP of the login target.
        src_ips: List of IP addresses, origin of the login attempt.
        timestamp: ISO 8601 timestamp of the alert.
    """

    username: str
    target_host: str
    src_ips: list[str]
    timestamp: datetime


@AnalyzerRegistry.register
class SuspiciousLoginAnalyzer(MISPCTIAnalyzer):
    """
    Analyzer for suspicious login attempts.
    """

    alert_type = AnalysisScenario.SUSPICIOUS_LOGIN.value
    schema = SuspiciousLoginAlert
    case_headline = "Suspicious or unauthorized login attempts detected"

    def build_ioc_mapping(self, alert: SuspiciousLoginAlert) -> dict[str, list[str]]:
        """
        Map the login alert fields to the MISP attribute types to search for.

        Args:
            alert: Validated suspicious login alert data.

        Returns:
            Mapping of MISP attribute type to the values to look up.
        """
        return {
            "ip-src": alert.src_ips,
            "ip-dst": [alert.target_host],
            "target-user": [alert.username],
        }
