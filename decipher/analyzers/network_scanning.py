"""
Network Scanning Analyzer

Analyzes IOCs related to suspicious network/web scanning activity with
real-time threat intelligence from MISP if available.
"""

from pydantic import BaseModel
from datetime import datetime

from .registry import AnalyzerRegistry
from .scenario_analyzer import MISPCTIAnalyzer
from .mixins.misp_enrichment import (
    MISPEnrichmentError,
    UnavailableMISPClientError,
)
from ..settings import AnalysisScenario
from ..runtime_settings import RuntimeSettings


class NetworkScanningAlert(BaseModel):
    """
    Schema for alerts related to suspicious network/web scanning threat scenarios.

    Attributes:
        src_ip: IP address(es) of the source of the scanning activity.
        uri: The requested (probed) URI/path(s) at the target host.
        user_agents: Observed 'User-Agent' string(s) in the HTTP request.
        http_method: The HTTP method(s) requested.
        target_host: Name or IP[:port] of the scanned endpoint (context only; not an IOC).
        timestamp: ISO 8601 timestamp of the detected activity.
        detection_chain: Chronologically ordered (rule_id, rule_name) pairs that
            resulted in the alert being triggered.
    """

    src_ip: list[str]
    uri: list[str]
    user_agents: list[str]
    http_method: list[str] | None = None
    target_host: str | None = None
    timestamp: datetime | None = None
    detection_chain: list[tuple[int, str]] | None = None


@AnalyzerRegistry.register
class NetworkScanningAnalyzer(MISPCTIAnalyzer):
    """
    Analyzer for suspicious network/web scanning activity.
    """

    alert_type = AnalysisScenario.NETWORK_SCANNING.value
    schema = NetworkScanningAlert
    case_headline = "Suspicious network/web scanning activity detected"
    case_notes = (
        "The identified-scanners field is contextual only (known research or "
        "benign scanning sources) and does not reduce the severity score.",
    )
    core_ioc_types = {"ip-src"}
    min_att_per_ev = 2

    def build_ioc_mapping(self, alert: NetworkScanningAlert) -> dict[str, list[str]]:
        ioc_mapping = {
            "ip-src": alert.src_ip,
            "uri": alert.uri,
            "user-agent": alert.user_agents,
        }
        if alert.http_method:
            ioc_mapping["http-method"] = alert.http_method
        return ioc_mapping

    def misp_search_params(self, config: RuntimeSettings) -> dict:
        return {**config.misp_search, "enforce_warninglist": False}

    def extend_analysis(self, alert: NetworkScanningAlert, report: dict) -> None:
        """
        Identify known/benign scanning sources (warninglists, research-scanner
        objects) for analyst context.

        Args:
            alert: Validated network scanning alert data.
            report: Analysis report to record the analysis output in.
        """
        try:
            # report["identified-scanners"] = self.identify_known_scanners(alert.src_ip)
            known_scanners = self.identify_known_scanners(alert.src_ip)
            # WARNING: Temporary structure to support integration with RADAR
            # to be removed in the upcoming release
            report["identified-scanners"] =  [f"{k}: {v};" for k, v in known_scanners.items()]
        except (UnavailableMISPClientError, MISPEnrichmentError) as e:
            report["log_summary"].append(
                f"Error while searching for known scanners: {str(e)}"
            )

    def case_suppression_reason(self, severity: float, report: dict) -> str | None:
        """
        Skip case creation unless threat intelligence backs the alert: a zero
        score means no evidence to escalate (SRS-059).
        """
        if severity == 0 and not report.get("identified-scanners", {}):
            return "No case created: no threat intelligence found for the alert IOCs."
        return None
