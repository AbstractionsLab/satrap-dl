"""
Suspicious Login Analyzer

Analyzes IOCs related to suspicious login attempts with real-time
threat intelligence from MISP if available.
"""

from pydantic import BaseModel
from datetime import datetime

from .base import BaseAnalyzer, AnalysisResult
from .registry import AnalyzerRegistry
from .mixins.misp_enrichment import (
    MISPEnrichmentError,
    MISPEnrichmentMixin,
    UnavailableMISPClientError,
)
from ..scoringengine.datamodels import FinalScoreResult
from ..casemanagement.flowintel_connector import (
    CaseCreationError,
    create_case_for_scenario,
)
from ..settings import AnalysisScenario, FLOWINTEL_CASE_URL
from ..runtime_settings import load_decipher_runtime_cfg
from ..commons.log_utils import get_logger
import decipher.scoringengine.misp_score as calculator

logger = get_logger(__name__)


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
class SuspiciousLoginAnalyzer(BaseAnalyzer, MISPEnrichmentMixin):
    """
    Analyzer for suspicious login attempts.
    """

    alert_type = AnalysisScenario.SUSPICIOUS_LOGIN.value
    schema = SuspiciousLoginAlert

    def analyze(self, alert: SuspiciousLoginAlert) -> AnalysisResult:
        """
        Analyze information on suspicious login attempts:
        1. Search for threat intelligence in MISP (IOC lookups + event correlation)
        2. Calculate severity score based on findings and MISP context
        3. Create case with the analysis result if enabled by configuration.

        Args:
            alert: Validated suspicious login alert data.

        Returns:
            Analysis result including created case id, severity, and details justifying the severity score.
        """
        config = (
            load_decipher_runtime_cfg()
        )  # ensure to run with up to date config values
        analysis_report = {"log_summary": []}

        if not config.enable_misp_search:
            return AnalysisResult(
                analyzed_scenario=self.alert_type,
                severity=0,
                report={
                    "misp_available": "False",
                    "log_summary": ["MISP IOC search disabled in configuration"],
                },
            )

        # Search for IOCs and related events in MISP
        analysis_report["misp_available"] = "True"
        try:
            misp_event_data = self.search_iocs_in_misp(
                {
                    "ip-src": alert.src_ips,
                    "ip-dst": [alert.target_host],
                    "target-user": [alert.username]
                },
                extra_search_params=config.misp_search,
            )
            analysis_report["misp_events_found"] = [e.id for e in misp_event_data]
        except UnavailableMISPClientError as e:
            analysis_report["misp_available"] = "False"
            analysis_report["log_summary"].append(str(e))
            misp_event_data = []
        except MISPEnrichmentError as e:
            analysis_report["log_summary"].append(str(e))
            misp_event_data = []

        # Calculate alert severity score
        scoring_result = calculator.score_events(misp_event_data)
        logger.debug(f"Scoring result: {scoring_result}")
        analysis_report["score_breakdown"] = scoring_result.event_results

        analysis = AnalysisResult(
            analyzed_scenario=self.alert_type,
            severity=scoring_result.score,
            report=analysis_report,
        )

        # Create case if enabled
        if config.enable_case_creation:
            try:
                associated_case = create_case_for_scenario(
                    AnalysisScenario.SUSPICIOUS_LOGIN,
                    self._build_case_description(alert, scoring_result, analysis),
                    analysis.severity,
                )
                analysis.created_case["id"] = associated_case
                analysis.created_case["link"] = (
                    f"{FLOWINTEL_CASE_URL}/{associated_case}"
                )
            except CaseCreationError as err:
                logger.error(str(err))
                analysis_report["log_summary"].append(
                    "Flowintel case creation failed. See logs for details."
                )
        else:
            logger.info("Case creation disabled in configuration (skipping...)")
            analysis_report["log_summary"].append(
                "Case creation for analysis disabled in configuration."
            )

        return analysis

    def _build_case_description(
        self,
        alert_data: SuspiciousLoginAlert,
        score_res: FinalScoreResult,
        analysis: AnalysisResult,
    ):
        """Build case description from decision data."""
        desc = "\n\n".join(
            [
                f"Scenario: Suspicious or unauthorized login attempts detected",
                f"Alert information:\n {alert_data}",
                f"Severity score: {score_res.score:.4f}",
                f"Score breakdown:\n {score_res}",
                f"Additional information:\n",
            ]
        )

        for k, v in analysis.report.items():
            if k != "score_breakdown":
                desc += f"{k}: {v}\n"

        desc += (
            "\nNote: The score is determined by a formula that quantifies the "
            "severity of a threat and the degree of confidence on the assessment. "
            "See details in the documentation of DECIPHER's scoring engine."
        )
        return desc
