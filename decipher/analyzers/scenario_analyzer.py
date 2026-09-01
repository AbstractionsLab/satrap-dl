"""
Generic analyzer scoring alert IOCs against MISP threat intelligence.

Holds the analysis logic shared by every scenario analyzer: runtime
configuration, MISP IOC search, severity scoring, and case creation. 
Concrete analyzers implement only the scenario-specific methods.
"""

from abc import abstractmethod

from pydantic import BaseModel

from .base import BaseAnalyzer, AnalysisResult
from .mixins.misp_enrichment import (
    MISPEnrichmentError,
    MISPEnrichmentMixin,
    UnavailableMISPClientError,
)
from ..scoringengine.datamodels import EventData, FinalScoreResult
from ..casemanagement.flowintel_connector import (
    CaseCreationError,
    create_case_for_scenario,
)
from ..settings import AnalysisScenario, FLOWINTEL_CASE_URL
from ..runtime_settings import RuntimeSettings, load_decipher_runtime_cfg
from ..commons.log_utils import get_logger
import decipher.scoringengine.misp_score as calculator

logger = get_logger(__name__)

SCORING_NOTE = (
    "Note: The score is determined by a formula that quantifies the severity "
    "of a threat and the degree of confidence on the assessment."
)
SCORING_NOTE_REFERENCE = (
    "See details in the documentation of DECIPHER's scoring engine."
)


class MISPCTIAnalyzer(BaseAnalyzer, MISPEnrichmentMixin):
    """
    Base analyzer for threat scenarios assessed with MISP threat intelligence.

    Subclasses must define `alert_type`, `schema`, `case_headline` and
    `build_ioc_mapping()`. The remaining methods only need to be
    overridden by scenarios that deviate from the default pipeline.

    Attributes:
        case_headline: Sentence describing the scenario in the case description.
        case_notes: Extra sentences appended to the scoring note of the case
            description, for scenario-specific caveats.
        core_ioc_types: MISP attribute types whose match makes a MISP event 
            to be scored in the scenario. None to accept a matched event regardless
            of the attribute types.
        min_att_per_ev: Minimun number of matched attributes an event must have to be
            included in the scoring. If None, this filter is ignored.
    """

    case_headline: str
    case_notes: tuple[str, ...] = ()
    core_ioc_types: set[str] | None = None
    min_att_per_ev: int | None = None

    # ------------------------------------------------------------------
    # Methods for concrete scenario analyzers
    # ------------------------------------------------------------------

    @abstractmethod
    def build_ioc_mapping(self, alert: BaseModel) -> dict[str, list[str]]:
        """
        Map the alert fields to the MISP attribute types to search for.

        Args:
            alert: Validated alert data matching this analyzer's schema.

        Returns:
            Mapping of MISP attribute type to the values to look up.
        """

    def misp_search_params(self, config: RuntimeSettings) -> dict:
        """
        Obtain the MISP search parameters set in the configuration file.
        Override to add search filter parameters not included or fix values
        for a specific scenario.

        Args:
            config: Runtime configuration loaded for the current analysis.

        Returns:
            Search parameters to be passed to the MISP IOC search.
        """
        return dict(config.misp_search)

    def extend_analysis(self, alert: BaseModel, report: dict) -> None:
        """
        Add scenario-specific analysis steps and input to the analysis report.

        Args:
            alert: Validated alert data matching this analyzer's schema.
            report: Analysis report to be modified.
        """

    def case_suppression_reason(self, severity: float, report: dict) -> str | None:
        """
        Decide whether case creation must be skipped for this analysis.

        Args:
            severity: Severity score computed for the alert.
            report: Analysis report built so far.

        Returns:
            Message explaining why no case is created, or None to create one.
        """
        return None

    # ------------------------------------------------------------------
    # Core MISP-informed analysis logic
    # ------------------------------------------------------------------

    def analyze(self, alert: BaseModel) -> AnalysisResult:
        """
        Analyze the alert against MISP threat intelligence:
        1. Search for threat intelligence in MISP (IOC lookups + event correlation)
        2. Optionally, add scenario-specific logic and input to the report
        3. Calculate severity score based on findings and MISP context
        4. Create case with the analysis result if enabled by configuration.

        Args:
            alert: Validated alert data matching this analyzer's schema.

        Returns:
            Analysis result including created case id, severity, and details justifying the severity score.
        """
        # ensure to run with up to date config values
        config = load_decipher_runtime_cfg()
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

        analysis_report["misp_available"] = "True"
        misp_event_data = self.retrieve_misp_cti(alert, config, analysis_report)

        self.extend_analysis(alert, analysis_report)

        # Calculate alert severity score
        scoring_result = calculator.score_events(misp_event_data)
        logger.debug(f"Scoring result: {scoring_result}")
        analysis_report["score_breakdown"] = scoring_result.event_results

        created_case = self._create_case(
            alert, scoring_result, analysis_report, config
        )

        return AnalysisResult(
            analyzed_scenario=self.alert_type,
            severity=scoring_result.score,
            report=analysis_report,
            created_case=created_case,
        )

    def retrieve_misp_cti(
        self,
        alert: BaseModel,
        config: RuntimeSettings,
        analysis_report: dict,
    ) -> list[EventData]:
        """
        Retrieve events related to the IOCs from MISP and add execution information
        to the given analysis_report. The events are filtered by `core_ioc_types` 
        and `min_att_per_ev` if specified for the scenario.

        Override to modify the CTI retrieval analysis logic. Implementations are
        responsible for recording the outcome of the lookup in the report: set
        `misp_available` and `misp_events_found`, and append any lookup error
        to `log_summary`.

        Args:
            alert: Validated alert data matching this analyzer's schema.
            config: Runtime configuration loaded for the current analysis.
            analysis_report: Analysis report to record the lookup outcome in.

        Returns:
            MISP events matching the alert IOCs, empty if none were found or
            the lookup failed.
        """
        try:
            misp_event_data = self.search_iocs_in_misp(
                self.build_ioc_mapping(alert),
                extra_search_params=self.misp_search_params(config),
                core_ioc_types=self.core_ioc_types,
                min_att_per_ev=self.min_att_per_ev
            )
            analysis_report["misp_events_found"] = [e.id for e in misp_event_data]
        except UnavailableMISPClientError as e:
            analysis_report["misp_available"] = "False"
            analysis_report["log_summary"].append(str(e))
            misp_event_data = []
        except MISPEnrichmentError as e:
            analysis_report["log_summary"].append(str(e))
            misp_event_data = []

        return misp_event_data

    def _create_case(
        self,
        alert: BaseModel,
        score_res: FinalScoreResult,
        report: dict,
        config: RuntimeSettings,
    ) -> dict:
        """
        Create a Flowintel case for the analysis, if enabled and warranted.

        Args:
            alert: Validated alert data matching this analyzer's schema.
            score_res: Result of scoring the MISP events found for the alert.
            report: Analysis report, updated in place with the outcome.
            config: Runtime configuration loaded for the current analysis.

        Returns:
            Identifier and link of the created case, or zero id and empty link
            if no case was created.
        """
        if not config.enable_case_creation:
            logger.info("Case creation disabled in configuration (skipping...)")
            report["log_summary"].append(
                "Case creation for analysis disabled in configuration."
            )
            return {"id": 0, "link": ""}

        suppression_reason = self.case_suppression_reason(score_res.score, report)
        if suppression_reason:
            logger.info(f"Skipping case creation: {suppression_reason}")
            report["log_summary"].append(suppression_reason)
            return {"id": 0, "link": ""}

        try:
            associated_case = create_case_for_scenario(
                AnalysisScenario(self.alert_type),
                self._build_case_description(alert, score_res, report),
                score_res.score,
            )
        except CaseCreationError as err:
            logger.error(str(err))
            report["log_summary"].append(
                "Flowintel case creation failed. See logs for details."
            )
            return {"id": 0, "link": ""}

        return {
            "id": associated_case,
            "link": f"{FLOWINTEL_CASE_URL}/{associated_case}",
        }


    def _build_case_description(
        self,
        alert_data: BaseModel,
        score_res: FinalScoreResult,
        report: dict,
    ) -> str:
        """
        Build case description from decision data.

        Args:
            alert_data: Validated alert data matching this analyzer's schema.
            score_res: Result of scoring the MISP events found for the alert.
            report: Analysis report built for the alert.

        Returns:
            Analyst-readable description of the analysis.
        """
        desc = "\n\n".join(
            [
                f"Scenario: {self.case_headline}",
                f"Alert information:\n {alert_data}",
                f"Severity score: {score_res.score:.4f}",
                f"Score breakdown:\n {score_res}",
                "Additional information:\n",
            ]
        )

        for k, v in report.items():
            if k != "score_breakdown":
                desc += f"{k}: {v}\n"

        desc += "\n" + " ".join(
            [SCORING_NOTE, *self.case_notes, SCORING_NOTE_REFERENCE]
        )
        return desc
