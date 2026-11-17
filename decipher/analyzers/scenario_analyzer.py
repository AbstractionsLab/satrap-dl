"""
Generic analyzer scoring alert IOCs against MISP threat intelligence.

Holds the analysis logic shared by every scenario analyzer: runtime
configuration, MISP IOC search, severity scoring, and case creation. 
Concrete analyzers implement only the scenario-specific methods.
"""

from abc import abstractmethod

from pydantic import BaseModel

from .base import BaseAnalyzer, AnalysisResult
from .mixins.misp_enrichment import MISPEnrichmentError, MISPEnrichmentMixin
from ..commons.misp_connector import UnavailableMISPClientError
from ..models import CTILookupResult
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

# Ordered tuple defining the result to be reported (highest to lowest precedence (ARC-017))
# when there is more that one outcome in the execution of the MISP queries set
CTI_LOOKUP_RESULT_PRECEDENCE = (
    CTILookupResult.MISP_DISABLED,
    CTILookupResult.MISP_UNAVAILABLE,
    CTILookupResult.MISP_LOOKUP_ERROR,
    CTILookupResult.CTI_FOUND,
    CTILookupResult.NO_CTI_FOUND,
)


def get_cti_lookup_err_code(error: UnavailableMISPClientError | MISPEnrichmentError) -> CTILookupResult:
    """
    Map a MISP enrichment error to the CTI lookup result it stands for.

    Args:
        error: Error raised by a MISP query.

    Returns:
        MISP_UNAVAILABLE for an unavailable client, MISP_LOOKUP_ERROR otherwise.
    """
    if isinstance(error, UnavailableMISPClientError):
        return CTILookupResult.MISP_UNAVAILABLE
    return CTILookupResult.MISP_LOOKUP_ERROR


def misp_available_entry(lookup_result: CTILookupResult) -> str:
    """
    Derive the deprecated `misp_available` report entry from the CTI lookup result.

    Args:
        lookup_result: CTI lookup result of the analysis.

    Returns:
        "False" if the analysis could not use MISP (disabled or unavailable),
        "True" otherwise.
    """
    unusable = lookup_result in (CTILookupResult.MISP_DISABLED, CTILookupResult.MISP_UNAVAILABLE)
    return str(not unusable)


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

        Propagate MISP errors since the analysis pipeline reports them 
        in the `log_summary` and in the CTI lookup result.

        Args:
            alert: Validated alert data matching this analyzer's schema.
            report: Analysis report to be modified.

        Raises:
            UnavailableMISPClientError: If a MISP connection cannot be established.
            MISPEnrichmentError: If a MISP lookup fails.
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
                cti_lookup_result=CTILookupResult.MISP_DISABLED,
                severity=0,
                report={
                    "misp_available": misp_available_entry(CTILookupResult.MISP_DISABLED),
                    "log_summary": ["MISP IOC search disabled in configuration"],
                },
            )

        misp_event_data, lookup_result = self.retrieve_misp_cti(alert, config, analysis_report)
        lookup_results = [lookup_result]

        if lookup_result != CTILookupResult.MISP_UNAVAILABLE:
            try:
                self.extend_analysis(alert, analysis_report)
            except (UnavailableMISPClientError, MISPEnrichmentError) as e:
                analysis_report["log_summary"].append(str(e))
                lookup_results.append(get_cti_lookup_err_code(e))

        # extract the result with the highest precedence (smallest position in the `key` tuple)
        cti_lookup_result = min(lookup_results, key=CTI_LOOKUP_RESULT_PRECEDENCE.index)
        analysis_report["misp_available"] = misp_available_entry(cti_lookup_result)

        # Calculate alert severity score
        scoring_result = calculator.score_events(misp_event_data)
        logger.debug(f"Scoring result: {scoring_result}")
        analysis_report["score_breakdown"] = scoring_result.event_results

        created_case = self._create_case(
            alert, scoring_result, analysis_report, config
        )

        return AnalysisResult(
            analyzed_scenario=self.alert_type,
            cti_lookup_result=cti_lookup_result,
            severity=scoring_result.score,
            report=analysis_report,
            created_case=created_case,
        )

    def retrieve_misp_cti(
        self,
        alert: BaseModel,
        config: RuntimeSettings,
        analysis_report: dict,
    ) -> tuple[list[EventData], CTILookupResult]:
        """
        Retrieve events related to the IOCs from MISP and add details to the
        given analysis_report. The events are filtered by `core_ioc_types`
        and `min_att_per_ev` if specified for the scenario.

        Override to modify the CTI retrieval analysis logic. Implementations are
        responsible for recording the outcome of the lookup in the report: set
        `misp_events_found` and `misp_failed_lookups`, and append any lookup error
        to `log_summary`.

        Args:
            alert: Validated alert data matching this analyzer's schema.
            config: Runtime configuration loaded for the current analysis.
            analysis_report: Analysis report to record the lookup outcome in.

        Returns:
            MISP events matching the alert IOCs (empty if none were found or
            MISP could not be queried) and the CTI lookup outcome code. 
            When search of only some IOC types failed, the events found by the other 
            searches are returned along with MISP_LOOKUP_ERROR status.
        """
        try:
            search_result = self.search_iocs_in_misp(
                self.build_ioc_mapping(alert),
                extra_search_params=self.misp_search_params(config),
                core_ioc_types=self.core_ioc_types,
                min_att_per_ev=self.min_att_per_ev
            )
        except (UnavailableMISPClientError, MISPEnrichmentError) as e:
            analysis_report["log_summary"].append(str(e))
            return [], get_cti_lookup_err_code(e)

        analysis_report["misp_events_found"] = [e.id for e in search_result.events]
        analysis_report["misp_failed_lookups"] = list(search_result.failed_types)

        if search_result.failed_types:
            analysis_report["log_summary"].append(
                f"MISP search failed for attribute types: {', '.join(search_result.failed_types)}. See logs for details."
            )
            return search_result.events, CTILookupResult.MISP_LOOKUP_ERROR
        if search_result.events:
            return search_result.events, CTILookupResult.CTI_FOUND
        return [], CTILookupResult.NO_CTI_FOUND

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
