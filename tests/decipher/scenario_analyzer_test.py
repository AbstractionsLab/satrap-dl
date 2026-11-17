"""
Unit tests for the core MISP CTI analyzer.
"""

import unittest

from pydantic import BaseModel

from decipher.analyzers.mixins.misp_enrichment import MISPEnrichmentError
from decipher.analyzers.scenario_analyzer import (
    MISPCTIAnalyzer,
)
from decipher.casemanagement.flowintel_connector import CaseCreationError
from decipher.commons.misp_connector import BulkSearchResult, UnavailableMISPClientError
from decipher.models import AnalysisResult, CTILookupResult
from decipher.runtime_settings import RuntimeSettings
from decipher.settings import AnalysisScenario, FLOWINTEL_CASE_URL
from tests.decipher.testing_utils import (
    AnalyzerPipelineMixin,
    fake_event
)


class _StubAlert(BaseModel):
    """Minimal alert schema for exercising the inherited pipeline."""

    value: str


class _StubAnalyzer(MISPCTIAnalyzer):
    """
    Analyzer implementing only the mandatory extension point.

    The stubs are deliberately not registered with AnalyzerRegistry: it rejects
    a duplicate alert_type, and the API tests assert the set of listed analyzers.
    """

    # A real scenario value is required: _create_case builds
    # AnalysisScenario(self.alert_type) before create_case_for_scenario is
    # reached, so a made-up identifier raises even when that function is patched.
    alert_type = AnalysisScenario.SUSPICIOUS_LOGIN.value
    schema = _StubAlert
    case_headline = "Stub scenario for pipeline tests"

    def build_ioc_mapping(self, alert: _StubAlert) -> dict[str, list[str]]:
        return {"ip-src": [alert.value]}


class _HookedStubAnalyzer(_StubAnalyzer):
    """Analyzer overriding every optional method, to check that they are correctly called."""

    case_notes = ("Stub caveat.",)

    def misp_search_params(self, config: RuntimeSettings) -> dict:
        return {**config.misp_search, "stub_param": True}

    def extend_analysis(self, alert: _StubAlert, report: dict) -> None:
        # Records that the hook ran, and that it ran before the scoring step.
        report["stub-extension"] = "score_breakdown" not in report

    def case_suppression_reason(self, severity: float, report: dict) -> str | None:
        return "Stub suppression." if severity == 0 else None


_ALERT = _StubAlert(value="203.0.113.42")


class TestMISPSearchDisabled(AnalyzerPipelineMixin, unittest.TestCase):
    """Tests for the early return when MISP search is disabled."""

    def build_analyzer(self):
        return _HookedStubAnalyzer()

    def setUp(self):
        super().setUp()
        self.config.enable_misp_search = False

    def test_analysis_stops_before_the_misp_lookup(self):
        """No IOC search is issued, nothing is scored, and the reason is reported."""
        result = self.analyzer.analyze(_ALERT)

        self.assertEqual(result.severity, 0)
        self.assertEqual(result.cti_lookup_result, CTILookupResult.MISP_DISABLED)
        self.assertEqual(result.report["misp_available"], "False")
        self.assertIn(
            "MISP IOC search disabled in configuration", result.report["log_summary"]
        )
        self.misp_client.bulk_search_iocs.assert_not_called()
        self.mock_score.assert_not_called()

    def test_scenario_extension_is_skipped(self):
        """extend_analysis must not run, so no scenario field reaches the report."""
        result = self.analyzer.analyze(_ALERT)

        self.assertNotIn("stub-extension", result.report)


class TestCTIRetrieval(AnalyzerPipelineMixin, unittest.TestCase):
    """Tests for MISPCTIAnalyzer.retrieve_misp_cti."""

    def build_analyzer(self):
        return _StubAnalyzer()

    def test_ioc_mapping_and_search_params_reach_the_client(self):
        """The IOC mapping of the analyzer and the configured search params are passed on."""
        self.config.misp_search = {"event_timestamp": "7d", "limit": 10}

        self.analyzer.analyze(_ALERT)

        # get the 2 first positional args of the call
        ioc_mapping, search_params = self.misp_client.bulk_search_iocs.call_args[0][:2]
        self.assertEqual(ioc_mapping, {"ip-src": ["203.0.113.42"]})
        self.assertEqual(search_params, {"event_timestamp": "7d", "limit": 10})

    def test_found_event_ids_are_reported(self):
        """Every event returned by the search is listed in misp_events_found."""
        self.misp_client.bulk_search_iocs.return_value = BulkSearchResult(
            events=[fake_event(101), fake_event(102)]
        )

        result = self.analyzer.analyze(_ALERT)

        self.assertEqual(result.cti_lookup_result, CTILookupResult.CTI_FOUND)
        self.assertEqual(result.report["misp_events_found"], [101, 102])
        self.assertEqual(result.report["misp_available"], "True")

    def test_no_event_found_is_reported(self):
        """A successful search without matches is distinguished from a failed one."""
        result = self.analyzer.analyze(_ALERT)

        self.assertEqual(result.cti_lookup_result, CTILookupResult.NO_CTI_FOUND)
        self.assertEqual(result.report["misp_events_found"], [])
        self.assertEqual(result.report["misp_failed_lookups"], [])

    def test_unavailable_client_is_reported_without_failing(self):
        """An unreachable MISP instance downgrades the report but analysis continues."""
        self.analyzer._misp_client = None
        self._patch(
            "decipher.analyzers.mixins.misp_enrichment.get_misp_extractor"
        ).side_effect = UnavailableMISPClientError("MISP client init failed: Unable to connect to MISP")

        result = self.analyzer.analyze(_ALERT)

        self.assertEqual(result.cti_lookup_result, CTILookupResult.MISP_UNAVAILABLE)
        self.assertNotIn("misp_events_found", result.report)
        self.assertNotIn("misp_failed_lookups", result.report)
        self.assertEqual(result.report["misp_available"], "False")
        self.assertIn(
            "MISP client init failed: Unable to connect to MISP",
            result.report["log_summary"],
        )
        self.mock_score.assert_called_once_with([])

    def test_enrichment_error_is_logged_without_failing(self):
        """A MISP API failure is recorded and the analysis carries on unscored."""
        self.misp_client.bulk_search_iocs.side_effect = Exception("unparseable response")

        result = self.analyzer.analyze(_ALERT)

        self.assertEqual(result.cti_lookup_result, CTILookupResult.MISP_LOOKUP_ERROR)
        self.assertEqual(result.report["misp_available"], "True")
        self.assertTrue(
            any(line.endswith("unparseable response") for line in result.report["log_summary"])
        )
        self.mock_score.assert_called_once_with([])

    def test_connection_failure_at_request_time_is_unavailable(self):
        """A configured client whose requests cannot reach MISP is not a lookup error."""
        self.misp_client.bulk_search_iocs.side_effect = UnavailableMISPClientError(
            "MISP unreachable during search for ip-src: timed out"
        )

        result = self.analyzer.analyze(_ALERT)

        self.assertEqual(result.cti_lookup_result, CTILookupResult.MISP_UNAVAILABLE)
        self.mock_score.assert_called_once_with([])

    def test_partial_failure_scores_the_events_found(self):
        """Events of the successful searches are scored, but the result is flagged as incomplete."""
        events = [fake_event(101)]
        self.misp_client.bulk_search_iocs.return_value = BulkSearchResult(
            events=events, failed_types=["ip-src"]
        )

        result = self.analyzer.analyze(_ALERT)

        self.assertEqual(result.cti_lookup_result, CTILookupResult.MISP_LOOKUP_ERROR)
        self.assertEqual(result.report["misp_events_found"], [101])
        self.assertEqual(result.report["misp_failed_lookups"], ["ip-src"])
        self.assertTrue(any("ip-src" in line for line in result.report["log_summary"]))
        self.mock_score.assert_called_once_with(events)


class _FailingExtensionAnalyzer(_StubAnalyzer):
    """Analyzer whose extend_analysis hook fails with a configurable MISP error."""

    extension_error: MISPEnrichmentError | None = None

    def extend_analysis(self, alert: _StubAlert, report: dict) -> None:
        raise self.extension_error


class TestCTILookupResultPrecedence(AnalyzerPipelineMixin, unittest.TestCase):
    """Tests for combining the outcomes of the IOC search and the scenario lookups."""

    def build_analyzer(self):
        return _FailingExtensionAnalyzer()

    def _analyze_with(self, extension_error: MISPEnrichmentError, events: list) -> AnalysisResult:
        self.analyzer.extension_error = extension_error
        self.misp_client.bulk_search_iocs.return_value = BulkSearchResult(events=events)
        return self.analyzer.analyze(_ALERT)

    def test_extension_lookup_error_overrides_cti_found(self):
        """A failed scenario lookup makes the analysis incomplete even when CTI was found."""
        result = self._analyze_with(MISPEnrichmentError("lookup failed"), [fake_event(101)])

        self.assertEqual(result.cti_lookup_result, CTILookupResult.MISP_LOOKUP_ERROR)
        self.assertIn("lookup failed", result.report["log_summary"])
        self.assertEqual(result.report["misp_events_found"], [101])

    def test_unavailable_overrides_lookup_error(self):
        """MISP becoming unreachable takes precedence over a failed query."""
        self.misp_client.bulk_search_iocs.return_value = BulkSearchResult(failed_types=["ip-src"])
        self.analyzer.extension_error = UnavailableMISPClientError("MISP unreachable: refused")

        result = self.analyzer.analyze(_ALERT)

        self.assertEqual(result.cti_lookup_result, CTILookupResult.MISP_UNAVAILABLE)
        self.assertEqual(result.report["misp_available"], "False")


class TestScoringAndExtension(AnalyzerPipelineMixin, unittest.TestCase):
    """Tests for the scoring step and the extend_analysis hook."""

    def build_analyzer(self):
        return _HookedStubAnalyzer()

    def test_scoring_result_sets_the_severity(self):
        """The severity of the result is the score returned by the scoring engine."""
        self.set_score(0.75)

        result = self.analyzer.analyze(_ALERT)

        self.mock_score.assert_called_once()
        self.assertAlmostEqual(result.severity, 0.75)

    def test_score_breakdown_is_added_to_the_report(self):
        """The per-event score details are exposed for analyst inspection."""
        result = self.analyzer.analyze(_ALERT)

        self.assertIn("score_breakdown", result.report)
        self.assertEqual(result.report["score_breakdown"], ())

    def test_extension_runs_after_the_lookup_and_before_scoring(self):
        """The hook sees the outcome of the MISP lookup but not yet the score breakdown."""
        result = self.analyzer.analyze(_ALERT)

        self.assertTrue(result.report["stub-extension"])

    def test_extension_is_skipped_when_misp_is_unavailable(self):
        """The scenario lookups would wait for the MISP timeout again only to fail alike."""
        self.misp_client.bulk_search_iocs.side_effect = UnavailableMISPClientError("MISP unreachable: timed out")

        result = self.analyzer.analyze(_ALERT)

        self.assertEqual(result.cti_lookup_result, CTILookupResult.MISP_UNAVAILABLE)
        self.assertNotIn("stub-extension", result.report)
        misp_messages = [line for line in result.report["log_summary"] if "MISP unreachable" in line]
        self.assertEqual(misp_messages, ["MISP unreachable: timed out"])

    def test_search_params_override_is_honored(self):
        """misp_search_params fully controls the parameters sent to the client."""
        self.config.misp_search = {"event_timestamp": "30d"}

        self.analyzer.analyze(_ALERT)

        _, search_params = self.misp_client.bulk_search_iocs.call_args[0][:2]
        self.assertEqual(search_params, {"event_timestamp": "30d", "stub_param": True})


class TestCaseCreation(AnalyzerPipelineMixin, unittest.TestCase):
    """Tests for MISPCTIAnalyzer._create_case."""

    def build_analyzer(self):
        return _StubAnalyzer()

    def test_no_case_when_case_creation_is_disabled(self):
        """created_case stays empty and Flowintel is never contacted."""
        result = self.analyzer.analyze(_ALERT)

        self.mock_create_case.assert_not_called()
        self.assertEqual(result.created_case, {"id": 0, "link": ""})
        self.assertIn(
            "Case creation for analysis disabled in configuration.",
            result.report["log_summary"],
        )

    def test_case_is_created_and_linked_when_enabled(self):
        """The created case id and its Flowintel link are reported on the result."""
        self.config.enable_case_creation = True
        self.set_score(0.4)

        result = self.analyzer.analyze(_ALERT)

        self.mock_create_case.assert_called_once()
        self.assertEqual(
            result.created_case,
            {"id": self.CASE_ID, "link": f"{FLOWINTEL_CASE_URL}/{self.CASE_ID}"},
        )

    def test_case_creation_failure_is_reported(self):
        """A Flowintel failure degrades gracefully instead of aborting the analysis."""
        self.config.enable_case_creation = True
        self.mock_create_case.side_effect = CaseCreationError("Flowintel unreachable")

        result = self.analyzer.analyze(_ALERT)

        self.assertEqual(result.created_case, {"id": 0, "link": ""})
        self.assertIn(
            "Flowintel case creation failed. See logs for details.",
            result.report["log_summary"],
        )

    def test_analyzed_scenario_matches_the_alert_type(self):
        """The result identifies the scenario the analyzer is registered for."""
        result = self.analyzer.analyze(_ALERT)

        self.assertEqual(result.analyzed_scenario, self.analyzer.alert_type)


class TestCaseSuppression(AnalyzerPipelineMixin, unittest.TestCase):
    """Tests for the case_suppression_reason hook."""

    def build_analyzer(self):
        return _HookedStubAnalyzer()

    def setUp(self):
        super().setUp()
        self.config.enable_case_creation = True

    def test_suppression_reason_skips_creation_and_is_logged(self):
        """No case is created and the reason is reported to the analyst."""
        self.set_score(0.0)

        result = self.analyzer.analyze(_ALERT)

        self.mock_create_case.assert_not_called()
        self.assertEqual(result.created_case, {"id": 0, "link": ""})
        self.assertIn("Stub suppression.", result.report["log_summary"])

    def test_case_is_created_when_nothing_is_suppressed(self):
        """A hook returning None lets the pipeline create the case."""
        self.set_score(0.4)

        result = self.analyzer.analyze(_ALERT)

        self.mock_create_case.assert_called_once()
        self.assertEqual(result.created_case["id"], self.CASE_ID)


if __name__ == "__main__":
    unittest.main()
