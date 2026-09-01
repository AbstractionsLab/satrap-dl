"""
Shared test helpers for DECIPHER analyzer unit tests.
"""

from unittest.mock import MagicMock, patch

from decipher.runtime_settings import RuntimeSettings
from decipher.scoringengine.datamodels import AttributeData, EventData, FinalScoreResult


def fake_score(score: float = 0.5) -> FinalScoreResult:
    """Build a minimal FinalScoreResult for mocking the scoring engine."""
    return FinalScoreResult(score=score, event_results=())


def fake_event(event_id: int, value: str = "203.0.113.42") -> EventData:
    """
    Build a minimal EventData for mocking MISP IOC search results.

    Args:
        event_id: Identifier of the event.
        value: Value of the single attribute carried by the event.

    Returns:
        Event holding one attribute, as EventData rejects an empty attribute list.
    """
    return EventData(id=event_id, attributes=[AttributeData(value=value, type="ip-src")])


def fake_runtime_cfg(
    enable_misp_search: bool = True,
    enable_case_creation: bool = False,
    misp_search: dict | None = None,
) -> RuntimeSettings:
    """
    Build a runtime configuration for mocking load_decipher_runtime_cfg.

    A real RuntimeSettings instance is returned on purpose: a MagicMock makes
    every attribute truthy, so a test setting a misspelled or obsolete setting
    name would pass without exercising the intended path.

    Args:
        enable_misp_search: Value of the MISP search gate.
        enable_case_creation: Value of the case creation gate.
        misp_search: MISP search parameters read by misp_search_params().

    Returns:
        Runtime settings with the analysis defaults used by the tests.
    """
    return RuntimeSettings(
        enable_misp_search=enable_misp_search,
        enable_case_creation=enable_case_creation,
        misp_search=dict(misp_search or {}),
    )


def mock_misp_client(
    available: bool = True,
    ioc_results: list | None = None,
    warninglist_matches: dict | None = None,
    object_matches: dict | None = None,
) -> MagicMock:
    """Build a MagicMock standing in for a MISPDataExtractor instance."""
    client = MagicMock()
    client.is_available.return_value = available
    client.bulk_search_iocs.return_value = ioc_results or []
    client.check_warninglists.return_value = warninglist_matches or {}
    client.search_object_matches.return_value = object_matches or {}
    return client


class AnalyzerPipelineMixin:
    """
    setUp helper for tests driving MISPCTIAnalyzer.analyze().

    Patches the three collaborators of the shared pipeline (runtime
    configuration, scoring engine and case creation) and attaches a mock MISP
    client to the analyzer under test. Everything is undone through addCleanup,
    so test order stays irrelevant.

    Mix into a unittest.TestCase listing this class FIRST, otherwise its setUp
    is never run, and implement build_analyzer().

    Attributes:
        analyzer: Analyzer under test, with a mock MISP client attached.
        misp_client: MagicMock standing in for the MISP data extractor.
        config: Runtime settings returned to the analyzer. Mutate it in the test
            to change the configuration under test.
        mock_score: Patched calculator.score_events, returning fake_score(0.5).
        mock_create_case: Patched create_case_for_scenario, returning CASE_ID.
    """

    CASE_ID = 333

    def build_analyzer(self):
        """Return the analyzer instance under test."""
        raise NotImplementedError

    def setUp(self):
        super().setUp()
        self.analyzer = self.build_analyzer()
        # AnalyzerRegistry.get() caches one instance per alert type, so the mock
        # client must be detached again to keep test order irrelevant.
        self.addCleanup(setattr, self.analyzer, "_misp_client", None)
        self.misp_client = mock_misp_client()
        self.analyzer._misp_client = self.misp_client

        self.config = fake_runtime_cfg()
        self._patch(
            "decipher.analyzers.scenario_analyzer.load_decipher_runtime_cfg"
        ).return_value = self.config

        self.mock_score = self._patch(
            "decipher.analyzers.scenario_analyzer.calculator.score_events"
        )
        self.mock_score.return_value = fake_score(0.5)

        self.mock_create_case = self._patch(
            "decipher.analyzers.scenario_analyzer.create_case_for_scenario"
        )
        self.mock_create_case.return_value = self.CASE_ID

    def _patch(self, target: str) -> MagicMock:
        """Start a patcher for the given target, stopping it after the test."""
        patcher = patch(target)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def set_score(self, score: float) -> None:
        """Make the patched scoring engine return the given severity."""
        self.mock_score.return_value = fake_score(score)
