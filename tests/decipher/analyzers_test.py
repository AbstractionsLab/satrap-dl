"""
Unit tests for alert analyzers.
"""

import re
import unittest
from unittest.mock import MagicMock, patch
from datetime import datetime

from pydantic import ValidationError

from decipher.analyzers import AnalyzerRegistry, AnalysisResult
from decipher.analyzers.suspicious_login import SuspiciousLoginAnalyzer, SuspiciousLoginAlert
from decipher.scoringengine.datamodels import FinalScoreResult


# Shared fixtures

_VALID_ALERT = {
    "username": "jdoe",
    "target_host": "192.168.0.10",
    "src_ips": ["10.0.0.1", "10.0.0.2"],
    "timestamp": "2026-02-23T12:00:00",
}

def _fake_score(score: float = 0.5) -> FinalScoreResult:
    return FinalScoreResult(score=score, event_results=())


def _mock_misp_client(available: bool = True, ioc_results: list | None = None):
    client = MagicMock()
    client.is_available.return_value = available
    client.bulk_search_iocs.return_value = ioc_results or []
    return client


class TestAnalyzerRegistry(unittest.TestCase):
    """Tests for AnalyzerRegistry functionality."""

    def test_list_registered_types(self):
        """Registry should list all registered alert types."""
        self.assertIn("suspicious_login", AnalyzerRegistry.list_types())

    def test_get_existing_analyzer(self):
        """Registry should return the registered SuspiciousLoginAnalyzer instance."""
        analyzer = AnalyzerRegistry.get("suspicious_login")
        self.assertIsNotNone(analyzer)
        self.assertIsInstance(analyzer, SuspiciousLoginAnalyzer)

    def test_get_nonexistent_analyzer(self):
        """Registry should return None for an unregistered alert type."""
        self.assertIsNone(AnalyzerRegistry.get("nonexistent_type"))

    def test_analyze_unknown_type_raises(self):
        """Registry.analyze should raise ValueError for an unknown alert type."""
        with self.assertRaises(ValueError) as ctx:
            AnalyzerRegistry.analyze("unknown_type", {})
        self.assertIn("Unknown alert type", str(ctx.exception))


class TestAnalysisResultModel(unittest.TestCase):
    """Tests for AnalysisResult Pydantic model."""

    def test_required_fields_accepted(self):
        """AnalysisResult should be constructable with its three required fields."""
        result = AnalysisResult(
            analyzed_scenario="suspicious_login",
            severity=0.5,
            report={"detail": "value"},
        )
        self.assertEqual(result.analyzed_scenario, "suspicious_login")
        self.assertAlmostEqual(result.severity, 0.5)

    def test_created_case_defaults_to_zero(self):
        """created_case should default to 0 when not provided."""
        result = AnalysisResult(
            analyzed_scenario="suspicious_login",
            severity=0.0,
            report={},
        )
        self.assertEqual(result.created_case, {"id": 0, "link": ""})

    def test_missing_required_field_raises(self):
        """A missing required field should raise a ValidationError."""
        with self.assertRaises(ValidationError):
            AnalysisResult(severity=0.5, report={})  # analyzed_scenario absent

    def test_json_serialization(self):
        """model_dump() should include all expected keys with correct values."""
        result = AnalysisResult(
            analyzed_scenario="suspicious_login",
            severity=0.9,
            report={"indicator": "found"},
            created_case={"id": 7, "link": ""},
        )
        data = result.model_dump()
        self.assertEqual(data["analyzed_scenario"], "suspicious_login")
        self.assertAlmostEqual(data["severity"], 0.9)
        self.assertEqual(data["created_case"], {"id": 7, "link": ""})
        self.assertIn("report", data)


# --- Suspicious login analyzer tests ---

class TestSuspiciousLoginAlert(unittest.TestCase):
    """Tests for SuspiciousLoginAlert input schema."""

    def test_valid_alert_accepted(self):
        """All required fields should parse correctly."""
        alert = SuspiciousLoginAlert(**_VALID_ALERT)
        self.assertEqual(alert.username, _VALID_ALERT["username"])
        self.assertEqual(alert.src_ips, _VALID_ALERT["src_ips"])
        self.assertEqual(alert.target_host, _VALID_ALERT["target_host"])
        self.assertEqual(alert.timestamp, datetime.fromisoformat(_VALID_ALERT["timestamp"]))

    def test_missing_field_raises_validation_error(self):
        """A missing required field should raise a ValidationError."""
        with self.assertRaises(ValidationError):
            SuspiciousLoginAlert(username="jdoe")  # target_host, src_ips, timestamp absent

    def test_extra_fields_ignored(self):
        """Extra fields in the input dict should not raise an error."""
        data = {**_VALID_ALERT, "unknown_field": "ignored"}
        alert = SuspiciousLoginAlert(**data)
        self.assertEqual(alert.username, _VALID_ALERT["username"])


class TestSuspiciousLoginAnalyzerMISPEnrichment(unittest.TestCase):
    """Tests covering MISP enrichment paths and scoring."""

    def setUp(self):
        self.analyzer = AnalyzerRegistry.get("suspicious_login")

    @patch("decipher.analyzers.suspicious_login.load_decipher_runtime_cfg")
    def test_misp_disabled_early_return(self, mock_settings):
        """Analysis should stop after phase 1 when MISP lookup is disabled."""
        mock_settings.return_value.enable_misp_search = False
        result = self.analyzer.analyze(SuspiciousLoginAlert(**_VALID_ALERT))
        self.assertEqual(result.severity, 0)
        self.assertEqual(result.report.get("misp_available"), "False")
        self.assertIn("MISP IOC search disabled in configuration", result.report.get("log_summary", []))

    @patch("decipher.analyzers.suspicious_login.calculator.score_events")
    @patch("decipher.analyzers.suspicious_login.load_decipher_runtime_cfg")
    def test_misp_events_scored(self, mock_settings, mock_score):
        """score_events is called and its result sets the severity."""
        mock_settings.return_value.enable_misp_search = True
        mock_settings.return_value.enable_case_creation = False
        mock_score.return_value = _fake_score(0.75)
        self.analyzer._misp_client = _mock_misp_client()

        result = self.analyzer.analyze(SuspiciousLoginAlert(**_VALID_ALERT))

        mock_score.assert_called_once()
        self.assertAlmostEqual(result.severity, 0.75)
        self.assertEqual(result.report["misp_available"], "True")

    @patch("decipher.analyzers.suspicious_login.calculator.score_events")
    @patch("decipher.analyzers.suspicious_login.load_decipher_runtime_cfg")
    def test_score_breakdown_in_report(self, mock_settings, mock_score):
        # configure the mock settings return value
        mock_settings.return_value.enable_misp_search = True
        mock_settings.return_value.enable_case_creation = False

        mock_score.return_value = _fake_score(0.5)
        self.analyzer._misp_client = _mock_misp_client()
        result = self.analyzer.analyze(SuspiciousLoginAlert(**_VALID_ALERT))
        self.assertIn("score_breakdown", result.report)
        self.assertEqual(result.report["score_breakdown"], ())



    @patch("decipher.analyzers.suspicious_login.calculator.score_events")
    @patch("decipher.analyzers.suspicious_login.load_decipher_runtime_cfg")
    def test_misp_unavailable_graceful(self, mock_settings, mock_score):
        """When the MISP client is unavailable, misp_available=False and analysis continues."""
        mock_settings.return_value.enable_misp_search = True
        mock_settings.return_value.enable_case_creation = False
        mock_score.return_value = _fake_score(0.0)
        self.analyzer._misp_client = _mock_misp_client(available=False)

        result = self.analyzer.analyze(SuspiciousLoginAlert(**_VALID_ALERT))

        self.assertEqual(result.report["misp_available"], "False")
        self.assertIsInstance(result, AnalysisResult)

    @patch("decipher.analyzers.suspicious_login.calculator.score_events")
    @patch("decipher.analyzers.suspicious_login.load_decipher_runtime_cfg")
    def test_misp_api_error_graceful(self, mock_settings, mock_score):
        """When a MISP API error occurs, misp_error is recorded and analysis continues."""
        mock_settings.return_value.enable_misp_search = True
        mock_settings.return_value.enable_case_creation = False
        mock_score.return_value = _fake_score(0.0)
        client = _mock_misp_client()
        client.bulk_search_iocs.side_effect = Exception("API timeout")
        self.analyzer._misp_client = client

        result = self.analyzer.analyze(SuspiciousLoginAlert(**_VALID_ALERT))

        self.assertIsInstance(result, AnalysisResult)
        self.assertTrue(
            any(re.search(r"API timeout$", log_line) for log_line in result.report.get("log_summary", []))
        )


class TestSuspiciousLoginAnalyzerCaseManagement(unittest.TestCase):
    """Tests covering Flowintel case creation behaviour."""

    def setUp(self):
        self.analyzer = AnalyzerRegistry.get("suspicious_login")

    @patch("decipher.analyzers.suspicious_login.calculator.score_events")
    @patch("decipher.analyzers.suspicious_login.load_decipher_runtime_cfg")
    def test_no_case_when_disabled(self, mock_settings, mock_score):
        """created_case should remain 0 when CASE_CREATION_ENABLED is False."""
        mock_settings.return_value.enable_misp_search = True
        mock_settings.return_value.enable_case_creation = False
        mock_score.return_value = _fake_score(0.3)
        self.analyzer._misp_client = _mock_misp_client()

        result = self.analyzer.analyze(SuspiciousLoginAlert(**_VALID_ALERT))

        self.assertEqual(result.created_case, {"id": 0, "link": ""})

    @patch("decipher.analyzers.suspicious_login.calculator.score_events")
    @patch("decipher.analyzers.suspicious_login.load_decipher_runtime_cfg")
    @patch("decipher.analyzers.suspicious_login.create_case_for_scenario")
    def test_case_creation_called_when_enabled(self, mock_create, mock_settings, mock_score):
        """When case creation is enabled, a case is created and recorded on the result."""
        mock_settings.return_value.analysis.enable_misp_search = True
        mock_settings.return_value.analysis.enable_case_creation = True
        mock_score.return_value = _fake_score(0.4)
        mock_create.return_value = 333
        self.analyzer._misp_client = _mock_misp_client()

        result = self.analyzer.analyze(SuspiciousLoginAlert(**_VALID_ALERT))

        mock_score.assert_called_once()
        mock_create.assert_called_once()
        self.assertEqual(result.created_case["id"], 333)
        self.assertAlmostEqual(result.severity, 0.4)


if __name__ == "__main__":
    unittest.main()
