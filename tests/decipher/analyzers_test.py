"""
Unit tests for the analyzer registry and shared AnalysisResult model.
"""

import unittest

from pydantic import ValidationError

from decipher.analyzers import AnalyzerRegistry, AnalysisResult
from decipher.analyzers.suspicious_login import SuspiciousLoginAnalyzer
from decipher.models import CTILookupResult
import decipher.settings as cfg


class TestAnalyzerRegistry(unittest.TestCase):
    """Tests for AnalyzerRegistry functionality."""

    def test_list_registered_types(self):
        """Registry should list all registered alert types."""
        registered = AnalyzerRegistry.list_types()
        for scenario in cfg.AnalysisScenario:
            self.assertIn(scenario.value, registered, f"{scenario.value} not registered")

    def test_get_existing_analyzer(self):
        """Registry should return the registered SuspiciousLoginAnalyzer instance."""
        analyzer = AnalyzerRegistry.get(cfg.AnalysisScenario.SUSPICIOUS_LOGIN.value)
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
        """AnalysisResult should be constructable with its required fields."""
        result = AnalysisResult(
            analyzed_scenario="scenario_x",
            cti_lookup_result=CTILookupResult.CTI_FOUND,
            severity=0.5,
            report={"detail": "value"},
        )
        self.assertEqual(result.analyzed_scenario, "scenario_x")
        self.assertAlmostEqual(result.severity, 0.5)

    def test_created_case_default_values(self):
        """created_case id should default to 0 when not provided."""
        result = AnalysisResult(
            analyzed_scenario="scenario_x",
            cti_lookup_result=CTILookupResult.CTI_FOUND,
            severity=0.6,
            report={},
        )
        self.assertEqual(result.created_case, {"id": 0, "link": ""})

    def test_missing_required_field_raises(self):
        """A missing required field should raise a ValidationError."""
        with self.assertRaises(ValidationError):
            AnalysisResult(cti_lookup_result="cti_found", severity=0.5, report={})  # analyzed_scenario absent
        with self.assertRaises(ValidationError):
            AnalysisResult(analyzed_scenario="scenario_x", severity=0.5, report={})  # cti_lookup_result absent

    def test_unknown_cti_lookup_result_raises(self):
        """Only the defined CTI lookup result values are accepted."""
        with self.assertRaises(ValidationError):
            AnalysisResult(analyzed_scenario="scenario_x", cti_lookup_result="misp_available", severity=0.5, report={})

    def test_out_of_range_severity_raises(self):
        """A severity score outside [0,1] should raise a ValidationError."""
        with self.assertRaises(ValidationError):
            AnalysisResult(analyzed_scenario="scenario_x", cti_lookup_result="cti_found", severity=4, report={})
        with self.assertRaises(ValidationError):
            AnalysisResult(analyzed_scenario="scenario_x", cti_lookup_result="cti_found", severity=-0.1, report={})

    def test_json_serialization(self):
        """model_dump() should include all expected keys with correct values."""
        result = AnalysisResult(
            analyzed_scenario="threat_scen_y",
            cti_lookup_result=CTILookupResult.NO_CTI_FOUND,
            severity=0.9,
            report={"indicator": "found"},
            created_case={"id": 7, "link": ""},
        )
        data = result.model_dump()
        self.assertEqual(data["analyzed_scenario"], "threat_scen_y")
        self.assertAlmostEqual(data["severity"], 0.9)
        self.assertEqual(data["created_case"], {"id": 7, "link": ""})
        self.assertIn("report", data)
        self.assertEqual(data["cti_lookup_result"], "no_cti_found")


if __name__ == "__main__":
    unittest.main()
