"""
Unit tests for the network scanning analyzer.
"""

import unittest

from pydantic import ValidationError

from decipher.analyzers import AnalyzerRegistry, AnalysisResult
from decipher.analyzers.network_scanning import NetworkScanningAlert
from decipher.settings import AnalysisScenario
from tests.decipher.testing_utils import AnalyzerPipelineMixin, fake_runtime_cfg


_VALID_ALERT = {
    "src_ip": ["203.0.113.42"],
    "uri": ["/wp-login.php", "/admin/config.php"],
    "user_agents": ["sqlmap/1.7.2#stable (http://sqlmap.org)"],
    "http_method": ["TRACE", "PROPFIND"],
    "target_host": "owncloud.abc.lu",
    "timestamp": "2026-08-24T10:15:32Z",
    "detection_chain": [(1, "burst"), (2, "scanner UA"), (3, "confirmed scan")]
}

SCENARIO_NAME = AnalysisScenario.NETWORK_SCANNING.value


class TestNetworkScanningAlert(unittest.TestCase):
    """Tests for NetworkScanningAlert input schema."""

    def test_valid_alert_accepted(self):
        """All required and optional fields should parse correctly."""
        alert = NetworkScanningAlert(**_VALID_ALERT)
        self.assertEqual(alert.src_ip, _VALID_ALERT["src_ip"])
        self.assertEqual(alert.uri, _VALID_ALERT["uri"])
        self.assertEqual(alert.user_agents, _VALID_ALERT["user_agents"])
        self.assertEqual(alert.http_method, _VALID_ALERT["http_method"])
        self.assertEqual(alert.target_host, _VALID_ALERT["target_host"])
        self.assertEqual(alert.detection_chain, [(1, "burst"), (2, "scanner UA"), (3, "confirmed scan")])

    def test_only_required_fields_accepted(self):
        """Optional fields should default to None when omitted."""
        alert = NetworkScanningAlert(
            src_ip=["203.0.113.42"],
            uri=["/admin/config.php"],
            user_agents=["nikto/2.5.0"],
        )
        self.assertIsNone(alert.http_method)
        self.assertIsNone(alert.target_host)
        self.assertIsNone(alert.timestamp)
        self.assertIsNone(alert.detection_chain)

    def test_missing_field_raises_validation_error(self):
        """A missing required field should raise a ValidationError."""
        with self.assertRaises(ValidationError):
            NetworkScanningAlert(src_ip=["203.0.113.42"])  # uri, user_agents absent

    def test_extra_fields_ignored(self):
        """Extra fields in the input dict should not raise an error."""
        data = {**_VALID_ALERT, "unknown_field": "ignored"}
        alert = NetworkScanningAlert(**data)
        self.assertEqual(alert.src_ip, _VALID_ALERT["src_ip"])


class TestNetworkScanningIOCSearch(unittest.TestCase):
    """Tests for the IOC mapping and the MISP search parameters of the scenario."""

    def setUp(self):
        self.analyzer = AnalyzerRegistry.get(SCENARIO_NAME)

    def test_ioc_mapping_covers_http_request_fields(self):
        """IOCs should be searched using the http-request object's attribute types."""
        ioc_mapping = self.analyzer.build_ioc_mapping(NetworkScanningAlert(**_VALID_ALERT))

        self.assertEqual(ioc_mapping["ip-src"], _VALID_ALERT["src_ip"])
        self.assertEqual(ioc_mapping["uri"], _VALID_ALERT["uri"])
        self.assertEqual(ioc_mapping["user-agent"], _VALID_ALERT["user_agents"])
        self.assertEqual(ioc_mapping["http-method"], _VALID_ALERT["http_method"])

    def test_ioc_mapping_omits_absent_http_method(self):
        """An optional field left out of the alert must not be searched for."""
        alert = NetworkScanningAlert(
            src_ip=["203.0.113.42"],
            uri=["/admin/config.php"],
            user_agents=["nikto/2.5.0"],
        )

        self.assertNotIn("http-method", self.analyzer.build_ioc_mapping(alert))

    def test_warninglist_enforcement_disabled_for_the_ioc_search(self):
        """A warninglist match must not remove evidence from the score (ARC-016)."""
        config = fake_runtime_cfg(misp_search={"event_timestamp": "7d"})

        search_params = self.analyzer.misp_search_params(config)

        self.assertFalse(search_params["enforce_warninglist"])
        self.assertEqual(search_params["event_timestamp"], "7d")


class TestNetworkScanningIdentifiedScanners(AnalyzerPipelineMixin, unittest.TestCase):
    """Tests covering the identified-scanners contextual field (ARC-016)."""

    def build_analyzer(self):
        return AnalyzerRegistry.get(SCENARIO_NAME)

    def test_no_match_returns_empty_list(self):
        """identified-scanners must be present and empty when no match is found."""
        result = self.analyzer.analyze(NetworkScanningAlert(**_VALID_ALERT))

        self.assertIn("identified-scanners", result.report)
        # Dict replaced with list temporarily; see comment in network_scanning.py
        # self.assertEqual(result.report["identified-scanners"], {})
        self.assertEqual(result.report["identified-scanners"], [])

    def test_scanner_matches_are_reported_without_altering_the_score(self):
        """Warninglist and research-scanner matches surface as context only (ARC-016)."""
        self.set_score(0.9)
        self.misp_client.check_warninglists.return_value = {
            "203.0.113.42": ["known-scanners"]
        }
        self.misp_client.search_object_matches.return_value = {
            "203.0.113.42": ["PROJECT - academic-scan-project"]
        }

        result = self.analyzer.analyze(NetworkScanningAlert(**_VALID_ALERT))

        self.assertEqual(
            result.report["identified-scanners"],
            ["203.0.113.42: ['PROJECT - academic-scan-project', 'known-scanners'];"],
        )
        self.assertAlmostEqual(result.severity, 0.9)

    def test_scanner_lookup_error_is_reported_without_breaking_the_analysis(self):
        """A failed lookup leaves the field unset and records the error for the analyst."""
        self.misp_client.check_warninglists.side_effect = Exception(
            "warninglist lookup failed"
        )

        result = self.analyzer.analyze(NetworkScanningAlert(**_VALID_ALERT))

        self.assertIsInstance(result, AnalysisResult)
        self.assertNotIn("identified-scanners", result.report)
        self.assertTrue(
            any(
                line.startswith("Error while searching for known scanners")
                for line in result.report["log_summary"]
            )
        )


class TestNetworkScanningCaseSuppression(AnalyzerPipelineMixin, unittest.TestCase):
    """Tests covering the zero-score case suppression of the scenario (SRS-059)."""

    SUPPRESSION_MESSAGE = (
        "No case created: no threat intelligence found for the alert IOCs."
    )

    def build_analyzer(self):
        return AnalyzerRegistry.get(SCENARIO_NAME)

    def setUp(self):
        super().setUp()
        self.config.enable_case_creation = True
        self.set_score(0.0)

    def test_no_case_without_threat_intelligence(self):
        """A zero score means no evidence to escalate, so no case is created (SRS-059 AC 6)."""
        result = self.analyzer.analyze(NetworkScanningAlert(**_VALID_ALERT))

        self.mock_create_case.assert_not_called()
        self.assertEqual(result.created_case, {"id": 0, "link": ""})
        self.assertIn(self.SUPPRESSION_MESSAGE, result.report["log_summary"])

    def test_case_with_score_zero_and_warninglist_match(self):
        """A known-scanner match is evidence, so a case is created even at score zero."""
        self.misp_client.check_warninglists.return_value = {
            "203.0.113.42": ["known-scanners"]
        }

        result = self.analyzer.analyze(NetworkScanningAlert(**_VALID_ALERT))

        self.mock_create_case.assert_called_once()
        self.assertNotEqual(result.created_case["id"], 0)
        self.assertNotIn(self.SUPPRESSION_MESSAGE, result.report["log_summary"])


if __name__ == "__main__":
    unittest.main()
