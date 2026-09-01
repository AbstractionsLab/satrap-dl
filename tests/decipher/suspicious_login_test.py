"""
Unit tests for the suspicious login analyzer.
"""

import unittest
from datetime import datetime

from pydantic import ValidationError

from decipher.analyzers import AnalyzerRegistry
from decipher.analyzers.suspicious_login import SuspiciousLoginAlert
from decipher.settings import AnalysisScenario
from tests.decipher.testing_utils import fake_runtime_cfg


_VALID_ALERT = {
    "username": "jdoe",
    "target_host": "192.168.0.10",
    "src_ips": ["10.0.0.1", "10.0.0.2"],
    "timestamp": "2026-02-23T12:00:00",
}

SCENARIO_NAME = AnalysisScenario.SUSPICIOUS_LOGIN.value


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


class TestSuspiciousLoginIOCSearch(unittest.TestCase):
    """Tests for the IOC mapping and the MISP search parameters of the scenario."""

    def setUp(self):
        self.analyzer = AnalyzerRegistry.get(SCENARIO_NAME)

    def test_ioc_mapping_covers_login_fields(self):
        """Origin, target and user of the login attempt should all be searched for."""
        ioc_mapping = self.analyzer.build_ioc_mapping(SuspiciousLoginAlert(**_VALID_ALERT))

        self.assertEqual(ioc_mapping["ip-src"], _VALID_ALERT["src_ips"])
        self.assertEqual(ioc_mapping["ip-dst"], [_VALID_ALERT["target_host"]])
        self.assertEqual(ioc_mapping["target-user"], [_VALID_ALERT["username"]])

    def test_warninglist_enforcement_left_to_the_configuration(self):
        """Opting out of warninglist filtering is specific to the scanning scenario."""
        config = fake_runtime_cfg(misp_search={"event_timestamp": "7d"})

        search_params = self.analyzer.misp_search_params(config)

        self.assertNotIn("enforce_warninglist", search_params)
        self.assertEqual(search_params, {"event_timestamp": "7d"})


if __name__ == "__main__":
    unittest.main()
