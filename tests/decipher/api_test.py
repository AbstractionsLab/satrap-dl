"""
Test suite for API endpoints data validations.
"""

import unittest
from unittest.mock import Mock, patch
from fastapi.testclient import TestClient

from decipher.api import app, ANALYZE_URL, INCIDENT_URL, LIST_ANALYZERS_URL, HEALTH_URL
from decipher.models import MISP_PRIORITY_LEVELS


class TestAPIValidations(unittest.TestCase):
    """Unit tests for FastAPI endpoints and data validation."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_health_check(self):
        """Health endpoint should return ok status."""
        response = self.client.get(HEALTH_URL)

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "ok")
        self.assertIn("analyzers_loaded", data)

    def test_list_analyzers(self):
        """Analyzers endpoint should list available types."""
        response = self.client.get(LIST_ANALYZERS_URL)

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("suspicious_login", data)
        self.assertIn("description", data["suspicious_login"])

    def test_root_returns_info(self):
        """Root endpoint should return API info."""
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("service", data)
        self.assertIn("docs", data)

    def test_analyze_valid_suspicious_login_data(self):
        """Should analyze valid suspicious login alert."""
        payload = {
            "username": "admin",
            "target_host": "10.0.0.1",
            "src_ips": ["185.220.100.1"],
            "timestamp": "2026-01-31T10:00:00Z",
        }

        url = ANALYZE_URL.format(alert_type="suspicious_login")
        response = self.client.post(url, json=payload)

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("created_case", data)
        self.assertIn("severity", data)
        self.assertIn("report", data)
        self.assertIn("analyzed_scenario", data)

    def test_analyze_unknown_type_404(self):
        """Should return 404 for unknown alert type and log a warning."""
        url = ANALYZE_URL.format(alert_type="unknown_type")

        with self.assertLogs("decipher.api", level="WARNING") as log:
            response = self.client.post(url, json={"data": "test"})

        self.assertEqual(response.status_code, 404)
        self.assertIn("Unknown alert type", response.json()["detail"])
        self.assertTrue(
            any("Unknown alert type" in message for message in log.output),
            "Expected a warning log for unknown alert type",
        )

    def test_analyze_invalid_alert_data_422(self):
        """Should return 422 for invalid data for the alert."""
        # Required fields missing
        payload = {
            "username": "admin",
        }

        url = ANALYZE_URL.format(alert_type="suspicious_login")
        response = self.client.post(url, json=payload)
        self.assertEqual(response.status_code, 422)
        self.assertIn("errors", response.json()["detail"])

    def test_incident_invalid_priority_level_422(self):
        """Should reject an invalid MISP priority level."""
        payload = {"priority_level": "priority-level:unknown"}
        response = self.client.post(INCIDENT_URL, json=payload)
        self.assertEqual(response.status_code, 422)

    def test_incident_missing_priority_level_422(self):
        """Should reject request without priority_level."""
        payload = {"title": "Missing priority_level"}
        response = self.client.post(INCIDENT_URL, json=payload)
        self.assertEqual(response.status_code, 422)

    def test_incident_invalid_template_id_422(self):
        """Should reject non-integer template_id."""
        payload = {"priority_level": "priority-level:high", "template_id": "not_an_int"}
        response = self.client.post(INCIDENT_URL, json=payload)
        self.assertEqual(response.status_code, 422)

    def test_incident_non_pos_template_id_422(self):
        """Should reject non-positive int template_id."""
        payload = {"priority_level": "priority-level:high", "template_id": 0}
        response = self.client.post(INCIDENT_URL, json=payload)
        self.assertEqual(response.status_code, 422)


class TestIncidentEndpointValidation(unittest.TestCase):
    """Validation tests for incident creation workflows.
    
    These tests focus on verifying that the API correctly processes the input data up to the interaction
    with the Flowintel client (e.g. passing the correct parameters, handling template lookups, etc), 
    as well as the Flowintel API response. The actual case creation in the Flowintel instance is mocked as successful.
    """

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def setUp(self):
        """Set up mocks for each test."""
        # Mock PyFlowintel client for incident creation tests
        self.mock_flowintel_client = Mock()
        self.mock_flowintel_client.cases.create.return_value = {"case_id": 42}
        
        # Patch PyFlowintel.from_config to return our mock client
        self.patcher = patch('decipher.casemanagement.flowintel_connector.PyFlowintel.from_config')
        self.mock_from_config = self.patcher.start()
        self.mock_from_config.return_value = self.mock_flowintel_client

    def tearDown(self):
        """Clean up mocks after each test."""
        self.patcher.stop()

    def test_create_incident_success_with_description(self):
        """Should create incident case with valid priority_level and description fields."""
        payload = {
            "priority_level": "priority-level:high",
            "description": {"description": "Multiple suspicious login attempts from external IP"},
        }

        response = self.client.post(INCIDENT_URL, json=payload)

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("id", data)
        self.assertIn("link", data)
        self.assertIsInstance(data["id"], int)
        self.assertGreater(data["id"], 0)

    def test_create_incident_success_minimal(self):
        """Should create incident case with only priority_level (minimal request)."""
        payload = {"priority_level": "priority-level:medium"}

        response = self.client.post(INCIDENT_URL, json=payload)

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("id", data)
        self.assertIn("link", data)

    def test_create_incident_all_valid_priority_levels(self):
        """Should accept all valid MISP priority-level taxonomy tags."""
        valid_levels = MISP_PRIORITY_LEVELS
        for level in valid_levels:
            payload = {"priority_level": level}
            response = self.client.post(INCIDENT_URL, json=payload)
            self.assertEqual(response.status_code, 200, f"Failed for priority_level={level}")

    def test_create_incident_with_template_id(self):
        """Should create incident case when template_id is provided."""
        payload = {
            "priority_level": "priority-level:high",
            "template_id": 1,
            "title": "Login anomaly detected",
        }

        response = self.client.post(INCIDENT_URL, json=payload)

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("id", data)


if __name__ == "__main__":
    unittest.main()
