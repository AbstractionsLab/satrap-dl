"""
Integration tests for the Analysis API endpoints.
"""

import unittest
from unittest.mock import Mock, patch
from fastapi.testclient import TestClient

from decipher.api import app, ANALYZE_URL, INCIDENT_URL, LIST_ANALYZERS_URL, GET_ANALYZER_URL, HEALTH_URL
from decipher.models import MISP_PRIORITY_LEVELS


class TestAnalysisAPI(unittest.TestCase):
    """Integration tests for FastAPI endpoints."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def setUp(self):
        """Set up mocks for each test."""
        # Mock PyFlowintel client for incident creation tests
        self.mock_flowintel_client = Mock()
        self.mock_flowintel_client.cases.create.return_value = {"case_id": 42}
        self.mock_flowintel_client.cases.delete.return_value = {}
        self.mock_flowintel_client.templates.find_case_temp_by_title.return_value = {"id": 1}
        self.mock_flowintel_client.templates.create_case_from_template.return_value = {"case_id": 42}
        
        # Patch PyFlowintel.from_config to return our mock client
        self.patcher = patch('decipher.casemanagement.flowintel_connector.PyFlowintel.from_config')
        self.mock_from_config = self.patcher.start()
        self.mock_from_config.return_value = self.mock_flowintel_client

    def tearDown(self):
        """Clean up mocks after each test."""
        self.patcher.stop()

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

    @unittest.skip("This endpoint is temporarily disabled as it's redundant with only 1 analyzer. Will re-enable when more analyzers are added.")
    def test_get_specific_analyzer(self):
        """Should return details for specific analyzer."""
        url = GET_ANALYZER_URL.format(alert_type="suspicious_login")
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["alert_type"], "suspicious_login")
        self.assertIn("schema", data)

    def test_get_unknown_analyzer_404(self):
        """Should return 404 for unknown analyzer type."""
        url = GET_ANALYZER_URL.format(alert_type="unknown_type")
        response = self.client.get(url)

        self.assertEqual(response.status_code, 404)

    def test_analyze_suspicious_login_success(self):
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
        """Should return 404 for unknown alert type."""
        url = ANALYZE_URL.format(alert_type="unknown_type")
        response = self.client.post(url, json={"data": "test"})

        self.assertEqual(response.status_code, 404)
        self.assertIn("Unknown alert type", response.json()["detail"])

    def test_analyze_invalid_data_422(self):
        """Should return 422 for invalid alert data."""
        payload = {
            "username": "admin",
            # Missing required fields
        }

        url = ANALYZE_URL.format(alert_type="suspicious_login")
        response = self.client.post(url, json=payload)
        self.assertEqual(response.status_code, 422)
        self.assertIn("errors", response.json()["detail"])

    def test_root_returns_info(self):
        """Root endpoint should return API info."""
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("service", data)
        self.assertIn("docs", data)

    # Tests for incident endpoint
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

    def test_create_incident_invalid_priority_level_422(self):
        """Should reject an invalid MISP priority level."""
        payload = {"priority_level": "priority-level:unknown"}
        response = self.client.post(INCIDENT_URL, json=payload)
        self.assertEqual(response.status_code, 422)

    def test_create_incident_missing_priority_level_422(self):
        """Should reject request without priority_level."""
        payload = {"title": "Missing priority_level"}
        response = self.client.post(INCIDENT_URL, json=payload)
        self.assertEqual(response.status_code, 422)

    def test_create_incident_with_template_id(self):
        """Should create incident case when template_id is provided."""
        payload = {
            "priority_level": "priority-level:high",
            "template_id": "suspicious_login",
            "title": "Login anomaly detected",
        }

        response = self.client.post(INCIDENT_URL, json=payload)

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("id", data)


if __name__ == "__main__":
    unittest.main()
