"""
Integration tests for the DECIPHER incident endpoint.

Tests make real HTTP calls to a running DECIPHER service and verify that
incident cases are created correctly in Flowintel.
"""

import json
import unittest
from pathlib import Path

import httpx
from pyflowintel import FlowintelConnectionError, PyFlowintel

from decipher.api import INCIDENT_URL
from decipher.commons.log_utils import get_logger
from decipher.settings import DEFAULT_API_PORT, DECIPHER_CONFIG_PATH, FLOWINTEL_CASE_URL

logger = get_logger(__name__)

TEST_BASE_URL = f"http://host.docker.internal:{DEFAULT_API_PORT}"
TEST_TIMEOUT = 5

RADAR_BUNDLE_PATH = Path(__file__).parent.parent / "data" / "radar-case-bundle.json"


def skip_if_no_service(cls):
    """Class decorator to skip all tests if either DECIPHER or Flowintel are unreachable.
    """
    # Check DECIPHER connectivity
    try:
        httpx.get(f"{TEST_BASE_URL}/health", timeout=3.0)
    except (httpx.ConnectError, httpx.TimeoutException):
        return unittest.skip(f"DECIPHER service not reachable at {TEST_BASE_URL}")(cls)
    
    # Simple API call to verify Flowintel connectivity since no health endpoint is available
    try:
        with PyFlowintel.from_config(str(DECIPHER_CONFIG_PATH)) as client:
            try:
                client.cases.search_by_id(1)
            except FlowintelConnectionError as e:
                return unittest.skip(f"Flowintel service not reachable: {e}")(cls)
    except Exception as e:
        return unittest.skip(f"Error initializing Flowintel: {e}")(cls)

    return cls

def _incident_url() -> str:
    """Build the full incident endpoint URL."""
    return f"{TEST_BASE_URL}{INCIDENT_URL}"


@skip_if_no_service
class TestIncidentCreationWithCaseBundle(unittest.TestCase):
    """Integration tests for incident creation using a full RADAR case bundle.

    Exercises POST /incident with a complete case bundle payload that matches
    the RADAR output format. The response is captured once in setUpClass and
    verified across individual test methods.
    """

    @classmethod
    def setUpClass(cls):
        with open(RADAR_BUNDLE_PATH, "r") as f:
            cls.incident_payload = json.load(f)

        cls.response = httpx.post(
            _incident_url(),
            json=cls.incident_payload,
            timeout=TEST_TIMEOUT,
        )
        cls.result = cls.response.json() if cls.response.status_code == 200 else {}

    @classmethod
    def tearDownClass(cls):
        """Print the created case ID and link for manual verification in Flowintel."""
        if cls.response.status_code == 200:
            try:
                pyflowint = PyFlowintel.from_config(str(DECIPHER_CONFIG_PATH))
                pyflowint.cases.delete(cls.result["id"])
            except Exception as e:
                logger.error(
                    f"Failed to delete case {cls.result['id']}. Delete manually: {e}"
                )

    def test_response_status_200(self):
        """Full case bundle request should return HTTP 200."""
        self.assertEqual(self.response.status_code, 200)

    def test_response_contains_case_id(self):
        """Response must contain a valid integer case ID greater than zero."""
        self.assertIn("id", self.result)
        self.assertIsInstance(self.result["id"], int)
        self.assertGreater(self.result["id"], 0)

    def test_response_contains_link(self):
        """Response must contain a non-empty Flowintel link string."""
        self.assertIn("link", self.result)
        self.assertIsInstance(self.result["link"], str)
        self.assertTrue(self.result["link"])
        self.assertIn(FLOWINTEL_CASE_URL, self.result["link"])


@skip_if_no_service
class TestIncidentCreationScenarios(unittest.TestCase):
    """Integration tests for the incident endpoint covering varied input scenarios.

    Each test method sends an independent request to verify that the endpoint
    correctly handles the full range of valid, boundary, and invalid inputs.
    """

    @classmethod
    def setUpClass(cls):
        cls.cases = []

    @classmethod
    def tearDownClass(cls):
        """Clean up any cases created during tests."""
        try:
            pyflowint = PyFlowintel.from_config(str(DECIPHER_CONFIG_PATH))
            for case_id in cls.cases:
                pyflowint.cases.delete(case_id)
        except Exception as e:
            logger.error(f"Failed cleaning up cases {cls.cases}; delete manually: {e}")
        finally:
            pyflowint.close()


    def _post_incident(self, payload: dict) -> httpx.Response:
        """Send a POST request to the incident endpoint.

        Args:
            payload: Request body as a dictionary.

        Returns:
            The HTTP response.
        """
        return httpx.post(_incident_url(), json=payload, timeout=TEST_TIMEOUT)

    def test_minimal_request_priority_level_only(self):
        """Endpoint should accept a request containing only the mandatory priority_level field."""
        response = self._post_incident(
            {"priority_level": "priority-level:low", "title": "Minimal request test"}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("id", data)
        self.assertIn("link", data)
        self.__class__.cases.append(data["id"])

    def test_description_fields_in_description_dict(self):
        """Extra metadata in the 'description' field should be accepted."""
        payload = {
            "priority_level": "priority-level:medium",
            "title": "Integration test with description fields",
            "description": {"source": "test_runner", "custom_field": "custom_value"},
        }
        response = self._post_incident(payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("id", data)
        self.assertGreater(data["id"], 0)
        self.__class__.cases.append(data["id"])


if __name__ == "__main__":
    unittest.main()
