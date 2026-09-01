"""
Integration tests for the MISP object lookup in the MISP connector.

Tests run against a real MISP instance: a test event holding a
`research-scanner` object is created in setUpClass, queried through
MISPDataExtractor.search_object_matches, and deleted afterwards.
"""

import unittest

from pymisp import MISPEvent, MISPObject, PyMISPError

from decipher.commons.log_utils import get_logger
from decipher.commons.misp_connector import MISPDataExtractor
from decipher.settings import MISP_URL, MISP_API_KEY, MISP_VERIFY_SSL, MISP_TIMEOUT

logger = get_logger(__name__)

SCANNING_IP = "192.0.2.77"
SCANNING_HOST = "scanner.decipher-integration.test"
DOMAIN = "decipher-integration.test"
PROJECT = "DECIPHER integration test scanner"
OBJECT_TYPE = "research-scanner"
UNKNOWN_IP = "192.0.2.199"


def skip_if_no_misp(cls):
    """Class decorator to skip all tests if the MISP instance is unreachable."""
    try:
        extractor = MISPDataExtractor(
            MISP_URL, MISP_API_KEY, MISP_VERIFY_SSL, MISP_TIMEOUT
        )
        if not extractor.is_available():
            return unittest.skip("MISP client not configured")(cls)
        extractor.client.misp_instance_version
    except (PyMISPError, Exception) as e:
        return unittest.skip(f"MISP instance not reachable at {MISP_URL}: {e}")(cls)

    return cls


def _build_scanner_event() -> MISPEvent:
    """Build an event containing a single research-scanner object."""
    scanner = MISPObject("research-scanner", strict=False)
    scanner.add_attribute("project", value=PROJECT, type="text")
    scanner.add_attribute("scanning_ip", value=SCANNING_IP, type="ip-src")
    scanner.add_attribute("scanning_host", value=SCANNING_HOST, type="hostname")
    scanner.add_attribute("domain", value=DOMAIN, type="domain")

    event = MISPEvent()
    event.info = "DECIPHER integration test - research scanner"
    event.distribution = 0
    event.threat_level_id = 4
    event.analysis = 2
    event.add_object(scanner)
    return event


@skip_if_no_misp
class TestSearchObjectMatches(unittest.TestCase):
    """Tests for MISPDataExtractor.search_object_matches."""

    @classmethod
    def setUpClass(cls):
        cls.extractor = MISPDataExtractor(
            MISP_URL, MISP_API_KEY, MISP_VERIFY_SSL, MISP_TIMEOUT
        )
        cls.event = cls.extractor.client.add_event(
            _build_scanner_event(), pythonify=True
        )
        # MISP validates attribute values and drops the invalid ones without
        # failing, so, we check that the test event has all the given attributes.
        stored = {
            att.object_relation for obj in cls.event.objects for att in obj.attributes
        }
        missing = {"project", "scanning_ip", "scanning_host", "domain"} - stored
        if missing:
            raise AssertionError(
                f"MISP rejected the test attributes {sorted(missing)} of event "
                f"{cls.event.id}. Check that their values are valid for their type."
            )

    @classmethod
    def tearDownClass(cls):
        try:
            cls.extractor.client.delete_event(cls.event)
        except PyMISPError as e:
            logger.error(f"Failed to delete event {cls.event.id}; delete manually: {e}")

    def test_stored_scanning_ip_is_matched(self):
        """The search finds the stored object and reports no unknown value."""
        result = self.extractor.search_object_matches(
            OBJECT_TYPE, [SCANNING_IP, UNKNOWN_IP], "scanning_ip", {"project"}
        )
        self.assertEqual(result, {SCANNING_IP: [f"PROJECT - {PROJECT}"]})

    def test_scanning_host_match_reports_the_requested_info(self):
        result = self.extractor.search_object_matches(
            OBJECT_TYPE, [SCANNING_HOST], "scanning_host", {"project"}
        )

        self.assertEqual(result, {SCANNING_HOST: [f"PROJECT - {PROJECT}"]})

    def test_match_outside_the_given_attribute_is_ignored(self):
        result = self.extractor.search_object_matches(
            OBJECT_TYPE, [DOMAIN], "scanning_ip", {"project"}
        )

        self.assertEqual(result, {})

    def test_no_matching_attribute_accepts_any_attribute(self):
        """Without a relation filter, a match on any relation is reported."""
        result = self.extractor.search_object_matches(
            OBJECT_TYPE, [DOMAIN], None, {"project"}
        )

        self.assertEqual(result, {DOMAIN: [f"PROJECT - {PROJECT}"]})


if __name__ == "__main__":
    unittest.main()
