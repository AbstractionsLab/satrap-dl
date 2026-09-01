"""
Unit tests for the known-scanner identification in the MISP enrichment mixin.
"""

import unittest
from unittest.mock import MagicMock

from decipher.analyzers.mixins.misp_enrichment import (
    SCANNER_OUT_ATTRIBUTES,
    MISPEnrichmentMixin,
)
from tests.decipher.testing_utils import mock_misp_client


class _Enricher(MISPEnrichmentMixin):
    """Minimal host class exposing the mixin for testing."""


def _enricher_with_client(client: MagicMock) -> _Enricher:
    enricher = _Enricher()
    enricher._misp_client = client
    return enricher


class TestIdentifyKnownScanners(unittest.TestCase):
    """Tests for MISPEnrichmentMixin.identify_known_scanners."""

    def setUp(self):
        self.client = mock_misp_client()
        self.enricher = _enricher_with_client(self.client)

    def test_no_match_returns_empty_dict(self):
        self.assertEqual(self.enricher.identify_known_scanners(["203.0.113.42"]), {})

    def test_scanner_info_is_keyed_by_matched_value(self):
        self.client.search_object_matches.return_value = {
            "203.0.113.42": ["PROJECT - academic-scan-project"]
        }

        result = self.enricher.identify_known_scanners(["203.0.113.42", "203.0.113.43"])

        self.assertEqual(result, {"203.0.113.42": ["PROJECT - academic-scan-project"]})

    def test_scanner_attributes_are_requested_from_the_client(self):
        self.enricher.identify_known_scanners(["203.0.113.42"])

        self.client.search_object_matches.assert_called_once_with(
            "research-scanner",
            ["203.0.113.42"],
            matching_att="scanning_ip",
            out_info=SCANNER_OUT_ATTRIBUTES,
        )

    def test_several_matched_objects_are_all_reported(self):
        self.client.search_object_matches.return_value = {
            "203.0.113.42": [
                "PROJECT - academic-scan-project",
                "DOMAIN - shodan.io; PROJECT - shodan",
            ]
        }

        result = self.enricher.identify_known_scanners(["203.0.113.42"])

        self.assertEqual(
            result,
            {
                "203.0.113.42": [
                    "DOMAIN - shodan.io; PROJECT - shodan",
                    "PROJECT - academic-scan-project",
                ]
            },
        )

    def test_warninglist_and_scanner_matches_on_same_value_are_merged(self):
        self.client.check_warninglists.return_value = {
            "203.0.113.42": ["known-scanners"]
        }
        self.client.search_object_matches.return_value = {
            "203.0.113.42": ["PROJECT - academic-scan-project"]
        }

        result = self.enricher.identify_known_scanners(["203.0.113.42"])

        self.assertEqual(
            result,
            {"203.0.113.42": ["PROJECT - academic-scan-project", "known-scanners"]},
        )

    def test_matches_on_distinct_values_are_kept_apart(self):
        self.client.check_warninglists.return_value = {
            "203.0.113.42": ["known-scanners"]
        }
        self.client.search_object_matches.return_value = {
            "203.0.113.43": ["PROJECT - academic-scan-project"]
        }

        result = self.enricher.identify_known_scanners(["203.0.113.42", "203.0.113.43"])

        self.assertEqual(
            result,
            {
                "203.0.113.42": ["known-scanners"],
                "203.0.113.43": ["PROJECT - academic-scan-project"],
            },
        )

    def test_duplicate_names_are_deduplicated(self):
        self.client.check_warninglists.return_value = {
            "203.0.113.42": ["known-scanners"]
        }
        self.client.search_object_matches.return_value = {
            "203.0.113.42": ["known-scanners"]
        }

        result = self.enricher.identify_known_scanners(["203.0.113.42"])

        self.assertEqual(result, {"203.0.113.42": ["known-scanners"]})


if __name__ == "__main__":
    unittest.main()
