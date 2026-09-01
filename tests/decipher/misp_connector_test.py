"""
Unit tests for the MISP data extractor's IOC search, warninglist and object lookups.
"""

import unittest
from unittest.mock import MagicMock

from pymisp import PyMISPError

from decipher.commons.misp_connector import (
    DEFAULT_EVENT_TIMESTAMP,
    DEFAULT_MAX_VALUES_PER_TYPE,
    DEFAULT_SEARCH_RESULT_LIMIT,
    MISPDataExtractor,
)


def _extractor_with_client(client: MagicMock) -> MISPDataExtractor:
    """Build a MISPDataExtractor bypassing __init__'s PyMISP connection setup."""
    extractor = MISPDataExtractor.__new__(MISPDataExtractor)
    extractor.client = client
    return extractor


class TestSearchIoc(unittest.TestCase):
    """Tests for the search parameters built by MISPDataExtractor.search_ioc."""

    @staticmethod
    def _search_kwargs(additional_params) -> dict:
        client = MagicMock()
        client.search.return_value = []
        extractor = _extractor_with_client(client)

        extractor.search_ioc("ip-src", "203.0.113.42", additional_params)

        return client.search.call_args.kwargs

    def test_warninglists_enforced_by_default(self):
        """Callers that say nothing keep MISP's warninglist filtering."""
        self.assertTrue(self._search_kwargs(None)["enforce_warninglist"])
        self.assertTrue(self._search_kwargs({})["enforce_warninglist"])

    def test_warninglist_enforcement_can_be_disabled(self):
        """Scenarios reporting warninglist matches as context opt out (ARC-016)."""
        kwargs = self._search_kwargs({"enforce_warninglist": False})
        self.assertFalse(kwargs["enforce_warninglist"])

    def test_timeframe_and_limit_defaults_apply_without_params(self):
        """The documented defaults must hold even when no parameters are given."""
        kwargs = self._search_kwargs(None)
        self.assertEqual(kwargs["event_timestamp"], DEFAULT_EVENT_TIMESTAMP)
        self.assertEqual(kwargs["limit"], DEFAULT_SEARCH_RESULT_LIMIT)

    def test_timeframe_and_limit_are_taken_from_params(self):
        kwargs = self._search_kwargs({"event_timestamp": "2d", "limit": 50})
        self.assertEqual(kwargs["event_timestamp"], "2d")
        self.assertEqual(kwargs["limit"], 50)

    def test_pymisp_error_propagates(self):
        client = MagicMock()
        client.search.side_effect = PyMISPError("connection failed")
        extractor = _extractor_with_client(client)

        with self.assertRaises(PyMISPError):
            extractor.search_ioc("ip-src", "203.0.113.42")


class TestBulkSearchIocs(unittest.TestCase):
    """Tests for how MISPDataExtractor.bulk_search_iocs batches its searches."""

    @staticmethod
    def _extractor_with_stubbed_search() -> MISPDataExtractor:
        """An extractor whose single-type search returns nothing, to inspect the calls made."""
        extractor = _extractor_with_client(MagicMock())
        extractor.search_ioc = MagicMock(return_value=[])
        return extractor

    def test_one_search_per_attribute_type(self):
        """All values of a type travel in a single request, not one request per value."""
        extractor = self._extractor_with_stubbed_search()
        iocs = {
            "ip-src": ["203.0.113.42", "203.0.113.43"],
            "uri": ["/wp-login.php", "/.env", "/admin"],
        }

        extractor.bulk_search_iocs(iocs)

        self.assertEqual(extractor.search_ioc.call_count, len(iocs))
        searched = {call.args[0]: call.args[1] for call in extractor.search_ioc.call_args_list}
        self.assertEqual(searched["ip-src"], iocs["ip-src"])
        self.assertEqual(searched["uri"], iocs["uri"])

    def test_duplicates_and_blanks_removed_keeping_order(self):
        extractor = self._extractor_with_stubbed_search()

        extractor.bulk_search_iocs({"uri": ["/a", "", "/b", "/a", "   ", "/c"]})

        self.assertEqual(extractor.search_ioc.call_args.args[1], ["/a", "/b", "/c"])

    def test_type_without_usable_values_is_not_searched(self):
        extractor = self._extractor_with_stubbed_search()

        extractor.bulk_search_iocs({"uri": ["", "  "], "ip-src": ["203.0.113.42"]})

        self.assertEqual(extractor.search_ioc.call_count, 1)
        self.assertEqual(extractor.search_ioc.call_args.args[0], "ip-src")

    def test_values_per_type_are_capped(self):
        """An alert reporting an excessive number of values cannot grow the request unbounded."""
        extractor = self._extractor_with_stubbed_search()
        values = [f"/path{i}" for i in range(10)]

        extractor.bulk_search_iocs({"uri": values}, {"max_values_per_type": 4})

        self.assertEqual(extractor.search_ioc.call_args.args[1], values[:4])

    def test_default_cap_applies_without_configuration(self):
        extractor = self._extractor_with_stubbed_search()
        values = [f"/path{i}" for i in range(DEFAULT_MAX_VALUES_PER_TYPE + 5)]

        extractor.bulk_search_iocs({"uri": values})

        self.assertEqual(
            len(extractor.search_ioc.call_args.args[1]), DEFAULT_MAX_VALUES_PER_TYPE
        )

    def test_failure_on_one_type_does_not_stop_the_others(self):
        extractor = _extractor_with_client(MagicMock())
        extractor.search_ioc = MagicMock(side_effect=[PyMISPError("search failed"), []])

        result = extractor.bulk_search_iocs({"uri": ["/a"], "ip-src": ["203.0.113.42"]})

        self.assertEqual(extractor.search_ioc.call_count, 2)
        self.assertEqual(result, [])


class TestCheckWarninglists(unittest.TestCase):
    """Tests for MISPDataExtractor.check_warninglists."""

    def test_empty_input_returns_empty_dict(self):
        extractor = _extractor_with_client(MagicMock())
        self.assertEqual(extractor.check_warninglists([]), {})

    def test_matches_are_extracted_by_name(self):
        client = MagicMock()
        client.values_in_warninglist.return_value = {
            "203.0.113.42": [{"id": "1", "name": "known-scanners"}]
        }
        extractor = _extractor_with_client(client)

        result = extractor.check_warninglists(["203.0.113.42", "10.0.0.1"])
        self.assertEqual(result, {"203.0.113.42": ["known-scanners"]})

    def test_multiple_matches_for_same_value(self):
        client = MagicMock()
        client.values_in_warninglist.return_value = {
            "203.0.113.42": [{"name": "list-a"}, {"name": "list-b"}]
        }
        extractor = _extractor_with_client(client)

        result = extractor.check_warninglists(["203.0.113.42"])

        self.assertEqual(result, {"203.0.113.42": ["list-a", "list-b"]})

    def test_empty_list_response_returns_empty_dict_without_warning(self):
        """MISP answers with an empty list when no value matches any warninglist."""
        client = MagicMock()
        client.values_in_warninglist.return_value = []
        extractor = _extractor_with_client(client)

        with self.assertNoLogs("decipher.commons.misp_connector", level="WARNING"):
            self.assertEqual(extractor.check_warninglists(["203.0.113.42"]), {})

    def test_unexpected_response_format_returns_empty_dict(self):
        client = MagicMock()
        client.values_in_warninglist.return_value = ["not", "a", "dict"]
        extractor = _extractor_with_client(client)

        self.assertEqual(extractor.check_warninglists(["203.0.113.42"]), {})

    def test_pymisp_error_propagates(self):
        client = MagicMock()
        client.values_in_warninglist.side_effect = PyMISPError("connection failed")
        extractor = _extractor_with_client(client)

        with self.assertRaises(PyMISPError):
            extractor.check_warninglists(["203.0.113.42"])


class TestSearchObjectMatches(unittest.TestCase):
    """Tests for MISPDataExtractor.search_object_matches."""

    def _mock_object(self, uuid: str, relation_values: dict[str, list[str]]) -> MagicMock:
        obj = MagicMock()
        obj.uuid = uuid
        obj.attributes = [
            MagicMock(value=v) for values in relation_values.values() for v in values
        ]
        obj.get_attributes_by_relation.side_effect = lambda relation: [
            MagicMock(value=v) for v in relation_values.get(relation, [])
        ]
        return obj

    def test_no_matching_objects_returns_empty_dict(self):
        client = MagicMock()
        client.search.return_value = []
        extractor = _extractor_with_client(client)

        result = extractor.search_object_matches(
            "research-scanner", ["203.0.113.42"], "scanning_ip", {"project"}
        )

        self.assertEqual(result, {})

    def test_requested_info_is_reported_for_matching_objects(self):
        client = MagicMock()
        client.search.return_value = [
            self._mock_object(
                "uuid-1",
                {"scanning_ip": ["203.0.113.42"], "project": ["academic-scan-project"]},
            ),
            self._mock_object(
                "uuid-2", {"scanning_ip": ["203.0.113.99"], "project": ["other-project"]}
            ),
        ]
        extractor = _extractor_with_client(client)

        result = extractor.search_object_matches(
            "research-scanner", ["203.0.113.42"], "scanning_ip", {"project"}
        )

        self.assertEqual(result, {"203.0.113.42": ["PROJECT - academic-scan-project"]})

    def test_several_requested_attributes_are_reported_alphabetically(self):
        client = MagicMock()
        client.search.return_value = [
            self._mock_object(
                "uuid-1",
                {
                    "scanning_ip": ["203.0.113.42"],
                    "project": ["academic-scan-project"],
                    "domain": ["shodan.io"],
                },
            ),
        ]
        extractor = _extractor_with_client(client)

        result = extractor.search_object_matches(
            "research-scanner", ["203.0.113.42"], "scanning_ip", {"project", "domain"}
        )

        self.assertEqual(
            result,
            {"203.0.113.42": ["DOMAIN - shodan.io; PROJECT - academic-scan-project"]},
        )


    def test_absent_requested_attribute_returns_empty_string(self):
        client = MagicMock()
        client.search.return_value = [
            self._mock_object(
                "uuid-1",
                {
                    "scanning_ip": ["203.0.113.42"],
                    "project": ["academic-scan-project"],
                    "domain": ["shodan.io"],
                },
            ),
        ]
        extractor = _extractor_with_client(client)

        result = extractor.search_object_matches(
            "research-scanner", ["203.0.113.42"], "scanning_ip", {"name"}
        )

        self.assertEqual(
            result,
            {"203.0.113.42": [""]},
        )

    def test_several_values_of_one_attribute_are_joined(self):
        client = MagicMock()
        client.search.return_value = [
            self._mock_object(
                "uuid-1",
                {"scanning_ip": ["203.0.113.42"], "domain": ["shodan.io", "census.io"]},
            ),
        ]
        extractor = _extractor_with_client(client)

        result = extractor.search_object_matches(
            "research-scanner", ["203.0.113.42"], "scanning_ip", {"domain"}
        )

        self.assertEqual(result, {"203.0.113.42": ["DOMAIN - shodan.io, census.io"]})

    def test_attribute_absent_from_the_object_is_skipped(self):
        client = MagicMock()
        client.search.return_value = [
            self._mock_object(
                "uuid-1",
                {"scanning_ip": ["203.0.113.42"], "project": ["academic-scan-project"]},
            ),
        ]
        extractor = _extractor_with_client(client)

        result = extractor.search_object_matches(
            "research-scanner", ["203.0.113.42"], "scanning_ip", {"project", "domain"}
        )

        self.assertEqual(result, {"203.0.113.42": ["PROJECT - academic-scan-project"]})

    def test_no_requested_info_reports_an_empty_string_per_match(self):
        client = MagicMock()
        client.search.return_value = [
            self._mock_object("uuid-1", {"scanning_ip": ["203.0.113.42"]}),
        ]
        extractor = _extractor_with_client(client)

        result = extractor.search_object_matches(
            "research-scanner", ["203.0.113.42"], "scanning_ip"
        )

        self.assertEqual(result, {"203.0.113.42": [""]})

    def test_match_outside_the_given_attribute_is_ignored(self):
        client = MagicMock()
        client.search.return_value = [
            self._mock_object(
                "uuid-1",
                {
                    "scanning_ip": ["203.0.113.99"],
                    "domain": ["203.0.113.42"],
                    "project": ["academic-scan-project"],
                },
            ),
        ]
        extractor = _extractor_with_client(client)

        result = extractor.search_object_matches(
            "research-scanner", ["203.0.113.42"], "scanning_ip", "project"
        )

        self.assertEqual(result, {})

    def test_no_matching_attribute_accepts_any_attribute(self):
        client = MagicMock()
        client.search.return_value = [
            self._mock_object(
                "uuid-1",
                {"domain": ["203.0.113.42"], "project": ["academic-scan-project"]},
            ),
        ]
        extractor = _extractor_with_client(client)

        result = extractor.search_object_matches(
            "research-scanner", ["203.0.113.42"], None, {"project"}
        )

        self.assertEqual(result, {"203.0.113.42": ["PROJECT - academic-scan-project"]})

    def test_each_matched_value_gets_its_own_entry(self):
        client = MagicMock()
        client.search.return_value = [
            self._mock_object(
                "uuid-1",
                {
                    "scanning_ip": ["203.0.113.42", "203.0.113.43"],
                    "project": ["academic-scan-project"],
                },
            ),
        ]
        extractor = _extractor_with_client(client)

        result = extractor.search_object_matches(
            "research-scanner", ["203.0.113.42", "203.0.113.43"], "scanning_ip", {"project"}
        )

        self.assertEqual(
            result,
            {
                "203.0.113.42": ["PROJECT - academic-scan-project"],
                "203.0.113.43": ["PROJECT - academic-scan-project"],
            },
        )
        self.assertEqual(client.search.call_count, 2)

    def test_one_object_matched_twice_is_reported_once(self):
        client = MagicMock()
        client.search.return_value = [
            self._mock_object(
                "uuid-1",
                {"scanning_ip": ["203.0.113.42"], "project": ["academic-scan-project"]},
            ),
            self._mock_object(
                "uuid-1",
                {"scanning_ip": ["203.0.113.42"], "project": ["academic-scan-project"]},
            ),
        ]
        extractor = _extractor_with_client(client)

        result = extractor.search_object_matches(
            "research-scanner", ["203.0.113.42"], "scanning_ip", {"project"}
        )

        self.assertEqual(result, {"203.0.113.42": ["PROJECT - academic-scan-project"]})

    def test_object_type_is_passed_to_the_search(self):
        client = MagicMock()
        client.search.return_value = []
        extractor = _extractor_with_client(client)

        extractor.search_object_matches("domain-ip", ["203.0.113.42"], "ip")

        self.assertEqual(client.search.call_args.kwargs["object_name"], "domain-ip")

    def test_pymisp_error_propagates(self):
        client = MagicMock()
        client.search.side_effect = PyMISPError("connection failed")
        extractor = _extractor_with_client(client)

        with self.assertRaises(PyMISPError):
            extractor.search_object_matches(
                "research-scanner", ["203.0.113.42"], "scanning_ip"
            )


if __name__ == "__main__":
    unittest.main()
