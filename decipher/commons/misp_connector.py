"""
Provides a class for querying MISP threat intelligence platform.
Supports IOC lookups, event correlation, and bulk searches.
"""

from typing import Any

from pymisp import PyMISP, MISPEvent, MISPAttribute, MISPObject, MISPSighting, PyMISPError

from decipher.commons.log_utils import get_logger
from decipher.scoringengine.datamodels import (
    EventData,
    AttributeData,
    Sightings,
    AdmiraltyTags,
)
from decipher.scoringengine.factors import (
    ThreatLevel,
    AnalysisStage,
    SourceReliability,
    InfoCredibility,
)
from decipher.settings import MISP_URL, MISP_API_KEY, MISP_VERIFY_SSL, MISP_TIMEOUT


logger = get_logger(__name__)

DEFAULT_EVENT_TIMESTAMP = "7d"
DEFAULT_SEARCH_RESULT_LIMIT = 1000
DEFAULT_MAX_VALUES_PER_TYPE = 50


class MISPDataExtractor:
    """
    Client for interacting with MISP threat intelligence platform.

    Provides methods for IOC searches, event correlation, and bulk queries.
    Handles connection management and error recovery gracefully.

    Attributes:
        url: MISP instance URL.
        api_key: MISP API authentication key.
        verify_ssl: Whether to verify SSL certificates.
        client: Underlying PyMISP client instance.
    """

    def __init__(
        self,
        url: str,
        api_key: str,
        verify_ssl: bool = False,
        timeout: int | None = None,
    ):
        """
        Initialize MISP client connection.

        Args:
            url: MISP instance URL.
            api_key: MISP API key.
            verify_ssl: Enable SSL certificate verification.
            timeout: Connection timeout in seconds.
        Raises:
            PyMISPError: If connection to MISP fails.
        """
        self.url = url
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.client: PyMISP | None = None

        if not url or not api_key:
            logger.warning("MISP URL or API key not configured - MISP client disabled")
            return

        try:
            self.client = PyMISP(url, api_key, verify_ssl, timeout=timeout)
            logger.info(f"MISP client initialized: {url}")
        except PyMISPError as e:
            raise PyMISPError(f"MISP client init failed: {e}") from e

    def is_available(self) -> bool:
        """Check if MISP client is available and connected."""
        return self.client is not None

    def search_ioc(self, ioc_type: str, value: str | list[str], additional_params: dict[str, Any] = None) -> list[MISPAttribute]:
        """
        Search MISP for IOCs of a given type.

        The search timeframe, result limit and warninglist enforcement can be set in the
        configuration file or by the caller. If not set, the search defaults to events in
        the last 7 days, without a limit of 1000 results returned, and excludes
        attributes found in enabled warninglists in the MISP instance.

        Args:
            ioc_type: MISP attribute type (e.g., 'ip-src', 'ip-dst', 'domain', 'target-user').
            value: IOC value, or list of values, to search for. MISP matches any of the
                values given in a list, so a whole list is resolved in a single request.
            additional_params: Additional MISP search parameters. Recognized keys are
                'event_timestamp', 'limit' and 'enforce_warninglist'.
        Returns:
            List of MISPAttribute objects matching the search criteria, including
            the containing MISP Event.

        Raises:
            PyMISPError: If search fails.
        """
        params = additional_params or {}

        try:
            search_params = {
                "controller": "attributes",
                "type_attribute": ioc_type,
                "value": value,
                "include_sightings": True,
                "include_context": True,
                "include_event_tags": True,
                "enforce_warninglist": params.get("enforce_warninglist", True),
                "event_timestamp": params.get("event_timestamp", DEFAULT_EVENT_TIMESTAMP),
                "limit": params.get("limit", DEFAULT_SEARCH_RESULT_LIMIT),
                "pythonify": True
            }

            results = self.client.search(**search_params)
            return results
        except PyMISPError as e:
            logger.error(f"MISP search failed for {ioc_type}={value}: {e}")
            raise

    def bulk_search_iocs(
            self, 
            iocs: dict[str, list[str]], 
            extra_search_params: dict[str, Any] = None,
            core_ioc_types: set[str] | None = None,
            min_att_per_ev: int | None = None,
        ) -> list[EventData]:
        """
        Perform searches for IOCs across multiple attribute types.

        Args:
            iocs: Dictionary associating MISP attribute types to lists of values to be searched for.
                  Example: {"ip-src": ["1.2.3.4", "5.6.7.8"], "domain": ["evil.com"]}
            extra_search_params: Additional parameters for the MISP search. The number of
                values searched per attribute type is capped by 'max_values_per_type'.
            core_ioc_types: Attribute types whose match makes a found event relevant.
                If None, no attribute type is deemed relevant on its own.
            min_att_per_ev: Number of matched attributes a found event must exceed to
                be relevant. If None, the number of attributes is not considered.

        Returns:
            Aggregated list of EventData objects with deduplication by event_id,
            restricted to the events deemed relevant.
        """
        max_values = (extra_search_params or {}).get(
            "max_values_per_type", DEFAULT_MAX_VALUES_PER_TYPE
        )
        all_attrs = []

        for ioc_type, values in iocs.items():
            search_list = self._prepare_search_values(ioc_type, values, max_values)
            if not search_list:
                continue
            try:
                attributes_found = self.search_ioc(ioc_type, search_list, extra_search_params)
                all_attrs.extend(attributes_found)
            except PyMISPError as e:
                logger.warning(f"Failed to search {len(search_list)} value(s) of type {ioc_type}: {e}")
                continue

        if not all_attrs:
            logger.info(f"No events found for IOCs of type: {list(iocs.keys())}")
            return []

        # Group attributes by event_id (key)
        events_dict: dict[int, tuple[MISPEvent, list[MISPAttribute]]] = {}
        for attr in all_attrs:
            event_id = attr.event_id
            if event_id not in events_dict:
                events_dict[event_id] = (attr.Event, [])
            events_dict.get(event_id)[1].append(attr)

        selected_events = self.filter_relevant_events(
            events_dict, relevant_att=core_ioc_types, min_att_num=min_att_per_ev)

        # Convert to EventData
        event_data_list = self._misp_to_decipher_data(selected_events.values())
        logger.debug(
            f"Found {len(event_data_list)} MISP events across {len(iocs)} IOC types"
        )
        return event_data_list

    @staticmethod
    def filter_relevant_events(
        events: dict[int, tuple[MISPEvent, list[MISPAttribute]]],
        relevant_att: set[str] | None = None,
        min_att_num: int | None = None,
    ) -> dict[int, tuple[MISPEvent, list[MISPAttribute]]]:
        """
        Select the events holding attributes considered relevant.

        An event is kept if it holds at least one attribute of a type in
        `relevant_att` or if it holds more than `min_att_num` attributes. The
        criteria are optional and combined disjunctively; if none is given, no
        filtering is applied.

        Args:
            events: Mapping of event id to the MISP event and the attributes
                found for it.
            relevant_att: MISP attribute types (e.g. 'ip-src') making an event
                relevant. If None, no type is deemed relevant on its own.
            min_att_num: Number of attributes an event must exceed to be
                relevant. If None, the number of attributes is not considered.

        Returns:
            The entries of `events` meeting at least one criterion, in the
            input order. The input mapping itself if no criterion is given.
        """
        if relevant_att is None and min_att_num is None:
            return events

        relevant_types = relevant_att or set()

        return {
            event_id: (event, attributes)
            for event_id, (event, attributes) in events.items()
            if (min_att_num is not None and len(attributes) > min_att_num)
            or any(attr.type in relevant_types for attr in attributes)
        }

    @staticmethod
    def _prepare_search_values(ioc_type: str, values: list[str], max_values: int) -> list[str]:
        """
        Prepare a list of values of one attribute type for a single MISP search.

        Blank values are discarded and duplicates removed. If the size of the list exceeds
        the max_values number, the list is pruned to bound the requested size and
        any discarded value is logged.

        Args:
            ioc_type: MISP attribute type the values belong to, used for logging.
            values: Values reported for that attribute type.
            max_values: Maximum number of values to search for.

        Returns:
            The values to search for, in reporting order.
        """
        unique = list(dict.fromkeys(value for value in values if value and value.strip()))

        if len(unique) > max_values:
            logger.warning(
                f"{len(unique)} values of type {ioc_type} exceed the limit of {max_values} "
                f"per search. Ignoring: {unique[max_values:]}"
            )
            unique = unique[:max_values]

        return unique

    def check_warninglists(self, values: list[str]) -> dict[str, list[str]]:
        """
        Check IOC values against MISP's enabled warninglists.

        Args:
            values: IOC values to check (e.g. IP addresses).

        Returns:
            Mapping of each matched value to the names of the warninglists it
            appears in. Values with no match are omitted.

        Raises:
            PyMISPError: If the warninglist check fails.
        """
        if not values:
            return {}

        try:
            response = self.client.values_in_warninglist(values)
        except PyMISPError as e:
            logger.error(f"Warninglist check failed for {values}: {e}")
            raise

        # MISP answers with an empty list, not a dict, when no value matches
        if not response:
            return {}

        if not isinstance(response, dict):
            logger.warning(f"Unexpected warninglist response format: {response}")
            return {}

        return {
            value: [entry.get("name") for entry in matches if entry.get("name")]
            for value, matches in response.items()
            if matches
        }

    def search_object_matches(
        self,
        misp_object_type: str,
        values: list[str],
        matching_att: str | None = None,
        out_info: set[str] | None = None
    ) -> dict[str, list[str]]:
        """
        Search MISP for objects of a given type referencing the given values.

        A MISP object search matches a value in any attribute of the object,
        so `matching_att` is used to restrict the match to a single attribute.

        Args:
            misp_object_type: Name of the MISP object template (e.g. 'research-scanner').
            values: Values to look up (e.g. IP addresses or hostnames).
            matching_att: Object's attribute (e.g. 'scanning_ip') where the value must appear. 
                If None, a match in any attribute of the object is accepted.
            out_info: Object's attributes (e.g. 'project') to report for each matched
                object. Reported in alphabetical order. If None, no information is
                reported and matched objects are represented by an empty string.

        Returns:
            Mapping of each matched value to the information reported for the
            objects it matched. One entry per matched object, formatted as
            "ATTRIBUTE - value(s)" pairs separated by '; '.

        Raises:
            PyMISPError: If the search fails.
        """
        scanners = {}

        for value in values:
            matches: list[str] = []
            matched_uuids: set[str] = set()
            try:
                objects = self.client.search(
                    controller="objects",
                    object_name=misp_object_type,
                    value=value,
                    pythonify=True
                )
            except PyMISPError as e:
                logger.error(f"{misp_object_type} search failed for {value}: {e}")
                raise

            for obj in objects:
                if obj.uuid in matched_uuids:
                    continue
                # This post-search filter is needed because misp's search ignores 
                # the 'type_attribute' parameter when using the controller "objects"
                # A more costly solution but a workaround for the buggy parameter
                if self._matches_attribute(obj, value, matching_att):
                    matched_uuids.add(obj.uuid)
                    matches.append(self._format_object_info(obj, out_info))

            if matches:
                scanners[value] = matches

        logger.debug(f"Found '{misp_object_type}' objects for {list(scanners)}")
        return scanners

    @staticmethod
    def _format_object_info(
        misp_object: MISPObject, out_info: set[str] | None = None
    ) -> str:
        """
        Report the values held by the given attributes of a MISP object.

        Args:
            misp_object: Object to read the attributes from.
            out_info: Object's attributes to report, taken in alphabetical order
                so that the result does not depend on the set iteration order.

        Returns:
            "ATTRIBUTE - value(s)" pairs separated by '; '. Attributes absent from
            the object are skipped. Empty string if no attribute is reported.
        """
        info = []
        for relation in sorted(out_info or ()):
            att_values = [
                attr.value
                for attr in misp_object.get_attributes_by_relation(relation)
                if attr.value
            ]
            if att_values:
                info.append(f"{relation.upper()} - {', '.join(att_values)}")

        return "; ".join(info)

    @staticmethod
    def _matches_attribute(
        misp_object: MISPObject, value: str, matching_att: str | None = None
    ) -> bool:
        """Check whether the value is held by the given attribute of the object.

        A `matching_att` of None accepts the value in any attribute.
        """
        attributes = (
            misp_object.attributes
            if matching_att is None
            else misp_object.get_attributes_by_relation(matching_att)
        )
        return any(attr.value == value for attr in attributes)

    def _extract_attribute_cti_data(self, attribute: MISPAttribute) -> dict:
        """Extract relevant analysis data from a MISPAttribute object."""
        return {
            "id": attribute.id,
            "value": attribute.value,
            "type": attribute.type,
            "category": attribute.category,
            "to_ids": attribute.to_ids,
            "event_id": attribute.event_id,
            "timestamp": (
                attribute.timestamp.isoformat()
                if hasattr(attribute, "timestamp")
                else None
            ),
            "comment": getattr(attribute, "comment", ""),
            "tags": [tag.name for tag in getattr(attribute, "Tag", [])],
            "true_positive_sightings": self._count_positive_sightings(
                attribute.sightings
            ),
            "false_positive_sightings": self._count_false_positive_sightings(
                attribute.sightings
            ),
        }

    def _misp_to_decipher_data(
        self, grouped_attributes: tuple[MISPEvent, list[MISPAttribute]]
    ) -> list[EventData]:
        """
        Convert grouped MISPAttribute objects to EventData format.

        Args:
            grouped_attributes: Iterable of (MISPEvent, list[MISPAttribute]) tuples

        Returns:
            List of EventData objects ready for scoring engine.
        """
        event_data_list = []
        logger.debug(f"--- Converting: {grouped_attributes}---")
        try:
            for event, attributes in grouped_attributes:
                # Extract event-level fields
                threat_level = self._to_scoring_threat_level(event.threat_level_id)
                analysis = self._to_scoring_analysis(event.analysis)

                # Check for MITRE ATT&CK tags at event level
                event_tags = [tag.name for tag in getattr(event, "Tag", [])]
                logger.debug(f"Tags: {event_tags}")
                has_mitre_threat_tags = any("mitre-attack-pattern" in tag or "mitre-intrusion-set" in tag for tag in event_tags)

                # Convert attributes - extract Admiralty tags from each attribute
                attribute_data_list = []
                for attr in attributes:
                    # Extract sightings from attribute
                    sightings = Sightings(
                        true_positives=self._count_positive_sightings(
                            getattr(attr, "sightings", [])
                        ),
                        false_positives=self._count_false_positive_sightings(
                            getattr(attr, "sightings", [])
                        ),
                    )

                    attribute_data_list.append(
                        AttributeData(
                            value=attr.value,
                            type=attr.type,
                            sightings=sightings,
                            admiralty=self._extract_admiralty_from_tags(
                                getattr(attr, "Tag", [])
                            ),
                        )
                    )

                # Ensure at least one attribute
                if not attribute_data_list:
                    attribute_data_list.append(AttributeData())

                event_data_list.append(
                    EventData(
                        id=int(event.id),
                        threat_level=threat_level,
                        analysis=analysis,
                        admiralty=AdmiraltyTags(),
                        attributes=attribute_data_list,
                        has_mitre_tags=has_mitre_threat_tags,
                    )
                )
        except Exception as e:
            logger.error(f"Failed to convert MISP objects to EventData: {e}")
            return []

        return event_data_list

    @staticmethod
    def _extract_admiralty_from_tags(tags: list) -> AdmiraltyTags:
        """
        Extract Admiralty scale tags from a list of MISPTag objects.
        Admiralty tags from the event are used if existing and if the attribute
        has no Admiralty tags of its own.
        """
        admiralty = AdmiraltyTags()
        no_att_sr = True
        no_att_ic = True

        for tag in tags:
            tag_name = str(tag.name).lower()

            if "admiralty-scale:source-reliability=" in tag_name and no_att_sr:
                sr_value = (
                    tag_name.split("admiralty-scale:source-reliability=")[-1]
                    .strip('"')
                    .lower()
                )
                if sr_value:
                    try:
                        admiralty.source_reliability = SourceReliability(sr_value)
                    except ValueError:
                        logger.debug(f"Invalid source_reliability value: {sr_value}")
                # Flag if we found the sr from the attribute; 'inherited' tags come from the event
                if getattr(tag, "inherited", "0") == "0":
                    no_att_sr = False

            elif "admiralty-scale:information-credibility=" in tag_name and no_att_ic:
                ic_value = (
                    tag_name.split("admiralty-scale:information-credibility=")[-1]
                    .strip('"')
                    .lower()
                )
                if ic_value:
                    try:
                        admiralty.info_credibility = InfoCredibility(ic_value)
                    except ValueError:
                        logger.debug(f"Invalid info_credibility value: {ic_value}")
                # Flag if we found the ic from the attribute
                if getattr(tag, "inherited", "0") == "0":
                    no_att_ic = False

        return admiralty

    @staticmethod
    def _count_positive_sightings(sightings: list[MISPSighting]) -> int:
        """Count the number of positive sightings in a list of MISPSighting objects."""
        if not sightings:
            return 0
        return sum(1 for s in sightings if s.type == "0")

    @staticmethod
    def _count_false_positive_sightings(sightings: list[MISPSighting]) -> int:
        """Count the number of false positive sightings in a list of MISPSighting objects."""
        if not sightings:
            return 0
        return sum(1 for s in sightings if s.type == "1")

    @staticmethod
    def _to_scoring_threat_level(level_id: str | int) -> ThreatLevel:
        """Convert MISP threat level ID to DECIPHER ThreatLevel."""
        threat_levels = {
            "1": ThreatLevel.HIGH,
            "2": ThreatLevel.MEDIUM,
            "3": ThreatLevel.LOW,
            "4": ThreatLevel.UNDEFINED,
        }
        return threat_levels.get(str(level_id), ThreatLevel.UNDEFINED)

    @staticmethod
    def _to_scoring_analysis(analysis_id: str | int) -> AnalysisStage:
        """Convert MISP analysis status ID to DECIPHER AnalysisStage."""
        analysis_statuses = {
            "0": AnalysisStage.INITIAL,
            "1": AnalysisStage.ONGOING,
            "2": AnalysisStage.COMPLETED,
        }
        return analysis_statuses.get(str(analysis_id), AnalysisStage.INITIAL)


# Module-level client instance (lazy initialization)
_misp_data_extractor_instance: MISPDataExtractor | None = None


def get_misp_extractor() -> MISPDataExtractor | None:
    """
    Get or create the shared MISP data extractor instance.

    Returns:
        MISPDataExtractor instance if configured, None otherwise.
    """
    global _misp_data_extractor_instance

    if _misp_data_extractor_instance is None:
        try:
            _misp_data_extractor_instance = MISPDataExtractor(
                MISP_URL, MISP_API_KEY, MISP_VERIFY_SSL, MISP_TIMEOUT
            )
        except PyMISPError as e:
            logger.error(f"Failed to create MISP data extractor. {e}")
            return None

    return _misp_data_extractor_instance
