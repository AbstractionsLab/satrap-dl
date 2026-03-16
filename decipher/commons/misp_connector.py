"""
Provides a class for querying MISP threat intelligence platform.
Supports IOC lookups, event correlation, and bulk searches.
"""

from typing import Any

from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute, MISPSighting, PyMISPError

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


class MISPDataExtractor:
    """
    Client for interacting with MISP threat intelligence platform.

    Provides methods for IOC searches, event correlation, and bulk queries.
    Handles connection management and error recovery gracefully.

    Attributes:
        url: MISP instance URL.
        api_key: MISP API authentication key.
        verify_ssl: Whether to verify SSL certificates.
        client: Underlying ExpandedPyMISP client instance.
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
        self.client: ExpandedPyMISP | None = None

        if not url or not api_key:
            logger.warning("MISP URL or API key not configured - MISP client disabled")
            return

        try:
            self.client = ExpandedPyMISP(url, api_key, verify_ssl, timeout=timeout)
            logger.info(f"MISP client initialized: {url}")
        except PyMISPError as e:
            raise PyMISPError(f"MISP client init failed: {e}") from e

    def is_available(self) -> bool:
        """Check if MISP client is available and connected."""
        return self.client is not None

    def search_ioc(self, ioc_type: str, value: str, additional_params: dict[str, Any] = None) -> list[MISPAttribute]:
        """
        Search MISP for a specific IOC by type and value. Attributes in enabled warninglists are excluded from the results.
        
        The search timeframe and result limit can be set in the configuration file. If not set, 
        the search defaults to events in the last 15 days without limit on the number of results
        returned.

        Args:
            ioc_type: MISP attribute type (e.g., 'ip-src', 'ip-dst', 'domain', 'target-user').
            value: IOC value to search for.
            additional_params: Additional MISP search parameters.
        Returns:
            List of MISPAttribute objects matching the search criteria, including
            the containing MISP Event.

        Raises:
            PyMISPError: If search fails.
        """
        try:
            search_params = {
                "controller": "attributes",
                "type_attribute": ioc_type,
                "value": value,
                "include_sightings": True,
                "include_context": True,
                "include_event_tags": True,
                "enforce_warninglist": True,
                "pythonify": True
            }

            if additional_params is not None:
                search_params["event_timestamp"] = additional_params.get("event_timestamp", "15d")
                search_params["limit"] = additional_params.get("limit", None)

            results = self.client.search(**search_params)
            return results
        except PyMISPError as e:
            logger.error(f"MISP search failed for {ioc_type}={value}: {e}")
            raise

    def bulk_search_iocs(self, iocs: dict[str, list[str]], extra_search_params: dict[str, Any] = None) -> list[EventData]:
        """
        Perform searches for IOCs across multiple attribute types.

        Args:
            iocs: Dictionary associating MISP attribute types to lists of values to be searched for.
                  Example: {"ip-src": ["1.2.3.4", "5.6.7.8"], "domain": ["evil.com"]}
            extra_search_params: Additional parameters for the MISP search.

        Returns:
            Aggregated list of EventData objects with deduplication by event_id.
        """
        all_attrs = []

        for ioc_type, values in iocs.items():
            for value in values:
                try:
                    attributes_found = self.search_ioc(ioc_type, value, extra_search_params)
                    all_attrs.extend(attributes_found)
                except PyMISPError as e:
                    logger.warning(f"Failed to search {ioc_type}={value}: {e}")
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

        # Convert to EventData
        event_data_list = self._misp_to_decipher_data(events_dict.values())
        logger.debug(
            f"Found {len(event_data_list)} MISP events across {len(iocs)} IOC types"
        )
        return event_data_list

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
