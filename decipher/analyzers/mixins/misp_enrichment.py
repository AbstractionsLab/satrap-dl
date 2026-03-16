"""
MISP enrichment mixin for analyzers that work with IOCs.

Provides reusable methods for IOC lookups and event correlation.
"""

from typing import Any

from decipher.commons.misp_connector import MISPDataExtractor, get_misp_extractor
from decipher.commons.log_utils import get_logger
from decipher.scoringengine.datamodels import EventData


logger = get_logger(__name__)


class MISPEnrichmentMixin:
    """
    Mixin providing MISP threat intelligence enrichment capabilities.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._misp_client: MISPDataExtractor | None = None

    @property
    def misp_client(self):
        """
        Lazy-initialized MISP extractor to avoid unnecessary
        initialization when MISP searches are disabled.

        Raises:
            UnavailableMISPClientError: If the MISP client cannot be reached or is not configured.
        """
        if self._misp_client is None:
            self._misp_client = get_misp_extractor()
        if not self._misp_client or not self._misp_client.is_available():
            raise UnavailableMISPClientError()
        return self._misp_client

    def search_iocs_in_misp(
        self,
        ioc_mapping: dict[str, list[str]],
        extra_search_params: dict[str, Any] = None,
    ) -> list[EventData]:
        """
        Enrich IOCs with MISP threat intelligence.

        Performs bulk IOC searches across MISP and returns EventData objects
        ready for the scoring engine.

        Args:
            ioc_mapping: Dictionary mapping MISP attribute types to values.
                Example: {
                    "ip-src": ["1.2.3.4", "5.6.7.8"],
                    "ip-dst": ["192.168.1.1"],
                    "domain": ["evil.com"],
                    "md5": ["abc123..."],
                    "target-user": ["admin"]
                }
            extra_search_params: Optional dictionary of additional MISP search parameters

        Returns:
            List of EventData objects ready for scoring engine. Empty list if MISP no matches found

        Raises:
            UnavailableMISPClientError: If the MISP client is not available.
            MISPEnrichmentError: If any error occurs during MISP enrichment (e.g. API errors, parsing issues).
        """
        try:
            logger.debug(f"Searching MISP for IOC types: {list(ioc_mapping.keys())}")
            event_data = self.misp_client.bulk_search_iocs(
                ioc_mapping, extra_search_params
            )
            logger.debug(f"MISP search returned {len(event_data)} events")
            return event_data
        except UnavailableMISPClientError:
            raise
        except Exception as e:
            logger.error(f"MISP enrichment failed: {e}")
            raise MISPEnrichmentError(f"MISP enrichment failed: {e}") from e


class MISPEnrichmentError(Exception):
    """Custom exception for MISP enrichment errors."""
    pass


class UnavailableMISPClientError(MISPEnrichmentError):
    """Raised when the MISP client is unavailable."""

    def __init__(self):
        super().__init__("MISP client unavailable or incorrectly configured.")
