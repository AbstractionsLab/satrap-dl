"""
MISP enrichment mixin for analyzers that work with IOCs.

Provides reusable methods for IOC lookups and event correlation.
"""

from typing import Any

from decipher.commons.misp_connector import (
    BulkSearchResult,
    MISPDataExtractor,
    UnavailableMISPClientError,
    get_misp_extractor,
)
from decipher.commons.log_utils import get_logger


logger = get_logger(__name__)

SCANNER_OUT_ATTRIBUTES = {"project", "domain"}


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
            UnavailableMISPClientError: If the MISP client is not configured or
                cannot be initialized.
        """
        if self._misp_client is None:
            self._misp_client = get_misp_extractor()

        return self._misp_client

    def search_iocs_in_misp(
        self,
        ioc_mapping: dict[str, list[str]],
        extra_search_params: dict[str, Any] = None,
        core_ioc_types: set[str] | None = None,
        min_att_per_ev: int | None = None,
    ) -> BulkSearchResult:
        """
        Enrich IOCs with MISP threat intelligence.

        Performs bulk IOC searches across MISP and returns EventData objects
        ready for the scoring engine, together with a list of attribute types whose search failed.

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
            core_ioc_types: MISP events having any of this attribute types will be included.
                If None, this filter is ignored.
            min_att_per_ev: Minimun number of matched attributes an event must have to be
                included in the result. If None, this filter is ignored.

        Returns:
            Tuple with EventData objects ready for the scoring engine, and 
            the attribute types whose search failed. Empty list in case of
            no matches or no failures, respectively.

        Raises:
            UnavailableMISPClientError: If the MISP client is not available,
                cannot be reached, or rejects the credentials.
            MISPEnrichmentError: If an unknown error occurs during MISP enrichment (e.g. data format conversion).
        """
        try:
            logger.debug(f"Searching MISP for IOC types: {list(ioc_mapping.keys())}")
            search_result = self.misp_client.bulk_search_iocs(
                ioc_mapping, extra_search_params, core_ioc_types, min_att_per_ev
            )
            logger.debug(f"MISP search returned {len(search_result.events)} events")
            return search_result
        except UnavailableMISPClientError:
            raise
        except Exception as e:
            logger.error(f"MISP enrichment failed: {e}")
            raise MISPEnrichmentError(f"MISP enrichment failed: {e}") from e

    def identify_known_scanners(self, values: list[str]) -> dict[str,list[str]]:
        """
        Checks the given values against MISP warninglists and against
        `research-scanner` objects' `scanning_ip`, to identify values already
        known as benign/research scanning sources

        Args:
            values: IOC values to check (e.g. source IP addresses).

        Returns:
            Mapping of each matched value to the names of the warninglists and
            the research-scanner project/domain labels it was found in.

        Raises:
            UnavailableMISPClientError: If the MISP client is not available, MISP
                cannot be reached, or MISP rejects the credentials.
            MISPEnrichmentError: If any other error occurs during the lookup.
        """
        try:
            logger.debug(f"Checking known-scanner status for: {values}")
            warninglist_matches = self.misp_client.check_warninglists(values)
            scanner_matches = self.misp_client.search_object_matches(
                    "research-scanner", 
                    values, 
                    matching_att="scanning_ip", 
                    out_info=SCANNER_OUT_ATTRIBUTES)
        except UnavailableMISPClientError:
            raise
        except Exception as e:
            raise MISPEnrichmentError(f"Known-scanner identification failed: {e}") from e

        identified: dict[str, set[str]] = {}
        for source in (warninglist_matches, scanner_matches):
            for value, names in source.items():
                identified.setdefault(value, set()).update(names)

        return {value: sorted(names) for value, names in identified.items()}


class MISPEnrichmentError(Exception):
    """Custom exception for MISP enrichment errors."""
    pass
