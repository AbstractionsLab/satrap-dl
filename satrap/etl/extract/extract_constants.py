"""Constants for the extractor."""

from datetime import datetime, timezone

# Extractor types
DOWNLOADER = 1
MISP_EXTRACTOR = 2
STIX_READER = 3


# keyargs for fetching on different extractors
# Downloader:
TARGET = "target"
OVERRIDE = "override"
MAX_CONNECTION_TIME = "max_connection_time"
MAX_RESP_TIME = "max_resp_time"
# MISP:
MISP_APIKEY = "apikey"

BASE_TIME = datetime(1970, 1, 1, 0, 0, 0, 0).astimezone(timezone.utc)

# Logging messages
EXTRACT_SUCCESS = "Extraction successfully finished"

READ_STIX_START = "Reading STIX source: %s"
READ_STIX_FAILED = "Reading of STIX source failed: %s"
READ_STIX_SUCCESS = "STIX objects fetched from %s"
READ_STIX_NO_OBJECTS = "Read STIX Object is either no bundle or does not have 'objects'"

REQUIRED_ARG = "The required argument '%s' is missing"
