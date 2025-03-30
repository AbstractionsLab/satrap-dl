"""Constants for the extractor."""

from datetime import datetime, timezone


DOWNLOADER = "download"
STIX_READER = "read_stix"
STIX_BUNDLE_OBJECTS = "objects"
OVERRIDE = "override"
TARGET = "target"
BASE_TIME = datetime(1970, 1, 1, 0, 0, 0, 0).astimezone(timezone.utc)

# Logging messages
DOWNLOAD_START = "Start download"
DOWNLOAD_SUCCESS = "Download successful"
DOWNLOAD_FAILED = "Download failed: %s"
DOWNLOAD_NO_TARGET = "No target file specified"

READ_STIX_START = "Reading STIX source: %s"
READ_STIX_FAILED = "Reading of STIX source failed: %s"
READ_STIX_SUCCESS = "Successful fetching of STIX objects from %s"
READ_STIX_NO_OBJECTS = "Read STIX Object is either no bundle or does not have objects property"
