import inspect
import re
from satrap.commons.log_utils import LOG_NEWLINE


class ExtractionError(Exception):
    """
    Exception raised for errors occurring during the extraction process.
    """
    DOWNLOAD_NO_TARGET = 101
    FAILED_DOWNLOAD = 102
    STIX_FILE_READ_FAILED = 103
    EMPTY_STIX_FILE_READ = 104
    STIX_PARSING_FAILED = 105

    ERROR_MESSAGES = {
        FAILED_DOWNLOAD: "Download failed",
        DOWNLOAD_NO_TARGET: "No target storage file specified",
        STIX_FILE_READ_FAILED: "Reading of STIX source failed",
        EMPTY_STIX_FILE_READ: "The STIX Object is not a bundle or has no 'objects' property",
        STIX_PARSING_FAILED: "Parsing of STIX datasource failed"
    }

    def __init__(self, error_code, message=None, datasrc=None, class_origin=None):
        """
        Constructor for the ExtractionError class.

        :param error_code: The error code representing the type of error.
        :type error_code: int
        :param message: Custom error message appended to the default error message
            that corresponds to the error_code; defaults to None
        :type message: str, optional
        :param datasrc: The data source where the error occurred, defaults to None
        :type datasrc: str, optional
        :param class_origin: The class where the error originated, defaults to None
        :type class_origin: str, optional
        """
        self.error_code = error_code

        # Get the name of the calling method
        method_origin = inspect.stack()[1].function
        # Get the name of the class if it is not None, 0, False,
        # an empty list, string or dictionary, or other "falsy" value
        if class_origin:
            method_origin = f"{class_origin}.{method_origin}"
        self.origin_info = f"{method_origin} extracting from {datasrc}" if datasrc else method_origin

        self.message = self.ERROR_MESSAGES.get(error_code, "Unknown extraction error.")
        if message:
            self.message = f"{self.message}{LOG_NEWLINE}{message}"

        super().__init__(self.message)

    def __str__(self):
        return f"[Error-{self.error_code}] in {self.origin_info}: {self.message}"


class MappingException(Exception):
    """Exceptions occurring during the mapping of STIX objects"""

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"[Invalid mapping] {self.message}"


class TransformationError(Exception):
    """Exceptions occurred during the transformation of STIX Objects"""
    MISSING_REQUIRED_PROPERTY = 201
    UNSPECIFIED_PROPERTY = 202
    UNSUPPORTED_CUSTOM_TYPE = 203
    INVALID_PROPERTY_VALUE = 204
    INVALID_PROPERTY_TYPE = 205
    GENERIC_ERROR = 206

    ERROR_MESSAGES = {
        MISSING_REQUIRED_PROPERTY: "Missing required property in STIX object",
        UNSPECIFIED_PROPERTY: "Property not specified",
        UNSUPPORTED_CUSTOM_TYPE: "The STIX object has an unsupported custom type",
        INVALID_PROPERTY_VALUE: "Invalid value for property",
        INVALID_PROPERTY_TYPE: "Invalid type for property",
        GENERIC_ERROR: "An error occurred during the transformation of the STIX object"
    }

    def __init__(self, error_code: int, message=None, reference_id=""):
        self.error_code = error_code
        self.reference_id = reference_id
        self.message = self.ERROR_MESSAGES.get(error_code, "Unknown transformation error")
        if message:
            self.message = f"{self.message}: {message}"
        super().__init__(self.message)

    def __str__(self):
        origin = f"In STIX object '{self.reference_id}': " if self.reference_id else ""
        return f"[TransformationError] {origin}{self.message}"


class LoadingError(Exception):
    """
    Exception raised for errors occurring during the loading process.
    """

    def __init__(self, err, failed_query, batch_size):
        self.batch_size = batch_size
        if "[THW08]" in err:
            pattern = r"'(.*?)'"
            matches = re.findall(pattern, err)
            self.message = (
                f"[THW08] Referenced STIX objects of type '{matches[0]}' are not valid "
                f"for the property '{matches[1].split(':')[0]}'")
        else:
            self.message = err

        self.message += f"{LOG_NEWLINE}Failed query:\n{failed_query}"

        super().__init__(self.message)

    def __str__(self):
        if self.batch_size == 1:
            intro = "Insert query skipped"
        else:
            intro = f"Fail loading batch of {self.batch_size} queries"
        intro += " due to a TypeDB insertion error"

        return f"[LoadingError] {intro}.{LOG_NEWLINE}{self.message}"


class STIXParsingError(Exception):
    """Exceptions occurred during the parsing of STIX Objects
    from a JSON file.
    """

    def __init__(self, original_exception: TransformationError, datasrc=None, class_origin=None):
        # Get the type of the exception
        self.err_type = type(original_exception).__name__

        # Get the name of the calling method
        method_origin = inspect.stack()[1].function
        # Get the name of the class if it is not None, 0, False,
        # an empty list, string or dictionary, or other "falsy" value
        if class_origin:
            method_origin = f"{class_origin}.{method_origin}"
        self.origin_info = f"{method_origin} from datasource '{datasrc}'" if datasrc else method_origin

        self.message = f"STIX parsing error:{LOG_NEWLINE} {original_exception}"

        super().__init__(self.message)

    def __str__(self):
        return f"[{self.err_type}] in {self.origin_info}. {self.message}"
