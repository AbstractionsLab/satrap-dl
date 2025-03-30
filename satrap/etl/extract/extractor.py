from abc import ABC, abstractmethod
from typing import Any

from stix2 import parse
from stix2.utils import get_timestamp, parse_into_datetime, format_datetime
from stix2.exceptions import STIXError
from requests import HTTPError

from satrap.commons.log_utils import logger
from satrap.commons.file_utils import download_file
from satrap.etl import stix_constants
from satrap.etl.exceptions import ExtractionError, STIXParsingError
import satrap.etl.extract.extract_constants as constants


class Extractor(ABC):
    """Extracts data from diverse datasources.
    """

    @staticmethod
    def get_extractor(extract_type: str):
        """Returns an extractor suitable for a given type of extraction.

        :param extract_type: the type of extraction, e.g. download, read_stix
        :type extract_type: str

        :raises ValueError: If the given extraction type is not defined

        :return: the corresponding extractor implementation
        :rtype: Extractor
        """
        logger.debug("Get extractor for: %s", extract_type)
        factory = {
            constants.DOWNLOADER: Downloader(),
            constants.STIX_READER: STIXExtractor()
        }
        if extract_type in factory:
            return factory[extract_type]

        raise ValueError(f"Unknown extraction type: '{extract_type}'")

    @abstractmethod
    def fetch(self, src, **kwargs) -> Any:
        """Fetches the data from 'src'.

        :param src: the source of the data
        """
        pass


class Downloader(Extractor):
    """Downloader.

    Fetches the data by downloading and saving them.
    """

    def fetch(self, src: str, **kwargs):
        """Downloads the data.

        :param src: the url of the file that is to be downloaded
        :type src: str
        :param target: the filepath of the file where to store the data
        :type target: str

        :raises ExtractionError: If the download failed
        """
        logger.debug(constants.DOWNLOAD_START)

        target = kwargs.get(constants.TARGET)
        if not target:
            raise ExtractionError(ExtractionError.DOWNLOAD_NO_TARGET, message=f"for file {src}", class_origin=__name__)

        override = False
        if kwargs.get(constants.OVERRIDE) == True:
            override = True

        try:
            download_file(
                src,
                target,
                override
            )
        except (ValueError, HTTPError) as e:
           raise ExtractionError(ExtractionError.FAILED_DOWNLOAD, e, src, __name__) from e
        logger.info(constants.DOWNLOAD_SUCCESS)


class STIXExtractor(Extractor):
    """STIXExtractor.

    Read and parse a STIX source file and return the objects.
    """

    def replace_attribute(self, stix_obj, attribute: str, new_value):
        """Replaces a value in a STIX Object.

        :param stix_obj: The STIX Object whose attribute value should
            be overridden
        :param attribute: The name of the attribute
        :type attribute: str
        :param new_value: The value that replaces the old value
        :type new_value: Any

        :return: The STIX Object with the replaced attribute
        """
        # TODO: For the docstring, find the super type for stix2
        #       STIX Objects.
        stix_dict = dict(stix_obj)
        stix_dict.update({attribute: new_value})
        return parse(stix_dict, allow_custom=True, version="2.1")

    def adapt_stix_object(self, stix_object, **kwargs):
        """Adapt the STIX objects such that they follow defined rules.

        :param stix_object: The STIX object

        :return: The adapted STIX Object
        """
        # TODO: This could also be a task for another transformer.
        base_time = format_datetime(
            parse_into_datetime(constants.BASE_TIME)
        )
        start = kwargs.get("start")

        # add x509_v3_extension_type to the extensions
        x509_extension = stix_object.get(
            stix_constants.STIX_PROPERTY_X509_V3_EXTENSIONS
        )
        if x509_extension:
            stix_dict = dict(stix_object)
            stix_dict.update({
                stix_constants.STIX_PROPERTY_EXTENSIONS: {
                    stix_constants.STIX_PROPERTY_X509_V3_EXTENSIONS:
                    x509_extension
                }
            })
            stix_dict.pop(stix_constants.STIX_PROPERTY_X509_V3_EXTENSIONS)
            stix_object = parse(stix_dict, allow_custom=True, version="2.1")

        # set the default timestamp for created if not given
        created = stix_object.get(stix_constants.STIX_PROPERTY_CREATED)
        if created:
            created = parse_into_datetime(created)
            if created >= start:
                stix_object = self.replace_attribute(
                    stix_object,
                    stix_constants.STIX_PROPERTY_CREATED,
                    base_time
                )

        # set the default timestamp for modified if not given
        modified = stix_object.get(stix_constants.STIX_PROPERTY_MODIFIED)
        if modified:
            modified = parse_into_datetime(modified)
            if modified >= start:
                stix_object = self.replace_attribute(
                    stix_object,
                    stix_constants.STIX_PROPERTY_MODIFIED,
                    base_time
                )

        return stix_object

    def adapt_meta_object(self, meta_object):
        """Adapt a STIX meta object in agreement with the predefined JSON mapping 
        file for SMOs.

        :param meta_object: The SMO to be adapted if needed
        """
        definition = meta_object.get(
            stix_constants.STIX_PROPERTY_MARKING_DEF_DEFINITION
        )
        if definition:
            stix_dict = dict(meta_object)

            marking_type = meta_object.get("definition_type")
            if marking_type not in ["statement", "tlp"]:
                raise STIXParsingError(f"The 'definition_type' in '{meta_object.get('id')}' \
                                       SHOULD be one of: statement or tlp")

            stix_dict.update({
                stix_constants.STIX_PROPERTY_EXTENSIONS: {
                    f"definition-{marking_type}": definition
                }
            })
            meta_object = parse(stix_dict, allow_custom=True, version="2.1")

        return meta_object

    def fetch(self, src: str, **kwargs):
        """Reads the STIX 2.1 data from a JSON file.

        :param src: The filepath where to read the data from
        :type src: str

        :raises ExtractionError: If the STIX source is invalid

        :return: The STIX Objects
        :rtype: Result
        """
        logger.debug(constants.READ_STIX_START, src)
        start = get_timestamp()

        try:
            with open(src, encoding="utf-8") as file:
                # 'parse' uses by default the latest version of STIX (here 2.1);
                # for a different version see https://stix2.readthedocs.io/en/latest/guide/ts_support.html
                stix_bundle = parse(file, allow_custom=True, version="2.1")
        except STIXError as e:
            raise STIXParsingError(e, src, class_origin=__name__) from e
        except Exception as e:
            raise ExtractionError(ExtractionError.STIX_FILE_READ_FAILED, e, src, __name__) from e

        objects = stix_bundle.get(stix_constants.STIX_PROPERTY_BUNDLE_OBJECTS)
        if objects is None:
            raise ExtractionError(
                ExtractionError.EMPTY_STIX_FILE_READ, e, src, __name__
            )

        logger.info(constants.READ_STIX_SUCCESS, src)

        for stix_object in objects:
            # logger.debug(f"Adapting STIX object {stix_object}\n")
            stix_object = self.adapt_stix_object(
                stix_object,
                start=start,
            )
            stix_object = self.adapt_meta_object(stix_object)
            yield stix_object
