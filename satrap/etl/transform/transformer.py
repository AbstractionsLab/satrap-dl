from abc import ABC, abstractmethod

from jsonschema import ValidationError, SchemaError

from satrap.settings import EXEC_ENVIRONMENT
from satrap.etl.exceptions import MappingException
from satrap.etl.transform import log_messages
from satrap.etl.transform.stix_to_typedb_mapper import STIXtoTypeDBMapper
from satrap.etl.exceptions import TransformationError
from satrap.etl.transform.stixobject_converter import STIXObjectConverter
from satrap.commons.log_utils import logger
from satrap.datamanagement.typedb.dataobjects import InsertQuery


class Transformer(ABC):
    """A transformer.

    Handles transformation of objects from one data format to another.
    """

    @abstractmethod
    def transform(self, src_object):
        """Transforms an object from one data format to another.

        :param object: The object that will be transformed
        """
        pass


class STIXtoTypeQLTransformer(Transformer):
    """A STIX2.1 to TypeQL Transformer.

    Transforms a STIX2.1 object represented in JSON format into 
    its TypeQL representation as per the schema of the SATRAP CTI SKB.
    """

    def transform(
        self, src_object: dict
    ) -> tuple[InsertQuery, InsertQuery, InsertQuery]:
        """Generates a triplet of insert queries in TypeQL 
        for inserting a STIX2.1 object in JSON format into 
        a TypeDB database that follows the SATRAP CTI SKB schema

        :param object: The JSON object that will be transformed
        :type object: dict or stix2 object

        :return: The TypeQL queries for inserting the STIX2.1 object
        """
        logger.debug(log_messages.START_TRANSFORM)

        # Read the mapping
        try:
            STIXtoTypeDBMapper.get_data(validate=True)
        except ValidationError as e:
            logger.error(log_messages.UNEXPECTED_EXCEPTION)
            logger.exception(e)
            return None
        except SchemaError as e:
            logger.error(log_messages.INVALID_SCHEMA)
            logger.exception(e)
            return None

        # Create the STIX Object
        try:
            stix_obj: STIXObjectConverter = STIXObjectConverter.create(src_object)
        except (MappingException, TransformationError) as e:
            logger.error("%s. %s",
                log_messages.STIX_OBJECT_CREATION_FAILED % src_object.get("id", "unknown"),
                e)
            return None
        except Exception as e:
            logger.error("%s. %s:\n%s",
                log_messages.STIX_OBJECT_CREATION_FAILED % src_object.get("id", "unknown"),
                log_messages.UNEXPECTED_EXCEPTION, e)
            return None

        # Transform
        try:
            queries = stix_obj.build_typeql_bundle()
            # order the query
            res = queries.order_bundle()
        except MappingException as e:
            logger.error("%s. %s",
                log_messages.BUILD_TYPEQL_FAILED % stix_obj.stix_id, e)
            return None
        except TransformationError as e:
            logger.error("%s. %s", log_messages.BUILD_TYPEQL_FAILED_TRANSF, e)
            return None
        except Exception as e:
            if EXEC_ENVIRONMENT == "dev":
                logger.exception("%s. \n%s",
                    log_messages.BUILD_TYPEQL_FAILED % stix_obj.stix_id, e)
            else:
                logger.error("%s. %s:\n%s", log_messages.UNEXPECTED_EXCEPTION,
                        log_messages.BUILD_TYPEQL_FAILED % stix_obj.stix_id, e)
            return None

        logger.debug(log_messages.TRANSFORMATION_COMPLETED, stix_obj.stix_id)
        return res
