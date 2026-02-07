import os

import satrap.etl.extract.extract_constants as extract_cts
from satrap.etl.extract.extractor import Extractor
from satrap.etl.transform.transformer import STIXtoTypeQLTransformer
from satrap.etl.load.loader import TypeDBLoader
from satrap.etl.exceptions import ExtractionError
from satrap import settings as conf
from satrap.commons.log_utils import logger


class ETLOrchestrator:
    """ETL Orchestrator for managing the Extract, Transform, and Load process."""

    def __init__(
        self,
        extractor_type,
        transformer_cls=STIXtoTypeQLTransformer,
        loader_cls=TypeDBLoader,
    ):
        """
        Initialize the ETL Orchestrator

        :param extractor_type: The type of data extractor from satrap.etl.extract.extract_constants.
        :param transformer_cls: The class responsible for data transformation.
        :param loader_cls: The class responsible for data loading.
        """
        self.extractor = Extractor.get_extractor(extractor_type)
        self.transformer_cls = transformer_cls
        self.loader_cls = loader_cls

    def extract(self, source, store_at, **kwargs):
        """Extract a datasource using the extractor of this class and store it in a selected path."""
        logger.info("Starting extraction from %s", source)
        if self.extractor.get_extractor_type() == extract_cts.DOWNLOADER:
            args = {
                extract_cts.TARGET: store_at,
                extract_cts.OVERRIDE: True,
                extract_cts.MAX_CONNECTION_TIME: kwargs.get(extract_cts.MAX_CONNECTION_TIME),
                extract_cts.MAX_RESP_TIME: kwargs.get(extract_cts.MAX_RESP_TIME)
            }
        elif self.extractor.get_extractor_type() == extract_cts.MISP_EXTRACTOR:
            args = {
                extract_cts.TARGET: store_at,
                extract_cts.MISP_APIKEY: kwargs.get(extract_cts.MISP_APIKEY)
            }
        else:
            raise ValueError("Unsupported or invalid extractor type")

        self.extractor.fetch(source, **args)
        logger.info("Extraction completed into %s", store_at)

    def transform(self, datasrc_path):
        """Transform the STIX objects in the file at the given path."""
        logger.info("Starting transformation")
        if self.extractor.get_extractor_type() == extract_cts.STIX_READER:
            stix_extractor = self.extractor
        else:
            stix_extractor = Extractor.get_extractor(extract_cts.STIX_READER)
        stix_objects = stix_extractor.fetch(datasrc_path)

        transformer = self.transformer_cls()
        entity_queries, sro_queries, embedded_relation_queries = [], [], []

        for stix_object in stix_objects:
            transformed = transformer.transform(stix_object)
            if transformed is None:
                continue

            entity_query, sro_query, embedded_relation_query = transformed
            if entity_query:
                entity_queries.append(entity_query)
            if sro_query:
                sro_queries.append(sro_query)
            if embedded_relation_query:
                embedded_relation_queries.append(embedded_relation_query)

        logger.info(
            "Transformation completed: %d entities, %d SROs, %d embedded relations",
            len(entity_queries),
            len(sro_queries),
            len(embedded_relation_queries)
        )
        return (entity_queries, sro_queries, embedded_relation_queries)

    def load(
        self,
        server_address,
        db_name,
        transformed_data
    ):
        """Load the transformed data into the database."""
        logger.info("Starting loading into database '%s' at '%s'", db_name, server_address)
        if self.loader_cls != TypeDBLoader:
            raise ValueError("Unsupported loader")
        loader = self.loader_cls(
            server_address, db_name, batch_size=conf.LOAD_BATCH_SIZE
        )

        entity_queries, sro_queries, embedded_relation_queries = transformed_data
        loader.load(entity_queries)
        loader.load(sro_queries)
        loader.load(embedded_relation_queries)

        logger.info("Loading into database '%s' completed", db_name)


    def etl(self, src, server_address, db_name, **kwargs):
        """
        Run a complete ETL process, from getting a STIX datasource 
        to loading it into a TypeDB database.

        :param src: The URL of the datasource
        :param server_address: The address of the TypeDB Server.
        :param db_name: The name of the TypeDB database.
        :param kwargs: Additional optional parameters.
            - transform_src (str): The local file path of the STIX data source to be transformed.
        :raises ExtractionError: If an error occurs during the extraction process.
        :raises ValueError: If invalid settings are provided for loading data.
        """
        stix_local_file = kwargs.get("transform_src")
        if not stix_local_file:
            stix_local_file = os.path.join(conf.STIX_DATA_PATH, "extracted_stix.json")
            logger.warning(
                "Extracted STIX data filename not provided. Using default: %s", stix_local_file
            )

        try:
            self.extract(src, stix_local_file, **kwargs)
            insert_bundle = self.transform(stix_local_file)
            self.load(server_address, db_name, insert_bundle)
        except ExtractionError as e:
            raise e
        except ValueError as e:
            logger.error("Invalid settings for loading data: %s", e)


    def transform_load(self, data_file, server_address, db_name):
        """
        Run a transform and load process for a given data file.

        :param data_file: The filepath of the file to be transformed.
        :param server_address: The address of the TypeDB Server.
        :param db_name: The name of the TypeDB database where data is to be loaded.
        """
        try:
            insert_bundle = self.transform(data_file)
            self.load(server_address, db_name, insert_bundle)
        except ExtractionError as e:
            raise e
        except ValueError as e:
            logger.error("Invalid settings for loading data: %s", e)
