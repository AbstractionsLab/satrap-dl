import satrap.commons.file_utils as utils

from satrap.etl.extract.extractor import Extractor, STIXExtractor
from satrap.etl.transform.transformer import STIXtoTypeQLTransformer
from satrap.etl.load.loader import TypeDBLoader
from satrap.etl.exceptions import ExtractionError
from satrap import settings as conf
from satrap.commons.log_utils import logger


class ETLOrchestrator:

    def __init__(self):
        #pass
        self.entity_queries = []
        self.sro_queries = []
        self.embedded_relation_queries = []


    def extract(self, extractor_type, source, dest):
        """Extract a datasource of a given type and store it in a selected path
        """
        extractor = Extractor.get_extractor(extractor_type)
        extractor.fetch(source, target=dest, override=True)


    def transform(self, datasrc_path):
        """Transform the STIX objects in the file at the given path
        """
        stix_extractor = STIXExtractor()
        generator = stix_extractor.fetch(datasrc_path)
        transformer = STIXtoTypeQLTransformer()

        # entity_queries = []
        # sro_queries = []
        # embedded_relation_queries = []

        for stix_object in generator:
            transformed = transformer.transform(stix_object)
            if transformed is None:
                continue

            entity_query, sro_query, embedded_relation_query = transformed

            if entity_query:
                self.entity_queries.append(entity_query)
            if sro_query:
                self.sro_queries.append(sro_query)
            if embedded_relation_query:
                self.embedded_relation_queries.append(embedded_relation_query)


    def load(self, server_address, db_name):
        loader = TypeDBLoader(server_address, db_name, batch_size=conf.LOAD_BATCH_SIZE)
        loader.load(self.entity_queries)
        self.entity_queries = []
        loader.load(self.sro_queries)
        self.sro_queries = []
        loader.load(self.embedded_relation_queries)
        self.embedded_relation_queries = []


    def etl(self,
            extractor_type,
            src,
            server_address,
            db_name,
            store_at=conf.STIX_DATA_PATH,
        ) -> bool:
        """Run a complete etl process from downloading a STIX source
        file to loading it into a TypeDB database.

        :param extractor_type: The type of the initial extractor. Valid types are defined 
            as constants in satrap.etl.extract.extract_constants
        :param extractor_type: str
        :param src: The URL of the datasource file
        :type src: str
        :param store_at: The filepath to where the file will be 
            saved to
        :type store_at: str
        :param server_address: The address of the TypeDB Server
        :type server_address: str
        :param db_name: The name of the TypeDB database
        :type db_name: str
        """
        stix_local_file = utils.create_local_filename(store_at,src)

        try:
            self.extract(extractor_type,src,stix_local_file)
            self.transform(stix_local_file)
            self.load(server_address, db_name)
        except ExtractionError as e:
            raise e
        except ValueError as e:
            logger.error("Invalid settings for loading data: %s", e)


    def transform_load(self,
            data_file,
            server_address,
            db_name
        ):
        """Run a complete etl process from downloading a STIX source
        file to loading it into a TypeDB database.

        :param server_address: The address of the TypeDB Server
        :type server_address: str
        :param db_name: The name of the TypeDB database fro loading
        :type db_name: str
        :param data_file: The filepath to the file to be transformed and loaded
        :type data_file: str

        :return: Whether it was a success or not
        :rtype: bool
        """
        self.transform(data_file)
        try:
            self.load(server_address, db_name)
        except ValueError as e:
            logger.error("Invalid settings for loading data: %s", e)
