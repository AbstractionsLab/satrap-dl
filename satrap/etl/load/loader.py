from abc import ABC, abstractmethod

from satrap.datamanagement.typedb.typeql_builder import TypeQLBuilder
from satrap.datamanagement.typedb.inserthandler import TypeDBBatchInsertHandler
from satrap.datamanagement.typedb.dataobjects import InsertQuery
from satrap.commons.log_utils import logger
from satrap.etl.load import log_messages
from satrap.settings import LOAD_BATCH_SIZE


class Loader(ABC):
    """Loader.
    
    Loads data into a data collection, e.g. a database.
    """

    @abstractmethod
    def load(self, data, **kwargs):
        """Loads the given data in a data collection.
        
        :param data: The data that should be loaded
        """
        pass

class TypeDBLoader(Loader):
    """TypeDB Loader.
    
    Executes TypeDB insert queries on a TypeDB database instance.
    """
    def __init__(
            self,
            database_server_address: str,
            database_name: str,
            batch_size=LOAD_BATCH_SIZE
        ):
        self.server_address = database_server_address
        self.db_name = database_name
        self.batch_size = batch_size

    def load(self, data: list[InsertQuery], **kwargs):
        """Load a list of InsertQuery objects into the database.
        
        :param data: A list of objects representing TypeQL insert queries
        :type data: list[InsertQuery]
        """
        logger.info(log_messages.LOAD_DATA_START)

        executables = list(map(TypeQLBuilder.build_insert_query, data))
        amount = len(executables)

        with TypeDBBatchInsertHandler(self.server_address, self.db_name) as inserter:
            for i in range(0, amount, self.batch_size):
                batch_inserted = inserter.insert(executables[i:i+self.batch_size])

                if not batch_inserted and self.batch_size>1:
                    logger.warning("Reloading failed batch with single inserts.")
                    for query in executables[i:i+self.batch_size]:
                        inserter.insert([query])
                    logger.info("Batch reloaded.")

        logger.info(log_messages.LOAD_DATA_END,amount)
