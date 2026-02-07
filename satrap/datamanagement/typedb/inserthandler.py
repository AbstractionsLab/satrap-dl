from typedb.driver import TypeDB, SessionType, TransactionType, TypeDBDriverException

from satrap.commons.log_utils import logger
from satrap.etl.exceptions import LoadingError
from satrap.datamanagement.typedb.typedb_constants import NON_EMPTY_SERVER, NON_EMPTY_DB


class TypeDBBatchInsertHandler:
    """Executes TypeDB insert queries on a TypeDB database instance."""

    def __init__(self, server_address, database_name):
        self.server_address = server_address
        self.database_name = database_name
        self.driver = None


    def insert(self, queries: list[str], database_name="") -> bool:
        """Inserts a set of queries.
        
        :param queries: The queries that should be inserted
        :type queries: list[str]
        :param database_name: The name of the database where the queries 
            should be inserted to
        :type database_name: str, optional

        :return: True if the set was successfully inserted, False otherwise
        :rtype: bool
        """
        if not database_name:
            database_name = self.database_name

        if not self.driver.databases.contains(database_name):
            raise ValueError(
                f"The database '{database_name}' does not exist at '{self.server_address}'")

        with self.driver.session(database_name, SessionType.DATA) as session:
            return self.manage_transactions(session, queries)


    def manage_transactions(self, session, queries: list[str]) -> bool:
        """Split the queries to transactions.
        
        :param session: A Data session on the database on which the 
            queries should be executed.
        :type session: TypeDBSession
        :param queries: The queries that should be inserted
        :type queries: list[str]
        :return: True if all queries were successfully inserted, False otherwise
        :rtype: bool
        """
        with session.transaction(TransactionType.WRITE) as transaction:
            try:
                for query in queries:
                    # logger.debug("Inserting:\n %s", query)
                    r = transaction.query.insert(query)
                    if len(list(r)) == 0:
                        logger.warning(
                            "The following query did no insertions. Data matching "
                            "the 'match' clause might not have been found:\n%s", query)
                transaction.commit()
                return True
            except TypeDBDriverException as err:
                logger.error(LoadingError(err.message, query, len(queries)))
                return False


    def __enter__(self):
        if not self.server_address:
            raise ValueError(NON_EMPTY_SERVER)
        if not self.database_name:
            raise ValueError(NON_EMPTY_DB)

        self.driver = TypeDB.core_driver(self.server_address)
        return self


    def __exit__(self, exception_type, exception_value, traceback):
        self.driver.close()
        return traceback is None
