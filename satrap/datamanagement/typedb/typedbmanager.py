from typedb.driver import TypeDB, SessionType, TransactionType, TypeDBOptions

from satrap.datamanagement.typedb.typedb_constants import NON_EMPTY_SERVER, NON_EMPTY_DB
import satrap.settings as conf
from satrap.commons.log_utils import logger


def create_database(
    server_addr: str,
    db_name: str,
    schema: str = conf.DB_SCHEMA,
    reset=False
):
    """Creates a database and loads a schema.

    :param server_addr: The address of the TypeDB server
    :type server_addr: str
    :param db_name: The name of the database
    :type db_name: str
    :param schema: The filepath to the schema file that is used for the
            database
    :type schema: str, optional
    :param reset: Whether the database should be replaced in case such
            a database already exists
    :type reset: bool, optional
    :raises ValueError: If `server_addr`, `db_name`, or `schema` are empty.
    """
    if not server_addr:
        raise ValueError(NON_EMPTY_SERVER)
    if not db_name:
        raise ValueError(NON_EMPTY_DB)
    if not schema:
        raise ValueError("The schema file path must not be None or empty.")

    with TypeDB.core_driver(server_addr) as driver:
        # Check whether database exists
        if driver.databases.contains(db_name):
            if reset:
                driver.databases.get(db_name).delete()
            else:
                raise ValueError(f"Database '{db_name}' already exists.")
        # create database
        driver.databases.create(db_name)

        with driver.session(db_name, SessionType.SCHEMA) as session:
            setup_db_schema(session, schema)
            setup_db_schema(session, conf.DB_RULES)
    logger.info(
        "Database '%s' successfully created with the schema at %s " \
        "and rules at %s", db_name, schema, conf.DB_RULES)


def setup_db_schema(schema_session: SessionType.SCHEMA, schema_file: str = conf.DB_SCHEMA):
    """Load a schema from a file containing a TypeQL define query.

    :param schema_session: A TypeDB Session of type SCHEMA
    :type schema_session: SessionType.SCHEMA
    :param schema_file: The path/name of the file containing the define query
    :type schema_file: str
    """
    with open(schema_file, 'r', encoding='utf-8') as data:
        define_query = data.read()

    with schema_session.transaction(TransactionType.WRITE) as tx:
        element = "rules" if schema_file == conf.DB_RULES else "types"
        logger.debug("Defining %s from file %s...", element, schema_file)
        tx.query.define(define_query)
        tx.commit()
        logger.debug("%s successfully committed", element)


def fetch_query(server_addr: str, db_name: str, query: str) -> list:
    """Run a fetch query on a TypeDB database.

    :param server_addr: The address of the TypeDB server
    :type server_addr: str
    :param db_name: The name of the database
    :type db_name: str
    :param query: The fetch query
    :type query: str
    :return: The result of the fetch query as a list
    :rtype: list
    """
    with TypeDB.core_driver(server_addr) as driver:
        with driver.session(db_name, SessionType.DATA) as session:
            with session.transaction(TransactionType.READ) as tx:
                res = list(tx.query.fetch(query))
    return res


def get_query(server_addr: str, db_name: str, query: str, inference: bool=False) -> list:
    """Run a get query on a TypeDB database.

    :param server_addr: The address of the TypeDB server
    :type server_addr: str
    :param db_name: The name of the database
    :type db_name: str
    :param query: The fetch query
    :type query: str
    :param inference: If True, runs the query with inference enabled
    :type inference: bool

    :return: The result of the fetch query as a list
    :rtype: list
    """
    with TypeDB.core_driver(server_addr) as driver:
        with driver.session(db_name, SessionType.DATA) as session:
            with session.transaction(TransactionType.READ, TypeDBOptions(infer=inference)) as ta:
                res = list(ta.query.get(query))
    return res


def aggregate_int_query(server_addr: str, db_name: str, query: str):
    """
    Run an aggregate query on a TypeDB database whose return 
    is expected to be an integer.

    :param server_addr: The address of the TypeDB server.
    :param db_name: The name of the database.
    :param query: The aggregate query to be executed.
    :return: The result of the aggregate query as an integer.
    :rtype: int
    """
    with TypeDB.core_driver(server_addr) as client:
        with client.session(db_name, SessionType.DATA) as session:
            with session.transaction(TransactionType.READ) as tx:
                result = tx.query.get_aggregate(query).resolve().as_long()
    return result


def delete_database(server_addr: str, db_name: str):
    """Delete a specified database.

        WARNING: Does not ask the user for permission!

        :param server_addr: The address of the TypeDB server
        :type server_addr: str
        :param db_name: The name of the database
        :type db_name: str
        """
    with TypeDB.core_driver(server_addr) as driver:
        driver.databases.get(db_name).delete()


def count_data_instances(server_addr: str, db_name: str):
    """Count the number of elements in a given database

    :param server_addr: The address of the TypeDB server
    :type server_addr: str
    :param db_name: The name of the database
    :type db_name: str
    """
    with TypeDB.core_driver(server_addr) as client:
        with client.session(db_name, SessionType.DATA) as session:
            with session.transaction(TransactionType.READ) as tx:
                count_query = ("match $x isa $t; "
                               "{$t type entity;} or {$t type relation;} or {$t type attribute;}; "
                               "get; count;")
                count = tx.query.get_aggregate(count_query).resolve().as_long()
    return count
