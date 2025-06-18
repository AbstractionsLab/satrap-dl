import json
import os

import satrap.commons.file_utils as utils
from satrap.etl.etlorchestrator import ETLOrchestrator
import satrap.etl.transform.stix_typeql_constants as constants
from satrap.settings import TYPEDB_SERVER_ADDRESS, DB_NAME_TST
from satrap.datamanagement.typedb import typedbmanager as TypeDBMgr
from satrap.commons.log_utils import logger

# Constants for the test environment
SERVER = TYPEDB_SERVER_ADDRESS
TEST_DB = DB_NAME_TST
STIX_TEST_FILE = os.path.join(
			os.path.dirname(__file__), "temp-TL-test.json")

PRE_TEXT = """
{
    "type": "bundle",
    "id": "bundle--423cac6c-245f-4a75-808b-117a1d161893",
    "spec_version": "2.1",
    "objects": ["""

POST_TEXT = """
    ]
}
"""


def get_stix_property_name(stix_type, search_value, file=None):
    """ Obtain the STIX name of a property of a STIX object, given the name
    of the corresponding property in the CTI SKB schema. The name is 
    retrieved according to a given JSON mapping file (sdos, scos, smos, sros).
    In all cases, the mapping file of common properties is considered too.

    Note that this method is intended for properties mapped to primitive and 
    composite types. Names of properties mapped to relations are not retrieved
    by this method.

    :param file: the JSON file with the mapping
    :type file: str
    :param stix_type: the type of STIX object
    :type stix_type: str
    :param search_value: the name of the typedb property to search for
    :type search_value: str
    """
    if file is not None:
        mapping = utils.read_json(file)

        for key, attr in mapping.get(stix_type).get("attributes").items():
            if attr.get("typedb_name") == search_value:
                return key

    common_att = utils.read_json(constants.FILE_COMMON_ATTRIBUTES)

    for key, attr in common_att.items():
        if attr.get("typedb_name") == search_value:
            return key
    return None


def get_stix_ext_prop_name(file, stix_type, ext_type, search_value):
    """ Obtain the name of a STIX property of a given extension of a STIX object, 
    from the given name of the property that models it in the CTI SKB schema.
    The name is searched in the given JSON mapping file (sdos, scos, smos, sros).

    Note that this method is only intended for properties mapped to primitive and 
    composite types. Names of properties mapped to relations are not considered.

    :param file: the JSON file with the applicable mapping
    :type file: str
    :param stix_type: the type of STIX object (e.g. 'process')
    :type stix_type: str
    :param ext_type: the extension of the stix_type (e.g. 'windows-service-ext')
    :type ext_type: str
    :param search_value: the name of the typedb property to search for (e.g., 'service-dll')
    :type search_value: str

    :return: the STIX property name if found, otherwise None
    :rtype: str or None
    """
    mapping = utils.read_json(file)

    stix_mapping = mapping.get(stix_type, {})
    extensions = stix_mapping.get("extensions", {})
    ext_mapping = extensions.get(ext_type, {})
    attributes = ext_mapping.get("attributes", {})

    for (key, attr) in attributes.items():
        if attr.get("typedb_name") == search_value:
            return key
    return None


def run_tl(stix_object: dict, orchestrator: ETLOrchestrator):
    """Runs the Transform and Load (TL) process for a given STIX object 
    using the provided ETLOrchestrator.

    :param stix_object: The STIX object to be transformed and loaded.
    :type stix_object: dict
    :param orchestrator: An orchestrator for transforming and loading the STIX object.
    :type orchestrator: ETLOrchestrator
    """
    stix_str = "\n" + json.dumps(stix_object, indent=8)
    utils.create_file_and_write(
        STIX_TEST_FILE, PRE_TEXT+stix_str+POST_TEXT)
    orchestrator.transform_load(STIX_TEST_FILE, SERVER, TEST_DB)


def run_tl_and_check_log(test_instance, orchestrator, sco, log_level, phrase):
    """
    Run the transformation and load (TL) process and check the log for a specific phrase.

    :param orchestrator: The orchestrator object responsible for managing the TL process.
    :type orchestrator: ETLOrchestrator
    :param sdo: The source data object to be processed.
    :type sdo: dict
    :param log_level: The logging level to capture (e.g., 'INFO', 'DEBUG').
    :type log_level: str
    :param phrase: The phrase to search for in the log output.
    :type phrase: str

    :raises AssertionError: If the specified phrase is not found in the log output.
    """
    with test_instance.assertLogs(logger, log_level) as log:
        run_tl(sco, orchestrator)
        test_instance.assertTrue(
            any(phrase in message
                for message in log.output))


def get_direct_relations_for_id(stix_id):
    """
    Retrieve the relations of a given STIX ID, that are direct subtypes 
    of 'relation' in the CTI SKB schema.

    :stix_id: The STIX ID for which to find top-level relations.
    :type stix_id: str

    :return: A list of relation names associated with the given STIX ID.
    :rtype: list
    """
    validation_query = ("match "
            f"$e1 has stix-id '{stix_id}';"
            "($e1,$e2) isa $x; "
            "$x sub! relation; "
            "get $x;")

    result = TypeDBMgr.get_query(SERVER, TEST_DB, validation_query)
    relations = []
    for res in result:
        relations.append(res.get('x').get_label().name)

    return relations


def check_relation_exists(relation_name:str, id1:str, id2:str) -> bool:
    """
    Check if a relation of a given type exists between two entities with given IDs.

    :param relation_name: The name of the relation whose existence is checked.
    :type relation_name: str
    :param id1: The STIX ID of the first entity.
    :type id1: str
    :param id2: The STIX ID of the second entity.
    :type id2: str

    :return: True if the relation exists, False otherwise.
    :rtype: bool
    """
    validation_query = ("match "
                f"$e1 has stix-id '{id1}';"
                f"$e2 has stix-id '{id2}';"
                "($e1,$e2) isa $x; "
                f"$x type {relation_name}; "
                "fetch $x;")           

    result = TypeDBMgr.fetch_query(SERVER, TEST_DB, validation_query)
    logger.debug("Relations between %s and %s: %s", id1, id2, result)
    return bool(result)


def check_inferred_relation_exists(relation_name:str, id1:str, id2:str) -> bool:
    """
    Check if a relation of a given type exists between two entities with given IDs
    when enabling the inference rules in the CTI SKB.

    :param relation_name: The name of the relation to be checked.
    :type relation_name: str
    :param id1: The STIX ID of the first entity.
    :type id1: str
    :param id2: The STIX ID of the second entity.
    :type id2: str

    :return: True if the relation exists or is inferred, False otherwise.
    :rtype: bool
    """
    validation_query = ("match "
                f"$e1 has stix-id '{id1}';"
                f"$e2 has stix-id '{id2}';"
                f"$x ($e1,$e2) isa {relation_name}; "
                "get $x;")                

    result = TypeDBMgr.get_query(SERVER, TEST_DB, validation_query, inference=True)
    logger.debug("Relation of type '%s' between %s and %s: %s", relation_name, id1, id2, result)
    return bool(result)


def get_attributes_num(stix_id):
    """
    Gets the number of attributes of a STIX object given its STIX ID.

    :stix_id: The STIX ID for which to find the number of attributes.
    :type stix_id: str

    :return: the number of attributes of the STIX object.
    :rtype: int
    """
    query = ("match "
        f"$v has stix-id '{stix_id}'; "
        "$v has $x; "
        "get $x; "
        "count;")
    num_attrs = TypeDBMgr.aggregate_int_query(SERVER, TEST_DB, query)
    return num_attrs


def is_of_type(stix_obj, typedb_type):
    """
    Check if a given STIX object is of a specified TypeDB type.

    :param stix_obj: The STIX object to check, which should contain an 'id' key.
    :type stix_obj: dict
    :param typedb_type: The TypeDB type to check against.
    :type typedb_type: str

    :return: True if the STIX object is of the specified TypeDB type, False otherwise.
    :rtype: bool
    """
    query = (
        f"match $v isa {typedb_type}, has stix-id '{stix_obj.get('id')}'; get $v;"
    )
    result = TypeDBMgr.get_query(SERVER, TEST_DB, query)
    return bool(result)
