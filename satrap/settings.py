"""SATRAP's configuration parameters"""

import os
import yaml

# Read user-defined parameters from YAML file into a dictionary
def read_yaml(path:str) -> dict:
    """Reads the content of a YAML file and returns it as a dictionary

    :param path: the path to the YAML file
    :type path: str
    """
    with open(path
        , 'r', encoding="utf-8") as file:
        try:
            res = yaml.safe_load(file)
        except yaml.YAMLError as exc:
            res = None
            print(exc)
    return res


## Folders and paths
ROOT_DIR = os.path.dirname(__file__)
ASSETS_FOLDER = "assets"
DB_SCHEMA_FOLDER = "schema"

LOGS_PATH = os.path.join(ROOT_DIR, ASSETS_FOLDER, "logs")
MAPPING_FILES_PATH = os.path.join(ROOT_DIR, "etl", "transform", "mapping")
TESTS_SAMPLES_PATH = os.path.abspath(os.path.join(ROOT_DIR, "..", "tests", "data"))

SATRAP_PARAMS_FILE_NAME = "satrap_params.yml"
SATRAP_PARAMS_FILE_PATH = os.path.join(ROOT_DIR, ASSETS_FOLDER, SATRAP_PARAMS_FILE_NAME)
satrap_params_dict = read_yaml(SATRAP_PARAMS_FILE_PATH)

# sample file for testing
TRANSFORM_SRC_TST = os.path.join(TESTS_SAMPLES_PATH, "test-sample.json")


## TypeDB server
# Only works in MacOS and Windows
# HOST = satrap_params_dict.get('typedb').get('host','host.docker.internal')
HOST = satrap_params_dict.get('typedb').get('host','typedb')
PORT = satrap_params_dict.get('typedb').get('port',"1729")
TYPEDB_SERVER_ADDRESS = f"{HOST}:{PORT}"


## Database
DB_NAME = satrap_params_dict.get('typedb').get('db_name')
# DB schema and rules files
DB_SCHEMA = os.path.join(ROOT_DIR, ASSETS_FOLDER, DB_SCHEMA_FOLDER, "cti-skb-types.tql")
DB_RULES = os.path.join(ROOT_DIR, ASSETS_FOLDER, DB_SCHEMA_FOLDER, "cti-skb-rules.tql")
# Testing database
DB_NAME_TST = 'satrap-test'


## ETL
# Extraction datasource
MITRE_ATTACK_GIT = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
)
MITRE_ATTACK_ENTERPRISE = (
    f"{MITRE_ATTACK_GIT}enterprise-attack/enterprise-attack.json"
)
MITRE_ATTACK_MOBILE = (
    f"{MITRE_ATTACK_GIT}mobile-attack/mobile-attack.json"
)
MITRE_ATTACK_ICS = (
    f"{MITRE_ATTACK_GIT}ics-attack/ics-attack.json"
)

try:
    MITRE_ATTACK_SRC = satrap_params_dict.get('etl').get('extract_src', MITRE_ATTACK_ENTERPRISE)
except:
    MITRE_ATTACK_SRC = MITRE_ATTACK_ENTERPRISE

DOWNLOAD_CHUNK_SIZE = 4096

# Local storage of STIX2.1 datasources
STIX_DATA_PATH = os.path.join(ROOT_DIR, ASSETS_FOLDER, "stixdata")

LOAD_BATCH_SIZE = 200


## Default CLI arguments
# ETL test mode (-tm)
EXTRACT_URL_TST = (
    "https://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/refs/heads/master/examples/indicator-to-campaign-relationship.json"
)

## Command "tl" (transform-load)
# Local path of a STIX2.1 file to be transformed to typeql
try:
    TRANSFORM_SRC_CLI = satrap_params_dict.get('tl').get('transform_src', TRANSFORM_SRC_TST)
except:
    TRANSFORM_SRC_CLI = TRANSFORM_SRC_TST


## Execution environment
# The value of this variable determines the logging level to be used
# and the output stream.
# dev:debug, testing:testing (info<testing<warning), prod:info
try:
    EXEC_ENVIRONMENT = satrap_params_dict.get('log').get('env',"err")
except:
    EXEC_ENVIRONMENT = "err"


## Logging
DEBUG_LOG_FILE_NAME = "debug"
INFO_LOG_FILE_NAME = "info"
ERROR_LOG_FILE_NAME = "error"
LOG_FILES_EXT = ".log"
# True to append a timestamp to the logging file name
TIMESTAMP_FILES = False
