# TypeDB schema
TYPEDB_ID_ATTRIBUTE = "stix-id"

from satrap.settings import MAPPING_FILES_PATH
import os

FILE_COMPOSITES = os.path.join(MAPPING_FILES_PATH, "composites.json")
FILE_SDO = os.path.join(MAPPING_FILES_PATH, "sdos.json")
FILE_SRO = os.path.join(MAPPING_FILES_PATH, "sros.json")
FILE_SCO = os.path.join(MAPPING_FILES_PATH, "scos.json")
FILE_SMO = os.path.join(MAPPING_FILES_PATH, "smos.json")
FILE_CLASSES = os.path.join(MAPPING_FILES_PATH, "classes.json")
FILE_COMMON_ATTRIBUTES = os.path.join(MAPPING_FILES_PATH, "common_attributes.json")
FILE_SRO_ROLES_INFO = os.path.join(MAPPING_FILES_PATH, "sros_roles.json")
FILE_KEY_VALUE_PAIRS = os.path.join(MAPPING_FILES_PATH, "key-value-pairs.json")
FILE_DICTIONARY_DATA = os.path.join(MAPPING_FILES_PATH, "dictionary.json")

SCHEMAS_DIR = os.path.join(MAPPING_FILES_PATH, "schemas")
FILE_SCHEMA_STIX_OBJECTS = os.path.join(SCHEMAS_DIR, "stix_objects_schema.json")
FILE_SCHEMA_EMBEDDEDS = os.path.join(SCHEMAS_DIR, "embedded_schema.json")
FILE_SCHEMA_COMPOSITES = os.path.join(SCHEMAS_DIR, "composites_schema.json")
FILE_SCHEMA_SRO_ROLES = os.path.join(SCHEMAS_DIR, "sro_roles_schema.json")
FILE_SCHEMA_KV_PAIRS = os.path.join(SCHEMAS_DIR, "key_value_pairs_schema.json")
FILE_SCHEMA_DICT = os.path.join(SCHEMAS_DIR, "dictionary_schema.json")
FILE_SCHEMA_COMMON_ATTRIBUTES = os.path.join(SCHEMAS_DIR, "common_attributes_schema.json")
FILE_SCHEMA_CLASSES = os.path.join(SCHEMAS_DIR, "classes_schema.json")

MAPPING_CLASS_SDO = "STIXDomainObject"
MAPPING_CLASS_SCO = "STIXCyberObservable"
MAPPING_CLASS_SRO = "STIXRelationshipObject"
MAPPING_CLASS_SMO = "STIXMetaObject"

OBJECTS_TYPEDB_TYPE = "typedb-thing-type"
OBJECTS_SUBTYPES = "subtypes"
OBJECTS_EXTENSIONS = "extensions"

MAPPING_ATTRIBUTES = "attributes"
MAPPING_ATTRIBUTE_STIX_TYPE = "stix_value_type"
MAPPING_ATTRIBUTE_TYPEDB_NAME = "typedb_name"
MAPPING_ATTRIBUTE_TYPEDB_VALUE_TYPE = "typedb_value_type"

MAPPING_COMPOSITE_NAME = "typedb-name"
MAPPING_COMPOSITE_RELATION = "helper-relation"
MAPPING_COMPOSITE_RELATION_OBJECT_ROLE = "object-role"
MAPPING_COMPOSITE_RELATION_VALUE_ROLE = "value-role"

MAPPING_DEFAULT_KEY = "_"
MAPPING_TYPE_SEPARATOR = ":"
MAPPING_ROLE_SEPARATION = "::"

RELATION_NAME = "relation-name"
RELATION_OBJECT_TYPE = "entity-type"
RELATION_ROLE_NAME = "role-name"

MAPPING_PAIRS_VALUE_TYPE = "value_type"
MAPPING_PAIRS_KEYS = "keys"
MAPPING_PAIRS_RELATION = "relation"
MAPPING_PAIRS_ATTRIBUTE_NAME = "attribute_name"
MAPPING_PAIR_CUSTOM = "custom"
MAPPING_KEY_VALUE_PAIR_KEYWORD = "key-value"
MAPPING_PAIR_CUSTOM_ENTITY = "entity-name"
MAPPING_PAIR_CUSTOM_ATTRIBUTE = "name-attribute"

MAPPING_ROLE_ITEM = "item-role"
MAPPING_ROLE_OBJECT = "object-role"

MAPPING_DICTIONARY_RELATION = "relation"
MAPPING_DICTIONARY_KEY = "attribute_key"
MAPPING_DICTIONARY_SUBITEMS = "subitems"
MAPPING_DICTIONARY_ATTRIBUTE_NAME = "attribute_property"
MAPPING_DICTIONARY_ITEM_ENTITY = "entity"
MAPPING_DICTIONARY_VALUE_ATTRIBUTE = "value-attribute"

# Value Types
TYPEQL_LIST_PREFIX = "list"
TYPEQL_COMPOSITE_PREFIX = "composite"
TYPEQL_RELATION_PREFIX = "relation"
TYPEQL_NOT_IMPLEMENTED_TYPE_KEYWORD = "empty"
TYPEQL_DICTIONARY_KEYWORD = "dictionary"
TYPEQL_ROLEPLAYER = "roleplayer"

# kwargs for value conversion to TypeQL
REFERENCE_KEYWORD = "reference"
ATTRIBUTE_NAME = "name"
