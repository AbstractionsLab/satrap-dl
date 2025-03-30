import re
from typing import Any

from jsonschema import validate

from satrap.commons import file_utils
from satrap.etl.exceptions import MappingException
import satrap.etl.stix_constants
import satrap.etl.transform.stix_typeql_constants as constants
from satrap.datamanagement.typedb import typedb_constants


class STIXtoTypeDBMapper:
    """Handles the mapping file that describes how to translate 
    STIX 2.1 to the TypeDB schema.
    """

    classes: dict = None
    stix_objects: dict = None
    composites_mapping: dict = None
    common_attributes: dict = None
    sros_role_info: dict = None
    key_value_pairs: dict = None
    dictionary_data: dict = None

    @staticmethod
    def split_type(value_type: str) -> tuple[str, str]:
        """Splits a compound value type to its ingredients according 
        to the mapping.
        If it is indeed a NonPrimitive Type, then the first value is 
        the abstract and the second the subtype. Otherwise, the first
        value is the value type and the second is empty.

        :param value_type: The type of a value
        :type value_type: str

        :return: The abstract and subtype of the type
        :rtype: tuple[str, str]
        """
        splitted = value_type.split(constants.MAPPING_TYPE_SEPARATOR, 1)
        abstract = splitted[0]
        if len(splitted) > 1:
            subtype = splitted[1]
        else:
            subtype = ""
        return abstract, subtype

    @staticmethod
    def join_type(tl_type: str, subtype: str) -> str:
        """Join an abstract and specific type together according 
        to the mapping.

        :param tl_type: The top-level-/ abstract  type
        :type tl_type: str
        :param subtype: The sub-/ specific type
        :type subtype: str

        :return: The two types joined together
        :rtype: str
        """
        return tl_type + constants.MAPPING_TYPE_SEPARATOR + subtype

    @staticmethod
    def validate():
        """Validates STIX to TypeDB JSON mappings against predefined schema files.

        This function reads various schema files in JSON format and validates
        the corresponding mappings in the STIXtoTypeDBMapper class against these
        schemas. The schemas include classes, STIX objects, composites, SRO roles,
        key-value pairs, a dictionary type, and common attributes.

        :raises ValidationError: If a mapping file does not match the schema
        :raises SchemaError: If a JSON schema file is invalid
        """
        schema_classes = file_utils.read_json(
            constants.FILE_SCHEMA_CLASSES
        )
        schema_stix_objects = file_utils.read_json(
            constants.FILE_SCHEMA_STIX_OBJECTS
        )
        schema_composites = file_utils.read_json(
            constants.FILE_SCHEMA_COMPOSITES
        )
        schema_sro_roles = file_utils.read_json(
            constants.FILE_SCHEMA_SRO_ROLES
        )
        schema_key_value_pairs = file_utils.read_json(
            constants.FILE_SCHEMA_KV_PAIRS
        )
        schema_dictionary = file_utils.read_json(
            constants.FILE_SCHEMA_DICT
        )
        schema_common_attributes = file_utils.read_json(
            constants.FILE_SCHEMA_COMMON_ATTRIBUTES
        )

        validate(STIXtoTypeDBMapper.classes, schema_classes)
        validate(STIXtoTypeDBMapper.stix_objects, schema_stix_objects)
        validate(STIXtoTypeDBMapper.composites_mapping, schema_composites)
        validate(STIXtoTypeDBMapper.common_attributes,
                 schema_common_attributes)
        validate(STIXtoTypeDBMapper.sros_role_info, schema_sro_roles)
        validate(STIXtoTypeDBMapper.key_value_pairs, schema_key_value_pairs)
        validate(STIXtoTypeDBMapper.dictionary_data, schema_dictionary)

    @staticmethod
    def get_data(validate=False) -> None:
        """Loads the data of the JSON map.

        Note that though every function calls this function here, 
        the data is loaded only once. Therefore, the first call to 
        this method decides which mappings to load.

        :param validate: Whether the data should be validated, too
        :type validate: bool, optional

        :raises SchemaError: If the schema is invalid 
            and validate = True
        :raises ValidationError: If the mapping is invalid
            and validate = True
        """
        if STIXtoTypeDBMapper.composites_mapping is None:
            STIXtoTypeDBMapper.composites_mapping = file_utils.read_json(
                constants.FILE_COMPOSITES
            )
        if STIXtoTypeDBMapper.stix_objects is None:
            STIXtoTypeDBMapper.stix_objects = file_utils.read_json(
                constants.FILE_SDO
            )
            STIXtoTypeDBMapper.stix_objects.update(
                file_utils.read_json(constants.FILE_SRO)
            )
            STIXtoTypeDBMapper.stix_objects.update(
                file_utils.read_json(constants.FILE_SCO)
            )
            STIXtoTypeDBMapper.stix_objects.update(
                file_utils.read_json(constants.FILE_SMO)
            )
        if STIXtoTypeDBMapper.classes is None:
            STIXtoTypeDBMapper.classes = file_utils.read_json(
                constants.FILE_CLASSES
            )
        if STIXtoTypeDBMapper.common_attributes is None:
            STIXtoTypeDBMapper.common_attributes = file_utils.read_json(
                constants.FILE_COMMON_ATTRIBUTES
            )
        if STIXtoTypeDBMapper.sros_role_info is None:
            STIXtoTypeDBMapper.sros_role_info = file_utils.read_json(
                constants.FILE_SRO_ROLES_INFO
            )
        if STIXtoTypeDBMapper.key_value_pairs is None:
            STIXtoTypeDBMapper.key_value_pairs = file_utils.read_json(
                constants.FILE_KEY_VALUE_PAIRS
            )
        if STIXtoTypeDBMapper.dictionary_data is None:
            STIXtoTypeDBMapper.dictionary_data = file_utils.read_json(
                constants.FILE_DICTIONARY_DATA
            )
        if validate:
            STIXtoTypeDBMapper.validate()

    @staticmethod
    def get_class(stix_object_type: str) -> str:
        """Returns the class used to build this STIX type.

        :param stix_object_type: The type of the STIX object, 
            e.g. attack-pattern
        :type stix_object_type: str

        :return: The class used for the building, None if the type 
            is a custom type
        :rtype: str
        """
        class_type = None
        for category, stix_object_types in STIXtoTypeDBMapper.classes.items():
            if stix_object_type in stix_object_types:
                class_type = category
                break
        return class_type

    @staticmethod
    def get_typeql_thing_name(
        stix_type: str,
        stix_properties: dict,
        stix_extensions: dict
    ) -> str:
        """Returns the name of the TypeQL thing for a certain 
        STIX Object. E.g. "attack-pattern" -> "attack-pattern".

        :param stix_type: The type of the STIX object
        :type stix_type: str
        :param stix_properties: The properties of the STIX Object
        :type stix_properties: dict 
        :param stix_extensions: The extensions of the STIX Object
        :type stix_extensions: dict 

        :raises MappingException: If the Type cannot be determined

        :return: The name of the object in TypeDB, None if the type 
            is a custom type
        :rtype: str
        """
        object_info = STIXtoTypeDBMapper.stix_objects \
            .get(stix_type)

        # Custom type
        if not object_info:
            return None

        assigned_type = object_info.get(constants.OBJECTS_TYPEDB_TYPE)
        subtypes = object_info.get(constants.OBJECTS_SUBTYPES)

        typedb_type = ""

        if not isinstance(assigned_type, str):
            raise MappingException(f"No TypeDB type specified for {stix_type}")
        typedb_type = assigned_type

        if subtypes:
            attribute: str = next(iter(subtypes.keys()))
            value: str = stix_properties.get(attribute)
            if value is None:
                raise MappingException(
                    f"The property '{attribute}' is required for STIX objects of type '{stix_type}'.")
            typedb_type = subtypes.get(attribute).get(str(value).lower())
            if typedb_type is None:
                typedb_type = subtypes.get(attribute) \
                    .get(constants.MAPPING_DEFAULT_KEY)
            if not typedb_type:
                raise MappingException(
                    # f"{stix_properties.get('id')}: subtyping for '{stix_type}' is not exhaustive")
                    f"In '{stix_properties.get('id')}': the value '{value}' "\
                    f"is not defined for '{attribute}' in the mapping of '{stix_type}'.")

        # update the type if the given object has a predefined extension
        if stix_extensions:
            obj_extensions = stix_extensions.keys()
            predefined_extensions = object_info \
                .get(constants.OBJECTS_EXTENSIONS)
            if not predefined_extensions:
                return typedb_type

            predefined_extensions = predefined_extensions.keys()
            final_extension = ""
            for extension in obj_extensions:
                if extension in predefined_extensions:
                    if final_extension:
                        raise MappingException(
                            f"Two predefined extensions given for '{stix_properties.get('id')}'. "
                            f"The extensions are mutually exclusive, a '{stix_type}' must have "
                            "at most one extension."
                        )
                    final_extension = extension
            if final_extension:
                typedb_type = object_info.get(constants.OBJECTS_EXTENSIONS) \
                    .get(final_extension).get(constants.OBJECTS_TYPEDB_TYPE, None)

        return typedb_type

    @staticmethod
    def get_typedb_supertype(stix_type: str) -> str:
        """Returns the least abstract supertype in TypeDB for a STIX 
        object type.

        :param stix_type: The STIX Object type, e.g. attack-pattern
        :type stix_type: str

        :raises MappingException: If the stix type is not defined or the
            mapping is invalid

        :return: The least abstract supertype in TypeDB for a STIX Object 
            type
        :rtype: str
        """
        object_map = STIXtoTypeDBMapper.stix_objects.get(stix_type)
        if not object_map:
            raise MappingException(f"STIX type '{stix_type}' not defined")
        sup_type = object_map.get(constants.OBJECTS_TYPEDB_TYPE)
        if not sup_type:
            raise MappingException(
                f"No TypeDB type defined for '{stix_type}'")
        return sup_type

    @staticmethod
    def get_default_value_implementation(value: Any) -> str:
        """Returns the default value type for a value of unknown type.

        :param value: The value whose type is unknown
        :type value: Any

        :return: The name of the value type, None if no value type
            is defined
        :rtype: str
        """
        res = ""
        match value:
            case int():
                res = typedb_constants.LONG
            case str():
                if re.match(satrap.etl.stix_constants.STIX_TIMESTAMP_REGEX, value):
                    res = typedb_constants.DATETIME
                else:
                    res = typedb_constants.STRING
            case float():
                res = typedb_constants.DOUBLE
            case bool():
                res = typedb_constants.BOOLEAN
            case list():
                value = list(value)
                list_type = constants.TYPEQL_LIST_PREFIX
                if len(value) > 0:
                    subtype = STIXtoTypeDBMapper \
                        .get_default_value_implementation(value[0])
                else:
                    subtype = typedb_constants.STRING
                res = STIXtoTypeDBMapper.join_type(list_type, subtype)
            case dict():
                # maybe check for predefined composite types
                res = constants.TYPEQL_DICTIONARY_KEYWORD
            case _:
                None
        return res

    @staticmethod
    def get_roleplayers_for_SRO(stix_type: str) -> list[str]:
        """Gives the properties that are implemented as roleplayers in
        a STIX relationship object.

        :param stix_type: The type of the STIX object
        :type stix_type: str

        :raises MappingException: If the STIX type does not exist

        :return: The properties that specify roleplayers
        :rtype: str
        """
        object_info = STIXtoTypeDBMapper.stix_objects.get(stix_type)
        if not object_info:
            raise MappingException(
                f"STIX Object {stix_type} not defined"
            )
        attributes = object_info.get(constants.MAPPING_ATTRIBUTES)
        if not attributes:
            raise MappingException(
                f"No attributes defined for STIX Object {stix_type}"
            )
        roleplayers = []
        for attribute, attribute_info in attributes.items():
            value_type = attribute_info \
                .get(constants.MAPPING_ATTRIBUTE_TYPEDB_VALUE_TYPE)
            if value_type == constants.TYPEQL_ROLEPLAYER:
                roleplayers.append(attribute)
        return roleplayers

    @staticmethod
    def get_object_attribute_info(
        stix_object: str,
        stix_attribute: str
    ) -> tuple[str, str]:
        """Returns the name and value of an attribute in the 
        TypeDB Schema.

        :param stix_object: The type of the STIX object, 
            e.g. attack-pattern
        :type stix_object: str
        :param stix_attribute: The attribute of the STIX Object
        :type stix_attribute: str

        :raises MappingException: If the stix type is not defined
            or the mapping is not valid/ complete

        :return: The TypeDB name and value, None if the attribute
            is a custom attribute
        :rtype: tuple[str, str]
        """
        common_attributes = STIXtoTypeDBMapper.common_attributes

        if stix_attribute in common_attributes.keys():
            attr_info = common_attributes.get(stix_attribute)
            name = attr_info.get(constants.MAPPING_ATTRIBUTE_TYPEDB_NAME)
            value = attr_info.get(
                constants.MAPPING_ATTRIBUTE_TYPEDB_VALUE_TYPE)
            if not name or not value:
                raise MappingException(
                    f"No name or no value given for '{stix_attribute}' in common attributes")
            return name, value

        stix_obj = STIXtoTypeDBMapper.stix_objects.get(stix_object)
        if not stix_object:
            raise MappingException(
                "The specified STIX Object does not exist"
            )

        specific_attributes = stix_obj.get(constants.MAPPING_ATTRIBUTES)
        if not specific_attributes:
            raise MappingException(
                "No attributes are defined for {stix_object}"
            )

        attr_info = specific_attributes.get(stix_attribute)
        if not attr_info:
            # Custom property
            return None, None

        name = attr_info.get(constants.MAPPING_ATTRIBUTE_TYPEDB_NAME)
        value = attr_info.get(constants.MAPPING_ATTRIBUTE_TYPEDB_VALUE_TYPE)
        if not name or not value:
            raise MappingException(
                f"No name or no value given for attribute {stix_attribute} of stix type {stix_object}"
            )
        return name, value

    @staticmethod
    def get_composite_name(composite_type: str) -> str:
        """Returns the TypeDB name used for the composite type.

        :param composite_type: The STIX name of the composite type
        :type composite_type: str

        :raises MappingException: If the composite type does not exist,
            i.e. the mapping is invalid or incomplete

        :return: The TypeDB name used for the composite type
        :rtype: str
        """
        composite = STIXtoTypeDBMapper.composites_mapping \
            .get(composite_type)

        if not composite:
            raise MappingException(
                f"Composite type {composite_type} does not exist"
            )

        name = composite.get(constants.MAPPING_COMPOSITE_NAME)
        if not name:
            raise MappingException(
                f"No TypeDB name specified for composite {composite_type}"
            )

        return name

    @staticmethod
    def get_composite_attribute_info(
        composite_type: str,
        stix_property: str
    ) -> tuple[str, str]:
        """Returns the TypeDB name of a specified attribute of a 
        specified composite type.

        :param composite_type: The name of the composite type
        :type composite_type: str
        :param stix_property: The name of the STIX attribute
        :type stix_property: str

        :raises MappingException: If the composite type or attribute
            is not defined in the mapping

        :return: The TypeDB name and value type for the attribute
        :rtype: tuple[str, str]
        """
        composite = STIXtoTypeDBMapper.composites_mapping \
            .get(composite_type)

        if not composite:
            raise MappingException(
                f"Composite type {composite_type} does not exist"
            )

        typedb_attribute = composite \
            .get(constants.MAPPING_ATTRIBUTES) \
            .get(stix_property)

        if not typedb_attribute:
            raise MappingException(
                f"Attribute {stix_property} does not exist for composite type {composite_type}"
            )

        attribute_name = typedb_attribute.get(
            constants.MAPPING_ATTRIBUTE_TYPEDB_NAME
        )
        attribute_type = typedb_attribute.get(
            constants.MAPPING_ATTRIBUTE_TYPEDB_VALUE_TYPE
        )

        if not attribute_name or not attribute_type:
            raise MappingException(
                f"Attribute name or value type for attribute {stix_property} of composite "
                f"{composite_type} not specified"
            )
        return attribute_name, attribute_type

    @staticmethod
    def get_composite_type_relation(composite_type: str) -> str:
        """Returns the name of the helper relation for the composite 
        type.

        :param composite_type: The name of the composite type
        :type composite_type: str

        :raises MappingException: If the composite type does not exist
            or no relation is specified

        :return: The name of the helper relation of the composite type
        :rtype: str
        """
        composite = STIXtoTypeDBMapper.composites_mapping \
            .get(composite_type)
        if not composite:
            raise MappingException(
                f"Composite type {composite_type} does not exist"
            )

        relation = composite.get(constants.MAPPING_COMPOSITE_RELATION)
        if not relation:
            raise MappingException(
                f"No relation specified for composite {composite_type}"
            )

        relation_name = relation.get(constants.RELATION_NAME)
        if not relation_name:
            raise MappingException(
                f"No relation name specified for composite {composite_type}"
            )

        return relation_name

    @staticmethod
    def get_composite_relation_roles(composite_type: str) -> tuple[str, str]:
        """Returns the names of the roles of the helper relation of a 
        composite type, i.e. the name of the object's role and the name
        of the values' role.

        :param composite_type: The name of the composite value type 
        :type composite_type: str

        :raises MappingException: If the composite type does not exist
            or its definition is incomplete

        :return: The name of the object's and values' role
        :rtype: tuple[str, str]
        """
        composite = STIXtoTypeDBMapper.composites_mapping \
            .get(composite_type)
        if not composite:
            raise MappingException(
                f"Composite type {composite_type} does not exist"
            )

        relation = composite.get(constants.MAPPING_COMPOSITE_RELATION)
        if not relation:
            raise MappingException(
                f"No relation specified for composite {composite_type}"
            )

        object_role = relation.get(
            constants.MAPPING_COMPOSITE_RELATION_OBJECT_ROLE
        )
        value_role = relation.get(
            constants.MAPPING_COMPOSITE_RELATION_VALUE_ROLE
        )
        if not object_role or not value_role:
            raise MappingException(
                f"No object or value role defined for helper relation of "
                f"composite type {composite_type}"
            )

        return object_role, value_role

    @staticmethod
    def get_sro_role(relation_name: str, attribute: str) -> str:
        """Returns the name of the role for an SRO attribute.

        :param relation_name: The name of the SRO
        :type relation_name: str
        :param role: The name of the attribute 
        :type role: str

        :raises MappingException: If the relation is not defined or the 
            attribute is not implemented as a roleplayer

        :return: The name of the role and TypeDB object type that 
            plays the role
        :rtype: str
        """
        relation = STIXtoTypeDBMapper.sros_role_info \
            .get(relation_name)
        if not relation:
            raise MappingException(
                f"Relation {relation_name} is not defined"
            )

        role_name = relation.get(attribute)
        if not role_name:
            raise MappingException(
                f"Role information for role {attribute} missing for relation {relation_name}"
            )

        return role_name

    @staticmethod
    def get_embedded_relation_roles(attribute_name: str) -> tuple[str, str]:
        """Returns the object's and value's role using the name of the
        attribute specified for the TypeDB translation of a STIX 
        property.

        :param attribute_name: The specified attribute name for the
            TypeDB translation
        :type attribute_name: str

        :raises MappingException: If the attribute name does not 
            fulfill the required format

        :return: The name of the object's and value's role
        :rtype: tuple[str, str]
        """
        roles = attribute_name.split(constants.MAPPING_ROLE_SEPARATION)
        if len(roles) != 2:
            raise MappingException(
                f"Roles are not properly specified: {attribute_name}"
            )

        return roles[0], roles[1]

    @staticmethod
    def get_key_value_pair_key_translation(pair_type: str, key: str) -> str:
        """Returns the entity type of the key. Returns None if the key
        is not defined.

        :param pair_type: The name of the Pair Type
        :type pair_type: str
        :param key: The name of the key
        :type key: str

        :raises MappingException: If the Mapping is invalid or 
            incomplete or the pair type does not exist

        :return: The name of the TypeDB Entity
        :rtype: str
        """
        pair_type = STIXtoTypeDBMapper.key_value_pairs \
            .get(pair_type)
        if not pair_type:
            raise MappingException(
                f"Pair type {pair_type} does not exist"
            )

        keys = pair_type.get(constants.MAPPING_PAIRS_KEYS)
        if not keys:
            raise MappingException(
                f"No keys defined for pair type {pair_type}"
            )
        key = keys.get(key)

        return key

    @staticmethod
    def get_key_value_pair_custom(data_type: str) -> tuple[str, str]:
        """Returns the name of the custom entity and the attribute 
        name for the key.

        :param pair_type: The name of the pair type
        :type pair_type: str

        :raises MappingException: If the Mapping is invalid or incomplete
            or the pair type does not exist

        :return: The name of the entity and key attribute
        :rtype: tuple[str, str]
        """
        pair_type = STIXtoTypeDBMapper.key_value_pairs \
            .get(data_type)
        if not pair_type:
            raise MappingException(
                f"A mapping for the key-value type '{pair_type}' is not defined"
            )

        mapping = pair_type.get(constants.MAPPING_PAIR_CUSTOM)
        if not mapping:
            raise MappingException(
                f"Custom keys are not supported in the STIX key-value type '{data_type}'."
                f"\nValid keys: {list(pair_type.get(constants.MAPPING_PAIRS_KEYS).keys())}."
            )

        entity = mapping.get(constants.MAPPING_PAIR_CUSTOM_ENTITY)
        attribute = mapping.get(constants.MAPPING_PAIR_CUSTOM_ATTRIBUTE)
        if not entity or not attribute:
            raise MappingException(
                f"No entity type or attribute name specified for custom keys "
                f"in key-value type '{data_type}'")

        return entity, attribute

    @staticmethod
    def get_pairs_value_and_type(pair_type: str) -> tuple[str, str]:
        """Returns the attribute name and value type of the pair type.

        :param pair_type: The name of the pair type
        :type pair_type: str

        :raises MappingException: If the Mapping is invalid or incomplete
            or the pair type does not exist

        :return: The attribute name and value type for the values
        :rtype: tuple[str, str]
        """
        pair_type = STIXtoTypeDBMapper.key_value_pairs \
            .get(pair_type)
        if not pair_type:
            raise MappingException(
                f"Pair Type {pair_type} does not exist"
            )

        attribute_name = pair_type.get(constants.MAPPING_PAIRS_ATTRIBUTE_NAME)
        value_type = pair_type.get(constants.MAPPING_PAIRS_VALUE_TYPE)

        if not attribute_name or not value_type:
            raise MappingException(
                f"Attribute name or value type not specified for pair type {pair_type}"
            )

        return attribute_name, value_type

    @staticmethod
    def get_pair_relation(pair_type: str) -> tuple[str, str, str]:
        """Returns the relation name of the helper relation for the 
        pair type and the roles for the object and pair item.

        :param pair_type: The name of the pair type
        :type pair_type: str

        :raises MappingException: If the pair type does not exist or 
            the mapping is invalid/ incomplete

        :return: The name of the relation, object role and item role
        :rtype: tuple[str, str, str]
        """
        pair_type = STIXtoTypeDBMapper.key_value_pairs \
            .get(pair_type)
        if not pair_type:
            raise MappingException(
                f"Pair Type {pair_type} does not exist"
            )

        relation = pair_type.get(constants.MAPPING_PAIRS_RELATION)
        if not relation:
            raise MappingException(
                f"Relation is not specified for pair type {pair_type}"
            )
        relation_name = relation.get(constants.RELATION_NAME)
        item_role = relation.get(constants.MAPPING_ROLE_ITEM)
        object_role = relation.get(constants.MAPPING_ROLE_OBJECT)

        if not relation_name or not item_role or not object_role:
            raise MappingException("Relation info is not fully specified")

        return relation_name, object_role, item_role

    @staticmethod
    def get_dictionary_item_data(value_type: str) -> tuple[str, str, str]:
        """Returns the name of the item entity, the name of the key 
        attribute name of the value attribute.

        :param value_type: The type of the value of the item
        :type value_type: str

        :raises MappingException: If the mapping is invalid/incomplete

        :return: The name of the item entity, key attribute and value 
            attribute
        :rtype: tuple[str, str, str]
        """
        abstract, specific = STIXtoTypeDBMapper.split_type(value_type)
        if not specific:
            value_type = abstract
        else:
            value_type = specific

        dict_data = STIXtoTypeDBMapper.dictionary_data
        key_name = dict_data.get(constants.MAPPING_DICTIONARY_KEY)
        items_data = dict_data.get(constants.MAPPING_DICTIONARY_SUBITEMS)

        if not key_name or not items_data:
            raise MappingException(
                "Dictionary data incomplete"
            )

        item_data: dict = items_data.get(value_type)
        if not item_data:
            raise MappingException(
                f"Value type '{value_type}' not supported in items of STIX properties "
                "of type 'dictionary' (e.g. exif_tags, additional_header_fields). "
                f"Valid types: {list(items_data.keys())}"
            )

        item_name = item_data.get(
            constants.MAPPING_DICTIONARY_ITEM_ENTITY
        )
        attr_name = item_data.get(
            constants.MAPPING_DICTIONARY_VALUE_ATTRIBUTE
        )
        if not item_name or not attr_name:
            raise MappingException(
                "No item entity name of value attribute given for dictionary"
            )
        return item_name, key_name, attr_name

    @staticmethod
    def get_dictionary_relation_data() -> tuple[str, str, str]:
        """Returns the name of the relation and roles used for building 
        the dictionary, i.e. connecting the object to the items.

        :raises MappingException: If there is no relation specified

        :return: The name of the relation, role of the item and role
            of the object
        :rtype: str
        """
        dict_data = STIXtoTypeDBMapper.dictionary_data
        relation = dict_data.get(constants.MAPPING_DICTIONARY_RELATION)
        if not relation:
            raise MappingException(
                "No relation specified for dictionaries"
            )
        name = relation.get(constants.RELATION_NAME)
        item_role = relation.get(constants.MAPPING_ROLE_ITEM)
        object_role = relation.get(constants.MAPPING_ROLE_OBJECT)
        if not name or not item_role or not object_role:
            raise MappingException(
                "Dictionary Data incomplete, relation name or roles missing"
            )
        return name, item_role, object_role

    @staticmethod
    def get_dictionary_property_attribute() -> str:
        """Gives the name of the attribute used for the name of the 
        STIX property that is implemented as a dictionary.

        :raises MappingException: If the mapping is invalid or 
            incomplete

        :return: The name of the attribute for the name of the STIX 
            property
        :rtype: str
        """
        dict_data = STIXtoTypeDBMapper.dictionary_data
        attribute_name = dict_data.get(
            constants.MAPPING_DICTIONARY_ATTRIBUTE_NAME
        )
        if not attribute_name:
            raise MappingException(
                "No attribute specified for name of the property"
            )
        return attribute_name

    @staticmethod
    def get_extension_attribute_info(
        stix_object: str,
        stix_extension: str,
        stix_name: str
    ) -> tuple[str, str]:
        """Returns the attribute info of an extension.

        :param stix_object: The name of the STIX type, e.g. malware
        :type stix_object: str
        :param stix_extension: The name of the extension
        :type stix_extension: str
        :param stix_name: The name of the attribute
        :type stix_name: str

        :raises MappingException: If the stix type or extension is not 
            defined in the mapping

        :return: The name and type of the attribute in TypeDB,
            (None, None) if it a custom attribute
        :rtype: tuple[str, str]
        """
        object_extensions = STIXtoTypeDBMapper.stix_objects \
            .get(stix_object) \
            .get(constants.OBJECTS_EXTENSIONS)

        if not object_extensions:
            raise MappingException(
                f"No extension specified for type {stix_object}"
            )
        extension = object_extensions.get(stix_extension)
        if not extension:
            raise MappingException(
                f"{stix_extension} is not a predefined extension for type {stix_object}"
            )
        attributes = extension.get(constants.MAPPING_ATTRIBUTES)
        if not attributes:
            raise MappingException(
                f"No attributes defined for extension {stix_extension} of stix type {stix_object}"
            )
        attribute_data = attributes.get(stix_name)

        if not attribute_data:
            return None, None

        name = attribute_data.get(constants.MAPPING_ATTRIBUTE_TYPEDB_NAME)
        value_type = attribute_data.get(
            constants.MAPPING_ATTRIBUTE_TYPEDB_VALUE_TYPE
        )

        if not name or not value_type:
            raise MappingException(
                f"No name or no value type specified for attribute {stix_name} "
                f"of extension {stix_extension} of stix type {stix_object}"
            )

        return name, value_type

    @staticmethod
    def is_defined_extension(stix_type: str, extension_name: str) -> bool:
        """States whether an extension name is defined according to
        STIX 2.1 or not, that means it is a custom extension.

        :param stix_type: The type of the STIX object
        :type stix_type: str
        :param extension_name: The name of the extension
        :type extension_name: str

        :raises MappingException: If the stix type is not defined

        :return: Whether the extension is a predefined extension
        :rtype: bool
        """
        stix_object_data = STIXtoTypeDBMapper.stix_objects \
            .get(stix_type)
        if not stix_object_data:
            raise MappingException(
                f"Stix type {stix_type} is not defined"
            )
        extensions = stix_object_data.get(constants.OBJECTS_EXTENSIONS)
        if not extensions:
            return False

        return extension_name in extensions.keys()
