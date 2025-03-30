from abc import ABC, abstractmethod
from typing import Any, Self

from stix2.utils import get_type_from_id

from satrap.commons.log_utils import logger
from satrap.datamanagement.typedb import typedb_constants
import satrap.etl.transform.stix_typeql_constants as constants
from satrap.etl import stix_constants
from satrap.etl.transform.stix_to_typedb_mapper import STIXtoTypeDBMapper
from satrap.etl.transform.valueconverter import ValueConverter
from satrap.datamanagement.typedb.dataobjects import Entity, Relation, Thing
from satrap.etl.transform.query import Identification, QueryBundle
from satrap.etl.transform import log_messages
from satrap.etl.exceptions import MappingException, TransformationError


class STIXObjectConverter(ABC):
    """Converts a STIX Object."""

    @staticmethod
    def create(properties: dict) -> Self:
        """Creates the corresponding subclass according 
        to the properties.

        :param properties: The properties of the STIX Object
        :type properties: dict

        :raises TransformationError: If the 'id' or 'type' property is 
            missing
        :raises MappingException: If the STIX object class is not 
            defined

        :return: The STIX Object (as a subclass instance)
        :rtype: STIXObject
        """
        logger.debug(log_messages.CREATE_START)

        stix_id = properties.get(stix_constants.STIX_PROPERTY_ID)
        if not stix_id:
            raise TransformationError(TransformationError.MISSING_REQUIRED_PROPERTY, "'id'")

        stix_type = properties.get(stix_constants.STIX_PROPERTY_TYPE)
        if not stix_type:
            raise TransformationError(TransformationError.MISSING_REQUIRED_PROPERTY, "\"type\"", stix_id)

        class_type = STIXtoTypeDBMapper.get_class(stix_type)

        match class_type:
            case constants.MAPPING_CLASS_SDO:
                obj = STIXDomainObjectConverter(properties)
            case constants.MAPPING_CLASS_SRO:
                obj = STIXRelationshipObjectConverter(properties)
            case constants.MAPPING_CLASS_SCO:
                obj = STIXCyberObservableConverter(properties)
            case constants.MAPPING_CLASS_SMO:
                obj = STIXMetaObjectConverter(properties)
            case None:
                obj = STIXCustomObjectConverter(properties)
            case _:
                raise MappingException(
                    f"Undefined STIX class keyword: {class_type}")

        logger.debug(log_messages.CREATE_SUCCESS(stix_id, stix_type, class_type))

        return obj

    def __init__(self, properties: dict):
        """Initialize.

        Set the id, type, properties and extensions.

        :param properties: The properties of the STIX Object
        :type properties: dict

        :raises TransformationError: If 'id' or 'type' property is missing.
        """
        self.stix_type: str = properties.get(stix_constants.STIX_PROPERTY_TYPE)
        if not self.stix_type:
            raise TransformationError(TransformationError.MISSING_REQUIRED_PROPERTY, "\"type\"")
        self.stix_id: str = properties.get(stix_constants.STIX_PROPERTY_ID)
        if not self.stix_id:
            raise TransformationError(TransformationError.MISSING_REQUIRED_PROPERTY, "\"id\"")
        self.extensions = properties.get(
            stix_constants.STIX_PROPERTY_EXTENSIONS,
            {}
        )
        self.properties: dict = properties

    @abstractmethod
    def build_typeql_bundle(self) -> QueryBundle:
        """Build the elements in each of the TypeQL statements for inserting this
        object into the TypeDB database.

        :return: The elements to build the insert queries of the object.
        None if an error occurs.
        :rtype: QueryBundle
        """
        pass

    def create_typeql_properties(
        self,
        reference: Identification
    ) -> tuple[dict[str, list[str]], QueryBundle]:
        """Returns a dictionary of all TypeDB attributes in 
        {name:value} format and all additional queries.

        :param reference: Reference values that identify the main 
            object.
        :type reference: Identification

        :return: TypeQL attributes and additional queries
        :rtype: tuple[dict[str, list[str]], QueryBundle]
        """
        logger.debug(log_messages.PROPERTIES_START)

        queries = QueryBundle()
        attributes = {}
        for prop_name, prop_value in self.properties.items():
            name, values, additional_queries = self \
                .create_typeql_property(prop_name, prop_value, reference)

            if name and values:
                if not attributes.get(name):
                    attributes[name] = values
                else:
                    attributes[name].extend(values)
            queries.extend(additional_queries)

        return attributes, queries

    def create_typeql_extension(
        self,
        ref: Identification,
        extension: str
    ) -> tuple[dict[str, list[str]], QueryBundle]:
        """Transforms an extension to TypeDB.

        :param ref: A reference to the main object
        :type ref: Identification
        :param extension: The name of the extension
        :type extension: str

        :return: The attributes and additional insert queries required
            to insert this extension
        :rtype: tuple[dict[str, list[str]], QueryBundle]
        """
        ext_attrs = dict()
        ext_queries = QueryBundle()
        extension_obj = self.extensions.get(extension)
        if not extension_obj:
            logger.warning(log_messages.EXTENSIONS_FAILED_MISSING_OBJECT)
            return ext_attrs, ext_queries
        ext_attrs, ext_queries = self.create_typeql_extension_properties(
            extension, extension_obj, ref
        )
        return ext_attrs, ext_queries

    def create_typeql_extensions(
        self,
        ref: Identification
    ) -> tuple[dict[str, list[str]], QueryBundle]:
        """Transform the extensions.

        :param ref: A reference to the main object
        :type ref: Identification

        :return: The attributes and additional insert queries
        :rtype: tuple[dict[str, list[str]], QueryBundle]
        """
        logger.debug(log_messages.EXTENSIONS_START)

        # Determine the relevant extension
        extension = self.get_relevant_extension()

        # build the extension
        ext_attrs = dict()
        ext_queries = QueryBundle()
        if extension:
            ext_attrs, ext_queries = self.create_typeql_extension(
                ref,
                extension
            )
        return ext_attrs, ext_queries

    def get_relevant_extension(self) -> str:
        """Determine which extension to choose for converting.

        :return: The name of the relevant extension
        :rtype: str
        """
        logger.debug(log_messages.EXTENSIONS_FIND_START)

        extension = ""
        for ext in self.extensions.keys():
            try:
                is_defined = STIXtoTypeDBMapper.is_defined_extension(
                    self.stix_type, ext
                )
            except MappingException as e:
                logger.error(
                    log_messages.MAPPING_INVALID.format(
                        reference=self.stix_id,
                        stix_name=ext,
                        stix_value="",
                        exception=e
                    )
                )
                continue

            if is_defined:
                if extension:
                    logger.warning(
                        log_messages.EXTENSIONS_FIND_MULTIPLE_DEFINED, ext)
                else:
                    extension = ext
                    logger.debug(
                        log_messages.EXTENSIONS_FIND_FOUND, ext)
            else:
                logger.warning(
                    log_messages.EXTENSIONS_FIND_CUSTOM, ext)
        if extension:
            logger.debug(
                log_messages.EXTENSIONS_FIND_FINAL, extension)
        else:
            logger.debug(log_messages.EXTENSIONS_FIND_NOTHING_FOUND)
        return extension

    def create_typeql_extension_properties(
        self,
        extension_name: str,
        extension_object: dict[str, Any],
        reference: Identification
    ) -> tuple[dict, QueryBundle]:
        """Build a single extension.

        :param extension_name: The name of the extension
        :type extension_name: str
        :param extension_object: The extension data
        :type extension_object: dict[str, dict]

        :return: TypeQL attributes and additional queries
        :rytpe: tuple[dict, QueryBundle]
        """
        logger.debug(
            log_messages.EXTENSIONS_BUILD_PROPERTIES_START, extension_name)

        queries = QueryBundle()
        attributes = dict()
        for key, value in extension_object.items():
            # Build single property
            typedb_name, typedb_values, additional_queries = self \
                .create_typeql_extension_property(
                    extension_name,
                    key,
                    value,
                    reference
                )

            # add to collection
            if typedb_name and typedb_values:
                if not attributes.get(typedb_name):
                    attributes[typedb_name] = typedb_values
                else:
                    attributes[typedb_name].extend(typedb_values)
            queries.extend(additional_queries)

        return attributes, queries

    def create_typeql_extension_property(
        self,
        extension_name: str,
        property_name: str,
        property_value: Any,
        ref: Identification
    ) -> tuple[str, list[str], QueryBundle]:
        """Build a single property of an extension. 

        :param extension_name: The name of the extension
        :type extension_name: str
        :param property_name: The name of the property
        :type property_name: str
        :param property_value: The value of the property
        :type property_value: Any

        :return: The name, values and additional queries for this 
            property
        :rtype: tuple[str, list[str], QueryBundle]
        """
        logger.debug(
            log_messages.EXTENSIONS_PROPERTY_START, property_name)

        try:
            typedb_attribute_name, typedb_type = STIXtoTypeDBMapper \
                .get_extension_attribute_info(
                    self.stix_type, extension_name, property_name
                )
        except MappingException as e:
            logger.error(
                log_messages.MAPPING_INVALID
                .format(
                    reference=ref.get_id(),
                    stix_name=property_name,
                    stix_value=property_value,
                    exception=e
                )
            )
            return "", [], QueryBundle()

        # Custom attribute
        if not typedb_attribute_name or not typedb_type:
            return "", [], QueryBundle()

        logger.debug(
            log_messages.EXTENSIONS_PROPERTY_TRANSFORM,
                property_name, typedb_attribute_name, typedb_type
        )

        try:
            typedb_values, queries = self.convert_value_to_typeql(
                typedb_type,
                property_value,
                reference=ref,
                name=typedb_attribute_name
            )
        except ValueError as e:
            logger.error(
                log_messages.CONVERSION_FAILED
                .format(
                    value_type=typedb_type,
                    stix_value=property_value,
                    exception=e
                )
            )
            return "", [], QueryBundle()

        return typedb_attribute_name, typedb_values, queries

    def create_typeql_property(
        self, stix_name: str, stix_value: Any, reference: Identification
    ) -> tuple[str, list[str], QueryBundle]:
        """Build a single TypeDB property.

        :param stix_name: The STIX name of the attribute.
        :type stix_name: str
        :param stix_value: The STIX value that belongs to the attribute
        :type stix_value: Any
        :param reference: Reference values that identify the main object
        :type reference: Identification

        :return: The name, values and additional insert queries for this 
            attribute.
        :rtype: tuple[str, list[str], QueryBundle]
        """
        # logger.debug(log_messages.PROPERTY_START, stix_name)

        try:
            typedb_attribute_name, typedb_type = STIXtoTypeDBMapper \
                .get_object_attribute_info(self.stix_type, stix_name)
        except MappingException as e:
            logger.error(
                log_messages.MAPPING_INVALID
                .format(
                    reference=reference.get_id(),
                    stix_name=stix_name,
                    stix_value=stix_value,
                    exception=e
                )
            )
            return "", [], QueryBundle()

        # Custom property
        if not typedb_attribute_name:
            logger.debug(
                log_messages.PROPERTY_CUSTOM_ENCOUNTERED, stix_name)
            return self.create_typeql_custom_property(
                stix_name,
                stix_value,
                reference
            )

        try:
            values, queries = self.convert_value_to_typeql(
                typedb_type,
                stix_value,
                reference=reference,
                name=typedb_attribute_name
            )
        except ValueError as e:
            logger.error(
                log_messages.CONVERSION_FAILED
                .format(
                    reference=reference.get_id(),
                    value_type=typedb_type,
                    stix_name=stix_name,
                    stix_value=stix_value,
                    exception=e
                )
            )
            return "", [], QueryBundle()
        except MappingException as e:
            logger.error(
                log_messages.MAPPING_INVALID
                .format(
                    reference=reference.get_id(),
                    stix_name=stix_name,
                    stix_value=stix_value,
                    exception=e
                )
            )
            return "", [], QueryBundle()

        logger.debug(
            log_messages.PROPERTY_SUCCESS, stix_name,
                typedb_attribute_name, typedb_type
        )

        return typedb_attribute_name, values, queries

    def create_typeql_custom_property(
        self, stix_name: str, stix_value: Any, reference: Identification
    ) -> tuple[str, list[str], QueryBundle]:
        """Build a custom TypeDB property.

        :param stix_name: The STIX name of the attribute.
        :type stix_name: str
        :param stix_value: The STIX value that belongs to the attribute
        :type stix_value: Any
        :param reference: Reference values that identify the main object
        :type reference: Identification

        :return: The name, values and additional insert queries for this 
            attribute.
        :rtype: tuple[str, list[str], QueryBundle]
        """
        # logger.warning(log_messages.PROPERTY_CUSTOM, stix_name, reference.get_id())
        return "", [], QueryBundle()

    def add_attributes_to_typedb_object(
        self,
        attributes: dict[str, list[str]],
        main_object: Thing
    ) -> None:
        """Helper method to add attributes to the thing that represents 
        the main object.

        :param attributes: The attributes to be added
        :type attributes: dict[str, list[str]]
        :param main_object: The thing that represents the main object
        :type main_object: Thing
        """
        for name, values in attributes.items():
            for value in values:
                main_object.add_attribute(name, value)

    def determine_typedb_name(self) -> str:
        """Returns the name of the type in the schema of this STIX 
        object. None if the type could not be determined.

        :return: The typedb type of this object
        :rtype: str
        :raises MappingException: If an error occurs while retrieving
            the TypeDB type corresponding to a STIX type
        """
        name = STIXtoTypeDBMapper.get_typeql_thing_name(
            self.stix_type,
            self.properties,
            self.extensions
        )
        logger.debug(log_messages.DETERMINE_TYPE_FINISHED, name)

        return name

    def get_stix_id(self) -> str:
        """Returns the stix-id of this STIX Object.

        :return: The id of this object
        :rtype: str
        """
        return self.stix_id

    def get_stix_type(self) -> str:
        """Returns the stix type of this STIX Object.

        :return: The stix type of this object
        :rtype: str
        """
        return self.stix_type

    def convert_value_to_typeql(
        self, value_type: str, stix_value: str, **kwargs
    ) -> tuple[list[str], QueryBundle]:
        """Convert a value. Returns None if an error occured.

        :param value_type: The type the value should have in TypeDB
        :type value_type: str
        :param stix_value: The stix value that should be converted
        :type stix_value: str

        :raises ValueError: If the value could not be converted

        :return: The values and additional insert queries
        :rtype: tuple[list[str], QueryBundle]
        """
        converter: ValueConverter = ValueConverter \
            .get_converter(value_type)
        converter.parse_stix_2_1(stix_value)
        values, queries = converter.convert_to_typeql(**kwargs)
        return values, queries


class STIXCustomObjectConverter(STIXObjectConverter):
    """Represents a Custom STIX Object."""

    def build_typeql_bundle(self):
        logger.warning(
            log_messages.BUILD_CUSTOM_OBJECT_START, self.stix_type
        )
        return QueryBundle()


class STIXCoreObjectConverter(STIXObjectConverter):
    """Represents STIX Core objects."""

    @abstractmethod
    def create_typeql_object(
        self,
        type_name: str,
        queries: QueryBundle
    ) -> tuple[Thing, Identification]:
        """Create the entity or relation that represents the main object 
        and add it to the builder.

        :param type_name: The TypeDB type of the main object
        :type type_name: str
        :param queries: The QueryBundle to which the created object will
            be added
        :type queries: QueryBundle

        :raises TransformationError: If the STIX Object does not have 
            required properties
        :raises MappingException: If the mapping is invalid

        :return: The thing that represents the main STIX Object and 
            a reference to it 
        :rtype: tuple[Thing, Identification]
        """

    def build_typeql_bundle(self):
        logger.debug(log_messages.BUILD_CORE_START,self.stix_id)

        # queries needed to set up this object
        queries = QueryBundle()

        # raises MappingException and TransformationError
        type_name = self.determine_typedb_name()
        if not type_name:
            raise TransformationError(TransformationError.UNSUPPORTED_CUSTOM_TYPE, reference_id=self.stix_id)

        thing, ref = self.create_typeql_object(type_name, queries)

        # transform the attributes
        attributes, additional_queries = self.create_typeql_properties(ref)
        queries.extend(additional_queries)
        self.add_attributes_to_typedb_object(attributes, thing)

        # transform the extensions
        attributes, additional_queries = self.create_typeql_extensions(ref)
        queries.extend(additional_queries)
        self.add_attributes_to_typedb_object(attributes, thing)

        return queries


class STIXDomainObjectConverter(STIXCoreObjectConverter):
    """Converts STIX Domain Objects."""

    def create_typeql_object(self, type_name, queries):
        entity = Entity(typedb_type=type_name)
        queries.add_main_entity(entity)
        ref = Identification(
            self.get_stix_id(),
            entity.get_variable(),
            type_name
        )
        return entity, ref


class STIXCyberObservableConverter(STIXCoreObjectConverter):
    """Converts STIX Cyber Observables."""

    def create_typeql_object(self, type_name, queries):
        entity = Entity(typedb_type=type_name)
        queries.add_main_entity(entity)
        ref = Identification(
            self.get_stix_id(),
            entity.get_variable(),
            type_name
        )
        return entity, ref


class STIXRelationshipObjectConverter(STIXCoreObjectConverter):
    """Converts STIX Relationship objects."""

    def create_role(
        self,
        role_name: str,
        roleplayer_id: str,
        relation: Relation
    ) -> Entity:
        """Create a single role for this relation.

        :param role_name: The name of the role
        :type role_name: str
        :param roleplayer_id: The id of the roleplayer
        :type roleplayer_id: str
        :param relation: The main object relation
        :type relation: Relation

        :return: The roleplayer's match object
        :rtype: Entity
        """
        stix_type = get_type_from_id(roleplayer_id)
        object_type = STIXtoTypeDBMapper.get_typedb_supertype(stix_type)

        match_object = Identification(roleplayer_id, "", object_type) \
            .get_match_object()
        relation.add_roleplayer(role_name, match_object.get_variable())
        return match_object

    def create_role_property(
        self,
        type_name: str,
        property_name: str,
        relation: Relation
    ) -> list[Entity]:
        """Creates a role property of the main relation, i.e. creates 
        the match objects and returns them.

        Note: Because a property's value type might be a list of 
            identifiers, we have to return a list of match objects

        :param type_name: The TypeDB type for this object
        :type type_name: str
        :param property_name: The name of the property that is 
            implemented as a role player
        :type property_name: str
        :param relation: The main relation object
        :type relation: Relation

        :raises TransformationError: If the property does not exist
        :raises MappingException:

        :return: The match objects for the created roleplayers
        :rtype: list[Entity]
        """
        match_objects = []

        role_name = STIXtoTypeDBMapper.get_sro_role(type_name, property_name)
        roleplayer_id = self.properties.get(property_name)

        if not roleplayer_id:
            raise TransformationError(TransformationError.UNSPECIFIED_PROPERTY, property_name, self.stix_id)
        if isinstance(roleplayer_id, str):
            match_objects = [
                self.create_role(role_name, roleplayer_id, relation)
            ]
        elif isinstance(roleplayer_id, list):
            roleplayer_ids = roleplayer_id
            if roleplayer_ids and isinstance(roleplayer_ids[0], str):
                for roleplayer_id in roleplayer_ids:
                    match_objects.append(
                        self.create_role(role_name, roleplayer_id, relation)
                    )
            else:
                raise TransformationError(
                    TransformationError.INVALID_PROPERTY_VALUE, property, self.stix_id)
        else:
            raise TransformationError(
                TransformationError.INVALID_PROPERTY_TYPE, property, self.stix_id)

        return match_objects

    def create_typeql_object(self, type_name, queries):
        relation = Relation(typedb_type=type_name)
        ref = Identification(
            self.get_stix_id(),
            relation.get_variable(),
            type_name
        )

        # create roles
        relation_properties = STIXtoTypeDBMapper \
            .get_roleplayers_for_SRO(self.stix_type)
        match_objects = []
        for property in relation_properties:
            if property in self.properties:
                # raises MappingException and TransformationError
                role_players = self.create_role_property(
                    type_name, property, relation)
                match_objects.extend(role_players)

        queries.add_main_relation(relation, *match_objects)

        # for custom relations add the relationship type as an attribute
        if type_name == "custom-relationship":
            relation.add_attribute("relation-name",
                        typedb_constants.to_typedb_string(
                            self.properties.get("relationship_type")))

        return relation, ref


class STIXMetaObjectConverter(STIXObjectConverter):
    """Converts STIX Meta Objects."""

    def create_typeql_object(self, type_name, queries):
        """
        Creates a TypeQL entity object and an identification reference.

        Args:
            type_name (str): The name of the TypeQL type to create.
            queries (Queries): The queries object to which the main entity will be added.

        Returns:
            tuple: A tuple containing the created Entity object and the Identification reference.
        """
        entity = Entity(typedb_type=type_name)
        queries.add_main_entity(entity)
        ref = Identification(
            self.get_stix_id(),
            entity.get_variable(),
            type_name
        )
        return entity, ref

    def build_typeql_bundle(self):
        logger.debug("Building STIX Meta Object")
        queries = QueryBundle()

        # raises MappingException and TransformationError
        type_name = self.determine_typedb_name()
        if not type_name:
            raise TransformationError(
                TransformationError.UNSUPPORTED_CUSTOM_TYPE, reference_id=self.stix_id)

        entity, ref = self.create_typeql_object(type_name, queries)

        # transform the attributes
        attributes, additional_queries = self.create_typeql_properties(ref)
        queries.extend(additional_queries)
        self.add_attributes_to_typedb_object(attributes, entity)

        # transform the extensions
        attributes, additional_queries = self.create_typeql_extensions(ref)
        queries.extend(additional_queries)
        self.add_attributes_to_typedb_object(attributes, entity)

        return queries
