from abc import ABC, abstractmethod
from typing import Any
import re

from stix2.utils import STIXdatetime, format_datetime
from stix2.utils import get_type_from_id

from satrap.etl.transform.stix_to_typedb_mapper import STIXtoTypeDBMapper
from satrap.etl.transform.query import Identification, QueryBundle
import satrap.etl.stix_constants as stix_constants
import satrap.etl.transform.stix_typeql_constants as constants
from satrap.datamanagement.typedb.dataobjects import Entity, Relation
import satrap.datamanagement.typedb.typedb_constants as typedb_constants


class ValueConverter(ABC):
    """Converts a value from one data representation to another."""

    @abstractmethod
    def parse_stix_2_1(self, value: Any) -> None:
        """Parse a STIX2.1 value.

        :param value: The value in STIX 2.1 format
        :type value: Any

        :raises ValueError: If the value could not be parsed
        """
        pass

    @abstractmethod
    def convert_to_typeql(
        self,
        **kwargs
    ) -> Any:
        """Create every query or query part that is required to add
        this value to the TypeDB database.

        :raises ValueError: If the underlying value could not be 
            converted
        :raises MappingException: If the mapping for the value
            transformation process is invalid

        :return: The transformed value
        :rtype: Any
        """
        pass

    @staticmethod
    def get_converter(value_type: str):
        """Returns an instance of a ValueConverter for the given type.

        :param value_type: The string that specifies the type of the 
            converter, e.g. "string" or "long"
        :type value_type: str

        :raises ValueError: If the value type has no converter 
            implementation

        :return: An instance of the corresponding ValueConverter
        :rtype: ValueConverterAdapter
        """
        res = None
        main_type, subtype = STIXtoTypeDBMapper.split_type(value_type)
        match main_type:
            case typedb_constants.STRING:
                res = StringConverter()
            case typedb_constants.DOUBLE:
                res = DoubleConverter()
            case typedb_constants.BOOLEAN:
                res = BooleanConverter()
            case typedb_constants.DATETIME:
                res = DatetimeConverter()
            case typedb_constants.LONG:
                res = LongConverter()
            case constants.TYPEQL_COMPOSITE_PREFIX:
                res = CompositeValueConverter(subtype)
            case constants.TYPEQL_RELATION_PREFIX:
                res = EmbeddedRelationConverter(subtype)
            case constants.TYPEQL_LIST_PREFIX:
                res = ListConverter(subtype)
            case constants.TYPEQL_NOT_IMPLEMENTED_TYPE_KEYWORD:
                res = EmptyValueConverter()
            case constants.TYPEQL_DICTIONARY_KEYWORD:
                res = DictionaryConverter()
            case constants.MAPPING_KEY_VALUE_PAIR_KEYWORD:
                res = KeyValuePairConverter(subtype)
            case constants.TYPEQL_ROLEPLAYER:
                res = EmptyValueConverter()
            case _:
                raise ValueError(
                    f"Value type '{value_type}' has no converter implementation")

        return ValueConverterAdapter(res)


class ValueConverterAdapter(ValueConverter):
    """Adapter class for the ValueConverters.

    This class is responsible for giving all ValueConverters the same 
    return type for their convert_value function.
    """

    def __init__(self, converter: ValueConverter):
        """Initializes a Converter Adapter

        :param converter: The underlying converter
        :type converter: ValueConverter
        """
        self.converter = converter

    def parse_stix_2_1(self, value: Any):
        """Parses a STIX 2.1 value. Delegates this task to the 
        underlying converter.

        :param value: The value that will be parsed
        :type value: Any
        """
        self.converter.parse_stix_2_1(value)

    def convert_to_typeql(
        self,
        **kwargs
    ) -> tuple[list[str], QueryBundle]:
        """Converts a value to the TypeDB representation.

        :raises ValueError: If there is a type error concerning 
            the return types.
        :raises MappingError: If the underlying mapping from STIX to 
            the TypeDB schema is invalid

        :return: The values and additional queries required to build 
            this value in TypeDB
        :rtype: tuple[list[str], QueryBundle]
        """
        res = self.converter.convert_to_typeql(**kwargs)
        # Primitive types
        if isinstance(res, str):
            if not res:
                return [], QueryBundle()
            return [res], QueryBundle()

        # List
        if isinstance(res, tuple):
            if len(res) != 2:
                raise ValueError("Value Conversion Type Error")
            values, queries = res
            if not isinstance(values, list):
                raise ValueError("Value Conversion Type Error")
            if len(values) > 0:
                if not isinstance(values[0], str):
                    raise ValueError("Value Conversion Type Error")
            if not isinstance(queries, QueryBundle):
                raise ValueError("Value Conversion Type Error")
            return values, queries

        # Non Primitive types
        if isinstance(res, QueryBundle):
            return [], res

        raise ValueError("Value Conversion Type Error")


class PrimitiveValueConverter(ValueConverter):
    """Converts a value of a primitive data format to another."""
    pass


class EmptyValueConverter(PrimitiveValueConverter):
    """Converts a value to an empty/ non-existing value."""

    def __init__(self):
        pass

    def parse_stix_2_1(self, value):
        pass

    def convert_to_typeql(self, **kwargs):
        # [] is not caught by the adapter
        return ""


class BooleanConverter(PrimitiveValueConverter):
    """Converts a *Boolean* value from one representation to another."""

    def __init__(self):
        self.boolean = None

    def parse_stix_2_1(self, value):
        if value is False:
            self.boolean = False
        elif value is True:
            self.boolean = True
        else:
            raise ValueError("Invalid boolean")

    def convert_to_typeql(self, **kwargs):
        if self.boolean:
            res = typedb_constants.BOOLEAN_TRUE
        else:
            res = typedb_constants.BOOLEAN_FALSE
        return res


class LongConverter(PrimitiveValueConverter):
    """Converts a *Long* value from one representation to another."""

    def __init__(self):
        self.number = 0

    def parse_stix_2_1(self, value):
        self.number = int(value)

    def convert_to_typeql(self, **kwargs):
        res = str(self.number)
        return res


class DoubleConverter(PrimitiveValueConverter):
    """Converts a *Double* value from one representation to another."""

    def __init__(self):
        self.number = 0.0

    def parse_stix_2_1(self, value):
        self.number = float(value)

    def convert_to_typeql(self, **kwargs):
        res = str(self.number)
        return res


class StringConverter(PrimitiveValueConverter):
    """Converts a *String* value from one representation to another."""

    def __init__(self):
        self.text = ""

    def parse_stix_2_1(self, value: str):
        self.text = value

    def convert_to_typeql(self, **kwargs):
        return typedb_constants.to_typedb_string(self.text)


class DatetimeConverter(PrimitiveValueConverter):
    """Converts a *Datetime* value from one representation to another."""

    def __init__(self):
        self.year: int = 0
        self.month: int = 0
        self.day: int = 0
        self.hour: int = 0
        self.minute: int = 0
        self.seconds: int = 0
        self.subseconds: list[int] = []

    def parse_stix_2_1(self, value):
        if isinstance(value, STIXdatetime):
            value = format_datetime(value)
        if not re.match(stix_constants.STIX_TIMESTAMP_REGEX, value):
            raise ValueError("Timestamp is not a STIX2.1 timestamp.")
        values = value.split(stix_constants.TIMESTAMP_DATE_SEPARATOR)
        self.year = int(values.pop(0))
        self.month = int(values.pop(0))
        values = values[0].split(stix_constants.TIMESTAMP_DATE_TIME_SEPARATOR)
        self.day = int(values.pop(0))
        values = values[0].split(stix_constants.TIMESTAMP_TIME_SEPARATOR)
        self.hour = int(values.pop(0))
        self.minute = int(values.pop(0))
        if stix_constants.TIMESTAMP_MILLIS_SEPARATOR in values[0]:
            values = values[0].split(stix_constants.TIMESTAMP_MILLIS_SEPARATOR)
            self.seconds = int(values.pop(0))
            millis = values[0] \
                .replace(stix_constants.TIMESTAMP_ENDING, "")
            self.subseconds = [int(i) for i in list(millis)]
        else:
            self.seconds = int(
                values[0].replace(stix_constants.TIMESTAMP_ENDING, "")
            )

    def convert_to_typeql(self, **kwargs):
        yyyymmdd = str(self.year).zfill(4)
        yyyymmdd += typedb_constants.DATETIME_DATE_SEPARATOR
        yyyymmdd += str(self.month).zfill(2)
        yyyymmdd += typedb_constants.DATETIME_DATE_SEPARATOR
        yyyymmdd += str(self.day).zfill(2)

        hhmmss = str(self.hour).zfill(2)
        hhmmss += typedb_constants.DATETIME_TIME_SEPARATOR
        hhmmss += str(self.minute).zfill(2)
        hhmmss += typedb_constants.DATETIME_TIME_SEPARATOR
        hhmmss += str(self.seconds).zfill(2)

        res = yyyymmdd
        res += typedb_constants.DATETIME_DATE_TIME_SEPARATOR
        res += hhmmss

        if self.subseconds:
            millis = self.subseconds
            num_millis = typedb_constants.DATETIME_NUMBER_MILLIS
            millis = millis[:num_millis]
            for _ in range(num_millis - len(millis)):
                millis.append(0)
            millis = "".join([str(i) for i in millis])
            millis = millis.zfill(num_millis)
            res += typedb_constants.DATETIME_MILLIS_SEPARATOR
            res += millis
        return res


class NonPrimitiveValueConverter(ValueConverter):
    """Converts a complex value from one representation to another."""

    def __init__(self, subtype: str):
        """Initializes a NonPrimitiveValueConverter and sets the 
        subtype of this NonPrimitive data type.

        E.g. for a list of strings, string is the subtype.

        :param subtype: The name of the subtype
        :type subtype: str
        """
        self.typedb_subtype = subtype


class KeyValuePairConverter(NonPrimitiveValueConverter):
    """Converts predefined KeyValuePairs from one representation 
    to another.
    """

    def __init__(self, subtype: str):
        super().__init__(subtype)
        self.key_value_pairs: dict = dict()

    def parse_stix_2_1(self, value: dict):
        self.key_value_pairs = value

    def convert_to_typeql(self, **kwargs):
        queries = QueryBundle()

        value_attribute, value_type = STIXtoTypeDBMapper \
            .get_pairs_value_and_type(self.typedb_subtype)

        for key, value in self.key_value_pairs.items():
            entity = Entity()

            # Transform the key
            typedb_type = STIXtoTypeDBMapper \
                .get_key_value_pair_key_translation(self.typedb_subtype, key)

            # Custom key
            if typedb_type is None:
                typedb_type, key_attribute = STIXtoTypeDBMapper \
                    .get_key_value_pair_custom(self.typedb_subtype)
                key = typedb_constants.to_typedb_string(key)
                entity.add_attribute(key_attribute, key)

            entity.set_type(typedb_type)

            # Transform the value
            # Raises ValueError
            converter: ValueConverter = ValueConverter \
                .get_converter(value_type)
            converter.parse_stix_2_1(value)
            values, additional_queries = converter.convert_to_typeql()
            if not additional_queries.is_empty():
                raise ValueError(
                    "NonPrimitive Types are currently not supported for "
                    "key value pairs"
                )
            for value in values:
                entity.add_attribute(value_attribute, value)

            # build the relation
            relation_name, object_role, item_role = STIXtoTypeDBMapper \
                .get_pair_relation(self.typedb_subtype)
            relation = Relation(typedb_type=relation_name)

            reference: Identification = kwargs \
                .get(constants.REFERENCE_KEYWORD)
            if not reference:
                raise ValueError(
                    "{constants.REFERENCE_KEYWORD} parameter missing in function call "
                    "for key-value pair creation")
            relation.add_roleplayer(object_role, reference.get_variable())
            relation.add_roleplayer(item_role, entity.get_variable())

            queries.add_structured_attribute(entity, relation)

        return queries


class CompositeValueConverter(NonPrimitiveValueConverter):
    """Converts a composite value from one representation to another."""

    def __init__(self, subtype: str):
        super().__init__(subtype)
        self.attributes = dict()

    def parse_stix_2_1(self, value: dict):
        self.attributes: dict = value

    def convert_to_typeql(self, **kwargs):
        # Set up the entity that represent the composite type
        queries = QueryBundle()
        entity = Entity(typedb_type=self.typedb_subtype)

        # set up the attributes of the composite type
        selfref = Identification(
            "",
            entity.get_variable(),
            self.typedb_subtype
        )
        for stix_name, stix_value in self.attributes.items():
            # Get the attribute name and value type in TypeDB
            typedb_name, typedb_type = STIXtoTypeDBMapper \
                .get_composite_attribute_info(self.typedb_subtype, stix_name)

            # Convert the value
            converter: ValueConverter = ValueConverter \
                .get_converter(typedb_type)
            converter.parse_stix_2_1(stix_value)
            typedb_values, additional_queries = converter \
                .convert_to_typeql(reference=selfref)

            for typedb_value in typedb_values:
                entity.add_attribute(typedb_name, typedb_value)
            queries.extend(additional_queries)

        reference: Identification = kwargs.get(constants.REFERENCE_KEYWORD)
        if not reference:
            raise ValueError(
                "{constants.REFERENCE_KEYWORD} parameter not specified for conversion of composite type")

        # set up the helper relation
        relation_name = STIXtoTypeDBMapper \
            .get_composite_type_relation(self.typedb_subtype)
        relation = Relation(typedb_type=relation_name)
        object_role, value_role = STIXtoTypeDBMapper \
            .get_composite_relation_roles(self.typedb_subtype)
        relation.add_roleplayer(object_role, reference.get_variable())
        relation.add_roleplayer(value_role, selfref.get_variable())

        queries.add_structured_attribute(entity, relation)
        return queries


class EmbeddedRelationConverter(NonPrimitiveValueConverter):
    """Converts a relation from one representation to another."""

    def __init__(self, subtype: str):
        super().__init__(subtype)

    def parse_stix_2_1(self, value):
        self.target_id: str = value

    def get_id_and_roles(self, **kwargs) -> tuple[Identification, str, str]:
        """Extracts the id of the calling object and the name of the 
        object's and value's roles.

        :raises ValueError: If a required parameter is not given

        :return: The id of the object and roles of the object and value
        :rtype: tuple[str, str, str]
        """
        reference: Identification = kwargs.get(constants.REFERENCE_KEYWORD)
        if not reference:
            raise ValueError(
                f"Parameter '{constants.REFERENCE_KEYWORD}' not given for embedded relation conversion")
        attribute_name = kwargs.get(constants.ATTRIBUTE_NAME)
        if not attribute_name:
            raise ValueError(
                f"Parameter '{constants.ATTRIBUTE_NAME}' not given for embedded relation conversion")
        obj_role, val_role = STIXtoTypeDBMapper \
            .get_embedded_relation_roles(attribute_name)
        return reference, obj_role, val_role

    def convert_to_typeql(self, **kwargs):
        # Get required information
        relation_name = self.typedb_subtype
        reference, object_role, value_role = self.get_id_and_roles(**kwargs)
        value_id = self.target_id

        try:
            stix_value_type = get_type_from_id(value_id)
        except AttributeError as err:
            raise ValueError(f"Error getting type of STIX object with id '{value_id}':\n{err}") from err
        value_type = STIXtoTypeDBMapper.get_typedb_supertype(stix_value_type)

        # set up the entities
        value_entity = Entity(typedb_type=value_type)
        value_id = typedb_constants.to_typedb_string(value_id)
        value_entity.add_attribute(constants.TYPEDB_ID_ATTRIBUTE, value_id)
        object_entity = reference.get_match_object()

        # set up the relation
        relation = Relation(typedb_type=relation_name)
        relation.add_roleplayer(object_role, object_entity.get_variable())
        relation.add_roleplayer(value_role, value_entity.get_variable())

        queries = QueryBundle()
        queries.add_embedded_relation(object_entity, value_entity, relation)

        return queries


class ListConverter(NonPrimitiveValueConverter):
    """Converts a typed list from one representation to another."""

    def __init__(self, subtype: str):
        super().__init__(subtype)
        # Check whether subtype is a valid type
        try:
            ValueConverter.get_converter(subtype)
        except ValueError as e:
            raise ValueError(e)
        self.elements = []

    def parse_stix_2_1(self, value):
        self.elements = value

    def convert_to_typeql(self, **kwargs):
        queries = QueryBundle()
        values = []

        for value in self.elements:
            converter: ValueConverter = ValueConverter \
                .get_converter(self.typedb_subtype)
            converter.parse_stix_2_1(value)
            additional_values, additional_queries = converter \
                .convert_to_typeql(**kwargs)

            values.extend(additional_values)
            queries.extend(additional_queries)

        return values, queries


class DictionaryConverter(NonPrimitiveValueConverter):
    """Convertes a Dictionary from one representation to another."""

    def __init__(self):
        self.dictionary: dict = dict()

    def parse_stix_2_1(self, value: dict):
        self.dictionary = value

    def convert_to_typeql(self, **kwargs):
        reference: Identification = kwargs.get(constants.REFERENCE_KEYWORD)
        if not reference:
            raise ValueError(
                "No reference passed for value conversion to dictionary"
            )
        queries = QueryBundle()
        property_attribute = STIXtoTypeDBMapper \
            .get_dictionary_property_attribute()

        for key, value in self.dictionary.items():
            # get the type of the value
            value_type = STIXtoTypeDBMapper \
                .get_default_value_implementation(value)

            if not value_type:
                raise ValueError(
                    "Dictionary contains value with unsupported value type: "
                    "{key} with value {value}")

            # convert the item's value to the TypeDB representation
            converter: ValueConverter = ValueConverter \
                .get_converter(value_type)
            converter.parse_stix_2_1(value)
            values, additional_queries = converter \
                .convert_to_typeql(reference=reference)
            if not additional_queries.is_empty():
                raise ValueError(
                    "Dictionaries do not support non primitive types"
                )

            # set up the item entity
            item_entity_type, key_attribute, value_attribute = \
                STIXtoTypeDBMapper.get_dictionary_item_data(value_type)

            item = Entity(typedb_type=item_entity_type)
            key = typedb_constants.to_typedb_string(key)
            item.add_attribute(key_attribute, key)
            for value in values:
                item.add_attribute(value_attribute, value)

            # Set up the relation that connects the item to main object
            # The relation has the name of the STIX property as an attribute
            relation_name, item_role, object_role = STIXtoTypeDBMapper \
                .get_dictionary_relation_data()

            relation = Relation(typedb_type=relation_name)
            property_name = kwargs.get(constants.ATTRIBUTE_NAME)
            if not property_name:
                raise ValueError(
                    "Property name must be given for Dictionary Conversion"
                )
            attribute_value = typedb_constants.to_typedb_string(property_name)
            relation.add_attribute(property_attribute, attribute_value)
            relation.add_roleplayer(object_role, reference.get_variable())
            relation.add_roleplayer(item_role, item.get_variable())

            queries.add_structured_attribute(item, relation)

        return ([], queries)
