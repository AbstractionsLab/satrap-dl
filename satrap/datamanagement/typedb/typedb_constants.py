"""Constants related to TypeDB."""

# TypeDB keywords
ENTITY = "entity"
RELATION = "relation"
THING = "thing"
MATCH_KEYWORD = "match"
INSERT_KEYWORD = "insert"
KEYWORD_SEPARATOR = "\n"  # symbol after keywords, e.g. after match
OBJECT_ENDING = ";"
OBJECT_SEPARATOR = "\n"  # symbol after entities or relation
ATTRIBUTE_SEPARATOR = ", "
ATTRIBUTE_KEYWORD = "has"
ATTRIBUTE_KEYWORD_KEY_SEPARATOR = " "
ATTRIBUTE_KEY_VALUE_SEPARATOR = " "
ROLE_VARIABLE_SEPARATOR = ": "
VARIABLE_PREFIX = "$"
BEFORE_TYPEKEYWORD_SEPARATOR = " "
TYPE_KEYWORD = "isa"
TYPEKEYWORD_TYPE_SEPARATOR = " "
ROLE_SEPARATOR = ", "
ROLES_BEGINNING = "("
ROLES_ENDING = ")"
VARIABLE_RELATION_SEPARATOR = " "

# TypeDB value types
BOOLEAN = "boolean"
DATETIME = "datetime"
DOUBLE = "double"
LONG = "long"
STRING = "string"

BOOLEAN_TRUE = "true"
BOOLEAN_FALSE = "false"

DATETIME_DATE_SEPARATOR = "-"
DATETIME_DATE_TIME_SEPARATOR = "T"
DATETIME_TIME_SEPARATOR = ":"
DATETIME_MILLIS_SEPARATOR = "."
DATETIME_NUMBER_MILLIS = 3

STRING_DELIMITER = "\""
ALT_STRING_DELIMITER = "'"

# helpers
ENTITY_MARKING = "entity"
RELATION_MARKING = "relation"

# Log messages
NON_EMPTY_SERVER = "The server address must not be 'None' or empty."
NON_EMPTY_DB = "The database name must not be 'None' or empty."

def to_typedb_string(text: str) -> str:
    """Returns the TypeDB string representation of a string.

    :param text: The string to be converted
    :type text: str

    :return: The TypeDB representation of the given string
    :rtype: str
    """
    try:
        text = text.replace("\\", "\\\\")
        sanitized = STRING_DELIMITER + \
            text.replace(STRING_DELIMITER, ALT_STRING_DELIMITER) + \
            STRING_DELIMITER
    except AttributeError as e:
        raise ValueError(
            "Error converting Python string to TypeDB string: "
            f"{e}\n Is the text {text} a string?") from e
    return sanitized
