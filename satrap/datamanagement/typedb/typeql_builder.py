from satrap.datamanagement.typedb import typedb_constants
from satrap.datamanagement.typedb.dataobjects import Entity, InsertQuery, Relation, Thing


class TypeQLBuilder:
    """Class for building the TypeQL representations of 
    TypeDB components.
    """

    @staticmethod
    def build_entity(entity: Entity) -> str:
        """Create the TypeQL representation of an Entity.

        :param entity: The entity to transform
        :type entity: Entity

        :return: The TypeQL string for this Entity
        :rtype: str
        """
        res = TypeQLBuilder.build_variable(entity.get_variable())
        res += TypeQLBuilder.build_typeql_type(entity.get_type())
        res += TypeQLBuilder.build_many_attributes(entity.get_attributes())
        res += TypeQLBuilder.build_end()
        return res

    @staticmethod
    def build_relation(relation: Relation) -> str:
        """Create the TypeQL representation of a Relation.

        :param relation: The relation to transform
        :type relation: Relation

        :return: The TypeQL string for this Relation
        :rtype: str
        """
        res = TypeQLBuilder.build_variable(relation.get_variable())
        res += typedb_constants.VARIABLE_RELATION_SEPARATOR
        res += TypeQLBuilder.build_all_roles(relation.get_roles())
        res += TypeQLBuilder.build_typeql_type(relation.get_type())
        res += TypeQLBuilder.build_many_attributes(relation.get_attributes())
        res += TypeQLBuilder.build_end()
        return res

    @staticmethod
    def build_thing(thing: Thing) -> str:
        """Builds a thing, i.e. either an entity or a relation.

        :param thing: The thing to transform
        :type thing: Thing

        :raises ValueError: If the Thing object is neither an entity,
            nor a relation.
        """
        if isinstance(thing, Entity):
            return TypeQLBuilder.build_entity(thing)
        elif isinstance(thing, Relation):
            return TypeQLBuilder.build_relation(thing)
        else:
            raise ValueError("Thing is neither Entity nor Relation")

    @staticmethod
    def build_insert_query(insert_query: InsertQuery) -> str:
        """Create the TypeQL representation of an Insert Query.

        :param insert_query: The Insert Query to transform
        :type insert_query: InsertQuery

        :return: The TypeQL representation for this InsertQuery
        :rtype: str
        """
        if insert_query.is_empty():
            return ""
        matches = insert_query.get_match_clause()
        res = ""
        if matches:
            res += (typedb_constants.MATCH_KEYWORD
                    + typedb_constants.KEYWORD_SEPARATOR)
            for match in matches:
                res += (TypeQLBuilder.build_thing(match)
                        + typedb_constants.OBJECT_SEPARATOR)
        res += (typedb_constants.INSERT_KEYWORD
                + typedb_constants.KEYWORD_SEPARATOR)
        for thing in insert_query.get_insert_clause():
            res += (TypeQLBuilder.build_thing(thing)
                    + typedb_constants.OBJECT_SEPARATOR)
        return res

    @staticmethod
    def build_variable(variable: str) -> str:
        """Create the TypeQL representation of a variable.

        :param variable: The name of the variable
        :type variable: str

        :return: The TypeQL representation for this variable
        :rtype: str
        """
        return typedb_constants.VARIABLE_PREFIX + variable

    @staticmethod
    def build_attribute(name: str, value: str) -> str:
        """Create the TypeQL representation of an attribute.

        :param name: The name of the attribute
        :type name: str
        :param value: The value in TypeQL representation
        :type value: str

        :return: The TypeQL representation of the attribute
        :rtype: str
        """
        return (typedb_constants.ATTRIBUTE_KEYWORD
                + typedb_constants.ATTRIBUTE_KEYWORD_KEY_SEPARATOR
                + name
                + typedb_constants.ATTRIBUTE_KEY_VALUE_SEPARATOR
                + value)

    @staticmethod
    def build_many_attributes(attributes: dict[str, list[str]]) -> str:
        """Create the TypeQL representation of many attributes.

        :param attributes: The names and values of the attributes
        :type attributes: dict[str, list[str]]

        :return: The TypeQL representation of the attributes
        :rtype: str
        """
        res = ""
        for name, values in attributes.items():
            for value in values:
                attribute = TypeQLBuilder.build_attribute(name, value)
                res += (typedb_constants.ATTRIBUTE_SEPARATOR + attribute)
        return res

    @staticmethod
    def build_typeql_type(type:str) -> str:
        """Create the TypeQL representation of the type of a thing.

        :param type: The name of the type.
        :type type: str

        :return: The TypeQL representation of the type.
        :rtype: str
        """
        return (typedb_constants.BEFORE_TYPEKEYWORD_SEPARATOR
                + typedb_constants.TYPE_KEYWORD
                + typedb_constants.TYPEKEYWORD_TYPE_SEPARATOR
                + type)

    @staticmethod
    def build_role(role_name: str, variable_name: str) -> str:
        """Create the TypeQL representation of a role in a relation.

        :param role_name: The name of the role
        :type role_name: str
        :param variable_name: The variable assigned to this role
        :type variable_name: str

        :return: The TypeQL representation of the role
        :rtype: str
        """
        return (role_name
                + typedb_constants.ROLE_VARIABLE_SEPARATOR
                + TypeQLBuilder.build_variable(variable_name))

    @staticmethod
    def build_all_roles(roles: dict[str, str]) -> str:
        """Create the TypeQL representation of all roles in a relation.

        :param roles: The names and variables of the roles
        :type roles: dict[str, str]

        :raises ValueError: If the roles are empty.

        :return: The TypeQL representation of the roles
        :rtype: str
        """
        if not roles:
            raise ValueError("Relation must have at least one role")
        rel = typedb_constants.ROLES_BEGINNING
        role, variables = roles.popitem()
        for variable in variables[:len(variables)-1]:
            rel += TypeQLBuilder.build_role(role, variable)
            rel += typedb_constants.ROLE_SEPARATOR
        rel += TypeQLBuilder.build_role(role, variables[-1])
        for role, variables in roles.items():
            for variable in variables:
                rel += (typedb_constants.ROLE_SEPARATOR
                        + TypeQLBuilder.build_role(role, variable))
        rel += typedb_constants.ROLES_ENDING
        return rel

    @staticmethod
    def build_end() -> str:
        """Creates the TypeQL representation of the end of a thing.

        :return: The TypeQL representation of the end
        :rtype: str
        """
        return typedb_constants.OBJECT_ENDING
