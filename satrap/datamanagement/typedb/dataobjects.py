from typing import Self

from satrap.datamanagement.typedb import typedb_constants


class VariableDealer:
    """Responsible for giving unique variable names.
    
    This version does not support concurrency.
    """ 
    # TODO: For concurrency, protect this variable with a lock
    #       to avoid data races.
    counter = 0

    @staticmethod
    def get_variable() -> str:
        """Returns an unused variable.
        
        :return: The name of the variable
        :rtype: str
        """
        var = "v" + str(VariableDealer.counter)
        VariableDealer.counter += 1
        return var

    @staticmethod
    def reset() -> None:
        """Resets the used variables.

        After this method call, variables can be returned that 
        have been used before.
        """
        VariableDealer.counter = 0


class Thing:
    """Represents a Thing object in TypeDB, i.e. entity or relation.
    
    Note: The Thing object will be deprecated in TypeDB 3.0.
    """

    def __init__(
            self,
            variable: str = "",
            typedb_type: str = typedb_constants.THING,
        ):
        """Instantiate a thing.
        
        :param variable: The name of the variable assigned to this 
            thing, defaults to an unused variable
        :type variable: str, optional
        :param typedb_type: The type in typedb of this thing, 
            defaults to "thing"
        :type typedb_type: str, optional
        """
        # Note: Using a default value in the constructor with a method 
        #       call leads to variables being skipped. 
        #       Therefore, "variable" is checked here.
        if variable == "":
            variable = VariableDealer.get_variable()
        self.variable: str = variable
        self.type: str = typedb_type
        # Note: For every attribute, a list of values is assigned.
        self.attributes: dict[str, list[str]] = {}
    
    def add_attribute(self, name: str, value: str) -> None:
        """Add an attribute to the thing.
        
        :param name: The name of the attribute
        :type name: str
        :param value: The value of the attribute
        :type value: str
        """
        if name and value:
            if not self.attributes.get(name):
                self.attributes[name] = []
            self.attributes[name].append(value)

    def get_attributes(self) -> dict[str, list[str]]:
        """Returns the names of the attributes and the values that are
        assigned to them.
        
        :return: The names and values assigned to them
        :rtype: dict[str, list[str]]
        """
        return self.attributes

    def set_type(self, object_type: str) -> None:
        """Set the type of the thing.
        
        :param object_type: The type of this thing
        :type object_type: str
        """
        self.type = object_type

    def get_type(self) -> str:
        """Returns the type of the Thing.
        
        :return: The type of this thing
        :rtype: str
        """
        return self.type

    def get_variable(self) -> str:
        """Returns the variable of the thing in the insert query.
        
        :return: The variable assigned to this Thing
        :rtype: str
        """
        return self.variable

    def __str__(self):
        return f"{self.variable}:{self.type}"


class Entity(Thing):
    """Represents an Entity object in TypeDB."""

    def __init__(
            self,
            variable: str = "",
            typedb_type: str = typedb_constants.ENTITY,
        ):
        """Instantiate an entity.
        
        :param variable: The name of the variable assigned to this 
            entity, defaults to an unused variable
        :type variable: str, optional
        :param typedb_type: The type in typedb of this entity, 
            defaults to "entity"
        :type typedb_type: str, optional
        """
        super().__init__(variable, typedb_type)

    def __eq__(self, other: Self) -> bool:
        # Note: Variables are not relevant for equivalence
        if isinstance(other, Entity):
            return (other.get_type() == self.get_type()
                    and other.get_attributes() == self.get_attributes())
        return False


class Relation(Thing):
    """Represents a Relation object in TypeDB."""

    def __init__(
            self,
            variable: str = "", 
            typedb_type: str = typedb_constants.RELATION, 
        ):
        """Instantiate a relation.
        
        :param variable: The name of the variable assigned to this 
            relation, defaults to an unused variable
        :type variable: str, optional
        :param typedb_type: The type in typedb of this relation, 
            defaults to "relation"
        :type typedb_type: str, optional
        """
        super().__init__(variable, typedb_type)
        # Note: For every role, a variable is assigned.
        #       So the dict is in {role: [variable]} format
        #       as in TypeQL queries.
        self.plays_roles: dict[str, list[str]] = {}

    def __eq__(self, other: Self) -> bool:
        # Note: Variables are not relevant for equivalence
        if isinstance(other, Relation):
            return (other.get_type() == self.get_type()
                    and other.get_attributes() == self.get_attributes()
                    and other.get_roles().keys() == self.get_roles().keys())
        return False

    def add_roleplayer(self, role: str, variable: str) -> None:
        """Add a role to the relation.
        
        :param role: The name of the role
        :type role: str
        :param variable: The variable of the entity that plays the role
        :type variable: str
        """
        if self.plays_roles.get(role):
            self.plays_roles[role].append(variable)
        else:
            self.plays_roles.update({role: [variable]})

    def get_roles(self) -> dict[str, list[str]]:
        """Returns the names and variables of the roles.
        
        :return: The names and variables of the roles
        :rtype: dict[str, list[str]]
        """
        return self.plays_roles

    def __str__(self):
        return f"{super().__str__()},roles: {self.plays_roles}"


class InsertQuery:
    """Structure containing a set of TypeDb types/Things (entity, relation, attribute) that can be 
    mapped to an Insert query in TypeQL."""

    def __init__(self):
        """Empty Insert query structure"""
        self.match_clause: list[Thing] = []
        self.insert_clause: list[Thing] = []

    def add_to_match_clause(self, instance: Thing) -> None:
        """Add an instance of a type (or object) to the match clause.

        :param instance: The instance to add
        :type instance: Thing
        """
        self.match_clause.append(instance)

    def add_to_insert_clause(self, insert: Thing) -> None:
        """Add a thing to the insert clause.

        :param insert: The thing to add
        :type insert: Thing
        """
        self.insert_clause.append(insert)

    def get_match_clause(self) -> list[Thing]:
        """Returns the things in the match clause.

        :return: The things in the match clause
        :rtype: list[Thing]
        """
        return self.match_clause

    def get_insert_clause(self) -> list[Thing]:
        """Returns the Things in the insert clause.

        :return: The things in the insert clause
        :rtype: list[Thing]
        """
        return self.insert_clause

    def is_empty(self) -> bool:
        """States whether this InsertQuery is empty, i.e. whether there
        is no insertion.

        :return: Whether there is no insertion
        :rtype: bool
        """
        return len(self.insert_clause) == 0

    def extend(self, insert_query: Self) -> None:
        """Combines this InsertQuery with a given one by clauses

        :param insert_query: The other InsertQuery
        :type insert_query: InsertQuery
        """
        self.match_clause.extend(insert_query.get_match_clause())
        self.insert_clause.extend(insert_query.get_insert_clause())

    def __str__(self):
        res = "match: ["
        for e in self.match_clause:
            res += e.__str__() + "; "
        res += "]\ninsert: ["
        for e in self.insert_clause:
            res += e.__str__() + "; "
        res += "]\n"

        return res
