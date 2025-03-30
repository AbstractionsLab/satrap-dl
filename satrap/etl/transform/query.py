from typing import Self

from satrap.datamanagement.typedb.dataobjects import Entity, InsertQuery, Relation, Thing
from satrap.datamanagement.typedb import typedb_constants
import satrap.etl.transform.stix_typeql_constants as constants


class QueryBundle:
    """Manages the insertions in a transformation process from 
    STIX 2.1 to TypeDB.
    """

    def __init__(self):
        """Instantiates an empty QueryBundle."""
        self.main_object_type: str = ""
        self.main_object = InsertQuery()
        self.attributes = InsertQuery()
        self.embedded_relations = InsertQuery()

    def add_main_entity(self, main_object: Entity) -> None:
        """Add the main STIX object to the queries.

        :param main_object: The main STIX Object
        :type main_object: Entity
        """
        if not self.main_object.is_empty():
            raise AttributeError("Main object already exists.")
        self.main_object.add_to_insert_clause(main_object)
        self.main_object_type = typedb_constants.ENTITY_MARKING

    def add_main_relation(
        self,
        main_object: Relation,
        *args
    ) -> None:
        """Add the main object to the queries.

        :param main_object: The main STIX Object
        :type main_object: Relation
        :param args: The match objects
        :type args: Entity

        :raises AttributeError: If a main object in this query bundle 
            already exists.
        """
        if not self.main_object.is_empty():
            raise AttributeError("Main object already exists.")
        # TODO: Input validation: Check variables of roles and matches.
        #       Are the variables in the match statement the same as
        #       in the role assignment?
        #       Or even pass the role assignment as a dict to the entities
        #       such that this function includes the role assignment
        for match_object in args:
            self.main_object.add_to_match_clause(match_object)
        self.main_object.add_to_insert_clause(main_object)
        self.main_object_type = typedb_constants.RELATION_MARKING

    def add_structured_attribute(
        self,
        attribute: Entity,
        relation: Relation
    ) -> None:
        """Add an attribute that is implemented as further insertions,
        e.g. a composite type.

        :param attribute: The entity that represents the attribute
        :type attribute: Entity
        :param relation: The relation that connects the attribute with 
            the main object
        :type relation: Relation
        """
        # TODO: Input validation: Is the attribute's variable
        #       in the role assignment of the relation?
        self.attributes.add_to_insert_clause(attribute)
        self.attributes.add_to_insert_clause(relation)

    def add_embedded_relation(
        self,
        match1: Thing,
        match2: Thing,
        relation: Relation
    ) -> None:
        """Add an embedded relation.

        :param match1: The first thing in the relation
        :type match1: Thing
        :param match2: The second thing in the relation
        :type match2: Thing
        :param relation: The relation that connects the two entities
        :type relation: Relation
        """
        # TODO: Input validation: Are the variables of the two match
        #       objects in the role assignment of the relation?
        self.embedded_relations.add_to_match_clause(match1)
        self.embedded_relations.add_to_match_clause(match2)
        self.embedded_relations.add_to_insert_clause(relation)

    def extend(self, query_bundle: Self) -> None:
        """Extend this QueryBundle by the contents of another. 
        This is not allowed if both contain a main object.

        :param query_bundle: The second QueryBundle
        :type query_bundle: QueryBundle

        :raises ValueError: If both QueryBundles contain 
            a main object.
        """
        if self.main_object.is_empty():
            self.main_object_type = query_bundle.main_object_type
        elif query_bundle.main_object.is_empty():
            pass
        else:
            raise ValueError("One of the two QueryBundles must be empty")
        self.main_object.extend(query_bundle.main_object)
        self.attributes.extend(query_bundle.attributes)
        self.embedded_relations.extend(
            query_bundle.embedded_relations
        )

    def order_bundle(self) -> tuple[InsertQuery, InsertQuery, InsertQuery]:
        """Construct the three InsertQueries. 
        The first one represents the entities and has to be executed 
        first.
        The second one represents the STIX relationship objects and has 
        to be inserted after all entity queries have been inserted.
        The third one represents the embedded relations and has to be 
        inserted after all other queries have been inserted.

        :raises ValueError: If there is not a main object but the 
            QueryBundle is not empty.

        :return: The three InsertQueries. If an InsertQuery is empty,
            None is returned for this InsertQuery
        :rtype: tuple[InsertQuery, InsertQuery, InsertQuery]
        """
        main_entities = InsertQuery()
        main_relations = InsertQuery()
        embedded_relations = InsertQuery()
        if self.main_object_type == typedb_constants.ENTITY_MARKING:
            main_entities.extend(self.main_object)
            main_entities.extend(self.attributes)
        elif self.main_object_type == typedb_constants.RELATION_MARKING:
            main_relations.extend(self.main_object)
            main_relations.extend(self.attributes)
        else:
            if not self.is_empty():
                raise ValueError("Invalid main object type")
        embedded_relations.extend(self.embedded_relations)
        if main_entities.is_empty():
            main_entities = None
        if main_relations.is_empty():
            main_relations = None
        if embedded_relations.is_empty():
            embedded_relations = None

        return main_entities, main_relations, embedded_relations

    def is_empty(self) -> bool:
        """States whether this QueryBundle is empty, i.e. whether 
        there are no main object, no attributes and no embedded 
        relations.

        :return: Whether this QueryBundle is empty
        :rtype: bool
        """
        return (self.main_object.is_empty()
                and self.embedded_relations.is_empty()
                and self.attributes.is_empty()
                and self.main_object_type == "")

    def __str__(self):
        return (f"QueryBundle({self.main_object_type})\n"
            f"{{main_object=\n{self.main_object}"
            f"attributes=\n{self.attributes}"
            f"embedded_relations=\n{self.embedded_relations} }}")


class Identification:
    """Class to identify a TypeDB object.

    Uses the stix-id as a key attribute, a variable for a reference
    within a query and the TypeDB object type for generating the 
    TypeQL representation.
    """

    def __init__(self, id: str, variable: str, object_type: str):
        """Identifies an object in TypeDB.

        :param id: The value of the key attribute in the schema
        :type id: str
        :param variable: The variable used in a query for the 
            referenced object
        :type variable: str
        :param object_type: The TypeDB object type of the referenced 
            object
        :type object_type: str
        """
        self.id = id
        self.variable = variable
        self.object_type = object_type

    def get_id(self) -> str:
        """Returns the id of the referenced object.

        :raises ValueError: If there is no ID given for the referenced 
            object.

        :return: The id of the object it identifies
        :rtype: str
        """
        if not self.id:
            raise ValueError("This object cannot be referenced by ID")
        return self.id

    def get_variable(self) -> str:
        """Returns the variable of the referenced object.

        :raises ValueError: If there is no variable given for this 
            object.

        :return: The variable of the object it identifies
        :rtype: str
        """
        if not self.variable:
            raise ValueError(
                "This object cannot be referenced by variable"
            )
        return self.variable

    def get_type(self) -> str:
        """Returns the TypeDB object type of the referenced object.

        :raises ValueError: If there is no type given for the 
            referenced object.

        :return: The type of the object it identifies
        :rtype: str
        """
        if not self.object_type:
            raise ValueError(
                "No object type defined for the referenced object"
            )
        return self.object_type

    def get_match_object(self) -> Thing:
        """Returns a TypeDB object that references/ matches the
        object that this object references.

        :raises ValueError: If this object cannot be matched by ID,
            i.e. if there is no ID or no type given.

        :return: A match statement to get the underlying object
        :rtype: Thing
        """
        if not self.can_be_ref_by_id():
            raise ValueError("This object cannot be matched by ID")
        id = typedb_constants.to_typedb_string(self.get_id())
        res = Entity(typedb_type=self.get_type())
        res.add_attribute(constants.TYPEDB_ID_ATTRIBUTE, id)
        return res

    def can_be_ref_by_var(self) -> bool:
        """States whether this object can be referenced by variable.

        :return: Whether the underlying object can be referenced by 
            variable.
        :rtype: bool
        """
        return bool(self.get_variable())

    def can_be_ref_by_id(self) -> bool:
        """States whether this object can be referenced by ID.

        :return: Whether the underlying object can be referenced by id
        :rtype: bool
        """
        return bool(self.get_id()) and bool(self.get_type())

    def __str__(self):
        return (f"Identification(id={self.id}, variable={self.variable}, "
                f"object_type={self.object_type})")
