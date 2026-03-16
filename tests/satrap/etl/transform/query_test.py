import unittest
import os
import sys

from satrap.etl.transform.query import Identification, QueryBundle
from satrap.datamanagement.typedb.dataobjects import Entity, Relation, VariableDealer
from satrap.datamanagement.typedb import typedb_constants

path = os.path.join(os.path.dirname(__file__), "../..")
parent_dir = os.path.abspath(path)
sys.path.append(parent_dir)


class TestObject(unittest.TestCase):

    def setUp(self):
        VariableDealer.reset()
        self.insert_builder = QueryBundle()

    def test_identification(self):
        identification = Identification("id-1337", "variable-42", "type")
        self.assertEqual(
            identification.get_id(),
            "id-1337"
        )
        self.assertEqual(
            identification.get_variable(),
            "variable-42"
        )

    def test_is_empty(self):
        self.assertTrue(self.insert_builder.is_empty())
        entity = Entity()
        self.insert_builder.add_main_entity(entity)
        self.assertFalse(self.insert_builder.is_empty())

    def test_add_main_entity(self):
        entity = Entity(typedb_type="main_entity")
        self.insert_builder.add_main_entity(entity)
        self.assertTrue(self.insert_builder.embedded_relations.is_empty())
        self.assertTrue(self.insert_builder.attributes.is_empty())
        self.assertEqual(
            len(self.insert_builder.main_object.get_match_clause()),
            0
        )
        self.assertEqual(
            len(self.insert_builder.main_object.get_insert_clause()),
            1
        )
        self.assertEqual(
            self.insert_builder.main_object.get_insert_clause()[0],
            entity
        )
        self.assertEqual(
            self.insert_builder.main_object_type,
            typedb_constants.ENTITY_MARKING
        )

    def test_add_main_relation(self):
        relation = Relation(typedb_type="main_relation")
        entity1 = Entity()
        entity2 = Entity()
        self.insert_builder.add_main_relation(relation, entity1, entity2)
        self.assertTrue(self.insert_builder.embedded_relations.is_empty())
        self.assertTrue(self.insert_builder.attributes.is_empty())
        self.assertEqual(
            len(self.insert_builder.main_object.get_match_clause()),
            2
        )
        self.assertEqual(
            len(self.insert_builder.main_object.get_insert_clause()),
            1
        )
        self.assertEqual(
            self.insert_builder.main_object.get_insert_clause()[0],
            relation
        )
        self.assertEqual(
            self.insert_builder.main_object_type,
            typedb_constants.RELATION_MARKING
        )

    def test_add_structured_attribute(self):
        attribute = Entity()
        helper_relation = Relation()
        self.insert_builder.add_structured_attribute(
            attribute, helper_relation
        )

        self.assertEqual(len(self.insert_builder.attributes.get_insert_clause()), 2)
        entity: Entity = self.insert_builder.attributes.get_insert_clause()[0]
        relation: Relation = self.insert_builder.attributes.get_insert_clause()[1]

        self.assertEqual(attribute, entity)
        self.assertEqual(helper_relation, relation)

    def test_add_embedded_relation(self):
        embedded_relation = Relation()
        match1 = Entity()
        match2 = Entity()
        self.insert_builder.add_embedded_relation(
            match1, match2, embedded_relation
        )

        self.assertEqual(
            len(self.insert_builder.embedded_relations.get_insert_clause()), 1
        )
        self.assertEqual(
            len(self.insert_builder.embedded_relations.get_match_clause()), 2
        )
        relation = self.insert_builder.embedded_relations.get_insert_clause()[0]
        entity1 = self.insert_builder.embedded_relations.get_match_clause()[0]
        entity2 = self.insert_builder.embedded_relations.get_match_clause()[1]

        self.assertEqual(relation, embedded_relation)
        if entity1 == match1:
            self.assertEqual(entity2, match2)
        else:
            self.assertEqual(entity1, match2)
            self.assertEqual(entity2, match1)

    def test_extend(self):
        second_builder = QueryBundle()
        entity1 = Entity(typedb_type="type1")
        entity2 = Entity(typedb_type="type2")
        relation1 = Relation(typedb_type="type3")
        relation2 = Relation(typedb_type="type4")
        self.insert_builder.add_main_entity(entity1)

        second_builder.add_structured_attribute(entity1, relation1)
        self.insert_builder.add_structured_attribute(entity2, relation2)

        self.insert_builder.extend(second_builder)
        self.assertEqual(len(self.insert_builder.attributes.get_match_clause()), 0)
        self.assertEqual(len(self.insert_builder.attributes.get_insert_clause()), 4)
        second_builder.add_main_entity(entity2)

        with self.assertRaises(ValueError):
            self.insert_builder.extend(second_builder)

    def test_build_entity(self):
        main_entity = Entity(typedb_type="test_type")
        self.insert_builder.add_main_entity(main_entity)

        first, second, third = self.insert_builder.order_bundle()
        self.assertFalse(first.is_empty())
        self.assertIsNone(second)
        self.assertIsNone(third)

        self.assertEqual(first.get_insert_clause()[0], main_entity)

    def test_build_entity_attribute(self):
        main_entity = Entity(typedb_type="test_type")
        self.insert_builder.add_main_entity(main_entity)

        attribute = Entity(typedb_type="attribute")
        helper_relation = Relation(typedb_type="helper")
        self.insert_builder.add_structured_attribute(
            attribute, helper_relation
        )

        first, second, third = self.insert_builder.order_bundle()
        self.assertFalse(first.is_empty())
        self.assertIsNone(second)
        self.assertIsNone(third)

        self.assertEqual(len(first.get_match_clause()), 0)
        self.assertEqual(len(first.get_insert_clause()), 3)
        self.assertEqual(first.get_insert_clause()[2], helper_relation)

    def test_build_entity_embedded_relation(self):
        main_entity = Entity(typedb_type="test_type")
        self.insert_builder.add_main_entity(main_entity)
        second_entity = Entity(typedb_type="match_type")
        embedded_relation = Relation(typedb_type="embedded")

        # is the main object really required? -> can be inferred
        # only dependency: variable
        self.insert_builder.add_embedded_relation(
            main_entity, second_entity, embedded_relation
        )
        first,second, third = self.insert_builder.order_bundle()
        self.assertFalse(first.is_empty())
        self.assertIsNone(second)
        self.assertFalse(third.is_empty())

        self.assertEqual(len(first.get_match_clause()), 0)
        self.assertEqual(len(first.get_insert_clause()), 1)
        insert = first.get_insert_clause()[0]
        self.assertEqual(insert,main_entity)
        self.assertEqual(len(third.get_match_clause()), 2)
        self.assertEqual(len(third.get_insert_clause()), 1)
        relation_insert = third.get_insert_clause()[0]
        self.assertEqual(relation_insert, embedded_relation)

    def test_build_entity_both(self):
        main_entity = Entity(typedb_type="main_type")
        self.insert_builder.add_main_entity(main_entity)

        second_entity = Entity(typedb_type="match_type")
        embedded_relation = Relation(typedb_type="embedded")
        self.insert_builder.add_embedded_relation(
            main_entity, second_entity, embedded_relation
        )

        attribute = Entity(typedb_type="attribute")
        helper_relation = Relation(typedb_type="helper")
        self.insert_builder.add_structured_attribute(
            attribute, helper_relation
        )

        first, second, third = self.insert_builder.order_bundle()
        self.assertEqual(len(first.get_match_clause()), 0)
        self.assertEqual(len(first.get_insert_clause()), 3)
        self.assertIsNone(second)
        self.assertEqual(len(third.get_match_clause()), 2)
        self.assertEqual(len(third.get_insert_clause()), 1)

    def test_build_relation(self):
        main_relation = Relation(typedb_type="test_type")
        match1 = Entity(typedb_type="type1")
        match2 = Entity(typedb_type="type2")
        self.insert_builder.add_main_relation(main_relation, match1, match2)

        first, second, third = self.insert_builder.order_bundle()
        self.assertIsNone(first)
        self.assertFalse(second.is_empty())
        self.assertIsNone(third)

        self.assertEqual(second.get_insert_clause()[0], main_relation)
        self.assertEqual(len(second.get_match_clause()), 2)

    def test_build_relation_attribute(self):
        main_relation = Relation(typedb_type="test_type")
        match1 = Entity(typedb_type="type1")
        match2 = Entity(typedb_type="type2")
        self.insert_builder.add_main_relation(main_relation, match1, match2)

        attribute = Entity(typedb_type="attribute")
        helper_relation = Relation(typedb_type="helper")
        self.insert_builder.add_structured_attribute(
            attribute, helper_relation
        )

        first, second, third = self.insert_builder.order_bundle()
        self.assertIsNone(first)
        self.assertFalse(second.is_empty())
        self.assertIsNone(third)

        self.assertEqual(len(second.get_match_clause()), 2)
        self.assertEqual(len(second.get_insert_clause()), 3)
        self.assertEqual(second.get_insert_clause()[2], helper_relation)

    def test_build_relation_embedded_relation(self):
        main_relation = Relation(typedb_type="test_type")
        match1 = Entity(typedb_type="type1")
        match2 = Entity(typedb_type="type2")
        self.insert_builder.add_main_relation(main_relation, match1, match2)

        second_entity = Entity(typedb_type="match_type")
        embedded_relation = Relation(typedb_type="embedded")
        self.insert_builder.add_embedded_relation(
            main_relation, second_entity, embedded_relation
        )

        first, second, third = self.insert_builder.order_bundle()
        self.assertIsNone(first)
        self.assertFalse(second.is_empty())
        self.assertFalse(third.is_empty())

        self.assertEqual(len(second.get_match_clause()), 2)
        self.assertEqual(len(second.get_insert_clause()), 1)
        self.assertEqual(len(third.get_match_clause()), 2)
        self.assertEqual(len(third.get_insert_clause()), 1)
        self.assertEqual(second.get_insert_clause()[0], main_relation)
        self.assertEqual(third.get_insert_clause()[0], embedded_relation)

    def test_build_relation_both(self):
        main_relation = Relation(typedb_type="main")
        match1 = Entity(typedb_type="match1")
        match2 = Entity(typedb_type="match2")
        self.insert_builder.add_main_relation(main_relation, match1, match2)

        second_entity = Entity(typedb_type="match_type")
        embedded_relation = Relation(typedb_type="embedded")
        self.insert_builder.add_embedded_relation(
            main_relation, second_entity, embedded_relation
        )

        attribute = Entity(typedb_type="attribute")
        helper_relation = Relation(typedb_type="helper")
        self.insert_builder.add_structured_attribute(
            attribute, helper_relation
        )

        first, second, third = self.insert_builder.order_bundle()

        self.assertIsNone(first)
        self.assertEqual(len(second.get_match_clause()), 2)
        self.assertEqual(len(second.get_insert_clause()), 3)
        self.assertEqual(len(third.get_match_clause()), 2)
        self.assertEqual(len(third.get_insert_clause()), 1)

    def test_empty(self):
        first, second, third = QueryBundle().order_bundle()
        self.assertIsNone(first)
        self.assertIsNone(second)
        self.assertIsNone(third)


if __name__ == "__main__":
    unittest.main()
