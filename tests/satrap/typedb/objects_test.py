import unittest

from satrap.datamanagement.typedb.dataobjects import (
    InsertQuery, Thing, Entity, Relation, VariableDealer
)


class TestObject(unittest.TestCase):

    def setUp(self):
        VariableDealer.reset()

    def test_variable_dealer(self):
        self.assertNotEqual(
            VariableDealer.get_variable(), 
            VariableDealer.get_variable()
        )

    def test_thing_type(self):
        t = Thing(typedb_type="attack-pattern")
        self.assertEqual(
            t.get_type(), 
            "attack-pattern"
        )

    def test_entity_type(self):
        e = Entity(typedb_type="attack-pattern")
        self.assertEqual(
            e.get_type(), 
            "attack-pattern"
        )

    def test_entity_attribute_simple(self):
        e = Entity()
        e.add_attribute("attribute", "value")
        self.assertEqual(
            e.get_attributes(),
            {"attribute": ["value"]}
        )

    def test_entity_attribute_twice(self):
        e = Entity()
        e.add_attribute("attribute", "value1")
        e.add_attribute("attribute", "value2")
        self.assertIn(
            e.get_attributes(),
            [
                {"attribute": ["value1", "value2"]},
                {"attribute": ["value2", "value1"]}
            ]
        )

    def test_entity_variable(self):
        e = Entity(variable="variable")
        self.assertEqual(
            e.get_variable(),
            "variable"
        )

    def test_relation(self):
        r = Relation(typedb_type="created_by_ref")
        r.add_attribute("name", "\"test\"")
        r.add_roleplayer("creator", "a")
        self.assertEqual(
            r.get_type(),
            "created_by_ref"
        )
        self.assertEqual(
            r.get_attributes(),
            {"name": ["\"test\""]}
        )
        self.assertEqual(
            r.get_roles(),
            {"creator": ["a"]}
        )

    def test_insert_query_simple(self):
        iq = InsertQuery()
        e = Entity("var", "type")
        iq.add_to_insert_clause(e)
        self.assertIn(
            e,
            iq.get_insert_clause()
        )

    def test_insert_query_fail(self):
        iq = InsertQuery()
        e1 = Entity("var", "type")
        e2 = Entity("var2", "type2")
        iq.add_to_insert_clause(e1)
        self.assertNotIn(
            e2,
            iq.get_insert_clause()
        )

    def test_insert_query_match(self):
        iq = InsertQuery()
        e1 = Entity("var", "type")
        e2 = Entity("var2", "type2")
        iq.add_to_insert_clause(e1)
        iq.add_to_match_clause(e2)
        self.assertIn(
            e1,
            iq.get_insert_clause()
        )
        self.assertIn(
            e2,
            iq.get_match_clause()
        )

    def test_entity_equality(self):
        e1 = Entity("var1", "type")
        e2 = Entity("var2", "type")
        e3 = Entity("var1", "type")

        e1.add_attribute("name1", "value1")
        e1.add_attribute("name1", "value2")
        e2.add_attribute("name1", "value1")
        e2.add_attribute("name1", "value2")

        self.assertEqual(e1, e2)
        self.assertNotEqual(e1,e3)

    def test_relation_equality(self):
        r1 = Relation("var1", "type")
        r2 = Relation("var2", "type")
        r3 = Relation("var1", "type")

        r1.add_roleplayer("role", "var")
        r2.add_roleplayer("role", "var2")
        r3.add_roleplayer("alt_role", "var")

        self.assertEqual(r1, r2)
        self.assertNotEqual(r1,r3)


if __name__ == "__main__":
    unittest.main()
