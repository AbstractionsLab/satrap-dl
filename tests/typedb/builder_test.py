import unittest
import os 
import sys

path = os.path.join(os.path.dirname(__file__), "../..")
parent_dir = os.path.abspath(path)
sys.path.append(parent_dir)

from satrap.datamanagement.typedb.dataobjects import Entity, Relation, VariableDealer
from satrap.datamanagement.typedb.typeql_builder import TypeQLBuilder
import satrap.datamanagement.typedb.typedb_constants as typedb_constants


class TestObject(unittest.TestCase):

    def setUp(self):
        VariableDealer.reset()

    def test_entity(self):
        e = Entity(variable="v0", typedb_type="attack-pattern")
        e.add_attribute("name", "\"value\"")

        expect = typedb_constants.VARIABLE_PREFIX
        expect += "v0"
        expect += typedb_constants.BEFORE_TYPEKEYWORD_SEPARATOR
        expect += typedb_constants.TYPE_KEYWORD
        expect += typedb_constants.TYPEKEYWORD_TYPE_SEPARATOR
        expect += "attack-pattern"
        expect += typedb_constants.ATTRIBUTE_SEPARATOR
        expect += typedb_constants.ATTRIBUTE_KEYWORD
        expect += typedb_constants.ATTRIBUTE_KEYWORD_KEY_SEPARATOR
        expect += "name"
        expect += typedb_constants.ATTRIBUTE_KEY_VALUE_SEPARATOR
        expect += "\"value\""
        expect += typedb_constants.OBJECT_ENDING

        self.assertEqual(
            TypeQLBuilder.build_entity(e), 
            expect
        )

    def test_relation(self):
        r = Relation(variable="v0", typedb_type="attack-pattern")
        r.add_attribute("name", "\"value\"")
        r.add_roleplayer("role", "player")

        expect = typedb_constants.VARIABLE_PREFIX
        expect += "v0"
        expect += typedb_constants.VARIABLE_RELATION_SEPARATOR
        expect += typedb_constants.ROLES_BEGINNING
        expect += "role"
        expect += typedb_constants.ROLE_VARIABLE_SEPARATOR
        expect += typedb_constants.VARIABLE_PREFIX
        expect += "player"
        expect += typedb_constants.ROLES_ENDING
        expect += typedb_constants.BEFORE_TYPEKEYWORD_SEPARATOR
        expect += typedb_constants.TYPE_KEYWORD
        expect += typedb_constants.TYPEKEYWORD_TYPE_SEPARATOR
        expect += "attack-pattern"
        expect += typedb_constants.ATTRIBUTE_SEPARATOR
        expect += typedb_constants.ATTRIBUTE_KEYWORD
        expect += typedb_constants.ATTRIBUTE_KEYWORD_KEY_SEPARATOR
        expect += "name"
        expect += typedb_constants.ATTRIBUTE_KEY_VALUE_SEPARATOR
        expect += "\"value\""
        expect += typedb_constants.OBJECT_ENDING

        self.assertEqual(
            TypeQLBuilder.build_relation(r), 
            expect
        )

    def test_thing(self):
        r = Relation(variable="v0", typedb_type="attack-pattern")
        r.add_attribute("name", "\"value\"")
        r.add_roleplayer("role", "player")

        expect = typedb_constants.VARIABLE_PREFIX
        expect += "v0"
        expect += typedb_constants.VARIABLE_RELATION_SEPARATOR
        expect += typedb_constants.ROLES_BEGINNING
        expect += "role"
        expect += typedb_constants.ROLE_VARIABLE_SEPARATOR
        expect += typedb_constants.VARIABLE_PREFIX
        expect += "player"
        expect += typedb_constants.ROLES_ENDING
        expect += typedb_constants.BEFORE_TYPEKEYWORD_SEPARATOR
        expect += typedb_constants.TYPE_KEYWORD
        expect += typedb_constants.TYPEKEYWORD_TYPE_SEPARATOR
        expect += "attack-pattern"
        expect += typedb_constants.ATTRIBUTE_SEPARATOR
        expect += typedb_constants.ATTRIBUTE_KEYWORD
        expect += typedb_constants.ATTRIBUTE_KEYWORD_KEY_SEPARATOR
        expect += "name"
        expect += typedb_constants.ATTRIBUTE_KEY_VALUE_SEPARATOR
        expect += "\"value\""
        expect += typedb_constants.OBJECT_ENDING

        self.assertEqual(
            TypeQLBuilder.build_thing(r), 
            expect
        )

    def test_insert_query(self):
        self.assertEqual("", "")

    def test_variable(self):
        expect = typedb_constants.VARIABLE_PREFIX + "var"

        self.assertEqual(
            TypeQLBuilder.build_variable("var"),
            expect
        )

    def test_attribute(self):
        expect = typedb_constants.ATTRIBUTE_KEYWORD
        expect += typedb_constants.ATTRIBUTE_KEYWORD_KEY_SEPARATOR
        expect += "name"
        expect += typedb_constants.ATTRIBUTE_KEY_VALUE_SEPARATOR
        expect += "3"

        self.assertEqual(
            TypeQLBuilder.build_attribute("name", "3"), 
            expect
        )

    def test_many_attributes(self):
        expect = typedb_constants.ATTRIBUTE_SEPARATOR
        expect += typedb_constants.ATTRIBUTE_KEYWORD
        expect += typedb_constants.ATTRIBUTE_KEYWORD_KEY_SEPARATOR
        expect += "name"
        expect += typedb_constants.ATTRIBUTE_KEY_VALUE_SEPARATOR
        expect += "value1"
        expect += typedb_constants.ATTRIBUTE_SEPARATOR
        expect += typedb_constants.ATTRIBUTE_KEYWORD
        expect += typedb_constants.ATTRIBUTE_KEYWORD_KEY_SEPARATOR
        expect += "name"
        expect += typedb_constants.ATTRIBUTE_KEY_VALUE_SEPARATOR
        expect += "value2"

        self.assertEqual(
            TypeQLBuilder.build_many_attributes(
                {"name": ["value1", "value2"]}
            ), 
            expect
        )
        self.assertEqual(
            TypeQLBuilder.build_many_attributes({}),
            ""
        )

    def test_type(self):
        expect = typedb_constants.BEFORE_TYPEKEYWORD_SEPARATOR
        expect += typedb_constants.TYPE_KEYWORD
        expect += typedb_constants.TYPEKEYWORD_TYPE_SEPARATOR
        expect += "test"
        
        self.assertEqual(
            TypeQLBuilder.build_typeql_type("test"), 
            expect
        ) 

    def test_role(self):
        expect = "role"
        expect += typedb_constants.ROLE_VARIABLE_SEPARATOR
        expect += typedb_constants.VARIABLE_PREFIX
        expect += "var"
        
        self.assertEqual(
            TypeQLBuilder.build_role("role", "var"), 
            expect
        ) 
        
    def test_all_roles(self):
        role1 = "role1"
        role1 += typedb_constants.ROLE_VARIABLE_SEPARATOR
        role1 += typedb_constants.VARIABLE_PREFIX
        role1 += "var1"

        role2 = "role2"
        role2 += typedb_constants.ROLE_VARIABLE_SEPARATOR
        role2 += typedb_constants.VARIABLE_PREFIX
        role2 += "var2"

        expect1 = typedb_constants.ROLES_BEGINNING
        expect2 = typedb_constants.ROLES_BEGINNING

        expect1 += role1
        expect1 += typedb_constants.ROLE_SEPARATOR
        expect1 += role2

        expect2 += role2
        expect2 += typedb_constants.ROLE_SEPARATOR
        expect2 += role1

        expect1 += typedb_constants.ROLES_ENDING
        expect2 += typedb_constants.ROLES_ENDING
        
        self.assertIn(
            TypeQLBuilder.build_all_roles(
                {"role1": ["var1"], "role2": ["var2"]}
            ), 
            [expect1, expect2]
        ) 
        
    def test_end(self):
        self.assertEqual(
            TypeQLBuilder.build_end(),
            typedb_constants.OBJECT_ENDING
        )


if __name__ == "__main__":
    unittest.main()
