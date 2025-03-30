import unittest

from satrap.etl.transform.stix_to_typedb_mapper import STIXtoTypeDBMapper
from satrap.datamanagement.typedb.dataobjects import Entity, Relation, VariableDealer
from satrap.etl.transform.stixobject_converter import (
    STIXDomainObjectConverter, STIXObjectConverter,
    STIXRelationshipObjectConverter
)
from satrap.datamanagement.typedb.typedb_constants import to_typedb_string
import satrap.etl.transform.stix_typeql_constants as constants


class TestSTIXObject(unittest.TestCase):

    def setUp(self):
        VariableDealer.reset()
        STIXtoTypeDBMapper.get_data()

    def test_simple_create(self):
        test = {"id": "testid", "type": "attack-pattern"}
        sdo = STIXObjectConverter.create(test)
        self.assertIsInstance(sdo, STIXDomainObjectConverter)

        test = {"id": "testid", "type": "sighting"}
        sro = STIXObjectConverter.create(test)
        self.assertIsInstance(sro, STIXRelationshipObjectConverter)

    def test_simple_build(self):
        test = {"id": "test1", "name": "test2", "type": "attack-pattern"}
        expect_entity = Entity(typedb_type="attack-pattern")
        expect_entity.add_attribute(
            constants.TYPEDB_ID_ATTRIBUTE,
            to_typedb_string("test1")
        )
        expect_entity.add_attribute("name", to_typedb_string("test2"))

        so: STIXObjectConverter = STIXObjectConverter.create(test)
        query = so.build_typeql_bundle()
        first, second, third = query.order_bundle()

        self.assertEqual(expect_entity, first.get_insert_clause()[0])
        self.assertIsNone(second)
        self.assertIsNone(third)

    def test_reduced_attack_pattern(self):
        test = {
            "type" : "attack-pattern",
            "spec_version" : "2.1",
            "id" : "attack-pattern--0001",
            "created_by_ref" : "identity--0002",
            "created" : "2024-05-02T14:10:11Z",
            "revoked" : False,
            "labels" : ["label01", "label02"],
            "confidence" : 2,
            "external_references" : [
                {
                    "source_name": "test1a",
                    "description": "test1b"
                }
            ],
            "name" : "attack-pattern-01",
            "description" : "An attack-pattern"
        }
        expect_entity = Entity(typedb_type="attack-pattern")
        expect_entity.add_attribute("spec-version", to_typedb_string("2.1"))
        expect_entity.add_attribute(
            constants.TYPEDB_ID_ATTRIBUTE, 
            to_typedb_string("attack-pattern--0001")
        )
        expect_entity.add_attribute("created", "2024-05-02T14:10:11")
        expect_entity.add_attribute("revoked", "false")
        expect_entity.add_attribute("label", to_typedb_string("label01"))
        expect_entity.add_attribute("label", to_typedb_string("label02"))
        expect_entity.add_attribute("confidence", "2")
        expect_entity.add_attribute("name", to_typedb_string("attack-pattern-01"))
        expect_entity.add_attribute(
            "description", 
            to_typedb_string("An attack-pattern")
        )

        so: STIXObjectConverter = STIXObjectConverter.create(test)
        query = so.build_typeql_bundle()
        first, second, third = query.order_bundle()

        self.assertEqual(len(first.get_match_clause()), 0)
        self.assertEqual(len(first.get_insert_clause()), 3)
        self.assertEqual(first.get_insert_clause()[0], expect_entity)
        self.assertIsInstance(first.get_insert_clause()[2], Relation)

        self.assertIsNone(second)

        self.assertEqual(len(third.get_insert_clause()), 1)
        self.assertIsInstance(third.get_insert_clause()[0], Relation)
        self.assertEqual(len(third.get_match_clause()), 2)

    def test_embedded_relation(self):
        test = {
            "type" : "attack-pattern",
            "id" : "attack-pattern--0001",
            "created_by_ref" : "identity--0002",
        }
        expect_relation = Relation(typedb_type="created-by-ref")
        expect_relation.add_roleplayer("creator", "_")
        expect_relation.add_roleplayer("object-created", "_")

        so: STIXObjectConverter = STIXObjectConverter.create(test)
        query = so.build_typeql_bundle()
        first, second, third = query.order_bundle()

        self.assertEqual(len(first.get_match_clause()), 0)
        self.assertEqual(len(first.get_insert_clause()), 1)
        self.assertIsNone(second)
        self.assertEqual(expect_relation, third.get_insert_clause()[0])
        self.assertEqual(len(third.get_match_clause()), 2)

    def test_simple_relationship(self):
        test = {
            "type": "relationship",
            "relationship_type" : "attributed-to",
            "id": "relationship--0001",
            "source_ref" : "identity--0001",
            "target_ref" : "identity--0002",
        }
        expect_relation = Relation(typedb_type="attributed-to")
        expect_relation.add_attribute(
            constants.TYPEDB_ID_ATTRIBUTE, 
            to_typedb_string("relationship--0001")
        )
        expect_relation.add_roleplayer("attributee", "_")
        expect_relation.add_roleplayer("attribution", "_")

        so: STIXObjectConverter = STIXObjectConverter.create(test)
        query = so.build_typeql_bundle()
        first, second, third = query.order_bundle()
        self.assertIsNone(first)
        self.assertEqual(len(second.get_match_clause()), 2)
        self.assertEqual(len(second.get_insert_clause()), 1)
        self.assertIsNone(third)

        relation = Relation(typedb_type="attributed-to")
        relation.add_attribute(
            "stix-id", to_typedb_string("relationship--0001")
        )
        relation.add_roleplayer("attributee", "_")
        relation.add_roleplayer("attribution", "_")
        self.assertEqual(relation, second.get_insert_clause()[0])

    def test_relationship_with_embedded_relation(self):
        test = {
            "type": "sighting",
            "id": "sighting--ee20065d-2555-424f-ad9e-0f8428623c75",
            "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
            "sighting_of_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
        }

        so: STIXObjectConverter = STIXObjectConverter.create(test)
        query = so.build_typeql_bundle()
        first, second, third = query.order_bundle()

        self.assertIsNone(first)
        self.assertFalse(second.is_empty())
        self.assertFalse(third.is_empty())

        self.assertEqual(len(second.get_insert_clause()), 1)
        self.assertEqual(len(second.get_match_clause()), 1)
        self.assertEqual(len(third.get_insert_clause()), 1)
        self.assertEqual(len(third.get_match_clause()), 2)

    def test_extension(self):
        test = {
            "type": "user-account",
            "id": "user-account--0001",
            "extensions": {
                "unix-account-ext": {
                    "gid": 3
                }
            }
        }
        so: STIXObjectConverter = STIXObjectConverter.create(test)
        query = so.build_typeql_bundle()
        first, second, third = query.order_bundle()
        self.assertFalse(first.is_empty())
        self.assertIsNone(second)
        self.assertIsNone(third)

        expect = Entity(typedb_type="unix-account-ext")
        expect.add_attribute(
            constants.TYPEDB_ID_ATTRIBUTE, 
            to_typedb_string("user-account--0001")
        )
        expect.add_attribute("gid", "3")

        so: STIXObjectConverter = STIXObjectConverter.create(test)
        query = so.build_typeql_bundle()
        first, second, third = query.order_bundle()

        self.assertFalse(first.is_empty())
        self.assertEqual(len(first.get_insert_clause()), 1)
        entity = first.get_insert_clause()[0]

        self.assertIsNone(second)
        self.assertIsNone(third)
        self.assertEqual(expect, entity)

    def test_sighting(self):
        test = {
            "type": "sighting",
            "id": "sighting--ee20065d-2555-424f-ad9e-0f8428623c75",
            "sighting_of_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
        }
        expect_relation = Relation(typedb_type="sighting")
        expect_relation.add_attribute(
            constants.TYPEDB_ID_ATTRIBUTE,
            to_typedb_string("sighting--ee20065d-2555-424f-ad9e-0f8428623c75")
        )
        expect_relation.add_roleplayer("sighting-of", "_")

        expect_match = Entity(typedb_type="indicator")
        expect_match.add_attribute(
            constants.TYPEDB_ID_ATTRIBUTE,
            to_typedb_string("indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f")
        )

        so: STIXObjectConverter = STIXObjectConverter.create(test)
        query = so.build_typeql_bundle()
        first, second, third = query.order_bundle()

        self.assertIsNone(first)
        self.assertFalse(second.is_empty())
        self.assertIsNone(third)
        inserts = second.get_insert_clause()
        matches = second.get_match_clause()
        self.assertEqual(len(inserts), 1)
        self.assertEqual(len(matches), 1)

        relation = inserts[0]
        match = matches[0]

        self.assertEqual(expect_relation, relation)
        self.assertEqual(expect_match, match)

    def test_list_roleplayers(self):
        test = {
            "type": "sighting",
            "id": "sighting--ee20065d-2555-424f-ad9e-0f8428623c75",
            "where_sighted_refs": [
                "identity--b67d30ff-02ac-498a-92f9-32f845f448ff",
                "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"
            ]
        }
        expect_relation = Relation(typedb_type="sighting")
        expect_relation.add_attribute(
            constants.TYPEDB_ID_ATTRIBUTE,
            to_typedb_string("sighting--ee20065d-2555-424f-ad9e-0f8428623c75")
        )
        expect_relation.add_roleplayer("sighting-of", "_")

        expect_match1 = Entity(typedb_type="identity")
        expect_match1.add_attribute(
            constants.TYPEDB_ID_ATTRIBUTE,
            to_typedb_string("identity--b67d30ff-02ac-498a-92f9-32f845f448ff")
        )
        expect_match2 = Entity(typedb_type="identity")
        expect_match2.add_attribute(
            constants.TYPEDB_ID_ATTRIBUTE,
            to_typedb_string("identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5")
        )

        so: STIXObjectConverter = STIXObjectConverter.create(test)
        query = so.build_typeql_bundle()
        first, second, third = query.order_bundle()

        self.assertIsNone(first)
        self.assertFalse(second.is_empty())
        self.assertIsNone(third)

        inserts = second.get_insert_clause()
        matches = second.get_match_clause()
        self.assertEqual(len(inserts), 1)
        self.assertEqual(len(matches), 2)
        match1 = matches[0]
        match2 = matches[1]

        if match1 == expect_match1:
            self.assertEqual(match2, expect_match2)
        else:
            self.assertEqual(match1, expect_match2)
            self.assertEqual(match2, expect_match1)


if __name__ == "__main__":
    unittest.main()