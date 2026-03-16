import unittest

from satrap.datamanagement.typedb.typedb_constants import to_typedb_string
from satrap.datamanagement.typedb import typedb_constants
from satrap.datamanagement.typedb.dataobjects import Entity, Relation, VariableDealer
from satrap.etl.transform.valueconverter import (
    BooleanConverter, CompositeValueConverter, DoubleConverter,
    EmbeddedRelationConverter, KeyValuePairConverter, LongConverter,
    StringConverter, DictionaryConverter, DatetimeConverter,
    ListConverter
)
from satrap.etl.transform.query import Identification
from satrap.etl.transform.stix_to_typedb_mapper import STIXtoTypeDBMapper


class TestTypes(unittest.TestCase):

    def setUp(self):
        VariableDealer.reset()
        self.datetime = DatetimeConverter()
        self.string = StringConverter()
        self.long = LongConverter()
        self.double = DoubleConverter()
        self.boolean = BooleanConverter()
        STIXtoTypeDBMapper.get_data()

    def test_simple_timestamp_parse(self):
        timestamp_str = "2024-05-02T14:10:11Z"
        self.datetime.parse_stix_2_1(timestamp_str)
        self.assertEqual(self.datetime.year, 2024)
        self.assertEqual(self.datetime.month, 5)
        self.assertEqual(self.datetime.day, 2)
        self.assertEqual(self.datetime.hour, 14)
        self.assertEqual(self.datetime.minute, 10)
        self.assertEqual(self.datetime.seconds, 11)
        self.assertEqual(self.datetime.subseconds, [])

    def test_timestamp_with_subseconds_parse(self):
        timestamp_str = "2024-05-02T14:10:11.123Z"
        self.datetime.parse_stix_2_1(timestamp_str)
        self.assertEqual(self.datetime.year, 2024)
        self.assertEqual(self.datetime.month, 5)
        self.assertEqual(self.datetime.day, 2)
        self.assertEqual(self.datetime.hour, 14)
        self.assertEqual(self.datetime.minute, 10)
        self.assertEqual(self.datetime.seconds, 11)
        self.assertEqual(self.datetime.subseconds, [1, 2, 3])

    def test_timestamp_without_year(self):
        timestamp_str = "-05-02T14:10:11.123Z"

        with self.assertRaises(ValueError):
            self.datetime.parse_stix_2_1(timestamp_str)

    def test_string_simple(self):
        test = "test"
        expect = to_typedb_string(test)

        self.string.parse_stix_2_1(test)
        res = self.string.convert_to_typeql()

        self.assertEqual(res, expect)

    def test_long_simple(self):
        test = 42
        expect = "42"

        self.long.parse_stix_2_1(test)
        res = self.long.convert_to_typeql()

        self.assertEqual(res, expect)

    def test_double_simple(self):
        test = 3.14
        expect = "3.14"

        self.double.parse_stix_2_1(test)
        res = self.double.convert_to_typeql()

        self.assertEqual(res, expect)

    def test_boolean_simple(self):
        test = True
        expect = typedb_constants.BOOLEAN_TRUE

        self.boolean.parse_stix_2_1(test)
        res = self.boolean.convert_to_typeql()

        self.assertEqual(res, expect)

    def test_boolean_invalid(self):
        test = ""
        with self.assertRaises(ValueError):
            self.boolean.parse_stix_2_1(test)

    def test_datetime_simple(self):
        test = "2024-05-02T14:10:11Z"

        expect = typedb_constants.DATETIME_DATE_SEPARATOR \
            .join(["2024", "05", "02"])
        expect += typedb_constants.DATETIME_DATE_TIME_SEPARATOR
        expect += typedb_constants.DATETIME_TIME_SEPARATOR \
            .join(["14", "10", "11"])

        self.datetime.parse_stix_2_1(test)
        res = self.datetime.convert_to_typeql()

        self.assertEqual(res, expect)

    def test_datetime_with_subseconds(self):
        test = "2024-05-02T14:10:11.12345Z"

        expect = typedb_constants.DATETIME_DATE_SEPARATOR \
            .join(["2024", "05", "02"])
        expect += typedb_constants.DATETIME_DATE_TIME_SEPARATOR
        expect += typedb_constants.DATETIME_TIME_SEPARATOR \
            .join(["14", "10", "11"])
        expect += typedb_constants.DATETIME_MILLIS_SEPARATOR
        expect += "12345"[:typedb_constants.DATETIME_NUMBER_MILLIS]

        self.datetime.parse_stix_2_1(test)
        res = self.datetime.convert_to_typeql()

        self.assertEqual(res, expect)

    def test_composite_external_reference(self):
        test = {
            "source_name": "test1",
            "description": "test2"
        }

        expect_entity = Entity(typedb_type="external-reference")
        expect_entity.add_attribute("source-name", to_typedb_string("test1"))
        expect_entity.add_attribute("description", to_typedb_string("test2"))

        expect_relation = Relation(typedb_type="external-referencing")
        expect_relation.add_roleplayer("referrer", "_")
        expect_relation.add_roleplayer("referenced", "_")

        composite = CompositeValueConverter("external-reference")
        composite.parse_stix_2_1(test)
        main_ref = Identification("", "var", "")
        queries = composite.convert_to_typeql(reference=main_ref)

        self.assertEqual(len(queries.attributes.get_insert_clause()), 2)
        self.assertEqual(len(queries.attributes.get_match_clause()), 0)
        self.assertTrue(queries.embedded_relations.is_empty())
        entity: Entity = queries.attributes.get_insert_clause()[0]
        relation: Relation = queries.attributes.get_insert_clause()[1]
        self.assertEqual(expect_entity, entity)
        self.assertEqual(expect_relation, relation)
        self.assertEqual(
            [entity.get_variable()],
            relation.get_roles()["referenced"]
        )
        self.assertEqual(["var"], relation.get_roles()["referrer"])

    def test_embedded_relation_created_by_ref(self):
        test = "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"

        expect_match1 = Entity(typedb_type="attack-pattern")
        expect_match1.add_attribute(
            "stix-id",
            to_typedb_string(
                "attack-pattern--0042a9f5-f053-4769-b3ef-9ad018dfa298"
            )
        )

        expect_match2 = Entity(typedb_type="identity")
        expect_match2.add_attribute(
            "stix-id",
            to_typedb_string(
                "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"
            )
        )

        expect_relation = Relation(typedb_type="created-by-ref")
        expect_relation.add_roleplayer("creator", "_")
        expect_relation.add_roleplayer("object-created", "_")

        rel = EmbeddedRelationConverter("created-by-ref")
        rel.parse_stix_2_1(test)
        main_ref = Identification(
            "attack-pattern--0042a9f5-f053-4769-b3ef-9ad018dfa298",
            "var",
            "attack-pattern"
        )
        queries = rel.convert_to_typeql(
            reference=main_ref,
            name="object-created::creator"
        )

        self.assertTrue(queries.attributes.is_empty())
        self.assertEqual(len(queries.embedded_relations.get_match_clause()), 2)
        self.assertEqual(
            len(queries.embedded_relations.get_insert_clause()), 1)

        matches = queries.embedded_relations.get_match_clause()
        insert: Relation = queries.embedded_relations.get_insert_clause()[0]

        self.assertEqual(insert, expect_relation)
        self.assertIn(expect_match1, matches)
        self.assertIn(expect_match2, matches)
        var1 = matches[0].get_variable()
        var2 = matches[1].get_variable()

        if expect_match1 == matches[0]:
            temp = var1
            var1 = var2
            var2 = temp

        self.assertEqual([var1], insert.get_roles()["creator"])
        self.assertEqual([var2], insert.get_roles()["object-created"])

    def test_list_embedded_relations(self):
        test = [
            "file--1190f2c9-166f-55f1-9706-eea3971d8082",
            "file--30038539-3eb6-44bc-a59e-d0d3fe84695a",
        ]
        converter = ListConverter("relation:malware-sample")
        converter.parse_stix_2_1(test)
        values, queries = converter.convert_to_typeql(
            reference=Identification(
                "malware--3a41e552-999b-4ad3-bedc-332b6d9ff80c",
                "var",
                "malware-instance"
            ),
            name="associated-to::sco-sample"
        )

        self.assertEqual(values, [])
        self.assertFalse(queries.embedded_relations.is_empty())
        self.assertTrue(queries.main_object.is_empty())
        self.assertTrue(queries.attributes.is_empty())
        embeddeds = queries.embedded_relations

        self.assertEqual(len(embeddeds.get_match_clause()), 4)
        self.assertEqual(len(embeddeds.get_insert_clause()), 2)

    def test_list_string(self):
        test = ["test1", "test2", "test3"]
        l = ListConverter(typedb_constants.STRING)
        l.parse_stix_2_1(test)
        values, queries = l.convert_to_typeql(
            reference=Identification("", "", "")
        )

        self.assertEqual(
            values,
            [
                to_typedb_string("test1"),
                to_typedb_string("test2"),
                to_typedb_string("test3")
            ]
        )
        self.assertTrue(queries.is_empty())

    def test_list_external_reference(self):
        test = [
            {
                "source_name": "test1a",
                "description": "test1b"
            },
            {
                "source_name": "test2a",
                "description": "test2b"
            }
        ]
        l = ListConverter("composite:external-reference")
        l.parse_stix_2_1(test)
        values, queries = l.convert_to_typeql(
            reference=Identification("id", "var", "")
        )

        self.assertEqual(values, [])
        self.assertTrue(queries.embedded_relations.is_empty())
        self.assertEqual(len(queries.attributes.get_insert_clause()), 4)

    def test_pair_type_simple(self):
        test = {
            "MD5": "hash",
        }

        expect_entity = Entity(typedb_type="md5")
        expect_entity.add_attribute("hash-value", to_typedb_string("hash"))
        expect_relation = Relation(typedb_type="has-hash")
        expect_relation.add_roleplayer("resource", "_")
        expect_relation.add_roleplayer("hash", "_")

        p = KeyValuePairConverter("hashes")
        p.parse_stix_2_1(test)
        queries = p.convert_to_typeql(
            reference=Identification("id", "test_var", "")
        )

        self.assertTrue(queries.embedded_relations.is_empty())
        self.assertEqual(len(queries.attributes.get_match_clause()), 0)
        self.assertEqual(len(queries.attributes.get_insert_clause()), 2)

        entity: Entity = queries.attributes.get_insert_clause()[0]
        relation: Relation = queries.attributes.get_insert_clause()[1]

        self.assertEqual(entity, expect_entity)
        self.assertEqual(relation, expect_relation)
        self.assertIn([entity.get_variable()],  relation.get_roles().values())
        self.assertEqual([entity.get_variable()],
                         relation.get_roles()["hash"])
        self.assertEqual(["test_var"], relation.get_roles()["resource"])

    @unittest.skip("Skipping test_pair_custom as custom hash algorithms are not allowed")
    def test_pair_custom(self):
        test = {
            "custom42": "hash",
        }
        expect_relation = Relation(typedb_type="has-hash")
        expect_relation.add_roleplayer("resource", "_")
        expect_relation.add_roleplayer("hash", "_")
        expect_entity = Entity(typedb_type="custom-hash")
        expect_entity.add_attribute("hash-value", to_typedb_string("hash"))
        expect_entity.add_attribute("hash-name", to_typedb_string("custom42"))

        p = KeyValuePairConverter("hashes")
        p.parse_stix_2_1(test)
        queries = p.convert_to_typeql(
            reference=Identification("id", "test_var", "")
        )

        self.assertTrue(queries.embedded_relations.is_empty())
        self.assertEqual(len(queries.attributes.get_match_clause()), 0)
        self.assertEqual(len(queries.attributes.get_insert_clause()), 2)

        entity: Entity = queries.attributes.get_insert_clause()[0]
        relation: Relation = queries.attributes.get_insert_clause()[1]

        self.assertEqual(entity, expect_entity)
        self.assertEqual(relation, expect_relation)
        self.assertIn([entity.get_variable()],  relation.get_roles().values())
        self.assertEqual([entity.get_variable()],
                         relation.get_roles()["hash"])
        self.assertEqual(["test_var"], relation.get_roles()["resource"])
        self.assertEqual("", "")

    def test_dictionary_int(self):
        test = {"key1": 1}

        expect_relation = Relation(typedb_type="has-dictionary")
        expect_relation.add_attribute(
            "name",
            to_typedb_string("attribute")
        )
        expect_relation.add_roleplayer("owner", "_")
        expect_relation.add_roleplayer("item", "_")

        expect_item = Entity(typedb_type="int-item")
        expect_item.add_attribute("item-key", to_typedb_string("key1"))
        expect_item.add_attribute("int-item-value", "1")

        converter = DictionaryConverter()
        converter.parse_stix_2_1(test)
        values, queries = converter.convert_to_typeql(
            name="attribute",
            reference=Identification("id", "var", "")
        )

        self.assertEqual(len(values), 0)
        self.assertFalse(queries.attributes.is_empty())
        self.assertTrue(queries.embedded_relations.is_empty())
        self.assertTrue(queries.main_object.is_empty())
        self.assertEqual(len(queries.attributes.get_match_clause()), 0)
        self.assertEqual(len(queries.attributes.get_insert_clause()), 2)

        inserts = queries.attributes.get_insert_clause()
        item: Entity = inserts[0]
        relation: Relation = inserts[1]

        self.assertEqual(relation, expect_relation)
        self.assertEqual(item, expect_item)

    def test_dictionary_multiple_string(self):
        test = {
            "key1": "value1",
            "key2": "value2"
        }

        expect_second_relation = Relation(typedb_type="has-dictionary")
        expect_second_relation.add_attribute(
            "name",
            to_typedb_string("attribute")
        )
        expect_second_relation.add_roleplayer("owner", "_")
        expect_second_relation.add_roleplayer("item", "_")

        expect_first_item = Entity(typedb_type="string-item")
        expect_first_item.add_attribute("item-key", to_typedb_string("key1"))
        expect_first_item.add_attribute(
            "string-item-value",
            to_typedb_string("value1")
        )

        expect_second_item = Entity(typedb_type="string-item")
        expect_second_item.add_attribute("item-key", to_typedb_string("key2"))
        expect_second_item.add_attribute(
            "string-item-value",
            to_typedb_string("value2")
        )

        converter = DictionaryConverter()
        converter.parse_stix_2_1(test)
        values, queries = converter.convert_to_typeql(
            name="attribute",
            reference=Identification("id", "var", "")
        )

        self.assertEqual(len(values), 0)
        self.assertFalse(queries.attributes.is_empty())
        self.assertTrue(queries.embedded_relations.is_empty())
        self.assertTrue(queries.main_object.is_empty())
        self.assertEqual(len(queries.attributes.get_match_clause()), 0)
        self.assertEqual(len(queries.attributes.get_insert_clause()), 4)

        inserts = queries.attributes.get_insert_clause()
        first_item: Entity = inserts[0]
        second_relation: Relation = inserts[3]

        if isinstance(inserts[1], Relation):
            first_relation = inserts[1]
            second_item = inserts[2]
        else:
            first_relation = inserts[2]
            second_item = inserts[1]

        self.assertEqual(first_relation, expect_second_relation)
        self.assertEqual(second_relation, expect_second_relation)
        self.assertEqual(first_item, expect_first_item)
        self.assertEqual(second_item, expect_second_item)

    def test_dictionary_list(self):
        test = {
            "key1": ["value1", "value2"]
        }
        converter = DictionaryConverter()
        converter.parse_stix_2_1(test)
        values, queries = converter.convert_to_typeql(
            name="attribute",
            reference=Identification("id", "var", "")
        )
        expect_item = Entity(typedb_type="string-item")
        expect_item.add_attribute(
            "item-key",
            to_typedb_string("key1")
        )
        expect_item.add_attribute(
            "string-item-value",
            to_typedb_string("value1")
        )
        expect_item.add_attribute(
            "string-item-value",
            to_typedb_string("value2")
        )

        expect_relation = Relation(typedb_type="has-dictionary")
        expect_relation.add_attribute(
            "name",
            to_typedb_string("attribute")
        )
        expect_relation.add_roleplayer("owner", "_")
        expect_relation.add_roleplayer("item", "_")

        self.assertEqual(len(values), 0)
        self.assertFalse(queries.attributes.is_empty())
        self.assertTrue(queries.embedded_relations.is_empty())
        self.assertTrue(queries.main_object.is_empty())
        self.assertEqual(len(queries.attributes.get_match_clause()), 0)
        self.assertEqual(len(queries.attributes.get_insert_clause()), 2)

        inserts = queries.attributes.get_insert_clause()
        item = inserts[0]
        relation = inserts[1]

        self.assertEqual(relation, expect_relation)
        self.assertEqual(item, expect_item)


if __name__ == "__main__":
    unittest.main()
