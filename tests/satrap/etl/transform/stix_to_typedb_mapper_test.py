import unittest

from satrap.etl.exceptions import MappingException
import satrap.etl.stix_constants
from satrap.etl.transform.stix_to_typedb_mapper import STIXtoTypeDBMapper
import satrap.etl.transform.stix_typeql_constants as constants
import satrap.datamanagement.typedb.typedb_constants as typedb_constants


class TestAttributeMapper(unittest.TestCase):

    def setUp(self):
        STIXtoTypeDBMapper.get_data()

    def test_validate(self):
        STIXtoTypeDBMapper.validate()

    def test_get_class(self):
        get_class = STIXtoTypeDBMapper.get_class
        self.assertEqual(
            constants.MAPPING_CLASS_SDO, 
            get_class("attack-pattern")
        )
        self.assertEqual(
            constants.MAPPING_CLASS_SRO,
            get_class("relationship")
        )
        self.assertEqual(
            constants.MAPPING_CLASS_SCO, 
            get_class("directory")
        )
        self.assertEqual(
            constants.MAPPING_CLASS_SMO,
            get_class("language-content")
        )

    def test_get_typeql_thing_name(self):
        get_type_name = STIXtoTypeDBMapper.get_typeql_thing_name
        self.assertEqual(
            "attack-pattern",
            get_type_name(
                "attack-pattern", {}, {}
            )
        )
        self.assertEqual(
            "uses",
            get_type_name(
                "relationship", 
                {satrap.etl.stix_constants.STIX_PROPERTY_RELATIONSHIP_TYPE: "uses"},
                {}
            )
        )
        self.assertEqual(
            "artifact",
            get_type_name("artifact", {}, {})
        )
        self.assertEqual(
            "language-content",
            get_type_name("language-content", {}, {})
        )
        self.assertEqual(
            "malware-family",
            get_type_name(
                "malware", {"is_family":True}, {}
            )
        )
        self.assertEqual(
            "unix-account-ext",
            get_type_name(
                "user-account",
                {},
                {"unix-account-ext": {}}
            )
        )

    def test_default_value_implementation(self):
        def_val_impl = STIXtoTypeDBMapper.get_default_value_implementation
        self.assertEqual(
            typedb_constants.STRING,
            def_val_impl("Hello, World!")
        )
        self.assertEqual(
            typedb_constants.LONG,
            def_val_impl(42)
        )
        self.assertEqual(
            typedb_constants.DOUBLE,
            def_val_impl(2.71828)
        )
        self.assertEqual(
            STIXtoTypeDBMapper.join_type(
                constants.TYPEQL_LIST_PREFIX, 
                typedb_constants.LONG
            ),
            def_val_impl([1,2,3,4])
        )
        self.assertEqual(
            constants.TYPEQL_DICTIONARY_KEYWORD,
            def_val_impl({"test": "test"})
        )
        self.assertEqual(
            typedb_constants.DATETIME,
            def_val_impl("2024-09-24T15:02:00.000Z")
        )

    def test_get_roleplayers_for_SRO(self):
        get_roleplayers = STIXtoTypeDBMapper.get_roleplayers_for_SRO
        self.assertEqual(
            set(["target_ref", "source_ref"]),
            set(get_roleplayers("relationship"))
        )

    def test_get_object_attribute_info(self):
        get_attr = STIXtoTypeDBMapper.get_object_attribute_info
        self.assertEqual(
            ("description", typedb_constants.STRING),
            get_attr("attack-pattern", "description")
        )
        self.assertEqual(
            ("stix-id", typedb_constants.STRING),
            get_attr("malware", "id")
        )

    def test_get_composite_name(self):
        get_comp_name = STIXtoTypeDBMapper.get_composite_name
        self.assertEqual(
            "external-reference", 
            get_comp_name("external-reference")
        )

    def test_get_composite_attribute_info(self):
        get_attr = STIXtoTypeDBMapper.get_composite_attribute_info
        self.assertEqual(
            ("source-name", typedb_constants.STRING),
            get_attr("external-reference", "source_name")
        )

    def test_get_composite_type_relation(self):
        get_rel = STIXtoTypeDBMapper.get_composite_type_relation
        self.assertEqual(
            "external-referencing",
            get_rel("external-reference")
        )

    def test_get_composite_relation_roles(self):
        get_roles = STIXtoTypeDBMapper.get_composite_relation_roles
        self.assertEqual(
            ("referrer", "referenced"), 
            get_roles("external-reference")
        )

    def test_get_embedded_relation_roles(self):
        get_roles = STIXtoTypeDBMapper.get_embedded_relation_roles
        self.assertEqual(
            ("creator", "object-created"),
            get_roles("creator{}object-created".format(
                constants.MAPPING_ROLE_SEPARATION
            ))
        )

    def test_get_typedb_supertype(self):
        get_sup = STIXtoTypeDBMapper.get_typedb_supertype
        self.assertEqual(
            "attack-pattern",
            get_sup("attack-pattern")
        )
        self.assertEqual(
            "stix-relationship-object",
            get_sup("relationship")
        )

    def test_get_key_value_pair_key_translation(self):
        get_key = STIXtoTypeDBMapper.get_key_value_pair_key_translation
        self.assertEqual(
            "md5",
            get_key("hashes", "MD5")
        )

    def test_get_key_value_pair_custom(self):
        get_custom = STIXtoTypeDBMapper.get_key_value_pair_custom
        with self.assertRaises(MappingException) as exc:
            get_custom("hashes")
        self.assertIn("Custom keys are not supported", exc.exception.message)
        # self.assertEqual(
        #     ("custom-hash", "hash-name"),
        #     get_custom("hashes")
        # )

    def test_get_pairs_value_and_type(self):
        get_name_type = STIXtoTypeDBMapper.get_pairs_value_and_type
        self.assertEqual(
            ("hash-value", "string"),
            get_name_type("hashes")
        )

    def test_get_pair_relation(self):
        get_rel = STIXtoTypeDBMapper.get_pair_relation
        self.assertEqual(
            ("has-hash", "resource", "hash"),
            get_rel("hashes")
        )

    def test_get_dictionary_item_data(self):
        item_type, key_name, value_attr = STIXtoTypeDBMapper \
            .get_dictionary_item_data(typedb_constants.STRING)
        self.assertEqual(key_name, "item-key")
        self.assertEqual(item_type, "string-item")
        self.assertEqual(value_attr, "string-item-value")


    def test_get_dictionary_relation_data(self):
        relation_name, item_role, object_role = STIXtoTypeDBMapper \
            .get_dictionary_relation_data()
        
        self.assertEqual(relation_name, "has-dictionary")
        self.assertEqual(item_role, "item")
        self.assertEqual(object_role, "owner")

    def test_get_dictionary_property_attribute(self):
        prop_attr = STIXtoTypeDBMapper.get_dictionary_property_attribute()
        self.assertEqual(prop_attr, "name")

    def test_get_extension_attribute_info(self):
        obj = "user-account"
        ext = "unix-account-ext"
        attr = "home_dir"

        name, value_type = STIXtoTypeDBMapper \
            .get_extension_attribute_info(obj, ext, attr)
        self.assertEqual(name, "home-dir")
        self.assertEqual(value_type, "string")

    def test_is_defined_extension(self):
        is_def = STIXtoTypeDBMapper.is_defined_extension
        self.assertTrue(is_def("user-account", "unix-account-ext"))
        self.assertFalse(is_def("user-account", "xyz"))


if __name__ == "__main__":
    unittest.main()
