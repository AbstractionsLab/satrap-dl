import unittest
import os
import uuid

from satrap.etl.etlorchestrator import ETLOrchestrator
from satrap.datamanagement.typedb import typedbmanager as TypeDBMgr
from satrap.etl.exceptions import STIXParsingError
import tests.etl.load as test_utils

class TestTLCommonProps(unittest.TestCase):
    """
    Test cases for the transformation and loading of common properties
    of STIX Objects into TypeDB.
    """

    @classmethod
    def setUpClass(cls):
        cls.server = test_utils.SERVER
        cls.db = test_utils.TEST_DB
        cls.stix_src = test_utils.STIX_TEST_FILE
        TypeDBMgr.create_database(cls.server, cls.db, reset=True)

    def setUp(self):
        self.orchestrator = ETLOrchestrator()

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.stix_src):
            os.remove(cls.stix_src)

    def test_object_marking_refs(self):
        """
        Test the handling of object marking references in a STIX object.

        Assertions:
            - The relation "object-marking" exists between the STIX object and the 
              referenced marking definition.
        """
        stix_id = f"course-of-action--{uuid.uuid4()}"

        stix_object = {
            "type": "course-of-action",
            "id": stix_id,
            "spec_version": "2.1",
            "created": "2023-01-01T00:00:00.000Z",
            "name": "Test course of action",
            "description": "This is a test object",
            "revoked": True,
            "object_marking_refs": ["marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"]
        }

        test_utils.run_tl(stix_object, self.orchestrator)
        self.assertTrue(
            test_utils.check_relation_exists(
                "object-marking", stix_id, stix_object.get("object_marking_refs")[0]))


    def test_statement_marking(self):
        ref_id = f"marking-definition--{uuid.uuid4()}"
        ref = {
            "type": "marking-definition",
            "id": ref_id,
            "spec_version": "2.1",
            "created": "2023-01-01T00:00:00.000Z",
            "definition_type": "custom",
            "definition": {
                "statement": "Copyright 2019, Example Corp",
                "tlp": "red"
            }
        }

        # invalid definition-type
        with self.assertRaises(STIXParsingError):
            test_utils.run_tl(ref, self.orchestrator)

        ref["definition_type"] = "statement"

        # since "definition_type" is "statement", 'definition' is expected to have
        # only the key 'statement'; 'tlp' is not allowed
        with self.assertRaises(STIXParsingError):
            test_utils.run_tl(ref, self.orchestrator)

        ref["definition"].pop("tlp")
        test_utils.run_tl(ref, self.orchestrator)

        self.assertEqual(test_utils.get_attributes_num(ref_id), 4)

    def test_tlp_marking(self):
        ref_id = f"marking-definition--{uuid.uuid4()}"
        ref_tlp = {
            "type": "marking-definition",
            "id": ref_id,
            "created": "2023-01-01T00:00:00.000Z",
            "definition_type": "tlp",
            "definition": {
                "tlp": "red"
            }
        }
        # the predefined STIX tandard marking definitions must be used to reference
        # or represent TLP markings
        with self.assertRaises(STIXParsingError):
            test_utils.run_tl(ref_tlp, self.orchestrator)

        ref_tlp = {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
            "created": "2017-01-20T00:00:00.000Z",
            "definition_type": "tlp",
            "name": "TLP:RED",
            "definition": {
                "tlp": "red"
            }
        }

        test_utils.run_tl(ref_tlp, self.orchestrator)
        self.assertTrue(test_utils.is_of_type(ref_tlp, "tlp-marking"))

    def test_simple_common_props(self):
        """
        Tests that the transformation logic handles correctly the common 
        properties of a simple STIX identity object.

        Note:
        The following validations are observed to be missing: 
        - The 'confidence' value MUST be a number in the range of 0-100
        - The 'lang' value MUST be a valid language tag as defined in RFC 5646
        """
        stix_obj = {
            "type": "identity",
            "id": "identity--" + str(uuid.uuid4()),
            "spec_version": "2.1",
            "created": "2023-01-01T00:00:00.000Z",
            "modified": "2024-01-01T00:00:00.000Z",
            "name": "Test identity",
            "revoked": False,
            "confidence": -10,
            "lang": "any"
        }
        test_utils.run_tl(stix_obj, self.orchestrator)

        validation_query = ("match"
                    f"$v has stix-id '{stix_obj.get('id')}';"
                    "$v has $att;"
                    "get $att;")
        result = TypeDBMgr.get_query(self.server, self.db, validation_query)

        for res in result:
            att_name = res.get('att').get_type().get_label().name
            property_name = test_utils.get_stix_property_name(
                "identity", att_name)

            if property_name is None:
                # this attribute of 'identity' is not a common property
                self.assertEqual(att_name, "name")
            else:
                self.assertIn(property_name, stix_obj.keys())


def load_tests(loader, tests, pattern):
    """
    Implements the unittest protocol to run the test cases in a specified order.
    The signature is predefined by the unittest framework.

    Returns:
        unittest.TestSuite: The suite containing all the specified test cases.
    """
    suite = unittest.TestSuite()
    suite.addTest(TestTLCommonProps('test_statement_marking'))
    suite.addTest(TestTLCommonProps('test_tlp_marking'))
    suite.addTest(TestTLCommonProps('test_object_marking_refs'))
    suite.addTest(TestTLCommonProps('test_simple_common_props'))

    return suite


if __name__ == '__main__':
    unittest.main()
