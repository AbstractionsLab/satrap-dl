import unittest
import os

from satrap.etl.etlorchestrator import ETLOrchestrator
from satrap.datamanagement.typedb import typedbmanager as TypeDBMgr
from satrap.etl.extract.extract_constants import STIX_READER
import tests.test_utils as test_utils
from satrap.commons.format_utils import format_dict, tabulate_groups, tabulate_stix_obj


class TestRuleTransitiveUse(unittest.TestCase):
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
        self.orchestrator = ETLOrchestrator(STIX_READER)
        
    def tearDown(self):
        TypeDBMgr.delete_all_data(self.server, self.db)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.stix_src):
            os.remove(cls.stix_src)

    def test_rule_transitive_use(self):
        test_file = "tests/data/test_transitive_xyz.json"
        self.orchestrator.transform_load(test_file, self.server, self.db)
        # check explicit relations
        self.assertTrue(
            test_utils.check_relation_exists(
                "uses",
                "intrusion-set--b1a2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", 
				"malware--c6d7e8f9-0a1b-4c2d-8e3f-4a5b6c7d8e9f"))
        self.assertTrue(
            test_utils.check_relation_exists(
                "uses",
                "malware--c6d7e8f9-0a1b-4c2d-8e3f-4a5b6c7d8e9f", 
				"tool--d1e2f3a4-b5c6-4d7e-8f9a-0b1c2d3e4f5a"))
        self.assertFalse(
            test_utils.check_relation_exists(
                "uses",
                "intrusion-set--b1a2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", 
				"tool--d1e2f3a4-b5c6-4d7e-8f9a-0b1c2d3e4f5a"))
        # check inferred relation
        self.assertTrue(
            test_utils.check_inferred_relation_exists(
                "uses",
                "intrusion-set--b1a2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
                "tool--d1e2f3a4-b5c6-4d7e-8f9a-0b1c2d3e4f5a"))
        self.assertTrue(
            test_utils.check_inferred_relation_exists(
                "indirectly-uses",
                "intrusion-set--b1a2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
                "tool--d1e2f3a4-b5c6-4d7e-8f9a-0b1c2d3e4f5a"))


    def test_no_inferred_when_explicit(self):
        test_file = "tests/data/test_transitive_xyz.json"
        self.orchestrator.transform_load(test_file, self.server, self.db)
        direct_use = {
			"type": "relationship",
			"spec_version": "2.1",
			"id": "relationship--0243bda4-7084-4ae4-803a-3697cb606d0e",
			"relationship_type": "uses",
			"source_ref": "intrusion-set--b1a2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
			"target_ref": "tool--d1e2f3a4-b5c6-4d7e-8f9a-0b1c2d3e4f5a"
		}
        test_utils.run_tl(direct_use, self.orchestrator)
        self.assertTrue(
            test_utils.check_relation_exists(
                "uses",
                "intrusion-set--b1a2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", 
				"tool--d1e2f3a4-b5c6-4d7e-8f9a-0b1c2d3e4f5a"))
        self.assertFalse(
            test_utils.check_inferred_relation_exists(
                "indirectly-uses",
                "intrusion-set--b1a2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
                "tool--d1e2f3a4-b5c6-4d7e-8f9a-0b1c2d3e4f5a"))
        
    def test_no_inferred_xyy(self):
        test_file = "tests/data/test_transitive_xyy.json"
        self.orchestrator.transform_load(test_file, self.server, self.db)
        # check explicit relations
        self.assertTrue(
            test_utils.check_relation_exists(
                "uses",
                "intrusion-set--b1a2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", 
				"malware--c6d7e8f9-0a1b-4c2d-8e3f-4a5b6c7d8e9f"))
        self.assertTrue(
            test_utils.check_relation_exists(
                "uses",
                "malware--c6d7e8f9-0a1b-4c2d-8e3f-4a5b6c7d8e9f",
				"malware--c6d7e8f9-0a1b-4c2d-8e3f-4a5b6c7d8e9f"))
        self.assertFalse(
            test_utils.check_inferred_relation_exists(
                "indirectly-uses",
                "intrusion-set--b1a2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", 
				"malware--c6d7e8f9-0a1b-4c2d-8e3f-4a5b6c7d8e9f"))

    def test_no_inferred_xxy(self):
        test_file = "tests/data/test_transitive_xxy.json"
        self.orchestrator.transform_load(test_file, self.server, self.db)
        # check explicit relations
        self.assertTrue(
            test_utils.check_relation_exists(
                "uses",
                "malware--c6d7e8f9-0a1b-4c2d-8e3f-4a5b6c7d8e9f",
				"malware--c6d7e8f9-0a1b-4c2d-8e3f-4a5b6c7d8e9f"))
        self.assertTrue(
            test_utils.check_relation_exists(
                "uses",
                "malware--c6d7e8f9-0a1b-4c2d-8e3f-4a5b6c7d8e9f",
				"tool--d1e2f3a4-b5c6-4d7e-8f9a-0b1c2d3e4f5a"))
        self.assertFalse(
            test_utils.check_inferred_relation_exists(
                "indirectly-uses",
				"malware--c6d7e8f9-0a1b-4c2d-8e3f-4a5b6c7d8e9f",
                "tool--d1e2f3a4-b5c6-4d7e-8f9a-0b1c2d3e4f5a"))


if __name__ == '__main__':
    unittest.main()
        