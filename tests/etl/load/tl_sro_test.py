import unittest
import os

from satrap.etl.etlorchestrator import ETLOrchestrator
from satrap.datamanagement.typedb import typedbmanager as TypeDBMgr
from satrap.etl.extract.extract_constants import STIX_READER
import tests.etl.load as test_utils

class TestTransformLoadSRO(unittest.TestCase):
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

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.stix_src):
            os.remove(cls.stix_src)
    
    def test_custom_relation(self):
        test_file = "tests/data/custom_rel.json"
        self.orchestrator.transform_load(test_file, self.server, self.db)


if __name__ == '__main__':
    unittest.main()
        