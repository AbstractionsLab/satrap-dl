import unittest
import os
import time

from satrap.commons import file_utils

class TestFileUtils(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.test_file = "./tests/data/test-file.json"

    def setUp(self):
        self.url = (
            "https://raw.githubusercontent.com/mitre-attack/"
            "attack-stix-data/master/enterprise-attack/enterprise-attack.json"
        )

    def test_get_file_name(self):
        self.assertEqual(file_utils.get_filename_from_url(self.url),"enterprise-attack.json")

    def test_create_local_filename(self):
        # note that this test has a negligible probability of failing
        # due to time difference at runtime
        now = time.strftime('%Y%m%d-%Hh%M')
        created_name = file_utils.create_local_filename("./tests/data/",self.url)
        expected = f"./tests/data/enterprise-attack_{now}.json"
        self.assertEqual(created_name,expected)

    def test_download(self):
        save_as = self.test_file
        file_utils.download_file(self.url, save_as, True)
        self.assertTrue(os.path.exists(save_as))

    def test_download_no_override(self):
        file_utils.download_file(self.url, self.test_file)
        self.assertTrue(os.path.exists(self.test_file))
        
        # try to download again with override=False
        with self.assertRaises(ValueError) as err:
            file_utils.download_file(self.url, self.test_file, False)
        self.assertIn("already exists and 'override' is set to False",
                      str(err.exception))

    def test_validate_file_access(self):
        # Test with a valid path and write permission
        file_utils.validate_file_access(self.test_file, write=True, override=False)

        # Test invalid access combination
        with self.assertRaises(ValueError) as err:
            file_utils.validate_file_access(self.test_file, write=False, override=True)
        self.assertIn("'override' is set to True but 'write' is False",
                      str(err.exception))

        # Test with a non-existent folder and no write permission
        invalid_folder = "./tests/data/new_folder/test.txt"
        with self.assertRaises(ValueError) as err:
            file_utils.validate_file_access(invalid_folder, write=False)
        self.assertIn("tests/data/new_folder' does not exist",
                      str(err.exception))

    def test_validate_and_create(self):
        new_dir = "./tests/data/new_folder"
        new_file = os.path.join(new_dir, "test.txt")
        file_utils.validate_file_access(new_file, write=True)
        self.assertTrue(os.path.exists(new_dir))
        os.rmdir(new_dir)

    def test_write_json_file(self):
        data = {
        "type": "bundle", "id": "bundle--1f126d0c-356c-43af-88f8-7a3b695dee83",
        "spec_version": "2.1",
        "objects": [		
            {"id": "attack-pattern--0042a9f5-f053-4769-b3ef-9ad018dfa298",
            "type": "attack-pattern",
            "modified": "2022-04-25T14:00:00.188Z",
            "name": "Extra Window Memory Injection",
            "spec_version": "2.1"}
        ]
        }
        new_dir = "./tests/new_data"
        file_path = os.path.join(new_dir, "sample.json")
        file_utils.write_json(file_path, data)
        self.assertTrue(os.path.exists(file_path))
        os.remove(file_path)
        os.rmdir(new_dir)

    def tearDown(self):
        '''Remove the downloaded file if it exists
        '''
        if os.path.exists(self.test_file):
            os.remove(self.test_file)

if __name__ == "__main__":
    unittest.main()
