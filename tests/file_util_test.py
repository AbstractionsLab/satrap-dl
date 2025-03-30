import unittest
import os
import time

from satrap.commons import file_utils

class TestFileUtils(unittest.TestCase):

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
        save_as = "./tests/data/test1.json"
        file_utils.download_file(self.url, save_as, True)
        self.assertTrue(os.path.exists(save_as))

    @classmethod
    def tearDownClass(cls):
        '''Remove the downloaded file if it exists
        '''
        downloaded = "./tests/data/test1.json"

        if os.path.exists(downloaded):
            os.remove(downloaded)

if __name__ == "__main__":
    unittest.main()
