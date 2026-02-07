import unittest
import os

from stix2.utils import parse_into_datetime

from satrap.etl import stix_constants
from satrap.etl.extract.extractor import Downloader, MISPExtractor, STIXExtractor, Extractor
from satrap.etl.extract import extract_constants
from satrap.etl.exceptions import ExtractionError

class TestDownloader(unittest.TestCase):

    def setUp(self):
        self.filepath = "./tests/data/"

    def test_select_extractor(self):
        '''Test that a correct Extractor class is retrieved
        according to the given type'''
        self.assertIsInstance(Extractor.get_extractor(extract_constants.DOWNLOADER),
                              Downloader)
        self.assertIsInstance(Extractor.get_extractor(extract_constants.STIX_READER),
                              STIXExtractor)
        self.assertIsInstance(Extractor.get_extractor(extract_constants.MISP_EXTRACTOR),
                              MISPExtractor)
        with self.assertRaises(ValueError):
            Extractor.get_extractor("unsupported")
    
    def test_download_simple(self):
        url = (
            "https://raw.githubusercontent.com/"
            "AbstractionsLab/c5dec/main/README.md"
        )
        target = self.filepath + "download_test_readme.md"
        downloader = Downloader()
        args = {extract_constants.TARGET: target, 
                extract_constants.OVERRIDE: True}
        downloader.fetch(url, **args)
        self.assertTrue(os.path.exists(target))
        # remove file to clear for future tests
        if os.path.exists(target):
            os.remove(target)

    def test_download_missing_args(self):
        url = (
            "https://raw.githubusercontent.com/"
            "AbstractionsLab/c5dec/main/README.md"
        )
        downloader = Downloader()
        with self.assertRaises(ExtractionError) as e:
            downloader.fetch(url)
        self.assertIn("ExtractionError-101", str(e.exception))

    def test_download_connect_timeout(self):
        url = (
            "https://raw.githubusercontent.com/"
            "AbstractionsLab/c5dec/main/README.md"
        )
        target = self.filepath + "download_test_readme.md"
        downloader = Downloader()
        args = {extract_constants.TARGET: target, 
                extract_constants.OVERRIDE: True,
                extract_constants.MAX_CONNECTION_TIME: 0.000000001}
        with self.assertRaises(ExtractionError) as err:
            downloader.fetch(url, **args)
        self.assertIn("Errno 101", str(err.exception))

    def test_download_read_timeout(self):
        url = (
            "https://raw.githubusercontent.com/"
            "AbstractionsLab/c5dec/main/README.md"
        )
        target = self.filepath + "download_test_readme.md"
        downloader = Downloader()
        args = {extract_constants.TARGET: target, 
            extract_constants.OVERRIDE: True,
            extract_constants.MAX_RESP_TIME: 0.000000001}
        with self.assertRaises(ExtractionError) as err:
            downloader.fetch(url, **args)
        self.assertIn("Read timed out", str(err.exception))

    def test_download_inexistent(self):
        url = (
            "https://raw.githubusercontent.com/"
            "AbstractionsLab/c5dec/main/README1.md"
        )
        target = self.filepath + "download_test_readme.md"
        downloader = Downloader()
        self.assertRaises(ExtractionError,downloader.fetch,url, target=target, override=True)

    def test_download_large(self):
        url = (
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
            "enterprise-attack/enterprise-attack.json"
        )
        target = self.filepath + "download_test_mitre_attack.json"
        downloader = Downloader()
        downloader.fetch(url, target=target, override=True)
        if os.path.exists(target):
            os.remove(target)

    def test_stix_extract(self):
        file = self.filepath + "test-sample.json"
        reader = STIXExtractor()
        for so in reader.fetch(file):
            self.assertFalse(so.get(stix_constants.STIX_PROPERTY_ID) is None)

    def test_x509_handling(self):
        file = self.filepath + "x509_test.json"
        reader = STIXExtractor()
        so = next(reader.fetch(file))
        self.assertTrue(so.get(stix_constants.STIX_PROPERTY_X509_V3_EXTENSIONS) is None)
        self.assertFalse(so.get(stix_constants.STIX_PROPERTY_EXTENSIONS) is None)

    def test_created_time(self):
        file = self.filepath + "missing_created.json"
        reader = STIXExtractor()
        so = next(reader.fetch(file))
        timestamp = so.get(stix_constants.STIX_PROPERTY_CREATED)
        self.assertFalse(timestamp is None)
        self.assertTrue(timestamp == parse_into_datetime(extract_constants.BASE_TIME))


if __name__ == "__main__":
    unittest.main()
