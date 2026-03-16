"""
Unit tests for `decipher.settings.load_decipher_settings` behaviour.

Covers environment variable overrides and missing-file fallback.
"""

import unittest
from unittest.mock import patch

from yaml import YAMLError

from decipher.runtime_settings import load_decipher_runtime_cfg


class TestDecipherSettingsLoader(unittest.TestCase):

    @patch('decipher.runtime_settings.load_yaml_file', side_effect=FileNotFoundError("The file does not exist"))
    def test_missing_file_uses_defaults(self, mock_loader):
        """If the settings file is absent, loader should return defaults."""
        settings = load_decipher_runtime_cfg()

        # Defaults: feature flags false and empty misp_search
        self.assertFalse(settings.enable_misp_search)
        self.assertFalse(settings.enable_case_creation)
        self.assertEqual(settings.misp_search, {})
        mock_loader.assert_called_once()

    @patch('decipher.runtime_settings.load_yaml_file', side_effect=YAMLError("invalid YAML"))
    def test_invalid_yaml_causes_exit(self, mock_loader):
        """If the settings loader encounters a non-FileNotFound error, it should exit."""

        with self.assertRaises(YAMLError):
            load_decipher_runtime_cfg()

        mock_loader.assert_called_once()


if __name__ == "__main__":
    unittest.main()
