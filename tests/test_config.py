import json
import os
import tempfile
import unittest

from config import ConfigManager


class ConfigManagerTests(unittest.TestCase):
    def test_new_config_does_not_share_nested_defaults(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "config.json")
            config = ConfigManager(config_path)

            config.set(30, "scan_thresholds", "window_seconds")

        self.assertEqual(
            ConfigManager.DEFAULT_CONFIG["scan_thresholds"]["window_seconds"],
            10,
        )

    def test_missing_nested_defaults_are_copied_when_loading(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "config.json")
            with open(config_path, "w", encoding="utf-8") as config_file:
                json.dump({"packet_thresholds": {"packets_per_sec_limit": 50}}, config_file)

            config = ConfigManager(config_path)
            config.set(30, "scan_thresholds", "window_seconds")

        self.assertEqual(
            ConfigManager.DEFAULT_CONFIG["scan_thresholds"]["window_seconds"],
            10,
        )


if __name__ == "__main__":
    unittest.main()
