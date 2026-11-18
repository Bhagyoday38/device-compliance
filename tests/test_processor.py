import os
import tempfile
import unittest

import pandas as pd

from app.services.processor import detect_source, load_data, version_is_below


class ProcessorLogicTests(unittest.TestCase):
    def test_version_comparison_uses_numeric_components(self):
        self.assertFalse(version_is_below("4.10", "4.9"))
        self.assertTrue(version_is_below("4.8", "4.9"))

    def test_missing_or_unparseable_actual_version_fails_minimum(self):
        self.assertTrue(version_is_below("", "4.9"))
        self.assertTrue(version_is_below("unknown", "4.9"))

    def test_no_minimum_version_does_not_fail(self):
        self.assertFalse(version_is_below("unknown", ""))

    def test_filename_source_detection_takes_priority_over_columns(self):
        frame = pd.DataFrame(
            columns=[
                "deviceName",
                "operatingSystem",
                "osVersion",
                "serialNumber",
                "userPrincipalName",
            ]
        )

        self.assertEqual(
            detect_source("bigfix_export.csv", frame),
            ("bigfix", "filename"),
        )

    def test_column_signatures_detect_source_without_filename_hint(self):
        frame = pd.DataFrame(
            columns=[
                "deviceName",
                "operatingSystem",
                "osVersion",
                "serialNumber",
                "userPrincipalName",
            ]
        )

        self.assertEqual(
            detect_source("inventory.csv", frame),
            ("intune", "columns"),
        )

    def test_csv_loading_preserves_trailing_zero_in_versions(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "inventory.csv")
            with open(path, "w", encoding="utf-8") as file:
                file.write("osVersion\n4.10\n")

            frame = load_data(path)

        self.assertEqual(frame.loc[0, "osVersion"], "4.10")


if __name__ == "__main__":
    unittest.main()