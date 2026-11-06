import csv
import io
import unittest

from utils.csv_exporter import export_alerts_to_csv


class CSVExporterTests(unittest.TestCase):
    def test_exports_alert_fields_and_resolution_status(self):
        alerts = [
            {
                "id": 7,
                "timestamp": "2026-11-06 10:00:00",
                "alert_type": "Port Scan",
                "source_ip": "192.0.2.10",
                "dest_ip": "192.0.2.1",
                "description": "Many ports contacted",
                "severity": "High",
                "resolved": 0,
            },
            {
                "id": 8,
                "timestamp": "2026-11-06 10:01:00",
                "alert_type": "DNS Anomaly",
                "source_ip": "192.0.2.11",
                "dest_ip": "192.0.2.53",
                "description": "Unusual query rate",
                "severity": "Medium",
                "resolved": 1,
            },
        ]

        rows = list(csv.reader(io.StringIO(export_alerts_to_csv(alerts))))

        self.assertEqual(rows[0][0], "Alert ID")
        self.assertEqual(rows[1][0], "7")
        self.assertEqual(rows[1][-1], "Unresolved")
        self.assertEqual(rows[2][0], "8")
        self.assertEqual(rows[2][-1], "Resolved")

    def test_quotes_fields_containing_commas_and_newlines(self):
        alerts = [{"description": "Comma, and newline\npreserved"}]

        rows = list(csv.reader(io.StringIO(export_alerts_to_csv(alerts))))

        self.assertEqual(rows[1][5], "Comma, and newline\npreserved")


if __name__ == "__main__":
    unittest.main()
