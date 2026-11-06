import unittest
from unittest.mock import Mock, patch

from detectors.ml_anomaly import MLAnomalyDetector


class MLAnomalyDetectorTests(unittest.TestCase):
    def setUp(self):
        self.config = Mock()
        self.config.get.return_value = True
        self.db = Mock()
        self.logger = Mock()
        self.detector = MLAnomalyDetector(self.config, self.db, self.logger)
        self.history = [
            {"packets_per_sec": 100.0, "bytes_per_sec": 1024.0}
            for _ in range(20)
        ]
        self.db.get_traffic_stats.return_value = self.history
        self.latest_stat = {"packets_per_sec": 100.0, "bytes_per_sec": 1024.0}

    def test_waits_until_minimum_baseline_is_available(self):
        self.db.get_traffic_stats.return_value = self.history[:14]

        self.assertEqual(self.detector.analyze_stats(self.latest_stat), [])
        self.db.add_alert.assert_not_called()

    @patch("detectors.ml_anomaly.time.time", return_value=1000)
    def test_alerts_when_current_rate_exceeds_baseline(self, _mock_time):
        self.latest_stat["packets_per_sec"] = 105.0
        self.db.add_alert.return_value = 42

        alerts = self.detector.analyze_stats(self.latest_stat)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["id"], 42)
        self.assertEqual(alerts[0]["alert_type"], "ML Anomaly")
        self.db.add_alert.assert_called_once()
        self.logger.warning.assert_called_once()

    @patch("detectors.ml_anomaly.time.time", return_value=1000)
    def test_suppresses_alerts_during_cooldown(self, _mock_time):
        self.latest_stat["packets_per_sec"] = 105.0
        self.detector.last_alert_time = 950

        self.assertEqual(self.detector.analyze_stats(self.latest_stat), [])
        self.db.add_alert.assert_not_called()


if __name__ == "__main__":
    unittest.main()
