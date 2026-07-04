import json
import tempfile
import unittest
from pathlib import Path

import engine.alerter as alerter


class AlerterTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.alerts_path = Path(self.tmpdir.name) / "alerts.json"
        self.original_path = alerter.ALERTS_PATH
        alerter.ALERTS_PATH = str(self.alerts_path)

    def tearDown(self):
        alerter.ALERTS_PATH = self.original_path
        self.tmpdir.cleanup()

    def test_write_alerts_deduplicates_by_fingerprint(self):
        event = {
            "timestamp": "2026-07-04T10:00:00+00:00",
            "observed_at": "2026-07-04T09:59:00",
            "severity": "HIGH",
            "confirmed": True,
            "port": 22,
            "ip": "192.168.1.10",
            "service": "ssh",
            "layer1_trigger": "UNKNOWN_IP",
        }

        first = alerter.write_alerts([event])
        second = alerter.write_alerts([event])

        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])
        self.assertEqual(len(json.loads(self.alerts_path.read_text())), 1)

    def test_acknowledge_alert_persists(self):
        event = {
            "timestamp": "2026-07-04T10:00:00+00:00",
            "observed_at": "2026-07-04T09:59:00",
            "severity": "LOW",
            "confirmed": False,
            "port": 80,
            "ip": "192.168.1.20",
            "service": "http",
            "layer1_trigger": "NEW_VERSION",
        }
        alert = alerter.write_alerts([event])[0]

        result = alerter.acknowledge_alert(alert["alert_id"])
        stored = json.loads(self.alerts_path.read_text())[0]

        self.assertTrue(result["success"])
        self.assertTrue(stored["acknowledged"])


if __name__ == "__main__":
    unittest.main()
