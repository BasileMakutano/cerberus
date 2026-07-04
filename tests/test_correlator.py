import unittest

import engine.correlator as correlator


class CorrelatorTests(unittest.TestCase):
    def setUp(self):
        self.original_score = correlator.score_observation
        self.original_log = correlator._log
        correlator.score_observation = lambda observation, port: {
            "score": None,
            "threshold": None,
            "anomaly": False,
            "model_status": "no_model",
        }
        correlator._log = lambda msg: None

    def tearDown(self):
        correlator.score_observation = self.original_score
        correlator._log = self.original_log

    def test_frequency_spike_is_added_as_trigger(self):
        profiles = {
            "22": {
                "status": "ok",
                "confidence": "HIGH",
                "known_ips": {"list": ["192.168.1.10"]},
                "service": {"expected": "ssh", "versions": []},
                "protocol": {"expected": "tcp"},
                "scan_frequency": {"upper": 3},
            }
        }
        row = {
            "timestamp": "2026-07-04T10:05:00",
            "ip": "192.168.1.10",
            "port": 22,
            "protocol": "tcp",
            "state": "open",
            "service": "ssh",
            "version": "",
            "current_hour_count": 4,
        }

        event = correlator.correlate_observation(row, {}, profiles)

        self.assertIsNotNone(event)
        self.assertEqual(event["layer1_trigger"], "FREQUENCY_SPIKE")
        self.assertEqual(event["severity"], "MEDIUM")


if __name__ == "__main__":
    unittest.main()
