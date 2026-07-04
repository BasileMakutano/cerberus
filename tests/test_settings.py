import unittest

from engine.server import validate_settings


class SettingsTests(unittest.TestCase):
    def test_validate_settings_accepts_clean_values(self):
        cleaned, errors = validate_settings({
            "target_ip": "192.168.1.10",
            "scan_interval": "5",
            "lookback_minutes": "60",
            "confirmed_only": True,
        })

        self.assertEqual(errors, {})
        self.assertEqual(cleaned["target_ip"], "192.168.1.10")
        self.assertEqual(cleaned["scan_interval"], 5)
        self.assertEqual(cleaned["lookback_minutes"], 60)
        self.assertTrue(cleaned["confirmed_only"])

    def test_validate_settings_rejects_bad_ip_and_ranges(self):
        cleaned, errors = validate_settings({
            "target_ip": "not an ip",
            "scan_interval": 0,
            "lookback_minutes": 2000,
        })

        self.assertEqual(cleaned, {})
        self.assertIn("target_ip", errors)
        self.assertIn("scan_interval", errors)
        self.assertIn("lookback_minutes", errors)


if __name__ == "__main__":
    unittest.main()
