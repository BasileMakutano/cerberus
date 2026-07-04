import unittest
import tempfile
from pathlib import Path

from engine.parser import _nmap_xml_parse_status, _parse_ss_fields, _split_addr_port


class ParserTests(unittest.TestCase):
    def test_split_ipv4_address_port(self):
        self.assertEqual(_split_addr_port("192.168.1.10:443"), ("192.168.1.10", 443))

    def test_parse_modern_ss_listen_line(self):
        line = 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=123,fd=3))'
        parsed = _parse_ss_fields(line)

        self.assertEqual(parsed["state"], "LISTEN")
        self.assertEqual(parsed["local_address"], "0.0.0.0")
        self.assertEqual(parsed["local_port"], 22)
        self.assertEqual(parsed["remote_address"], "0.0.0.0")
        self.assertEqual(parsed["remote_port"], 0)
        self.assertIn("sshd", parsed["process"])

    def test_parse_state_first_line(self):
        line = "ESTAB 0 0 192.168.1.5:50500 192.168.1.10:443"
        parsed = _parse_ss_fields(line)

        self.assertEqual(parsed["state"], "ESTAB")
        self.assertEqual(parsed["local_port"], 50500)
        self.assertEqual(parsed["remote_port"], 443)

    def test_classifies_valid_host_down_nmap_xml(self):
        xml = """<?xml version="1.0"?>
<nmaprun>
  <runstats>
    <finished exit="success"/>
    <hosts up="0" down="1" total="1"/>
  </runstats>
</nmaprun>
"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.xml"
            path.write_text(xml)

            self.assertEqual(_nmap_xml_parse_status(str(path)), "host_down")


if __name__ == "__main__":
    unittest.main()
