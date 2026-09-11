import unittest
import os
import sys
import shutil
import tempfile
import json

# Add root project dir to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import database
from ingestion.detector import FormatDetector
from ingestion.normalizer import SIEMNormalizer
from ingestion.pipeline import LogIngestionPipeline
from ingestion.parsers.csv_parser import CSVParser
from ingestion.parsers.json_parser import JSONParser
from ingestion.parsers.syslog_parser import SyslogParser
from ingestion.parsers.snort_parser import SnortParser
from ingestion.parsers.fallback_parser import FallbackParser
from ingestion.parsers.evtx_parser import EVTXParser

class TestSIEMIngestionSystem(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_backup = database.DB_PATH
        database.DB_PATH = os.path.join(self.test_dir, "test_siem.db")
        if os.path.exists(database.DB_PATH):
            os.remove(database.DB_PATH)
        database.init_db()

    def tearDown(self):
        database.DB_PATH = self.db_backup
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_format_detector(self):
        csv_path = os.path.join(self.test_dir, "test.csv")
        with open(csv_path, "w") as f:
            f.write("timestamp,src_ip,dst_ip\n2026-09-11 10:00:00,10.0.0.1,10.0.0.2\n")
        self.assertEqual(FormatDetector.detect(csv_path), "CSV")

        json_path = os.path.join(self.test_dir, "test.json")
        with open(json_path, "w") as f:
            f.write('{"timestamp": "2026-09-11", "src_ip": "1.1.1.1"}')
        self.assertEqual(FormatDetector.detect(json_path), "JSON")

        ndjson_path = os.path.join(self.test_dir, "test.ndjson")
        with open(ndjson_path, "w") as f:
            f.write('{"a":1}\n{"b":2}\n')
        self.assertEqual(FormatDetector.detect(ndjson_path), "NDJSON")

        snort_path = os.path.join(self.test_dir, "test.alert")
        with open(snort_path, "w") as f:
            f.write("[**] [1:100:1] Test Alert [**] {TCP} 1.1.1.1 -> 2.2.2.2")
        self.assertEqual(FormatDetector.detect(snort_path), "SNORT")

    def test_02_csv_parser_dynamic_mapping_and_label_preservation(self):
        csv_path = os.path.join(self.test_dir, "ids2018.csv")
        with open(csv_path, "w") as f:
            f.write("Timestamp,Src IP,Dst IP,Protocol,Label\n2026-09-11 10:15:00,172.31.66.83,10.0.0.5,TCP,SSH-Bruteforce\n")

        parser = CSVParser()
        records = list(parser.parse_file(csv_path, organization="OrgA", source="FW1"))
        self.assertEqual(len(records), 1)
        r = records[0]
        self.assertEqual(r.ip_address, "172.31.66.83")
        self.assertEqual(r.destination_ip, "10.0.0.5")
        self.assertEqual(r.attack_type, "SSH-Bruteforce")  # Preserved from CSV label!
        self.assertEqual(r.organization, "OrgA")

    def test_03_json_and_ndjson_parser(self):
        ndjson_path = os.path.join(self.test_dir, "test.ndjson")
        with open(ndjson_path, "w") as f:
            f.write('{"timestamp": "2026-09-11T12:00:00Z", "src_ip": "192.168.1.5", "user": "alice"}\n')

        parser = JSONParser()
        records = list(parser.parse_file(ndjson_path))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].user, "alice")
        self.assertEqual(records[0].ip_address, "192.168.1.5")

    def test_04_syslog_parser(self):
        syslog_path = os.path.join(self.test_dir, "syslog.log")
        with open(syslog_path, "w") as f:
            f.write("<34>Sep 11 10:20:15 host01 sshd[123]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2\n")

        parser = SyslogParser()
        records = list(parser.parse_file(syslog_path))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].hostname, "host01")
        self.assertEqual(records[0].ip_address, "192.168.1.100")
        self.assertEqual(records[0].user, "admin")

    def test_05_snort_parser(self):
        snort_path = os.path.join(self.test_dir, "snort.log")
        with open(snort_path, "w") as f:
            f.write("[**] [1:1000001:2] ICMP Ping Detected [**] [Priority: 2] {ICMP} 192.168.1.10 -> 192.168.1.20\n")

        parser = SnortParser()
        records = list(parser.parse_file(snort_path))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].event_type, "ICMP Ping Detected")
        self.assertEqual(records[0].ip_address, "192.168.1.10")
        self.assertEqual(records[0].destination_ip, "192.168.1.20")

    def test_06_generic_fallback_parser(self):
        text_path = os.path.join(self.test_dir, "unknown.log")
        with open(text_path, "w") as f:
            f.write("2026-09-11 14:00:00 Custom log line from unknown app src_ip=10.20.30.40 user=bob status=login_denied\n")

        parser = FallbackParser()
        records = list(parser.parse_file(text_path))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].ip_address, "10.20.30.40")
        self.assertEqual(records[0].user, "bob")
        self.assertEqual(records[0].source_type, "GENERIC_TEXT")

    def test_07_empty_file_handling(self):
        empty_path = os.path.join(self.test_dir, "empty.log")
        with open(empty_path, "w") as f:
            f.write("")

        result = LogIngestionPipeline.process_file(empty_path)
        self.assertIn("status", result)

    def test_08_fault_tolerance_malformed_lines(self):
        malformed_path = os.path.join(self.test_dir, "malformed.log")
        with open(malformed_path, "w") as f:
            f.write("2026-09-11 10:00:00 | HOST1 | 192.168.1.1 | admin | LOGIN | SUCCESS\n")
            f.write("CORRUPTED_LINE_WITHOUT_DELIMITERS_OR_STRUCTURE\n")
            f.write("2026-09-11 10:05:00 | HOST1 | 192.168.1.2 | user2 | LOGOUT | SUCCESS\n")

        result = LogIngestionPipeline.process_file(malformed_path)
        self.assertEqual(result["events_received"], 3)
        self.assertEqual(result["events_stored"], 3)
        self.assertGreaterEqual(result["warnings_count"], 1)

    def test_09_no_invented_attack_labels(self):
        csv_path = os.path.join(self.test_dir, "normal.csv")
        with open(csv_path, "w") as f:
            f.write("timestamp,src_ip,dst_ip\n2026-09-11 10:00:00,10.0.0.1,10.0.0.2\n")

        parser = CSVParser()
        records = list(parser.parse_file(csv_path))
        self.assertIsNone(records[0].attack_type)
        self.assertIsNone(records[0].suspicious)

    def test_10_multi_organization_persistence(self):
        file1 = os.path.join(self.test_dir, "org1.csv")
        with open(file1, "w") as f:
            f.write("timestamp,src_ip\n2026-09-11 10:00:00,1.1.1.1\n")
        LogIngestionPipeline.process_file(file1, organization="Organization A")

        file2 = os.path.join(self.test_dir, "org2.csv")
        with open(file2, "w") as f:
            f.write("timestamp,src_ip\n2026-09-11 11:00:00,2.2.2.2\n")
        LogIngestionPipeline.process_file(file2, organization="Organization B")

        events, total = database.get_events(page=1, per_page=100)
        self.assertEqual(total, 2)
        orgs = database.get_unique_organizations()
        self.assertIn("Organization A", orgs)
        self.assertIn("Organization B", orgs)

    def test_11_duplicate_fingerprinting(self):
        file1 = os.path.join(self.test_dir, "dup.csv")
        with open(file1, "w") as f:
            f.write("timestamp,src_ip,dst_ip\n2026-09-11 10:00:00,10.0.0.1,10.0.0.2\n")

        res1 = LogIngestionPipeline.process_file(file1, organization="OrgX")
        self.assertEqual(res1["duplicate_count"], 0)

        # Upload exact same file again
        res2 = LogIngestionPipeline.process_file(file1, organization="OrgX")
        self.assertEqual(res2["duplicate_count"], 1)

    def test_12_evtx_field_aliases_and_ip_sniffing(self):
        parser = EVTXParser()
        # Verify alias dictionaries contain key EVTX names
        from ingestion.parsers.evtx_parser import SRC_IP_KEYS, DST_IP_KEYS, SRC_PORT_KEYS, DST_PORT_KEYS, USER_KEYS
        self.assertIn("ipaddress", SRC_IP_KEYS)
        self.assertIn("destip", DST_IP_KEYS)
        self.assertIn("ipport", SRC_PORT_KEYS)
        self.assertIn("destport", DST_PORT_KEYS)
        self.assertIn("targetusername", USER_KEYS)

if __name__ == "__main__":
    unittest.main()
