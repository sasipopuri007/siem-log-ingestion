import unittest
import os
import sys
import tempfile
import shutil
import io

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import app
import database

class TestSIEMAPIRoutes(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_backup = database.DB_PATH
        database.DB_PATH = os.path.join(self.test_dir, "test_siem.db")
        database.init_db()

        app.app.config["TESTING"] = True
        self.client = app.app.test_client()

    def tearDown(self):
        database.DB_PATH = self.db_backup
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_api_upload_and_process_flow(self):
        # 1. Upload File
        csv_data = b"timestamp,src_ip,dst_ip,label\n2026-09-11 10:00:00,192.168.1.1,10.0.0.1,Benign\n"
        upload_resp = self.client.post(
            "/api/upload",
            data={"file": (io.BytesIO(csv_data), "test_upload.csv")},
            content_type="multipart/form-data"
        )
        self.assertEqual(upload_resp.status_code, 200)
        up_json = upload_resp.get_json()
        self.assertTrue(up_json["success"])

        # 2. Process File
        proc_resp = self.client.post(
            "/api/process",
            json={
                "filepath": up_json["filepath"],
                "filename": up_json["filename"],
                "organization": "Org Alpha",
                "source": "Firewall01"
            }
        )
        self.assertEqual(proc_resp.status_code, 200)
        proc_json = proc_resp.get_json()
        self.assertEqual(proc_json["events_stored"], 1)

        # 3. GET /api/events
        ev_resp = self.client.get("/api/events?organization=Org+Alpha")
        self.assertEqual(ev_resp.status_code, 200)
        ev_json = ev_resp.get_json()
        self.assertEqual(len(ev_json["events"]), 1)
        self.assertEqual(ev_json["events"][0]["ip_address"], "192.168.1.1")

        # 4. GET /api/events/<id>
        event_id = ev_json["events"][0]["id"]
        detail_resp = self.client.get(f"/api/events/{event_id}")
        self.assertEqual(detail_resp.status_code, 200)

        # 5. GET /api/stats
        stats_resp = self.client.get("/api/stats")
        self.assertEqual(stats_resp.status_code, 200)
        stats_json = stats_resp.get_json()
        self.assertEqual(stats_json["total_events"], 1)

        # 6. GET /api/sources & /api/organizations
        self.assertEqual(self.client.get("/api/sources").status_code, 200)
        self.assertEqual(self.client.get("/api/organizations").status_code, 200)

        # 7. GET /api/export (ML Handoff CSV)
        export_resp = self.client.get("/api/export")
        self.assertEqual(export_resp.status_code, 200)
        self.assertIn("text/csv", export_resp.content_type)
        self.assertIn(b"timestamp,organization,source", export_resp.data)

if __name__ == "__main__":
    unittest.main()
