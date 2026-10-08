import os
import shutil
import tempfile
import unittest
from pathlib import Path

from src.storage.broker_store import BrokerStore, snapshot, write_finding


class TestBrokerStore(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_broker_store_")
        self.db_path = os.path.join(self.test_dir, "test_broker.db")
        self.store = BrokerStore(db_path=self.db_path)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_wal_mode_enabled(self):
        self.assertTrue(self.store.verify_wal_mode())

    def test_write_and_get_finding(self):
        sample_finding = {
            "source_tool": "slither",
            "severity": "HIGH",
            "title": "Arbitrary send detected",
            "details": {"line": 42, "contract": "VulnerableVault"},
        }
        f_id = self.store.write_finding(sample_finding)
        self.assertIsNotNone(f_id)

        retrieved = self.store.get_finding(f_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["source_tool"], "slither")
        self.assertEqual(retrieved["severity"], "HIGH")
        self.assertEqual(retrieved["title"], "Arbitrary send detected")
        self.assertEqual(retrieved["details"]["contract"], "VulnerableVault")

    def test_list_findings(self):
        self.store.write_finding({"source_tool": "t1", "severity": "LOW", "title": "F1", "details": {}})
        self.store.write_finding({"source_tool": "t2", "severity": "CRITICAL", "title": "F2", "details": {}})

        findings = self.store.list_findings()
        self.assertEqual(len(findings), 2)
        titles = {f["title"] for f in findings}
        self.assertEqual(titles, {"F1", "F2"})

    def test_pre_swarm_snapshot_creation(self):
        self.store.write_finding({"source_tool": "t1", "severity": "HIGH", "title": "F1", "details": {}})
        snap_res = self.store.snapshot(label="test_snap_1")

        self.assertEqual(snap_res["snapshot_id"], "test_snap_1")
        self.assertEqual(snap_res["finding_count"], 1)
        self.assertTrue(Path(snap_res["snapshot_path"]).is_file())
        self.assertTrue(len(snap_res["checksum"]) == 64)

        # Confirm restored snapshot has valid SQLite WAL header
        snap_store = BrokerStore(db_path=snap_res["snapshot_path"])
        self.assertEqual(len(snap_store.list_findings()), 1)

    def test_module_level_helpers(self):
        # Test default delegator does not raise NotImplementedError
        f_id = write_finding({"source_tool": "helper_test", "severity": "INFO", "title": "H1", "details": {}})
        self.assertIsNotNone(f_id)
        snap_info = snapshot(label="helper_snap")
        self.assertEqual(snap_info["snapshot_id"], "helper_snap")


if __name__ == "__main__":
    unittest.main()
