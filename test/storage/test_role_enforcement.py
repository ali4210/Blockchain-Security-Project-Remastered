import os
import shutil
import tempfile
import unittest

from src.storage.broker_store import BrokerStore, READ_ONLY_ROLES


class TestRoleEnforcement(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_roles_")
        self.db_path = os.path.join(self.test_dir, "role_test.db")
        # Initialize database with admin / default role
        self.admin_store = BrokerStore(db_path=self.db_path, role="coordinator")
        self.sample_finding = {
            "source_tool": "slither",
            "severity": "HIGH",
            "title": "Reentrancy detected",
            "details": {"line": 15},
        }
        self.finding_id = self.admin_store.write_finding(self.sample_finding)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_read_only_agent_roles_blocked_from_writing(self):
        for role in ["agent_a", "agent_b", "agent_c", "agent_f", "auditor", "reader"]:
            ro_store = BrokerStore(db_path=self.db_path, role=role)
            self.assertTrue(ro_store.is_read_only)
            with self.assertRaises(PermissionError) as ctx:
                ro_store.write_finding({"source_tool": "test", "severity": "LOW", "title": "blocked"})
            self.assertIn("restricted to read-only access", str(ctx.exception))

    def test_read_only_agent_roles_blocked_from_snapshot(self):
        ro_store = BrokerStore(db_path=self.db_path, role="agent_b")
        with self.assertRaises(PermissionError) as ctx:
            ro_store.snapshot(label="unauthorized_snap")
        self.assertIn("cannot trigger snapshot operations", str(ctx.exception))

    def test_read_only_agent_roles_can_query_findings(self):
        for role in ["agent_a", "agent_b", "agent_f", "reader"]:
            ro_store = BrokerStore(db_path=self.db_path, role=role)
            findings = ro_store.list_findings()
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["title"], "Reentrancy detected")

            finding = ro_store.get_finding(self.finding_id)
            self.assertIsNotNone(finding)
            self.assertEqual(finding["severity"], "HIGH")

    def test_write_permitted_roles_can_write_and_snapshot(self):
        admin_store = BrokerStore(db_path=self.db_path, role="pipeline_admin")
        self.assertFalse(admin_store.is_read_only)
        f_id = admin_store.write_finding({"source_tool": "t2", "severity": "INFO", "title": "OK"})
        self.assertIsNotNone(f_id)
        snap = admin_store.snapshot(label="admin_snap")
        self.assertEqual(snap["snapshot_id"], "admin_snap")


if __name__ == "__main__":
    unittest.main()
