"""
Task P10A-002: Unit tests for Forensics Database and Chain of Custody.
Validates append-only trigger enforcement, entry hash chaining, and
tamper-evident chain verification.
"""

from pathlib import Path
import sqlite3
import tempfile
import unittest

from src.forensics.evidence_db import EvidenceDatabaseManager, GENESIS_HASH


class TestEvidenceDatabase(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test_forensics.db"
        self.db = EvidenceDatabaseManager(str(self.db_path))

    def tearDown(self):
        self.db.close()
        self.tmp_dir.cleanup()

    def test_register_evidence_and_initial_custody(self):
        ev = self.db.register_evidence(
            evidence_id="ev-001",
            file_path="/evidence/sample.raw",
            byte_size=1024,
            sha256="a" * 64,
            sha512="b" * 128,
            acquired_by="soc-operator",
        )
        self.assertEqual(ev["evidence_id"], "ev-001")
        self.assertTrue(self.db.verify_chain_integrity("ev-001"))

    def test_hash_chain_progression(self):
        self.db.register_evidence(
            evidence_id="ev-002",
            file_path="/evidence/traffic.pcap",
            byte_size=2048,
            sha256="c" * 64,
            sha512="d" * 128,
        )

        event1 = self.db.append_custody_event(
            evidence_id="ev-002",
            action="VERIFIED",
            actor="soc-operator",
            details="Integrity re-check verified SHA-256",
        )
        self.assertEqual(event1["sequence_num"], 2)

        event2 = self.db.append_custody_event(
            evidence_id="ev-002",
            action="TRANSFER",
            actor="compliance-officer",
            details="Transferred to offline cold storage",
        )
        self.assertEqual(event2["sequence_num"], 3)
        self.assertEqual(event2["prev_hash"], event1["record_hash"])

        self.assertTrue(self.db.verify_chain_integrity("ev-002"))

    def test_triggers_prevent_update_on_evidence(self):
        self.db.register_evidence(
            evidence_id="ev-003",
            file_path="/evidence/disk.img",
            byte_size=4096,
            sha256="e" * 64,
            sha512="f" * 128,
        )

        with self.assertRaises(sqlite3.IntegrityError) as ctx:
            self.db.conn.execute(
                "UPDATE evidence SET status = 'TAMPERED' WHERE evidence_id = 'ev-003'"
            )
        self.assertIn("Mutation forbidden: evidence table is append-only", str(ctx.exception))

    def test_triggers_prevent_delete_on_custody(self):
        self.db.register_evidence(
            evidence_id="ev-004",
            file_path="/evidence/log.txt",
            byte_size=512,
            sha256="1" * 64,
            sha512="2" * 128,
        )

        with self.assertRaises(sqlite3.IntegrityError) as ctx:
            self.db.conn.execute("DELETE FROM chain_of_custody WHERE evidence_id = 'ev-004'")
        self.assertIn("Deletion forbidden: chain_of_custody is append-only", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
