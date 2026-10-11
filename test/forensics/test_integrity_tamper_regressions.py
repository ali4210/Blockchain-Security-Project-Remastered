"""
Task P10A-004: Forensic Integrity & Tamper Regression Suite.
Systematically tests sealed-file modification detection, chain-of-custody
record alteration detection, and SQLite append-only trigger abort rejections.
"""

from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest

from src.forensics.evidence_db import EvidenceDatabaseManager
from src.forensics.vault import EvidenceVaultManager


class TestIntegrityTamperRegressions(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.tmp_dir.name)
        self.vault_path = self.base_path / "vault"
        self.db_path = str(self.base_path / "forensics.db")
        self.workspace_dir = self.base_path / "workspace"
        self.workspace_dir.mkdir(parents=True, exist_ok=True)

        self.vault = EvidenceVaultManager(vault_root=self.vault_path, db_path=self.db_path)
        self.db = self.vault.db

        self.sample_file = self.base_path / "packet_trace.pcap"
        self.sample_file.write_bytes(b"AUTHENTIC_FORENSIC_PCAP_STREAM_0xCAFEBABE")

    def tearDown(self):
        self.vault.close()
        self.tmp_dir.cleanup()

    # --- Surface 1: Sealed File Alteration Detection ---

    def test_verify_detects_single_byte_disk_alteration(self):
        rec = self.vault.seal(
            artifact_path=self.sample_file,
            evidence_id="ev-tamp-001",
            acquired_by="soc-operator",
        )
        sealed_file = Path(rec["file_path"])

        # Tamper: change one byte
        sealed_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
        content = bytearray(sealed_file.read_bytes())
        content[0] ^= 0xFF
        sealed_file.write_bytes(bytes(content))
        sealed_file.chmod(stat.S_IRUSR)

        with self.assertRaises(ValueError) as ctx:
            self.vault.verify("ev-tamp-001")
        self.assertIn("Integrity violation", str(ctx.exception))
        self.assertIn("SHA-256 mismatch", str(ctx.exception))

    def test_open_working_copy_refuses_corrupted_sealed_file(self):
        rec = self.vault.seal(
            artifact_path=self.sample_file,
            evidence_id="ev-tamp-002",
            acquired_by="soc-operator",
        )
        sealed_file = Path(rec["file_path"])

        # Truncate file
        sealed_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
        sealed_file.write_bytes(b"TRUNCATED")
        sealed_file.chmod(stat.S_IRUSR)

        with self.assertRaises(ValueError) as ctx:
            self.vault.open_working_copy(
                evidence_id="ev-tamp-002",
                destination_dir=self.workspace_dir,
                requester="agent_dfir",
            )
        self.assertIn("Cannot dispatch corrupted sealed artifact", str(ctx.exception))

    # --- Surface 2: Chain of Custody Record Alteration Detection ---

    def test_verify_chain_detects_altered_custody_row_content(self):
        # Setup genuine chain of 3 records
        self.db.register_evidence(
            evidence_id="ev-chain-001",
            file_path="/evidence/core.dmp",
            byte_size=1024,
            sha256="1" * 64,
            sha512="2" * 128,
        )
        self.db.append_custody_event(
            evidence_id="ev-chain-001",
            action="INSPECT",
            actor="soc-operator",
            details="Preliminary memory analysis",
        )
        self.db.append_custody_event(
            evidence_id="ev-chain-001",
            action="STORE",
            actor="compliance-officer",
            details="Cold storage transition",
        )
        self.assertTrue(self.db.verify_chain_integrity("ev-chain-001"))

        # Bypass trigger using temporary raw connection without trigger or raw DB inspection
        # To simulate disk-level / low-level SQLite database modification:
        raw_conn = sqlite3.connect(self.db_path)
        # Drop triggers temporarily to simulate raw file tamper on the database
        raw_conn.execute("DROP TRIGGER trg_prevent_custody_update")
        raw_conn.execute(
            """
            UPDATE chain_of_custody
            SET details = 'MALICIOUS_TAMPERED_LOG_DETAILS'
            WHERE evidence_id = 'ev-chain-001' AND sequence_num = 2
            """
        )
        raw_conn.commit()
        raw_conn.close()

        # Chain verification must fail closed
        with self.assertRaises(ValueError) as ctx:
            self.db.verify_chain_integrity("ev-chain-001")
        self.assertIn("Record tamper detected at sequence 2", str(ctx.exception))

    def test_verify_chain_detects_sequence_gap_or_reordering(self):
        self.db.register_evidence(
            evidence_id="ev-chain-002",
            file_path="/evidence/ram.bin",
            byte_size=2048,
            sha256="3" * 64,
            sha512="4" * 128,
        )
        self.db.append_custody_event(
            evidence_id="ev-chain-002",
            action="VERIFY",
            actor="soc-operator",
            details="Verification step",
        )

        raw_conn = sqlite3.connect(self.db_path)
        raw_conn.execute("DROP TRIGGER trg_prevent_custody_update")
        # Change sequence number from 2 to 5 to create a discontinuity gap
        raw_conn.execute(
            """
            UPDATE chain_of_custody
            SET sequence_num = 5
            WHERE evidence_id = 'ev-chain-002' AND sequence_num = 2
            """
        )
        raw_conn.commit()
        raw_conn.close()

        with self.assertRaises(ValueError) as ctx:
            self.db.verify_chain_integrity("ev-chain-002")
        self.assertIn("Sequence discontinuity", str(ctx.exception))

    # --- Surface 3: Trigger UPDATE/DELETE Abort Rejections ---

    def test_sql_triggers_strictly_block_update_and_delete(self):
        self.db.register_evidence(
            evidence_id="ev-trig-001",
            file_path="/evidence/audit.log",
            byte_size=512,
            sha256="5" * 64,
            sha512="6" * 128,
        )

        # 1. Block UPDATE on evidence
        with self.assertRaises(sqlite3.IntegrityError) as ctx:
            self.db.conn.execute(
                "UPDATE evidence SET status = 'UNSEALED' WHERE evidence_id = 'ev-trig-001'"
            )
        self.assertIn("Mutation forbidden: evidence table is append-only", str(ctx.exception))

        # 2. Block DELETE on evidence
        with self.assertRaises(sqlite3.IntegrityError) as ctx:
            self.db.conn.execute(
                "DELETE FROM evidence WHERE evidence_id = 'ev-trig-001'"
            )
        self.assertIn("Deletion forbidden: evidence table is append-only", str(ctx.exception))

        # 3. Block UPDATE on chain_of_custody
        with self.assertRaises(sqlite3.IntegrityError) as ctx:
            self.db.conn.execute(
                "UPDATE chain_of_custody SET actor = 'agent_a' WHERE evidence_id = 'ev-trig-001'"
            )
        self.assertIn("Mutation forbidden: chain_of_custody is append-only", str(ctx.exception))

        # 4. Block DELETE on chain_of_custody
        with self.assertRaises(sqlite3.IntegrityError) as ctx:
            self.db.conn.execute(
                "DELETE FROM chain_of_custody WHERE evidence_id = 'ev-trig-001'"
            )
        self.assertIn("Deletion forbidden: chain_of_custody is append-only", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
