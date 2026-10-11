"""
Task P10A-003: Unit tests for Write-Once Evidence Vault.
Tests seal(), verify(), and open_working_copy() integrity validations.
"""

from pathlib import Path
import stat
import tempfile
import unittest

from src.forensics.vault import EvidenceVaultManager


class TestEvidenceVault(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.tmp_dir.name)
        self.vault_path = self.base_path / "vault"
        self.db_path = str(self.base_path / "forensics.db")
        self.workspace_dir = self.base_path / "workspace"
        self.workspace_dir.mkdir(parents=True, exist_ok=True)

        self.vault = EvidenceVaultManager(vault_root=self.vault_path, db_path=self.db_path)

        # Create sample evidence file
        self.sample_file = self.base_path / "memory_dump.bin"
        self.sample_file.write_bytes(b"EVIDENCE_RAW_BINARY_DATA_PAYLOAD_TEST_10A")

    def tearDown(self):
        self.vault.close()
        self.tmp_dir.cleanup()

    def test_seal_artifact_enforces_read_only(self):
        rec = self.vault.seal(
            artifact_path=self.sample_file,
            evidence_id="ev-vlt-001",
            acquired_by="soc-operator",
        )
        self.assertEqual(rec["evidence_id"], "ev-vlt-001")
        self.assertEqual(rec["status"], "SEALED")

        sealed_file = Path(rec["file_path"])
        self.assertTrue(sealed_file.exists())
        # Check permissions: write bit should not be set for user
        mode = sealed_file.stat().st_mode
        self.assertFalse(mode & stat.S_IWUSR)

    def test_verify_confirms_integrity(self):
        self.vault.seal(
            artifact_path=self.sample_file,
            evidence_id="ev-vlt-002",
            acquired_by="soc-operator",
        )
        self.assertTrue(self.vault.verify("ev-vlt-002"))

    def test_verify_detects_tampered_sealed_file(self):
        rec = self.vault.seal(
            artifact_path=self.sample_file,
            evidence_id="ev-vlt-003",
            acquired_by="soc-operator",
        )
        sealed_file = Path(rec["file_path"])

        # Force write permissions to simulate unauthorized tampering
        sealed_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
        sealed_file.write_bytes(b"TAMPERED_MODIFIED_DATA_PAYLOAD_CORRUPTED")
        sealed_file.chmod(stat.S_IRUSR)

        with self.assertRaises(ValueError) as ctx:
            self.vault.verify("ev-vlt-003")
        self.assertIn("Integrity violation", str(ctx.exception))

    def test_open_working_copy_creates_verified_replica(self):
        self.vault.seal(
            artifact_path=self.sample_file,
            evidence_id="ev-vlt-004",
            acquired_by="soc-operator",
        )

        working_file = self.vault.open_working_copy(
            evidence_id="ev-vlt-004",
            destination_dir=self.workspace_dir,
            requester="agent_c",
        )
        self.assertTrue(working_file.exists())
        self.assertEqual(working_file.read_bytes(), self.sample_file.read_bytes())

        # Verify working copy is writable for agent analysis
        mode = working_file.stat().st_mode
        self.assertTrue(bool(mode & stat.S_IWUSR))

        # Check that custody chain was updated with working copy dispatch event
        cur = self.vault.db.conn.cursor()
        cur.execute(
            "SELECT action, actor FROM chain_of_custody WHERE evidence_id = ? ORDER BY sequence_num DESC LIMIT 1",
            ("ev-vlt-004",),
        )
        row = cur.fetchone()
        self.assertEqual(row["action"], "WORKING_COPY_DISPATCHED")
        self.assertEqual(row["actor"], "soc-operator")


if __name__ == "__main__":
    unittest.main()
