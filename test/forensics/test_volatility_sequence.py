"""
Task P10C-002: Unit tests for Volatile-First Collection Sequence.
Validates RFC 3227 order enforcement, sequence inversion rejection,
timestamp progression monotonicity, and custody ledger integrity across tiers.
"""

from datetime import datetime
from pathlib import Path
import stat
import tempfile
import unittest

from src.forensics.collector import VolatilityEvidenceCollector, VOLATILITY_ORDER
from src.forensics.vault import EvidenceVaultManager


class TestVolatilitySequence(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.tmp_dir.name).resolve()
        self.vault_path = self.base_path / "vault" / "sealed"
        self.db_path = str(self.base_path / "forensics.db")

        self.vault = EvidenceVaultManager(vault_root=self.vault_path, db_path=self.db_path)
        self.collector = VolatilityEvidenceCollector(vault_manager=self.vault)

    def tearDown(self):
        self.vault.close()
        self.tmp_dir.cleanup()

    def test_strict_volatile_first_order_and_sequence_numbers(self):
        results = self.collector.collect_evidence_bundle(
            incident_id="INC-SEQ-001",
            operator_principal="soc-operator",
        )

        expected_stages = ["MEMORY", "NETWORK", "DISK", "LOGS"]
        actual_stages = [r.stage for r in results]
        self.assertEqual(actual_stages, expected_stages)

        # Assert sequence numbers are exactly 1, 2, 3, 4
        sequence_nums = [r.order_sequence for r in results]
        self.assertEqual(sequence_nums, [1, 2, 3, 4])

    def test_detects_and_rejects_sequence_inversion(self):
        # Attempt to collect Disk before Memory
        inverted_stages = ["DISK", "MEMORY", "NETWORK", "LOGS"]
        with self.assertRaises(ValueError) as ctx:
            self.collector.collect_evidence_bundle(
                incident_id="INC-SEQ-002",
                operator_principal="soc-operator",
                stages=inverted_stages,
            )
        self.assertIn("Order of Volatility violation", str(ctx.exception))

    def test_detects_and_rejects_missing_volatile_stages(self):
        # Attempt to skip volatile memory collection entirely
        partial_stages = ["NETWORK", "DISK", "LOGS"]
        with self.assertRaises(ValueError) as ctx:
            self.collector.collect_evidence_bundle(
                incident_id="INC-SEQ-003",
                operator_principal="soc-operator",
                stages=partial_stages,
            )
        self.assertIn("Order of Volatility violation", str(ctx.exception))

    def test_timestamp_monotonicity_across_stages(self):
        results = self.collector.collect_evidence_bundle(
            incident_id="INC-SEQ-004",
            operator_principal="soc-operator",
        )

        timestamps = [datetime.fromisoformat(r.timestamp) for r in results]
        for i in range(len(timestamps) - 1):
            self.assertLessEqual(
                timestamps[i],
                timestamps[i + 1],
                f"Timestamp violation between {results[i].stage} and {results[i + 1].stage}",
            )

    def test_all_tiers_sealed_read_only_with_custody_continuity(self):
        results = self.collector.collect_evidence_bundle(
            incident_id="INC-SEQ-005",
            operator_principal="soc-operator",
        )

        for r in results:
            file_path = Path(r.file_path)
            self.assertTrue(file_path.exists())
            mode = file_path.stat().st_mode
            # Read-only check
            self.assertFalse(bool(mode & stat.S_IWUSR))
            # Cryptographic chain integrity check
            self.assertTrue(self.vault.db.verify_chain_integrity(r.evidence_id))


if __name__ == "__main__":
    unittest.main()
