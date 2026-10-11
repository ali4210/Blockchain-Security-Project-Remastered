"""
Task P10C-001: Unit tests for Volatility-Ordered Evidence Collector.
Validates RFC 3227 acquisition sequencing, soc-operator principal enforcement,
vault sealing, and database chain of custody tracking.
"""

from pathlib import Path
import tempfile
import unittest

from src.forensics.collector import VolatilityEvidenceCollector, VOLATILITY_ORDER
from src.forensics.vault import EvidenceVaultManager


class TestEvidenceCollector(unittest.TestCase):
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

    def test_collects_strictly_in_order_of_volatility(self):
        simulated_data = {
            "MEMORY": {"processes": ["geth", "node"], "memory_rss_mb": 4096},
            "NETWORK": {"active_sockets": 14, "listening_ports": [8545, 30303]},
            "DISK": {"block_hashes": ["0xabc", "0xdef"], "fs_status": "clean"},
            "LOGS": {"audit_entries": 120, "last_event": "BLOCK_IMPORT"},
        }

        results = self.collector.collect_evidence_bundle(
            incident_id="INC-VLT-001",
            operator_principal="soc-operator",
            simulated_data=simulated_data,
        )

        # Assert exactly 4 stages collected
        self.assertEqual(len(results), 4)

        # Assert order matches RFC 3227 specification
        expected_stages = ["MEMORY", "NETWORK", "DISK", "LOGS"]
        actual_stages = [r.stage for r in results]
        self.assertEqual(actual_stages, expected_stages)

        # Verify each stage artifact exists and is verified in vault
        for r in results:
            self.assertTrue(Path(r.file_path).exists())
            self.assertTrue(self.vault.verify(r.evidence_id))

    def test_rejects_autonomous_agent_principal(self):
        agent_principals = ["agent", "agent_a", "agent_g", "unauthorized_user"]
        for p in agent_principals:
            with self.assertRaises(PermissionError) as ctx:
                self.collector.collect_evidence_bundle(
                    incident_id="INC-VLT-002",
                    operator_principal=p,
                )
            self.assertIn("requires human 'soc-operator' authority", str(ctx.exception))

    def test_verifies_chain_of_custody_continuity_for_all_stages(self):
        results = self.collector.collect_evidence_bundle(
            incident_id="INC-VLT-003",
            operator_principal="soc-operator",
        )

        for r in results:
            # Check db integrity replay
            self.assertTrue(self.vault.db.verify_chain_integrity(r.evidence_id))


if __name__ == "__main__":
    unittest.main()
