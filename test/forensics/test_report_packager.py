"""
Task P10C-003: Unit tests for Incident Report Packager.
Validates report structure, Merkle root verification, HMAC-SHA256 signing,
and tamper detection.
"""

from pathlib import Path
import tempfile
import unittest

from src.forensics.collector import VolatilityEvidenceCollector
from src.forensics.report_packager import IncidentReportPackager
from src.forensics.vault import EvidenceVaultManager


class TestReportPackager(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.tmp_dir.name).resolve()
        self.vault_path = self.base_path / "vault" / "sealed"
        self.db_path = str(self.base_path / "forensics.db")
        self.signing_key = b"SOC_SECURE_HMAC_MASTER_SIGNING_KEY_2026"

        self.vault = EvidenceVaultManager(vault_root=self.vault_path, db_path=self.db_path)
        self.collector = VolatilityEvidenceCollector(vault_manager=self.vault)
        self.packager = IncidentReportPackager(vault_manager=self.vault)

        # Collect sample bundle
        self.acquired_bundle = self.collector.collect_evidence_bundle(
            incident_id="INC-PKG-001",
            operator_principal="soc-operator",
        )

    def tearDown(self):
        self.vault.close()
        self.tmp_dir.cleanup()

    def test_package_and_verify_authentic_report(self):
        package = self.packager.package_report(
            incident_id="INC-PKG-001",
            acquired_stages=self.acquired_bundle,
            operator_principal="soc-operator",
            signing_key=self.signing_key,
            metadata={"classification": "CRITICAL_EXPLOIT", "triage_score": 9.5},
        )

        self.assertIn("report", package)
        self.assertIn("signature", package)

        report = package["report"]
        self.assertEqual(report["incident_id"], "INC-PKG-001")
        self.assertEqual(report["evidence_count"], 4)
        self.assertEqual(len(report["custody_timeline"]), 8)  # 4 genesis + 4 verify
        self.assertTrue(len(report["merkle_root"]) == 64)

        sig = package["signature"]
        self.assertEqual(sig["algorithm"], "HMAC-SHA256")
        self.assertEqual(sig["signer"], "soc-operator")

        # Verify authenticity
        is_valid = self.packager.verify_report(package, self.signing_key)
        self.assertTrue(is_valid)

    def test_tampered_report_fails_verification(self):
        package = self.packager.package_report(
            incident_id="INC-PKG-001",
            acquired_stages=self.acquired_bundle,
            operator_principal="soc-operator",
            signing_key=self.signing_key,
        )

        # Tamper with metadata field
        package["report"]["metadata"]["tampered"] = True
        self.assertFalse(self.packager.verify_report(package, self.signing_key))

    def test_wrong_signing_key_fails_verification(self):
        package = self.packager.package_report(
            incident_id="INC-PKG-001",
            acquired_stages=self.acquired_bundle,
            operator_principal="soc-operator",
            signing_key=self.signing_key,
        )

        wrong_key = b"INCORRECT_SIGNING_KEY_ATTACKER"
        self.assertFalse(self.packager.verify_report(package, wrong_key))

    def test_rejects_non_operator_author(self):
        with self.assertRaises(PermissionError):
            self.packager.package_report(
                incident_id="INC-PKG-001",
                acquired_stages=self.acquired_bundle,
                operator_principal="agent_g",
                signing_key=self.signing_key,
            )


if __name__ == "__main__":
    unittest.main()
