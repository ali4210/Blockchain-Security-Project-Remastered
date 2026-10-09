"""
Task P06-006: Non-Blocking Rejection Verification Suite for AVS Consensus Gate.
Validates that hallucinated, benign, or non-reproducible findings are safely rejected
without halting pipeline flow, and that subsequent legitimate findings achieve
QuorumCertificates smoothly.
"""

import unittest
from src.consensus.avs_gate import AVSGate, ConsensusStatus, BatchProcessingReport


class TestFindingRejection(unittest.TestCase):
    def setUp(self):
        self.validators = ["validator-1", "validator-2", "validator-3"]
        self.gate = AVSGate(registered_validators=self.validators)

    def test_single_hallucinated_finding_rejection(self):
        hallucinated_finding = {
            "id": "FINDING-FAKE-001",
            "target_contract": "contracts/solidity/VulnerableVault.sol",
            "category": "HALLUCINATED_ZERO_DAY",
            "severity": "LOW",
        }
        report = self.gate.process_finding_batch([hallucinated_finding])

        self.assertEqual(report.total_processed, 1)
        self.assertEqual(report.agreed_count, 0)
        self.assertEqual(report.rejected_count, 1)
        self.assertIn("FINDING-FAKE-001", report.rejected_finding_ids)
        self.assertEqual(len(report.certificates), 0)

    def test_mixed_finding_batch_resilience_and_continuity(self):
        batch = [
            {
                "id": "FINDING-REENTRANCY-001",
                "target_contract": "contracts/solidity/VulnerableVault.sol",
                "category": "REENTRANCY_VULNERABILITY",
                "severity": "HIGH",
            },
            {
                "id": "FINDING-HALLUCINATED-002",
                "target_contract": "contracts/solidity/VulnerableVault.sol",
                "category": "IMAGINARY_FLASH_LOAN",
                "severity": "LOW",
            },
            {
                "id": "FINDING-BENIGN-003",
                "target_contract": "contracts/solidity/SafeVault.sol",
                "category": "NATSPEC_MISSING_COMMENT",
                "severity": "INFORMATIONAL",
            },
            {
                "id": "FINDING-REENTRANCY-004",
                "target_contract": "contracts/solidity/VulnerableVault.sol",
                "category": "REENTRANCY_VULNERABILITY",
                "severity": "CRITICAL",
            },
        ]

        report = self.gate.process_finding_batch(batch)

        self.assertEqual(report.total_processed, 4)
        self.assertEqual(report.agreed_count, 2)
        self.assertEqual(report.rejected_count, 2)
        self.assertIn("FINDING-HALLUCINATED-002", report.rejected_finding_ids)
        self.assertIn("FINDING-BENIGN-003", report.rejected_finding_ids)

        cert_finding_ids = [c.attestation_id for c in report.certificates]
        self.assertEqual(len(report.certificates), 2)
        for cert in report.certificates:
            self.assertEqual(cert.threshold_fraction, "3/3")
            self.assertIn(cert.participating_validators, [
                ["validator-1", "validator-2", "validator-3"]
            ])

    def test_pipeline_does_not_halt_on_empty_or_all_rejected_batch(self):
        all_fake = [
            {"id": "FAKE-1", "category": "NON_EXISTENT_BUG", "severity": "LOW"},
            {"id": "FAKE-2", "category": "BOGUS_LOGIC_ERROR", "severity": "LOW"},
        ]
        report = self.gate.process_finding_batch(all_fake)
        self.assertEqual(report.total_processed, 2)
        self.assertEqual(report.agreed_count, 0)
        self.assertEqual(report.rejected_count, 2)
        self.assertEqual(len(report.certificates), 0)


if __name__ == "__main__":
    unittest.main()
