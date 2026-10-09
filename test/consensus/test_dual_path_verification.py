"""
Task P06-007: Comprehensive Dual-Path Verification Test Suite.
Formally validates end-to-end execution across two distinct paths:
1. Confirmed-exploit path: reproducible PoC, state balance drain delta,
   unanimous validator verification, supermajority threshold met, QuorumCertificate minted.
2. Deliberate-false-finding path: fabricated vulnerabilities, benign assertions,
   zero state delta, validator rejection, certificate denied, pipeline unblocked.
"""

import unittest
from src.consensus.avs_gate import AVSGate, ConsensusStatus
from src.consensus.anvil_sandbox import AnvilSandbox
from src.consensus.bls_aggregation import BLSAggregator, ValidatorKeyring


class TestDualPathVerification(unittest.TestCase):
    def setUp(self):
        self.validators = ["validator-1", "validator-2", "validator-3"]
        self.keyring = ValidatorKeyring(seed="dual-path-test-seed")
        self.gate = AVSGate(registered_validators=self.validators, keyring=self.keyring)

    def test_confirmed_exploit_path_end_to_end(self):
        """Path 1: Confirmed reentrancy exploit with verifiable balance drainage."""
        exploit_finding = {
            "id": "FINDING-EXPLOIT-CONFIRMED-001",
            "target_contract": "contracts/solidity/VulnerableVault.sol",
            "category": "REENTRANCY_VULNERABILITY",
            "severity": "CRITICAL",
            "poc_payload": "0x2e1a7d4d0000000000000000000000000000000000000000000000056bc75e2d63100000",
        }

        report = self.gate.process_finding_batch([exploit_finding])

        # Assert full quorum agreement
        self.assertEqual(report.total_processed, 1)
        self.assertEqual(report.agreed_count, 1)
        self.assertEqual(report.rejected_count, 0)
        self.assertEqual(len(report.certificates), 1)

        cert = report.certificates[0]
        self.assertEqual(cert.threshold_fraction, "3/3")
        self.assertEqual(len(cert.individual_signatures), 3)

        # Confirm cryptographic verification of the QuorumCertificate using matching sandbox context
        sandbox = AnvilSandbox(sandbox_id="avs-batch-coordinator")
        sandbox.start()
        receipt = sandbox.execute_poc(exploit_finding)
        sandbox.stop()

        self.assertTrue(receipt.success)
        self.assertEqual(receipt.balance_drained, 100_000_000_000_000_000_000)
        self.assertTrue(self.gate.aggregator.verify_quorum_certificate(cert, receipt.receipt_hash))

    def test_deliberate_false_finding_path_end_to_end(self):
        """Path 2: Deliberate false-finding injection with zero balance mutation."""
        deliberate_false_finding = {
            "id": "FINDING-DELIBERATE-FALSE-002",
            "target_contract": "contracts/solidity/VulnerableVault.sol",
            "category": "SYNTHETIC_FALSE_POSITIVE",
            "severity": "INFORMATIONAL",
            "poc_payload": "0x00000000",
        }

        report = self.gate.process_finding_batch([deliberate_false_finding])

        # Assert rejection and zero certificates
        self.assertEqual(report.total_processed, 1)
        self.assertEqual(report.agreed_count, 0)
        self.assertEqual(report.rejected_count, 1)
        self.assertEqual(len(report.certificates), 0)
        self.assertIn("FINDING-DELIBERATE-FALSE-002", report.rejected_finding_ids)

        # Confirm sandbox replay rejects without state mutation
        sandbox = AnvilSandbox(sandbox_id="avs-batch-coordinator")
        sandbox.start()
        receipt = sandbox.execute_poc(deliberate_false_finding)
        sandbox.stop()

        self.assertFalse(receipt.success)
        self.assertEqual(receipt.balance_drained, 0)
        self.assertEqual(receipt.initial_balance, receipt.final_balance)

    def test_interleaved_confirmed_and_false_finding_pipeline_execution(self):
        """Interleaved execution ensuring zero cross-contamination between findings."""
        findings = [
            {
                "id": "EXP-VALID-1",
                "category": "REENTRANCY_VULNERABILITY",
                "severity": "HIGH",
                "target_contract": "contracts/solidity/VulnerableVault.sol",
            },
            {
                "id": "FALSE-BENIGN-1",
                "category": "COMMENT_TYPO",
                "severity": "LOW",
                "target_contract": "contracts/solidity/VulnerableVault.sol",
            },
            {
                "id": "EXP-VALID-2",
                "category": "REENTRANCY_EXPLOIT",
                "severity": "CRITICAL",
                "target_contract": "contracts/solidity/VulnerableVault.sol",
            },
            {
                "id": "FALSE-FABRICATED-2",
                "category": "PHANTOM_OVERFLOW",
                "severity": "MEDIUM",
                "target_contract": "contracts/solidity/SafeVault.sol",
            },
        ]

        report = self.gate.process_finding_batch(findings)

        self.assertEqual(report.total_processed, 4)
        self.assertEqual(report.agreed_count, 2)
        self.assertEqual(report.rejected_count, 2)
        self.assertEqual(len(report.certificates), 2)
        self.assertEqual(report.rejected_finding_ids, ["FALSE-BENIGN-1", "FALSE-FABRICATED-2"])

        for cert in report.certificates:
            self.assertEqual(cert.threshold_fraction, "3/3")
            self.assertEqual(len(cert.individual_signatures), 3)


if __name__ == "__main__":
    unittest.main()
