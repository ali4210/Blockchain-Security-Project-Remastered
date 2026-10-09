"""
Task P06-003: Isolated Anvil Sandbox Verification Test Suite.
Validates sandbox lifecycle, PoC re-execution fidelity, balance drain tracking,
deterministic execution receipt generation, and snapshot reverts.
"""

import unittest
from src.consensus.anvil_sandbox import AnvilSandbox, ExecutionReceipt


class TestAnvilSandbox(unittest.TestCase):
    def setUp(self):
        self.sandbox = AnvilSandbox(sandbox_id="sandbox-test-node-1", port=18545)
        self.sandbox.start()

    def tearDown(self):
        self.sandbox.stop()

    def test_sandbox_lifecycle_activation_and_cleanup(self):
        self.assertTrue(self.sandbox.is_active)
        self.assertIsNotNone(self.sandbox.snapshot_id)
        self.sandbox.stop()
        self.assertFalse(self.sandbox.is_active)
        self.assertIsNone(self.sandbox.snapshot_id)

    def test_unactivated_sandbox_raises_error(self):
        inactive_sandbox = AnvilSandbox(sandbox_id="inactive-sandbox")
        with self.assertRaises(RuntimeError):
            inactive_sandbox.execute_poc({"target_contract": "VulnerableVault.sol"})

    def test_reentrancy_poc_reexecution_success(self):
        finding = {
            "id": "FINDING-REENTRANCY-001",
            "target_contract": "contracts/solidity/VulnerableVault.sol",
            "category": "REENTRANCY_VULNERABILITY",
            "severity": "HIGH",
        }
        receipt = self.sandbox.execute_poc(finding)

        self.assertIsInstance(receipt, ExecutionReceipt)
        self.assertTrue(receipt.success)
        self.assertEqual(receipt.initial_balance, 100_000_000_000_000_000_000)
        self.assertEqual(receipt.final_balance, 0)
        self.assertEqual(receipt.balance_drained, 100_000_000_000_000_000_000)
        self.assertEqual(len(receipt.state_delta_hash), 64)
        self.assertEqual(len(receipt.receipt_hash), 64)

    def test_invalid_poc_reexecution_failure_handling(self):
        non_exploit = {
            "id": "FINDING-BENIGN-002",
            "target_contract": "contracts/solidity/SafeVault.sol",
            "category": "CODE_STYLE_INFORMATIONAL",
            "severity": "LOW",
        }
        receipt = self.sandbox.execute_poc(non_exploit)

        self.assertFalse(receipt.success)
        self.assertEqual(receipt.balance_drained, 0)
        self.assertEqual(receipt.initial_balance, receipt.final_balance)
        self.assertEqual(len(receipt.receipt_hash), 64)

    def test_snapshot_revert_functionality(self):
        self.assertTrue(self.sandbox.revert_to_snapshot())
        self.sandbox.stop()
        self.assertFalse(self.sandbox.revert_to_snapshot())

    def test_deterministic_receipt_generation(self):
        finding = {
            "id": "FINDING-DETERMINISM-003",
            "target_contract": "contracts/solidity/VulnerableVault.sol",
            "category": "REENTRANCY_VULNERABILITY",
            "severity": "CRITICAL",
        }
        r1 = self.sandbox.execute_poc(finding)
        r2 = self.sandbox.execute_poc(finding)

        self.assertEqual(r1.state_delta_hash, r2.state_delta_hash)
        self.assertEqual(r1.logs_digest, r2.logs_digest)
        self.assertEqual(r1.receipt_hash, r2.receipt_hash)


if __name__ == "__main__":
    unittest.main()
