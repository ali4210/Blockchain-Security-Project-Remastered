import unittest
from src.agents.upgrade5_defi_attacks import (
    front_running_detector,
    rug_pull_scanner,
    flash_loan_invariant_generator,
)


class TestUpgrade5DeFiAttacks(unittest.TestCase):

    def test_front_running_detector_safe_stub_none(self):
        result = front_running_detector(None)
        self.assertEqual(result["status"], "pending_phase_11_mempool")
        self.assertEqual(result["alerts"], [])
        self.assertEqual(result["total_evaluated"], 0)
        self.assertIn("Phase 11", result["note"])

    def test_front_running_detector_empty_snapshot(self):
        result = front_running_detector([])
        self.assertEqual(result["status"], "analyzed")
        self.assertEqual(result["alerts"], [])
        self.assertEqual(result["total_evaluated"], 0)

    def test_front_running_detector_detects_gas_outbidding(self):
        snapshot = [
            {
                "hash": "0xvictim123",
                "to": "0xTargetVault",
                "input": "0x2e1a7d4d0000000000000000000000000000000000000000000000000de0b6b3a7640000",
                "gas_price": 50000000000,
            },
            {
                "hash": "0xpredator456",
                "to": "0xTargetVault",
                "input": "0x2e1a7d4d0000000000000000000000000000000000000000000000000de0b6b3a7640000",
                "gas_price": 75000000000,
            },
        ]
        result = front_running_detector(snapshot)
        self.assertEqual(result["status"], "analyzed")
        self.assertEqual(result["total_evaluated"], 2)
        self.assertEqual(len(result["alerts"]), 1)

        alert = result["alerts"][0]
        self.assertEqual(alert["attack_type"], "gas_outbidding")
        self.assertEqual(alert["target_tx_hash"], "0xvictim123")
        self.assertEqual(alert["predator_tx_hash"], "0xpredator456")
        self.assertEqual(alert["victim_gas_price"], 50000000000)
        self.assertEqual(alert["predator_gas_price"], 75000000000)
        self.assertEqual(alert["similarity_score"], 1.0)
        self.assertEqual(alert["details"]["gas_premium"], 25000000000)

    def test_front_running_detector_ignores_different_targets(self):
        snapshot = [
            {"hash": "0x1", "to": "0xContractA", "input": "0xabcd", "gas_price": 50},
            {"hash": "0x2", "to": "0xContractB", "input": "0xabcd", "gas_price": 75},
        ]
        result = front_running_detector(snapshot)
        self.assertEqual(result["alerts"], [])

    def test_future_phase_stubs_raise_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            rug_pull_scanner(None)
        with self.assertRaises(NotImplementedError):
            flash_loan_invariant_generator("contracts/dummy.sol")


if __name__ == "__main__":
    unittest.main()
