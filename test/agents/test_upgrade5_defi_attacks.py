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

    def test_rug_pull_scanner_invalid_input(self):
        result = rug_pull_scanner(None)
        self.assertEqual(result["status"], "invalid_input")
        self.assertEqual(result["alerts"], [])

    def test_rug_pull_scanner_clean_contract(self):
        clean_ast = {
            "nodes": [
                {
                    "nodeType": "ContractDefinition",
                    "name": "SecureToken",
                    "nodes": [
                        {
                            "nodeType": "FunctionDefinition",
                            "name": "mint",
                            "modifiers": [{"modifierName": {"name": "onlyOwner"}}],
                        },
                        {
                            "nodeType": "FunctionDefinition",
                            "name": "setFee",
                            "fee_cap_basis_points": 500,  # 5% max cap
                        },
                        {
                            "nodeType": "FunctionDefinition",
                            "name": "renounceOwnership",
                            "modifiers": [],
                        },
                    ]
                }
            ]
        }
        result = rug_pull_scanner(clean_ast)
        self.assertEqual(result["status"], "analyzed")
        self.assertEqual(result["alerts"], [])

    def test_rug_pull_scanner_detects_all_four_signatures(self):
        malicious_ast = {
            "nodes": [
                {
                    "nodeType": "ContractDefinition",
                    "name": "RugToken",
                    "nodes": [
                        # 1. Unrestricted mint
                        {
                            "nodeType": "FunctionDefinition",
                            "name": "publicMint",
                            "modifiers": [],
                        },
                        # 2. Untimelocked LP drain
                        {
                            "nodeType": "FunctionDefinition",
                            "name": "emergencyLPWithdraw",
                            "modifiers": [{"modifierName": {"name": "onlyOwner"}}],
                        },
                        # 4. Hidden fee control without hard cap
                        {
                            "nodeType": "FunctionDefinition",
                            "name": "setTax",
                            "fee_cap_basis_points": 9900,  # 99% honeypot fee
                        },
                        # 3. Ownership state variable present without renounce
                        {
                            "nodeType": "VariableDeclaration",
                            "name": "owner",
                        },
                    ]
                }
            ]
        }
        result = rug_pull_scanner(malicious_ast)
        self.assertEqual(result["status"], "analyzed")
        self.assertEqual(len(result["alerts"]), 4)

        risk_types = {a["risk_type"] for a in result["alerts"]}
        expected_types = {"unrestricted_mint", "untimelocked_lp", "unsafe_ownership", "hidden_fee_controls"}
        self.assertEqual(risk_types, expected_types)

    def test_flash_loan_invariant_generator_still_stubbed(self):
        with self.assertRaises(NotImplementedError):
            flash_loan_invariant_generator("contracts/dummy.sol")


if __name__ == "__main__":
    unittest.main()
