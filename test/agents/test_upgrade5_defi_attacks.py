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
                            "name": "renounceOwnership",
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
                        {"nodeType": "FunctionDefinition", "name": "publicMint"},
                        {"nodeType": "FunctionDefinition", "name": "emergencyLPWithdraw"},
                        {"nodeType": "FunctionDefinition", "name": "setTax", "fee_cap_basis_points": 9900},
                        {"nodeType": "VariableDeclaration", "name": "owner"},
                    ]
                }
            ]
        }
        result = rug_pull_scanner(malicious_ast)
        self.assertEqual(result["status"], "analyzed")
        self.assertEqual(len(result["alerts"]), 4)

    def test_flash_loan_invariant_generator_default(self):
        res = flash_loan_invariant_generator("contracts/solidity/VulnerableVault.sol")
        self.assertEqual(res["status"], "generated")
        self.assertEqual(res["test_contract_name"], "VulnerableVaultFlashLoanInvariantTest")
        self.assertIn("contract VulnerableVaultFlashLoanInvariantTest", res["generated_code"])
        self.assertIn("invariant_protocolSolvencyPostFlashLoan", res["properties_asserted"])
        self.assertIn("invariant_reservesBoundedByOracleTolerance", res["properties_asserted"])
        self.assertEqual(res["parameters"]["pool_token"], "WETH")

    def test_flash_loan_invariant_generator_custom_params(self):
        custom_params = {
            "max_flash_loan": "500_000 ether",
            "pool_token": "USDC",
            "oracle_tolerance_bps": 100
        }
        res = flash_loan_invariant_generator("contracts/solidity/LendingPool.sol", custom_params)
        self.assertEqual(res["status"], "generated")
        self.assertEqual(res["test_contract_name"], "LendingPoolFlashLoanInvariantTest")
        self.assertIn("uint256 internal constant MAX_FLASH_LOAN = 500_000 ether;", res["generated_code"])
        self.assertIn("uint256 internal constant ORACLE_TOLERANCE_BPS = 100;", res["generated_code"])
        self.assertEqual(res["parameters"]["pool_token"], "USDC")


if __name__ == "__main__":
    unittest.main()
