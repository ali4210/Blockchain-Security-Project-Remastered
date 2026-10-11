"""
Task P12-009: Verification test for VulnerableWallet fixture.
Ensures that the deliberate vulnerability patterns are accurately identified
by the WalletAuditMcpRegistry engine with appropriate severity levels.
"""

from pathlib import Path
import unittest

from src.wallet.wallet_audit_mcp import WalletAuditMcpRegistry


class TestVulnerableWalletFixture(unittest.TestCase):
    def setUp(self):
        self.mcp = WalletAuditMcpRegistry()
        fixture_path = Path("test/wallet/fixtures/VulnerableWallet.sol")
        self.assertTrue(fixture_path.exists(), "VulnerableWallet.sol fixture file must exist.")
        self.contract_source = fixture_path.read_text(encoding="utf-8")

    def test_audit_identifies_all_deliberate_flaws(self):
        result = self.mcp.call_tool(
            "audit_wallet_contract",
            {
                "contract_source": self.contract_source,
                "contract_name": "VulnerableWallet",
            },
        )

        self.assertEqual(result["contract_name"], "VulnerableWallet")
        self.assertTrue(result["requires_quarantine"])
        self.assertGreaterEqual(result["critical_count"], 3)

        detected_rules = {f["rule_id"] for f in result["findings"]}
        # Flaw 1: Signature Replay
        self.assertIn("RULE-WLT-001", detected_rules)
        # Flaw 2: Zero address ecrecover return
        self.assertIn("RULE-WLT-002", detected_rules)
        # Flaw 3: Arbitrary delegatecall hijacking
        self.assertIn("RULE-WLT-003", detected_rules)
        # Flaw 4: Missing reentrancy in batch
        self.assertIn("RULE-WLT-004", detected_rules)
        # Flaw 5: Signature malleability
        self.assertIn("RULE-WLT-005", detected_rules)


if __name__ == "__main__":
    unittest.main()
