"""
Task P12-008: Unit tests for Wallet Audit MCP Tool Registry.
Validates tool registration, JSON schema compliance, rule detections
(signature replay, ecrecover zero-address, delegatecall), and rate limiting.
"""

import unittest

from src.wallet.wallet_audit_mcp import (
    RateLimitExceededError,
    TokenBucketRateLimiter,
    WalletAuditMcpRegistry,
    WalletAuditRuleEngine,
)


class TestWalletAuditMcp(unittest.TestCase):
    def setUp(self):
        self.mcp = WalletAuditMcpRegistry()

    def test_tool_registration_and_schema_metadata(self):
        tools = self.mcp.list_tools()
        self.assertEqual(len(tools), 1)
        tool = tools[0]
        self.assertEqual(tool["name"], "audit_wallet_contract")
        self.assertIn("contract_source", tool["parameters_schema"]["properties"])
        self.assertIn("contract_source", tool["parameters_schema"]["required"])

    def test_detect_vulnerable_wallet_patterns(self):
        vulnerable_code = """
        contract VulnerableMultiSig {
            function execute(bytes calldata data, uint8 v, bytes32 r, bytes32 s) external {
                bytes32 hash = keccak256(data);
                address signer = ecrecover(hash, v, r, s);
                // Missing zero address check and missing nonce!
                (bool ok, ) = target.delegatecall(data);
            }
        }
        """
        result = self.mcp.call_tool("audit_wallet_contract", {"contract_source": vulnerable_code})

        self.assertGreaterEqual(result["finding_count"], 2)
        self.assertTrue(result["requires_quarantine"])
        self.assertGreater(result["critical_count"], 0)

        rule_ids = {f["rule_id"] for f in result["findings"]}
        self.assertIn("RULE-WLT-001", rule_ids)  # Signature replay / missing nonce
        self.assertIn("RULE-WLT-003", rule_ids)  # Delegatecall

    def test_clean_safe_contract_yields_zero_critical(self):
        clean_code = """
        contract HardenedSafe {
            mapping(uint256 => bool) public nonces;
            function execute(bytes calldata data, uint256 nonce, bytes calldata sig) external {
                require(!nonces[nonce], "Nonce used");
                nonces[nonce] = true;
                bytes32 hash = keccak256(abi.encode(data, nonce, DOMAIN_SEPARATOR));
                address signer = ECDSA.recover(hash, sig);
                require(signer != address(0), "Invalid signer");
            }
        }
        """
        result = self.mcp.call_tool("audit_wallet_contract", {"contract_source": clean_code})
        self.assertEqual(result["critical_count"], 0)
        self.assertFalse(result["requires_quarantine"])

    def test_invalid_arguments_rejected(self):
        with self.assertRaises(ValueError):
            self.mcp.call_tool("audit_wallet_contract", {"contract_source": ""})

    def test_unknown_tool_rejected(self):
        with self.assertRaises(ValueError):
            self.mcp.call_tool("nonexistent_tool", {})

    def test_rate_limiting_exhaustion_raises_error(self):
        limiter = TokenBucketRateLimiter(capacity=2, refill_rate=0.0)
        mcp_limited = WalletAuditMcpRegistry(rate_limiter=limiter)

        mcp_limited.call_tool("audit_wallet_contract", {"contract_source": "contract Test {}"})
        mcp_limited.call_tool("audit_wallet_contract", {"contract_source": "contract Test {}"})

        with self.assertRaises(RateLimitExceededError):
            mcp_limited.call_tool("audit_wallet_contract", {"contract_source": "contract Test {}"})


if __name__ == "__main__":
    unittest.main()
