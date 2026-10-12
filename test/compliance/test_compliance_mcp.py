"""
Task P13-005: Unit tests for Compliance MCP Server Interface.
Validates:
1. Tool registration and metadata schemas.
2. Execution of compliance_screen_address endpoint.
3. Execution of compliance_evaluate_aml_telemetry endpoint.
4. Execution of compliance_generate_draft_sar with invariant checks.
5. Execution of compliance_verify_zk_attestation endpoint.
6. Rate limiting and invalid parameter rejection.
"""

import time
import unittest

from src.compliance.compliance_mcp import ComplianceMCPRegistry
from src.compliance.zk_attestation import SimpleZKAttestor


class TestComplianceMCP(unittest.TestCase):
    def setUp(self):
        self.mcp = ComplianceMCPRegistry(rate_limit_per_minute=20)

    def test_tool_registration_and_metadata(self):
        tools = self.mcp.get_tool_metadata()
        tool_names = [t["name"] for t in tools]
        self.assertEqual(len(tools), 4)
        self.assertIn("compliance_screen_address", tool_names)
        self.assertIn("compliance_evaluate_aml_telemetry", tool_names)
        self.assertIn("compliance_generate_draft_sar", tool_names)
        self.assertIn("compliance_verify_zk_attestation", tool_names)

    def test_screen_address_via_mcp(self):
        # Ronin Bridge Exploiter address
        addr = "0x098B716B8Aaf21512996dC57EB0615e2383E2f96"
        res = self.mcp.call_tool("compliance_screen_address", {"address": addr})

        self.assertEqual(res["status"], "success")
        data = res["result"]
        self.assertTrue(data["is_flagged"])
        self.assertEqual(data["risk_tier"], "CRITICAL_SANCTIONED")
        self.assertEqual(data["entity_name"], "Ronin Bridge Exploiter")

    def test_evaluate_aml_via_mcp(self):
        txs = [
            {
                "tx_hash": "0xMixerTx",
                "sender": "0xTrader",
                "recipient": "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",
                "value_wei": "1000000000000000000",
                "timestamp": time.time(),
                "block_number": 100,
            }
        ]
        res = self.mcp.call_tool("compliance_evaluate_aml_telemetry", {"transactions": txs})
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["result"]["findings_count"], 1)
        self.assertEqual(res["result"]["findings"][0]["risk_type"], "MIXER_INTERACTION")

    def test_generate_draft_sar_via_mcp(self):
        args = {
            "case_id": "MCP-TEST-001",
            "findings": [
                {"rule_id": "RULE-AML-002", "risk_type": "MIXER_INTERACTION", "description": "Mixer hit"}
            ],
            "subjects": [{"address": "0xTrader", "role": "SENDER", "risk_tier": "CRITICAL"}],
            "transactions": [{"tx_hash": "0xMixerTx", "value_wei": 10**18}],
        }
        res = self.mcp.call_tool("compliance_generate_draft_sar", args)
        self.assertEqual(res["status"], "success")
        sar = res["result"]
        self.assertEqual(sar["status"], "DRAFT_PENDING_REVIEW")
        self.assertEqual(sar["filing_channel"], "LOCAL_STAGING_ONLY")
        self.assertTrue(sar["requires_human_approval"])
        self.assertIsNotNone(sar["draft_digest"])

    def test_verify_zk_attestation_via_mcp(self):
        attestor = SimpleZKAttestor()
        proof, _ = attestor.generate_attestation(
            sender_address="0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
            volume_wei=10**18,
            max_threshold_wei=10**19,
            known_sanctioned_addresses=[],
        )
        res = self.mcp.call_tool(
            "compliance_verify_zk_attestation",
            {
                "proof": {
                    "proof_id": proof.proof_id,
                    "nullifier_hash": proof.nullifier_hash,
                    "address_commitment": proof.address_commitment,
                    "volume_commitment": proof.volume_commitment,
                    "max_threshold_wei": proof.max_threshold_wei,
                    "merkle_root": proof.merkle_root,
                    "challenge": proof.challenge,
                    "response_signature": proof.response_signature,
                    "is_sanctions_free": proof.is_sanctions_free,
                }
            },
        )
        self.assertEqual(res["status"], "success")
        self.assertTrue(res["result"]["is_valid"])

    def test_missing_parameter_fails_gracefully(self):
        res = self.mcp.call_tool("compliance_screen_address", {})
        self.assertEqual(res["status"], "error")
        self.assertIn("Missing required parameter", res["error"])

    def test_unknown_tool_fails_gracefully(self):
        res = self.mcp.call_tool("non_existent_tool", {})
        self.assertEqual(res["status"], "error")
        self.assertIn("not found", res["error"])

    def test_rate_limiting_exhaustion_raises(self):
        tight_mcp = ComplianceMCPRegistry(rate_limit_per_minute=2)
        tight_mcp.call_tool("compliance_screen_address", {"address": "0x1"})
        tight_mcp.call_tool("compliance_screen_address", {"address": "0x2"})
        with self.assertRaises(RuntimeError) as ctx:
            tight_mcp.call_tool("compliance_screen_address", {"address": "0x3"})
        self.assertIn("Rate limit exceeded", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
