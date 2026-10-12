"""
Task P13-008: Integration tests for Agent B, C, and G compliance capabilities.
Validates:
1. Agent B (Threat Hunter) queries compliance screening/AML telemetry.
2. Agent C (Compliance Judge) synthesizes regulatory framework mapping and draft SAR.
3. Agent G (Guardrail Watchdog) strictly intercepts and blocks autonomous filing or blocking.
"""

import time
import unittest

from src.agents.state import SwarmState
from src.compliance.compliance_mcp import ComplianceMCPRegistry
from src.compliance.compliance_policy import CompliancePolicyEngine
from src.compliance.graph_integrator import ComplianceGraphIntegrator


class TestComplianceAgentIntegrations(unittest.TestCase):
    def setUp(self):
        self.mcp = ComplianceMCPRegistry()
        self.policy_engine = CompliancePolicyEngine()
        self.graph_integrator = ComplianceGraphIntegrator()
        self.now = time.time()

        self.base_state = SwarmState(
            target_contract="0x098B716B8Aaf21512996dC57EB0615e2383E2f96",
            findings=[],
            current_stage="compliance_pipeline",
            escalation_needed=False,
            errors=[],
            metadata={},
        )

    def test_agent_b_threat_hunter_screening_telemetry(self):
        """
        Agent B screens the target address using compliance_screen_address MCP tool.
        """
        target = self.base_state["target_contract"]
        # Agent B executes screening via MCP
        res = self.mcp.call_tool("compliance_screen_address", {"address": target})
        self.assertEqual(res["status"], "success")
        data = res["result"]
        self.assertTrue(data["is_flagged"])
        self.assertEqual(data["risk_tier"], "CRITICAL_SANCTIONED")
        self.assertEqual(data["entity_name"], "Ronin Bridge Exploiter")

        # Findings appended to state via graph integrator
        screening_finding = {
            "finding_id": "FINDING-AGENT-B-COMPLIANCE-001",
            "rule_id": "RULE-COMPLIANCE-SCREEN",
            "severity": "CRITICAL",
            "zone": "ZONE_8_COMPLIANCE",
            "compliance_category": "SANCTIONS_HIT",
            "description": f"Agent B detected sanctioned target {target} ({data['entity_name']})",
        }
        updated_state = {
            **self.base_state,
            "findings": [screening_finding],
            "metadata": {"compliance_summary": {"sanctions_flagged_count": 1}},
        }
        self.assertEqual(len(updated_state["findings"]), 1)
        self.assertEqual(updated_state["findings"][0]["compliance_category"], "SANCTIONS_HIT")

    def test_agent_c_compliance_judge_synthesizes_draft_sar(self):
        """
        Agent C maps findings to FinCEN framework and invokes compliance_generate_draft_sar.
        """
        findings = [
            {
                "rule_id": "RULE-AML-002",
                "risk_type": "MIXER_INTERACTION",
                "description": "Direct interaction with Tornado Cash Vault.",
            }
        ]
        subjects = [
            {
                "address": "0x8576acc5c05d6ce88f4e49bf65bdf0c62f91353c",
                "role": "RECIPIENT",
                "risk_tier": "CRITICAL_SANCTIONED",
                "sanction_category": "OFAC_SDN",
            }
        ]
        txs = [{"tx_hash": "0xMixerTxHash001", "value_wei": 10**19}]

        # Agent C calls draft generator tool
        res = self.mcp.call_tool(
            "compliance_generate_draft_sar",
            {
                "case_id": "AGENT-C-CASE-001",
                "findings": findings,
                "subjects": subjects,
                "transactions": txs,
            },
        )
        self.assertEqual(res["status"], "success")
        draft = res["result"]
        self.assertEqual(draft["status"], "DRAFT_PENDING_REVIEW")
        self.assertEqual(draft["filing_channel"], "LOCAL_STAGING_ONLY")
        self.assertTrue(draft["requires_human_approval"])
        self.assertIn("FINCEN", draft["jurisdiction"])

    def test_agent_g_guardrail_blocks_autonomous_filing(self):
        """
        Agent G evaluates and blocks any autonomous agent attempt to file or approve SAR.
        """
        # Simulated agent attempting unauthorized filing
        for agent in ["agent_b_threat_hunter", "agent_c_compliance_judge"]:
            eval_res = self.policy_engine.evaluate({
                "principal": agent,
                "action": "file_sar_report",
                "current_timestamp": self.now,
                "token": None,
            })
            self.assertFalse(eval_res["allow"])
            self.assertIn("strictly denied", eval_res["reason"])

    def test_agent_g_guardrail_blocks_transaction_censorship(self):
        """
        Agent G strictly denies any action attempting to block on-chain transaction inclusion.
        """
        for agent in ["agent_b_threat_hunter", "agent_c_compliance_judge", "agent_g_guardrail"]:
            eval_res = self.policy_engine.evaluate({
                "principal": agent,
                "action": "block_transaction_inclusion",
                "current_timestamp": self.now,
            })
            self.assertFalse(eval_res["allow"])
            self.assertIn("cannot block blockchain transaction inclusion", eval_res["reason"])


if __name__ == "__main__":
    unittest.main()
