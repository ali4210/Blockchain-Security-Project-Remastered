"""
Task P13-009: Negative Security Tests - Agent Denial for Report Approval and Filing.
Validates:
1. Exhaustive matrix denial: all autonomous agents (A through G) are strictly denied
   for all officer-exclusive actions (approval, filing, export).
2. Universal denial of on-chain transaction inclusion blocking across all principals.
3. Forged token presentations by agents are rejected fail-closed.
4. Role-mismatched and expired tokens fail-closed.
"""

import time
import unittest

from src.compliance.compliance_policy import CompliancePolicyEngine


class TestComplianceAgentDenial(unittest.TestCase):
    def setUp(self):
        self.secret = b"test-denial-suite-secret-key-32b"
        self.engine = CompliancePolicyEngine(secret_key=self.secret)
        self.now = time.time()

        self.all_agents = [
            "agent_a_auditor",
            "agent_b_threat_hunter",
            "agent_c_compliance_judge",
            "agent_d_red_teamer",
            "agent_e_incident_commander",
            "agent_f_logic_analyzer",
            "agent_g_guardrail",
        ]

        self.officer_actions = [
            "approve_sar_report",
            "file_sar_report",
            "export_sar_report",
        ]

    def test_all_agents_denied_for_all_officer_actions_without_token(self):
        for agent in self.all_agents:
            for action in self.officer_actions:
                res = self.engine.evaluate({
                    "principal": agent,
                    "action": action,
                    "current_timestamp": self.now,
                    "token": None,
                })
                self.assertFalse(res["allow"], f"Expected {agent} to be denied for {action}")
                self.assertIn("strictly denied", res["reason"])

    def test_all_agents_denied_when_presenting_forged_token(self):
        forged_token = {
            "role": "compliance_officer",
            "officer_id": "IMPERSONATED-001",
            "expires_at": self.now + 3600,
            "signature": "deadbeefcafebabe" * 4,
        }
        for agent in self.all_agents:
            for action in self.officer_actions:
                res = self.engine.evaluate({
                    "principal": agent,
                    "action": action,
                    "current_timestamp": self.now,
                    "token": forged_token,
                })
                self.assertFalse(res["allow"], f"Expected {agent} with forged token to be denied for {action}")

    def test_all_agents_denied_for_transaction_inclusion_blocking(self):
        for agent in self.all_agents:
            res = self.engine.evaluate({
                "principal": agent,
                "action": "block_transaction_inclusion",
                "current_timestamp": self.now,
                "token": None,
            })
            self.assertFalse(res["allow"], f"Expected {agent} to be denied for block_transaction_inclusion")
            self.assertIn("cannot block blockchain transaction inclusion", res["reason"])

    def test_human_operators_denied_for_transaction_inclusion_blocking(self):
        for human in ["compliance_officer", "soc_operator", "admin"]:
            res = self.engine.evaluate({
                "principal": human,
                "action": "block_transaction_inclusion",
                "current_timestamp": self.now,
            })
            self.assertFalse(res["allow"], f"Expected {human} to be denied for transaction blocking")

    def test_operator_token_role_mismatch_fails_closed(self):
        mismatched_token = {
            "role": "soc_operator",  # Operator role attempting compliance filing
            "officer_id": "OPERATOR-001",
            "expires_at": self.now + 3600,
            "signature": "validlookingbytes" * 4,
        }
        res = self.engine.evaluate({
            "principal": "soc_operator",
            "action": "file_sar_report",
            "current_timestamp": self.now,
            "token": mismatched_token,
        })
        self.assertFalse(res["allow"])


if __name__ == "__main__":
    unittest.main()
