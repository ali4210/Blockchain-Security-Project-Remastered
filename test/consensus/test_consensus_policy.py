"""
Task P11-009: Unit tests for Consensus OPA Policy Evaluator.
Validates zero-trust role boundaries: agents may read/correlate,
agents are strictly blocked from mitigations/overrides, human operators
require valid tokens, compliance officers are read-only, and unknown
principals are denied by default.
"""

from pathlib import Path
import unittest

from src.consensus.consensus_policy import ConsensusPolicyEvaluator


class TestConsensusPolicy(unittest.TestCase):
    def setUp(self):
        self.evaluator = ConsensusPolicyEvaluator(rego_policy_path="policy/consensus_boundary.rego")

    def test_rego_policy_file_exists_and_contains_package(self):
        policy_file = Path("policy/consensus_boundary.rego")
        self.assertTrue(policy_file.exists())
        content = policy_file.read_text(encoding="utf-8")
        self.assertIn("package consensus.boundary", content)

    def test_agents_allowed_for_read_and_observe_actions(self):
        for agent in ["agent_b", "agent_e", "agent_g"]:
            for action in ["read", "observe", "correlate", "get_mempool_telemetry", "evaluate_eclipse_status"]:
                result = self.evaluator.evaluate(principal=agent, action=action)
                self.assertTrue(result.allowed, f"Expected {agent} to be allowed for {action}")
                self.assertIn("read-only", result.reason)

    def test_agents_strictly_denied_for_mitigation_actions(self):
        for agent in ["agent_b", "agent_e", "agent_g"]:
            for action in ["mitigate", "evict_peer", "slash_validator", "override_gate", "quarantine_node"]:
                result = self.evaluator.evaluate(principal=agent, action=action)
                self.assertFalse(result.allowed, f"Expected {agent} to be denied for {action}")
                self.assertIn("prohibited", result.reason)

    def test_operator_allowed_with_valid_token(self):
        for op in ["operator", "soc_lead", "soc_operator"]:
            for action in ["mitigate", "evict_peer", "override_gate", "read"]:
                result = self.evaluator.evaluate(principal=op, action=action, token_valid=True)
                self.assertTrue(result.allowed, f"Expected {op} with valid token to be allowed for {action}")
                self.assertIn("authorized", result.reason)

    def test_operator_denied_without_valid_token(self):
        result = self.evaluator.evaluate(principal="operator", action="mitigate", token_valid=False)
        self.assertFalse(result.allowed)
        self.assertIn("missing or invalid credentials", result.reason)

    def test_compliance_officer_boundary(self):
        # Read allowed
        res_read = self.evaluator.evaluate(principal="compliance_officer", action="read")
        self.assertTrue(res_read.allowed)

        # Mitigate denied
        res_mitigate = self.evaluator.evaluate(principal="compliance_officer", action="mitigate")
        self.assertFalse(res_mitigate.allowed)
        self.assertIn("prohibited", res_mitigate.reason)

    def test_unknown_principal_denied(self):
        result = self.evaluator.evaluate(principal="external_attacker", action="read")
        self.assertFalse(result.allowed)
        self.assertIn("Unknown or unauthorized principal", result.reason)


if __name__ == "__main__":
    unittest.main()
